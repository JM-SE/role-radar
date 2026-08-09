"""Entrypoint de proceso del worker (no ejecuta migraciones)."""

import asyncio
import os
import signal
from pathlib import Path

from role_radar.broker.factory import create_deep_llm_provider, create_llm_provider
from role_radar.config import Settings
from role_radar.db.engine import get_engine
from role_radar.db.session import get_session_factory
from role_radar.discovery.acquisition_config import AcquisitionConfigError, load_acquisition_config
from role_radar.discovery.credentials import (
    CredentialError,
    read_worker_secret,
    resolve_worker_credentials,
)
from role_radar.discovery.providers.brave import BraveSearchProvider
from role_radar.discovery.providers.tavily import TavilySearchProvider
from role_radar.mailbox.configuration import FileCredentialResolver
from role_radar.notifications.contracts import TelegramGateway
from role_radar.notifications.fake import FakeTelegramGateway
from role_radar.notifications.telegram_client import TelegramClient
from role_radar.services.acquisition_budget_service import AcquisitionBudgetService
from role_radar.services.search_routing_service import SearchRoutingService
from role_radar.worker.pipeline import Pipeline
from role_radar.worker.runner import WorkerRunner


def run_worker(settings: Settings | None = None) -> None:
    current = settings or Settings()
    engine = get_engine(current.database_url)
    factory = get_session_factory(engine)
    provider = create_llm_provider(current)
    deep_provider = create_deep_llm_provider(current)
    brave_search = tavily_search = None
    discovery_provider = None
    discovery_hmac: bytes | None = None
    acquisition_config = None
    mailbox_descriptor_resolver = None
    mailbox_credential_resolver = None
    mailbox_url_hmac_key = mailbox_content_hmac_key = None
    try:
        acquisition_config = load_acquisition_config(current.acquisition_config_path)
        credential_dir = os.environ.get("CREDENTIALS_DIRECTORY")
        local_credential_dir = "/etc/role-radar/credentials"
        credentials = resolve_worker_credentials(
            brave_path=(
                f"{credential_dir}/brave_api_key"
                if credential_dir
                else f"{local_credential_dir}/brave_api_key"
            ),
            tavily_path=(
                f"{credential_dir}/tavily_api_key"
                if credential_dir
                else f"{local_credential_dir}/tavily_api_key"
            ),
            hmac_path=(
                f"{credential_dir}/query_hmac_key"
                if credential_dir
                else f"{local_credential_dir}/query_hmac_key"
            ),
        )
        brave_search = BraveSearchProvider(credentials.brave_api_key.get_secret_value())
        tavily_search = TavilySearchProvider(credentials.tavily_api_key.get_secret_value())
        asyncio.run(brave_search.__aenter__())
        asyncio.run(tavily_search.__aenter__())
        discovery_hmac = credentials.query_hmac_key
        discovery_provider = SearchRoutingService(
            factory,
            brave=brave_search,
            tavily=tavily_search,
            budget=AcquisitionBudgetService(factory, acquisition_config),
            config=acquisition_config,
        )
    except (AcquisitionConfigError, CredentialError, OSError, UnicodeError):
        # Credentialed acquisition is fail-closed; the rest of the worker runs.
        discovery_provider = None
    if acquisition_config is not None and acquisition_config.mailboxes:
        try:
            credential_dir = os.environ.get(
                "CREDENTIALS_DIRECTORY", "/etc/role-radar/credentials"
            )
            mailbox_descriptors = {
                alias: descriptor.descriptor()
                for alias, descriptor in acquisition_config.mailboxes.items()
            }
            mailbox_descriptor_resolver = mailbox_descriptors.__getitem__
            handles = {
                handle
                for descriptor in mailbox_descriptors.values()
                for handle in (
                    descriptor.username_handle,
                    descriptor.oauth2_handle,
                    descriptor.app_password_handle,
                )
                if handle is not None
            }
            mailbox_credential_resolver = FileCredentialResolver(
                {handle: Path(credential_dir) / handle for handle in handles}
            )
            first_descriptor = next(iter(mailbox_descriptors.values()))
            mailbox_url_hmac_key = read_worker_secret(
                str(Path(credential_dir) / first_descriptor.message_hmac_handle)
            )
            mailbox_content_hmac_key = read_worker_secret(
                str(Path(credential_dir) / first_descriptor.content_hmac_handle)
            )
        except (CredentialError, OSError, UnicodeError, ValueError):
            # Gmail remains disabled without changing the rest of acquisition.
            mailbox_descriptor_resolver = mailbox_credential_resolver = None
            mailbox_url_hmac_key = mailbox_content_hmac_key = None
    gateway: TelegramGateway | None = None
    if current.telegram_provider == "fake":
        gateway = FakeTelegramGateway()
    elif current.telegram_provider == "http":
        assert current.telegram_bot_token is not None and current.telegram_chat_id is not None
        gateway = TelegramClient(
            current.telegram_bot_token,
            current.telegram_chat_id,
            timeout=current.http_timeout_seconds,
            retry_after_max_seconds=current.telegram_retry_after_max_seconds,
        )
    runner = WorkerRunner(
        factory,
        Pipeline(
            factory,
            provider=provider,
            deep_provider=deep_provider,
            settings=current,
            notification_gateway=gateway,
            notification_recipient=(
                current.telegram_chat_id.get_secret_value()
                if current.telegram_chat_id
                else "disabled"
            ),
            discovery_provider=discovery_provider,
            discovery_query_key_secret=discovery_hmac,
            free_source_terms=(
                acquisition_config.jobicy.acceptance()
                if acquisition_config is not None and acquisition_config.jobicy is not None
                else None
            ),
            mailbox_descriptor_resolver=mailbox_descriptor_resolver,
            mailbox_credential_resolver=mailbox_credential_resolver,
            mailbox_url_hmac_key=mailbox_url_hmac_key,
            mailbox_content_hmac_key=mailbox_content_hmac_key,
        ),
        settings=current,
    )
    stop = asyncio.Event()

    def request_stop(_signal: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        asyncio.run(runner.run_forever(stop))
    finally:
        close = getattr(provider, "aclose", None)
        if close is not None:
            asyncio.run(close())
        close_deep = getattr(deep_provider, "aclose", None)
        if close_deep is not None:
            asyncio.run(close_deep())
        close_gateway = getattr(gateway, "aclose", None)
        if close_gateway is not None:
            asyncio.run(close_gateway())
        if brave_search is not None:
            asyncio.run(brave_search.aclose())
        if tavily_search is not None:
            asyncio.run(tavily_search.aclose())
        engine.dispose()
