"""Entrypoint de proceso del worker (no ejecuta migraciones)."""

import asyncio
import signal
from collections.abc import Callable
from typing import Any

from sqlalchemy.orm import Session

from role_radar.acquisition.configuration import (
    AcquisitionConfig,
    AcquisitionConfigError,
    ProductionAcquisitionFilePolicy,
    load_acquisition_config,
)
from role_radar.acquisition.credentials import CredentialError
from role_radar.acquisition.discovery_policy import (
    DiscoveryPolicyFileError,
    load_discovery_policy,
    production_discovery_policy_file_policy,
)
from role_radar.broker.factory import create_deep_llm_provider, create_llm_provider
from role_radar.config import Settings
from role_radar.db.engine import get_engine
from role_radar.db.session import get_session_factory
from role_radar.mailbox.contracts import CredentialMaterial, MailboxDescriptor
from role_radar.notifications.contracts import TelegramGateway
from role_radar.notifications.fake import FakeTelegramGateway
from role_radar.notifications.telegram_client import TelegramClient
from role_radar.services.acquisition_budget_service import AcquisitionBudgetService
from role_radar.services.search_routing_service import SearchRoutingService
from role_radar.worker.acquisition import compose_acquisition_capabilities
from role_radar.worker.pipeline import Pipeline
from role_radar.worker.runner import WorkerRunner


def compose_discovery_provider(
    session_factory: Callable[[], Session],
    *,
    brave_search: Any | None = None,
    tavily_search: Any | None = None,
    query_hmac: bytes | None = None,
    acquisition_config: AcquisitionConfig | None = None,
) -> SearchRoutingService | None:
    """Compose the daily discovery provider.

    Returns None when the HMAC secret, both search providers, or the
    acquisition config is unavailable, keeping discovery advisory-only.
    """

    if query_hmac is None:
        return None
    if brave_search is None and tavily_search is None:
        return None
    if acquisition_config is None:
        return None
    return SearchRoutingService(
        session_factory,
        brave=brave_search,
        tavily=tavily_search,
        budget=AcquisitionBudgetService(session_factory, acquisition_config),
        config=acquisition_config,
    )


def load_discovery_policy_v1() -> Any | None:
    """Load the operator-owned v2 discovery policy, or None when unavailable."""

    try:
        loaded = load_discovery_policy(
            file_policy=production_discovery_policy_file_policy(),
        )
    except DiscoveryPolicyFileError:
        return None
    return loaded.policy


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
    discovery_policy_v1 = load_discovery_policy_v1()
    mailbox_descriptor_resolver = None
    mailbox_credential_resolver = None
    mailbox_hmac_keys: dict[str, tuple[bytes, bytes]] = {}
    try:
        acquisition_config = load_acquisition_config(
            current.acquisition_config_path,
            policy=ProductionAcquisitionFilePolicy(),
        )
        capabilities = compose_acquisition_capabilities(acquisition_config)
        brave_search = capabilities.brave
        tavily_search = capabilities.tavily
        discovery_hmac = capabilities.query_hmac
        if brave_search is not None:
            asyncio.run(brave_search.__aenter__())
        if tavily_search is not None:
            asyncio.run(tavily_search.__aenter__())
        discovery_provider = compose_discovery_provider(
            factory,
            brave_search=brave_search,
            tavily_search=tavily_search,
            query_hmac=discovery_hmac,
            acquisition_config=acquisition_config,
        )
        mailbox_descriptor_resolver = capabilities.mailbox_descriptors.get
        if capabilities.mailbox_credentials is not None:
            credential_provider = capabilities.mailbox_credentials

            def resolve_mailbox_credential(descriptor: MailboxDescriptor) -> CredentialMaterial:
                alias = descriptor.connection_alias
                return credential_provider(alias)

            mailbox_credential_resolver = resolve_mailbox_credential
            mailbox_hmac_keys = dict(capabilities.mailbox_hmacs)
    except (AcquisitionConfigError, CredentialError, OSError, UnicodeError, ValueError):
        # Config/credential failures block only acquisition; the worker heartbeat survives.
        discovery_provider = None
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
            discovery_policy_v1=discovery_policy_v1,
            free_source_terms=capabilities.jobicy_terms if acquisition_config is not None else None,
            mailbox_descriptor_resolver=mailbox_descriptor_resolver,
            mailbox_credential_resolver=mailbox_credential_resolver,
            mailbox_hmac_keys=mailbox_hmac_keys,
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
