"""Entrypoint de proceso del worker (no ejecuta migraciones)."""

import asyncio
import signal

from role_radar.broker.factory import create_deep_llm_provider, create_llm_provider
from role_radar.config import Settings
from role_radar.db.engine import get_engine
from role_radar.db.session import get_session_factory
from role_radar.notifications.contracts import TelegramGateway
from role_radar.notifications.fake import FakeTelegramGateway
from role_radar.notifications.telegram_client import TelegramClient
from role_radar.worker.pipeline import Pipeline
from role_radar.worker.runner import WorkerRunner


def run_worker(settings: Settings | None = None) -> None:
    current = settings or Settings()
    engine = get_engine(current.database_url)
    factory = get_session_factory(engine)
    provider = create_llm_provider(current)
    deep_provider = create_deep_llm_provider(current)
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
        engine.dispose()
