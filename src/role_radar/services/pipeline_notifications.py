"""Worker boundary for the notification stage."""

from collections.abc import Callable

from sqlalchemy.orm import Session

from role_radar.config import Settings
from role_radar.db.models import NotificationBatch
from role_radar.notifications.contracts import TelegramGateway
from role_radar.services.notification_service import NotificationService


class PipelineNotificationService:
    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        settings: Settings,
        gateway: TelegramGateway,
    ) -> None:
        self._service = NotificationService(session_factory, settings=settings)
        self._settings = settings
        self._gateway = gateway

    async def process(
        self, run_id: str, *, recipient_key: str
    ) -> tuple[NotificationBatch, ...]:
        return await self._service.process(
            run_id, recipient_key=recipient_key, gateway=self._gateway
        )
