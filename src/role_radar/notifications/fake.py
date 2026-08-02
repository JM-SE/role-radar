"""Offline Telegram gateway used by tests and local development."""

from collections.abc import Iterable

from role_radar.notifications.contracts import (
    Accepted,
    Indeterminate,
    TelegramDeliveryResult,
    TelegramSendRequest,
)


class FakeTelegramGateway:
    def __init__(self, results: Iterable[TelegramDeliveryResult] | None = None) -> None:
        self.calls: list[TelegramSendRequest] = []
        self._results = list(results or [])

    async def send_message(self, request: TelegramSendRequest) -> TelegramDeliveryResult:
        self.calls.append(request)
        if self._results:
            return self._results.pop(0)
        return Accepted(len(self.calls))


class DisabledTelegramGateway:
    async def send_message(self, request: TelegramSendRequest) -> TelegramDeliveryResult:
        del request
        return Indeterminate("telegram_disabled")
