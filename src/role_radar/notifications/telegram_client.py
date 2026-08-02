"""Small Telegram Bot API adapter; no selection, SQL, or sensitive logging."""

import httpx
from pydantic import SecretStr

from role_radar.notifications.contracts import (
    Accepted,
    Indeterminate,
    PermanentFailure,
    RateLimited,
    TelegramDeliveryResult,
    TelegramSendRequest,
)

TELEGRAM_API_BASE = "https://api.telegram.org"


class TelegramClient:
    def __init__(
        self,
        bot_token: SecretStr,
        chat_id: SecretStr,
        *,
        http_client: httpx.AsyncClient | None = None,
        timeout: float = 30.0,
        retry_after_max_seconds: int = 300,
    ) -> None:
        self._token = bot_token.get_secret_value()
        self._chat_id = chat_id.get_secret_value()
        self._client = http_client or httpx.AsyncClient(base_url=TELEGRAM_API_BASE, timeout=timeout)
        self._owns_client = http_client is None
        self._retry_after_max = retry_after_max_seconds

    async def send_message(self, request: TelegramSendRequest) -> TelegramDeliveryResult:
        payload = {
            "chat_id": self._chat_id,
            "text": request.body,
            "parse_mode": request.parse_mode,
            "link_preview_options": {"is_disabled": request.disable_web_page_preview},
            "protect_content": request.protect_content,
        }
        try:
            response = await self._client.post(
                f"{TELEGRAM_API_BASE}/bot{self._token}/sendMessage", json=payload
            )
        except httpx.TimeoutException:
            return Indeterminate("timeout")
        except httpx.NetworkError:
            return Indeterminate("network_error")
        except httpx.HTTPError:
            return Indeterminate("http_error")
        if response.status_code == 429:
            try:
                data = response.json()
            except (ValueError, TypeError):
                return Indeterminate("malformed_rate_limit", 429)
            retry_after = _retry_after(data, self._retry_after_max)
            if retry_after is None:
                return Indeterminate("malformed_rate_limit", 429)
            return RateLimited(retry_after)
        if 500 <= response.status_code <= 599:
            return Indeterminate("http_5xx", response.status_code)
        if response.status_code != 200:
            return PermanentFailure(_http_error_code(response.status_code), response.status_code)
        try:
            data = response.json()
            message_id = data["result"]["message_id"]
            if data.get("ok") is not True or not isinstance(message_id, int) or message_id <= 0:
                return Indeterminate("malformed_success", 200)
            return Accepted(message_id)
        except (ValueError, KeyError, TypeError):
            return Indeterminate("malformed_response", 200)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


def _retry_after(data: object, maximum: int) -> int | None:
    try:
        value = data["parameters"]["retry_after"]  # type: ignore[index]
    except (KeyError, TypeError, ValueError):
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return max(1, min(value, maximum))


def _http_error_code(status: int) -> str:
    return {400: "bad_request", 401: "unauthorized", 403: "forbidden"}.get(status, "http_4xx")


TelegramHttpClient = TelegramClient
