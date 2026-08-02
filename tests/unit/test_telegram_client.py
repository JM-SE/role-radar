import httpx
import pytest
from pydantic import SecretStr

from role_radar.notifications.contracts import (
    Accepted,
    Indeterminate,
    RateLimited,
    TelegramSendRequest,
)
from role_radar.notifications.telegram_client import TelegramClient


@pytest.mark.asyncio
async def test_client_posts_exact_safe_send_message_payload() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 42}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        gateway = TelegramClient(SecretStr("token"), SecretStr("chat"), http_client=client)
        result = await gateway.send_message(TelegramSendRequest("<b>hello</b>"))
    assert isinstance(result, Accepted)
    assert len(requests) == 1
    assert requests[0].url == "https://api.telegram.org/bottoken/sendMessage"
    assert requests[0].content == (
        b'{"chat_id":"chat","text":"<b>hello</b>","parse_mode":"HTML",'
        b'"link_preview_options":{"is_disabled":true},"protect_content":true}'
    )


@pytest.mark.asyncio
async def test_client_marks_malformed_success_indeterminate() -> None:
    transport = httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True, "result": {}}))
    async with httpx.AsyncClient(transport=transport) as client:
        result = await TelegramClient(
            SecretStr("t"), SecretStr("c"), http_client=client
        ).send_message(TelegramSendRequest("body"))
    assert isinstance(result, Indeterminate)


@pytest.mark.asyncio
async def test_client_marks_server_error_indeterminate() -> None:
    transport = httpx.MockTransport(lambda _: httpx.Response(503, text="unavailable"))
    async with httpx.AsyncClient(transport=transport) as client:
        result = await TelegramClient(
            SecretStr("t"), SecretStr("c"), http_client=client
        ).send_message(TelegramSendRequest("body"))
    assert result == Indeterminate("http_5xx", 503)


@pytest.mark.asyncio
async def test_client_marks_malformed_rate_limit_indeterminate() -> None:
    transport = httpx.MockTransport(lambda _: httpx.Response(429, json={"ok": False}))
    async with httpx.AsyncClient(transport=transport) as client:
        result = await TelegramClient(
            SecretStr("t"), SecretStr("c"), http_client=client
        ).send_message(TelegramSendRequest("body"))
    assert result == Indeterminate("malformed_rate_limit", 429)


@pytest.mark.asyncio
async def test_client_bounds_valid_rate_limit() -> None:
    transport = httpx.MockTransport(
        lambda _: httpx.Response(429, json={"parameters": {"retry_after": 999}})
    )
    async with httpx.AsyncClient(transport=transport) as client:
        result = await TelegramClient(
            SecretStr("t"), SecretStr("c"), http_client=client, retry_after_max_seconds=30
        ).send_message(TelegramSendRequest("body"))
    assert result == RateLimited(30)
