"""Pure DTOs for the notification boundary.

ORM objects and HTTP clients deliberately do not cross this boundary.
"""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class DigestCandidate:
    job_id: str
    job_score_id: str
    deep_evaluation_id: str
    title: str
    company: str
    location: str | None
    application_url: str
    final_score: int
    preliminary_score: int
    first_seen_at: object
    strengths: tuple[str, ...] = ()
    gaps: tuple[str, ...] = ()
    model_concerns: tuple[str, ...] = ()
    uncertainties: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TelegramSendRequest:
    body: str
    parse_mode: str = "HTML"
    disable_web_page_preview: bool = True
    protect_content: bool = True


@dataclass(frozen=True, slots=True)
class Accepted:
    message_id: int


@dataclass(frozen=True, slots=True)
class RateLimited:
    retry_after: int


@dataclass(frozen=True, slots=True)
class DefinitePreSendFailure:
    code: str


@dataclass(frozen=True, slots=True)
class PermanentFailure:
    code: str
    status: int


@dataclass(frozen=True, slots=True)
class Indeterminate:
    code: str
    status: int | None = None


TelegramDeliveryResult = (
    Accepted | RateLimited | DefinitePreSendFailure | PermanentFailure | Indeterminate
)


class TelegramGateway(Protocol):
    async def send_message(self, request: TelegramSendRequest) -> TelegramDeliveryResult:
        """Submit one already prepared digest."""
