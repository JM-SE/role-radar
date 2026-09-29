"""Deterministic one-message Telegram HTML renderer."""

from dataclasses import dataclass
from hashlib import sha256
from html import escape

from role_radar.notifications.contracts import DigestCandidate

FORMATTER_VERSION = "telegram-digest-v2"
LEGACY_DIGEST_FORMATTER_VERSION = "telegram-digest-v1"
ALERT_FORMATTER_VERSION = "telegram-match-alert-v1"
TELEGRAM_MESSAGE_MAX_UNITS = 4096
DISPLAY_TITLE_MAX = 180
DISPLAY_COMPANY_MAX = 120
DISPLAY_LOCATION_MAX = 100
DISPLAY_DETAIL_MAX = 180


@dataclass(frozen=True, slots=True)
class FormattedDigest:
    body: str
    candidates: tuple[DigestCandidate, ...]
    level: int

    @property
    def body_hash(self) -> str:
        return sha256(self.body.encode("utf-8")).hexdigest()


def utf16_units(value: str) -> int:
    return len(value.encode("utf-16-le")) // 2


def format_digest(
    candidates: tuple[DigestCandidate, ...] | list[DigestCandidate],
    *,
    max_units: int = TELEGRAM_MESSAGE_MAX_UNITS,
    heading: str = "Daily digest",
) -> FormattedDigest | None:
    source = tuple(candidates)
    if not source:
        return None
    for level in range(4):
        for count in range(len(source), 0, -1):
            chosen = source[:count]
            body = _render(chosen, level, heading=heading)
            if utf16_units(body) <= max_units:
                return FormattedDigest(body, chosen, level)
    # A bounded minimal representation is still rendered from fields, never sliced HTML.
    for count in range(len(source), 0, -1):
        chosen = source[:count]
        body = _render(chosen, 3, caps=True, heading=heading)
        if utf16_units(body) <= max_units:
            return FormattedDigest(body, chosen, 3)
    return None


def format_digest_batches(
    candidates: tuple[DigestCandidate, ...] | list[DigestCandidate],
    *,
    max_units: int = TELEGRAM_MESSAGE_MAX_UNITS,
    max_items: int = 5,
    heading: str = "Daily digest",
) -> tuple[FormattedDigest, ...]:
    """Render every candidate into ordered bounded Telegram messages."""
    if max_items < 1:
        raise ValueError("digest_max_items_invalid")
    remaining = tuple(candidates)
    batches: list[FormattedDigest] = []
    while remaining:
        limit = min(max_items, len(remaining))
        rendered: FormattedDigest | None = None
        for count in range(limit, 0, -1):
            candidate = format_digest(
                remaining[:count], max_units=max_units, heading=heading
            )
            if candidate is not None and len(candidate.candidates) == count:
                rendered = candidate
                break
        if rendered is None:
            raise ValueError("digest_candidate_unrenderable")
        batches.append(rendered)
        remaining = remaining[len(rendered.candidates) :]
    return tuple(batches)


def _render(
    items: tuple[DigestCandidate, ...],
    level: int,
    *,
    caps: bool = False,
    heading: str = "Daily digest",
) -> str:
    lines = [f"<b>{escape(_text(heading, 80), quote=True)}</b>"]
    for index, item in enumerate(items, 1):
        title = _text(item.title, DISPLAY_TITLE_MAX if caps or level >= 3 else None)
        company = _text(item.company, DISPLAY_COMPANY_MAX if caps or level >= 3 else None)
        location = _text(item.location or "", DISPLAY_LOCATION_MAX if caps or level >= 3 else None)
        url = escape(item.application_url, quote=True)
        lines.append(f'\n<b>{index}. {escape(title, quote=True)}</b> — <a href="{url}">Apply</a>')
        if level < 3 and company:
            lines.append(f"\n{escape(company, quote=True)}")
        if level < 2 and location:
            lines.append(f" · {escape(location, quote=True)}")
        if heading == "New Role Radar matches":
            publication = (
                f"Published {item.published_at.date().isoformat()}"
                if item.published_at is not None
                else "Detected recently; publication date unavailable"
            )
            explanation = item.match_explanation or (
                "Role fit and Argentina location/work mode passed the active profile's rules. "
                "This is not a legal work-authorization guarantee; verify terms with the employer."
            )
            lines.append(f"\n{escape(publication, quote=True)}")
            lines.append(f"\n{escape(_text(explanation, DISPLAY_DETAIL_MAX), quote=True)}")
        if level < 2:
            strengths = item.strengths[: (1 if level == 1 else 2)]
            if strengths:
                lines.append(
                    "\nStrengths: "
                    + ", ".join(escape(_text(x, DISPLAY_DETAIL_MAX), quote=True) for x in strengths)
                )
            attention = (item.gaps[:1] + item.model_concerns[:1] + item.uncertainties[:1])[:1]
            if attention:
                lines.append(
                    "\nAttention: " + escape(_text(attention[0], DISPLAY_DETAIL_MAX), quote=True)
                )
        elif level == 2:
            strength = item.strengths[:1]
            if strength:
                lines.append(
                    "\nStrengths: " + escape(_text(strength[0], DISPLAY_DETAIL_MAX), quote=True)
                )
    return "".join(lines)


def _text(value: str, limit: int | None = None) -> str:
    value = str(value)
    if limit is not None and len(value) > limit:
        return value[: max(0, limit - 1)] + "…"
    return value
