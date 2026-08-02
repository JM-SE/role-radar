"""Deterministic one-message Telegram HTML renderer."""

from dataclasses import dataclass
from hashlib import sha256
from html import escape

from role_radar.notifications.contracts import DigestCandidate

FORMATTER_VERSION = "telegram-digest-v1"
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
) -> FormattedDigest | None:
    source = tuple(candidates)
    if not source:
        return None
    for level in range(4):
        for count in range(len(source), 0, -1):
            chosen = source[:count]
            body = _render(chosen, level)
            if utf16_units(body) <= max_units:
                return FormattedDigest(body, chosen, level)
    # A bounded minimal representation is still rendered from fields, never sliced HTML.
    for count in range(len(source), 0, -1):
        chosen = source[:count]
        body = _render(chosen, 3, caps=True)
        if utf16_units(body) <= max_units:
            return FormattedDigest(body, chosen, 3)
    return None


def _render(items: tuple[DigestCandidate, ...], level: int, *, caps: bool = False) -> str:
    lines = ["<b>Daily digest</b>"]
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
