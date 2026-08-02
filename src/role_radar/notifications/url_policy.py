"""Strict, side-effect-free policy for application links."""

from urllib.parse import urlsplit, urlunsplit

MAX_APPLICATION_URL_LENGTH = 2048


def canonical_application_url(value: str | None) -> str | None:
    if not value or len(value) > MAX_APPLICATION_URL_LENGTH:
        return None
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            return None
        canonical = urlunsplit(("https", parsed.netloc, parsed.path, parsed.query, ""))
        return canonical if len(canonical) <= MAX_APPLICATION_URL_LENGTH else None
    except ValueError:
        return None


def is_notifiable_application_url(value: str | None) -> bool:
    return canonical_application_url(value) is not None
