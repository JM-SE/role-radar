"""Normalización de URLs sin acceso a red."""

from urllib.parse import (
    parse_qsl,
    urlencode,
    urlsplit,
    urlunsplit,
)

TRACKING_PARAMS = frozenset(
    {"gclid", "fbclid", "ref", "mc_cid", "mc_eid", "_ga", "yclid"}
)


def clean_url(url: str | None) -> str | None:
    """Devuelve una URL HTTP(S) sin parámetros de tracking ni fragmento."""
    if url is None or not url.strip():
        return None

    value = url.strip()
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None

    query = [
        (key, item)
        for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        if not (key.lower().startswith("utm_") or key.lower() in TRACKING_PARAMS)
    ]
    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc,
            parsed.path or "/",
            urlencode(query),
            "",
        )
    )
