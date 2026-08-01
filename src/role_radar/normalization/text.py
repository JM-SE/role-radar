"""Normalización de texto y descripciones HTML usando solo la stdlib."""

import re
from hashlib import sha256
from html import unescape
from html.parser import HTMLParser

_WHITESPACE = re.compile(r"\s+")


def normalize_whitespace(value: str) -> str:
    """Colapsa whitespace y elimina espacios en los extremos."""
    return _WHITESPACE.sub(" ", value).strip()


class _TextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"br", "p", "div", "li", "section", "article", "h1", "h2", "h3"}:
            self.parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"p", "div", "li", "section", "article", "h1", "h2", "h3"}:
            self.parts.append(" ")


def html_to_text(html: str) -> str:
    """Convierte HTML a texto plano y colapsa el whitespace resultante."""
    parser = _TextParser()
    parser.feed(unescape(html))
    parser.close()
    return normalize_whitespace("".join(parser.parts))


def normalize_company(value: str) -> str:
    return normalize_whitespace(value)


def normalize_title(value: str) -> str:
    return normalize_whitespace(value)


def normalize_location(value: str | None) -> tuple[str | None, str | None]:
    if value is None:
        return None, None
    display = normalize_whitespace(value)
    if not display:
        return None, None
    return display, display.casefold()


def description_hash(text: str | None) -> str | None:
    """Calcula SHA-256 del texto normalizado, o ``None`` si está vacío."""
    if text is None:
        return None
    normalized = normalize_whitespace(text)
    if not normalized:
        return None
    return sha256(normalized.encode("utf-8")).hexdigest()
