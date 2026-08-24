"""Inert HTML parsing and deterministic visible-text layout for display v2."""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser

from role_radar.evaluation.blind_labeling.display_policy import (
    DISPLAY_BLOCK_TAGS,
    DISPLAY_BREAK_TAG,
    DISPLAY_ERROR_ENTITY_INVALID,
    DISPLAY_ERROR_HTML_DEPTH_EXCEEDED,
    DISPLAY_ERROR_HTML_MALFORMED,
    DISPLAY_ERROR_OUTPUT_TOO_LARGE,
    DISPLAY_ERROR_PARSE_LIMIT_EXCEEDED,
    DISPLAY_HTML_VOID_TAGS,
    DISPLAY_LIST_CONTAINER_TAGS,
    DISPLAY_LIST_ITEM_TAG,
    DISPLAY_MAX_FIELD_OUTPUT_BYTES,
    DISPLAY_MAX_HTML_DEPTH,
    DISPLAY_MAX_PARSE_EVENTS,
    DISPLAY_SUPPRESSED_TAGS,
    DisplayError,
)


@dataclass(frozen=True, slots=True)
class _Frame:
    tag: str
    suppressed: bool


_LITERAL_AMPERSAND_SENTINEL = "\x01"
_HTML_NAME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:.-_"
)
_HTML_SPACE_CHARS = " \t\n\f\r"


def _scan_markup_end(value: str, start: int) -> int:
    quote: str | None = None
    index = start + 1
    while index < len(value):
        char = value[index]
        if quote is not None:
            if char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char == ">":
            return index
        index += 1
    raise DisplayError(DISPLAY_ERROR_HTML_MALFORMED)


def _validate_raw_markup(value: str) -> None:
    """Reject syntax that HTMLParser otherwise silently normalizes away."""

    index = 0
    while index < len(value):
        start = value.find("<", index)
        if start < 0:
            return
        if start + 1 >= len(value):
            raise DisplayError(DISPLAY_ERROR_HTML_MALFORMED)
        marker = value[start + 1]
        if value.startswith("<!--", start):
            end = value.find("-->", start + 4)
            if end < 0 or "--" in value[start + 4 : end]:
                raise DisplayError(DISPLAY_ERROR_HTML_MALFORMED)
            index = end + 3
            continue
        if marker == "!":
            end = _scan_markup_end(value, start + 1)
            declaration = value[start + 2 : end]
            if (
                len(declaration) <= 8
                or declaration[:7].casefold() != "doctype"
                or declaration[7] not in _HTML_SPACE_CHARS
                or not declaration[8:].strip()
            ):
                raise DisplayError(DISPLAY_ERROR_HTML_MALFORMED)
            index = end + 1
            continue
        if marker == "?":
            raise DisplayError(DISPLAY_ERROR_HTML_MALFORMED)
        if marker == "/":
            end = _scan_markup_end(value, start + 1)
            cursor = start + 2
            name_start = cursor
            while cursor < end and value[cursor] in _HTML_NAME_CHARS:
                cursor += 1
            if cursor == name_start or not all(
                "A" <= char <= "Z" or "a" <= char <= "z" for char in value[name_start]
            ):
                raise DisplayError(DISPLAY_ERROR_HTML_MALFORMED)
            if value[cursor:end].strip(_HTML_SPACE_CHARS):
                raise DisplayError(DISPLAY_ERROR_HTML_MALFORMED)
            index = end + 1
            continue
        if "A" <= marker <= "Z" or "a" <= marker <= "z":
            end = _scan_markup_end(value, start + 1)
            cursor = start + 1
            while cursor < end and value[cursor] in _HTML_NAME_CHARS:
                cursor += 1
            if cursor == start + 1:
                raise DisplayError(DISPLAY_ERROR_HTML_MALFORMED)
            index = end + 1
            continue
        index = start + 1


class _LayoutBuffer:
    def __init__(self) -> None:
        self._chunks: list[str] = []
        self._bytes = 0
        self._line_has_content = False
        self._trailing_newlines = 0
        self._list_depth = 0
        self._li_levels: list[int] = []

    @property
    def text(self) -> str:
        return "".join(self._chunks)

    def _append_raw(self, value: str) -> None:
        if value:
            self._bytes += len(value.encode("utf-8"))
            if self._bytes > DISPLAY_MAX_FIELD_OUTPUT_BYTES:
                raise DisplayError(DISPLAY_ERROR_OUTPUT_TOO_LARGE)
            self._chunks.append(value)
            trailing = len(value) - len(value.rstrip("\n"))
            if trailing:
                if value[:-trailing]:
                    self._trailing_newlines = trailing
                else:
                    self._trailing_newlines += trailing
                self._line_has_content = False
            else:
                self._trailing_newlines = 0
                self._line_has_content = True

    def append_text(self, value: str) -> None:
        index = 0
        while index < len(value):
            newline = value.find("\n", index)
            end = len(value) if newline < 0 else newline
            if end > index:
                if not self._line_has_content and self._li_levels:
                    self._append_raw(" " * (2 * (self._li_levels[-1] + 1)))
                self._append_raw(value[index:end])
            if newline < 0:
                break
            self._append_raw("\n")
            index = newline + 1

    def block_boundary(self) -> None:
        if not self._chunks:
            return
        if self._trailing_newlines >= 2:
            return
        if self._trailing_newlines == 1:
            self._append_raw("\n")
        else:
            self._append_raw("\n\n")

    def line_break(self) -> None:
        if self._chunks:
            self._append_raw("\n")

    def start_list(self) -> None:
        self._list_depth += 1

    def end_list(self) -> None:
        self._list_depth = max(0, self._list_depth - 1)

    def start_item(self) -> None:
        if self._line_has_content:
            self._append_raw("\n")
        level = max(0, self._list_depth - 1)
        self._li_levels.append(level)
        self._append_raw(" " * (2 * level) + "- ")

    def end_item(self) -> None:
        if self._li_levels:
            self._li_levels.pop()
        if self._chunks and self._trailing_newlines == 0:
            self._append_raw("\n")

    def finish(self) -> str:
        value = self.text
        value = value.strip("\n")
        lines = value.split("\n")
        while lines and not lines[-1].strip():
            lines.pop()
        while lines and not lines[0].strip():
            lines.pop(0)
        result: list[str] = []
        blank_count = 0
        for line in lines:
            if not line.strip():
                blank_count += 1
                if blank_count > 1:
                    continue
            else:
                blank_count = 0
                line = line.rstrip()
            result.append(line)
        return "\n".join(result)


class _DisplayHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self._frames: list[_Frame] = []
        self._layout = _LayoutBuffer()
        self._events = 0
        self._saw_structure = False

    def close(self) -> None:
        pending = self.rawdata
        super().close()
        if pending:
            raise DisplayError(DISPLAY_ERROR_HTML_MALFORMED)

    @property
    def result(self) -> str:
        if self._frames:
            raise DisplayError(DISPLAY_ERROR_HTML_MALFORMED)
        return self._layout.finish() if self._saw_structure else self._layout.text

    def _event(self) -> None:
        self._events += 1
        if self._events > DISPLAY_MAX_PARSE_EVENTS:
            raise DisplayError(DISPLAY_ERROR_PARSE_LIMIT_EXCEEDED)

    def _suppressed(self) -> bool:
        return any(frame.suppressed for frame in self._frames)

    def _push(self, tag: str) -> None:
        if len(self._frames) >= DISPLAY_MAX_HTML_DEPTH:
            raise DisplayError(DISPLAY_ERROR_HTML_DEPTH_EXCEEDED)
        self._frames.append(_Frame(tag, self._suppressed() or tag in DISPLAY_SUPPRESSED_TAGS))

    def _start_tag(self, tag: str, *, self_closing: bool) -> None:
        normalized = tag.lower()
        if normalized in DISPLAY_HTML_VOID_TAGS:
            if normalized == DISPLAY_BREAK_TAG and not self._suppressed():
                self._layout.line_break()
            return
        if self_closing:
            if normalized in DISPLAY_BLOCK_TAGS and not self._suppressed():
                self._layout.block_boundary()
            return
        if not self._suppressed() and normalized in DISPLAY_BLOCK_TAGS:
            self._layout.block_boundary()
        if not self._suppressed() and normalized in DISPLAY_LIST_CONTAINER_TAGS:
            self._layout.start_list()
        if not self._suppressed() and normalized == DISPLAY_LIST_ITEM_TAG:
            self._layout.start_item()
        self._push(normalized)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        self._event()
        self._saw_structure = True
        self._start_tag(tag, self_closing=False)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        self._event()
        self._saw_structure = True
        self._start_tag(tag, self_closing=True)

    def handle_endtag(self, tag: str) -> None:
        self._event()
        self._saw_structure = True
        normalized = tag.lower()
        if normalized in DISPLAY_HTML_VOID_TAGS or not self._frames:
            raise DisplayError(DISPLAY_ERROR_HTML_MALFORMED)
        frame = self._frames[-1]
        if frame.tag != normalized:
            raise DisplayError(DISPLAY_ERROR_HTML_MALFORMED)
        self._frames.pop()
        if not frame.suppressed:
            if normalized == DISPLAY_LIST_ITEM_TAG:
                self._layout.end_item()
            elif normalized in DISPLAY_LIST_CONTAINER_TAGS:
                self._layout.end_list()
            elif normalized in DISPLAY_BLOCK_TAGS:
                self._layout.block_boundary()

    def handle_data(self, data: str) -> None:
        self._event()
        if not self._suppressed():
            self._layout.append_text(data)

    def handle_comment(self, data: str) -> None:
        del data
        self._event()
        self._saw_structure = True

    def handle_decl(self, decl: str) -> None:
        del decl
        self._event()
        self._saw_structure = True

    def handle_pi(self, data: str) -> None:
        del data
        self._event()
        self._saw_structure = True
        raise DisplayError(DISPLAY_ERROR_HTML_MALFORMED)

    def unknown_decl(self, data: str) -> None:
        del data
        self._event()
        self._saw_structure = True
        raise DisplayError(DISPLAY_ERROR_HTML_MALFORMED)

    def handle_entityref(self, name: str) -> None:
        del name
        self._event()
        self._saw_structure = True
        raise DisplayError(DISPLAY_ERROR_ENTITY_INVALID)

    def handle_charref(self, name: str) -> None:
        del name
        self._event()
        self._saw_structure = True
        raise DisplayError(DISPLAY_ERROR_ENTITY_INVALID)


def layout_html(value: str) -> str:
    _validate_raw_markup(value)
    parser = _DisplayHTMLParser()
    parser_error = False
    try:
        parser.feed(value.replace("&", _LITERAL_AMPERSAND_SENTINEL))
        parser.close()
    except DisplayError:
        raise
    except (AssertionError, IndexError, ValueError):
        parser_error = True
    if parser_error:
        raise DisplayError(DISPLAY_ERROR_HTML_MALFORMED)
    return parser.result.replace(_LITERAL_AMPERSAND_SENTINEL, "&")


__all__ = ["layout_html"]
