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
    DISPLAY_ERROR_PARSE_LIMIT_EXCEEDED,
    DISPLAY_HTML_VOID_TAGS,
    DISPLAY_LIST_CONTAINER_TAGS,
    DISPLAY_LIST_ITEM_TAG,
    DISPLAY_MAX_HTML_DEPTH,
    DISPLAY_MAX_PARSE_EVENTS,
    DISPLAY_SUPPRESSED_TAGS,
    DisplayError,
)


@dataclass(frozen=True, slots=True)
class _Frame:
    tag: str
    suppressed: bool


class _LayoutBuffer:
    def __init__(self) -> None:
        self._chunks: list[str] = []
        self._line_has_content = False
        self._list_depth = 0
        self._li_levels: list[int] = []

    @property
    def text(self) -> str:
        return "".join(self._chunks)

    def _append_raw(self, value: str) -> None:
        if value:
            self._chunks.append(value)
            for char in value:
                self._line_has_content = char != "\n"

    def append_text(self, value: str) -> None:
        for char in value:
            if char == "\n":
                self._append_raw(char)
                continue
            if not self._line_has_content and self._li_levels:
                self._append_raw(" " * (2 * (self._li_levels[-1] + 1)))
            self._append_raw(char)

    def block_boundary(self) -> None:
        if not self._chunks:
            return
        text = self.text
        if text.endswith("\n\n"):
            return
        if text.endswith("\n"):
            self._append_raw("\n")
        else:
            self._append_raw("\n\n")

    def line_break(self) -> None:
        if self._chunks and not self.text.endswith("\n"):
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
        if self._chunks and not self.text.endswith("\n"):
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
    parser = _DisplayHTMLParser()
    try:
        parser.feed(value)
        parser.close()
    except DisplayError:
        raise
    except (AssertionError, IndexError, ValueError) as exc:
        raise DisplayError(DISPLAY_ERROR_HTML_MALFORMED) from exc
    return parser.result


__all__ = ["layout_html"]
