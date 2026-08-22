"""Injected plain-text terminal interaction for one blind item at a time."""
# ruff: noqa: E501

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from role_radar.evaluation.blind_labeling.contracts import Decision, Label, PilotItem, ReviewItem
from role_radar.evaluation.blind_labeling.policy import LABEL_DEFINITIONS, LABEL_DOMAINS
from role_radar.evaluation.blind_labeling.validation import validate_decision


class TerminalIO(Protocol):
    def read_line(self, prompt: str) -> str: ...
    def write(self, value: str) -> None: ...
    @property
    def is_tty(self) -> bool: ...


class InteractionCancelled(EOFError):
    """The operator did not confirm a complete decision."""


class InteractionError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass
class StdTerminalIO:
    input_fn: Callable[[str], str]
    output_fn: Callable[[str], object]
    is_tty: bool = True

    def read_line(self, prompt: str) -> str:
        return self.input_fn(prompt)

    def write(self, value: str) -> None:
        self.output_fn(value)


def render_item(item: PilotItem, *, index: int, total: int) -> str:
    def render(value: str) -> str:
        return value.replace("\t", r"\t")

    location = render(item.location) if item.location is not None else "(not provided)"
    return f"\n[{index}/{total}]\nTitle: {render(item.title)}\nCompany: {render(item.company)}\nLocation: {location}\n\n{render(item.description)}\n"


def collect_decision(io: TerminalIO, item: PilotItem, *, index: int, total: int) -> Decision:
    io.write(render_item(item, index=index, total=total))
    try:
        label = Label(io.read_line("Label [apply/maybe/reject]: ").strip().lower())
    except ValueError as exc:
        raise InteractionError("label_invalid") from exc
    io.write("Definition: " + LABEL_DEFINITIONS[label.value] + "\n")
    reasons = LABEL_DOMAINS[label.value]
    io.write("Allowed reasons: " + ", ".join(reasons) + "\n")
    primary = io.read_line("Primary reason: ").strip()
    secondary_raw = io.read_line("Secondary reasons (comma-separated, optional): ").strip()
    secondary = tuple(value.strip() for value in secondary_raw.split(",") if value.strip())
    note = io.read_line("Note (optional/required for other_*): ")
    decision = validate_decision(Decision(label, primary, secondary, note or None))
    if io.read_line("Confirm decision [y/N]: ").strip().lower() not in {"y", "yes"}:
        raise InteractionCancelled()
    io.write("Decision accepted.\n")
    return decision


def collect_review_decision(io: TerminalIO, item: ReviewItem) -> Decision:
    return collect_decision(io, item.item, index=item.index, total=item.total)


__all__ = [
    "InteractionCancelled",
    "InteractionError",
    "StdTerminalIO",
    "TerminalIO",
    "collect_decision",
    "collect_review_decision",
    "render_item",
]
