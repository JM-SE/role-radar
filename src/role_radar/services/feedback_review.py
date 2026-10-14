"""Standard interactive labeling session over the current product feedback loop."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from sqlalchemy.orm import Session

from role_radar.evaluation.blind_labeling.contracts import Label
from role_radar.evaluation.blind_labeling.interaction import TerminalIO
from role_radar.evaluation.blind_labeling.policy import LABEL_DEFINITIONS, LABEL_DOMAINS
from role_radar.evaluation.blind_labeling.validation import ValidationError
from role_radar.repositories.feedback import FeedbackConflictError
from role_radar.services.feedback_service import (
    FeedbackCandidate,
    FeedbackItem,
    build_surface,
    collect_candidates,
    render_candidate,
    submit_feedback,
)

_LABEL_ALIASES = {
    "a": Label.APPLY,
    "apply": Label.APPLY,
    "m": Label.MAYBE,
    "maybe": Label.MAYBE,
    "r": Label.REJECT,
    "reject": Label.REJECT,
}

_MAX_ATTEMPTS_PER_ITEM = 3


@dataclass(frozen=True, slots=True)
class ReviewReport:
    """Outcome of one interactive labeling session."""

    run_id: str
    decided: int
    replayed: int
    skipped: int
    conflicts: int
    quit_requested: bool
    remaining: int


class _QuitRequested(Exception):
    """The operator stopped the session; persisted decisions are kept."""


def _read(io: TerminalIO, prompt: str) -> str:
    try:
        return io.read_line(prompt)
    except EOFError as exc:
        raise _QuitRequested() from exc


def _choose_label(io: TerminalIO) -> Label | None:
    """Return the chosen label, None to skip, or raise _QuitRequested."""

    while True:
        raw = _read(io, "Label ([a]pply/[m]aybe/[r]eject/[s]kip/[q]uit): ").strip().lower()
        if raw in {"q", "quit"}:
            raise _QuitRequested()
        if raw in {"s", "skip"}:
            return None
        label = _LABEL_ALIASES.get(raw)
        if label is not None:
            return label
        io.write("Unknown label. Use a, m, r, s, or q.\n")


def _choose_reason(io: TerminalIO, label: Label) -> tuple[str, tuple[str, ...]]:
    """Collect primary and secondary reasons by number or code."""

    domain = LABEL_DOMAINS[label.value]
    io.write(f"Definition: {LABEL_DEFINITIONS[label.value]}\n")
    for position, code in enumerate(domain, start=1):
        io.write(f"  {position}. {code}\n")

    def resolve(token: str) -> str | None:
        cleaned = token.strip()
        if cleaned.isdigit():
            index = int(cleaned) - 1
            if 0 <= index < len(domain):
                return domain[index]
            return None
        return cleaned if cleaned in domain else None

    def check_quit(raw: str) -> None:
        if raw.strip().lower() in {"q", "quit"}:
            raise _QuitRequested()

    while True:
        raw = _read(io, "Primary reason (number or code): ")
        check_quit(raw)
        primary = resolve(raw)
        if primary is not None:
            break
        io.write("Unknown reason. Pick a number or code from the list.\n")
    while True:
        raw = _read(io, "Secondary reasons (numbers/codes, comma-separated, empty=none): ")
        check_quit(raw)
        if not raw.strip():
            return primary, ()
        resolved = [resolve(token) for token in raw.split(",")]
        if all(code is not None for code in resolved):
            unique = tuple(dict.fromkeys(code for code in resolved if code is not None))
            if primary in unique:
                io.write("The primary reason cannot repeat as secondary.\n")
                continue
            return primary, unique
        io.write("Unknown secondary reason. Pick from the list or leave empty.\n")


def _confirm(io: TerminalIO, label: Label, primary: str) -> bool | None:
    """Return True to persist, False to skip, or raise _QuitRequested."""

    while True:
        raw = _read(io, f"Confirm {label.value}/{primary} ([y]es/[n]o/[q]uit): ").strip().lower()
        if raw in {"q", "quit"}:
            raise _QuitRequested()
        if raw in {"y", "yes"}:
            return True
        if raw in {"n", "no", ""}:
            return False
        io.write("Answer y, n, or q.\n")


def _describe_band(item: FeedbackItem) -> str:
    if item.band is None:
        return "Relevance: unranked (no approved phrases on this run)."
    if item.matched_phrases:
        matched = ", ".join(item.matched_phrases)
        return f"Relevance: {item.band} (matched: {matched})."
    return f"Relevance: {item.band}."


def run_review(
    session: Session,
    run_id: str,
    io: TerminalIO,
    *,
    relabel: bool = False,
    limit: int | None = None,
    scope: Literal["all", "current", "reprocessed"] = "all",
) -> ReviewReport:
    """Walk the selected immutable feedback surface one item at a time.

    Already-decided items are skipped so an interrupted session resumes
    naturally, unless ``relabel`` revisits them for correction. Every
    confirmed decision commits immediately; quitting keeps prior work.
    """

    if limit is not None and limit < 1:
        raise ValueError("limit must be a positive integer")
    surface = build_surface(session, run_id, scope=scope)
    candidates = {item.job_id: item for item in collect_candidates(session, run_id, scope=scope)}
    queue = [item for item in surface.items if relabel or item.decision is None]
    if limit is not None:
        queue = queue[:limit]
    if not surface.items:
        io.write(f"No feedback candidates on run {run_id}.\n")
        return ReviewReport(run_id, 0, 0, 0, 0, False, 0)
    if not queue:
        io.write(
            f"All {len(surface.items)} candidates on run {run_id} already have a "
            "decision. Re-run with --relabel to correct one.\n"
        )
        return ReviewReport(run_id, 0, 0, 0, 0, False, 0)

    io.write(
        f"Reviewing run {run_id}: {len(queue)} to label, "
        f"{len(surface.items) - len(queue)} already decided.\n"
    )
    positions = {entry.job_id: number for number, entry in enumerate(surface.items, start=1)}
    total = len(surface.items)
    decided = replayed = skipped = conflicts = 0
    quit_requested = False
    try:
        for item in queue:
            outcome = _review_item(
                session,
                surface.run_id,
                item,
                candidates,
                io,
                index=positions.get(item.job_id, total),
                total=total,
            )
            if outcome == "decided":
                decided += 1
            elif outcome == "replayed":
                replayed += 1
            elif outcome == "conflict":
                conflicts += 1
            else:
                skipped += 1
            io.write(
                f"Progress: decided={decided} replayed={replayed} "
                f"skipped={skipped} conflicts={conflicts}.\n"
            )
    except _QuitRequested:
        quit_requested = True
    remaining = len(
        [entry for entry in build_surface(session, run_id).items if entry.decision is None]
    )
    io.write(
        f"Session stopped: decided={decided} replayed={replayed} skipped={skipped} "
        f"conflicts={conflicts} remaining={remaining} (run {run_id}).\n"
    )
    return ReviewReport(run_id, decided, replayed, skipped, conflicts, quit_requested, remaining)


def _review_item(
    session: Session,
    run_id: str,
    item: FeedbackItem,
    candidates: dict[str, FeedbackCandidate],
    io: TerminalIO,
    *,
    index: int,
    total: int,
) -> str:
    candidate = candidates.get(item.job_id)
    if candidate is None:
        session.rollback()
        io.write(f"Skipped {item.job_id}: candidate left the run surface.\n")
        return "skipped"
    io.write(_describe_band(item) + "\n")
    io.write(render_candidate(candidate, index=index, total=total))
    attempts = 0
    while attempts < _MAX_ATTEMPTS_PER_ITEM:
        label = _choose_label(io)
        if label is None:
            io.write("Skipped (no decision recorded).\n")
            return "skipped"
        primary, secondary = _choose_reason(io, label)
        note_raw = _read(io, 'Note (optional; required when a reason starts with "other_"): ')
        note = note_raw.strip() or None
        if _confirm(io, label, primary) is not True:
            io.write("Skipped (not confirmed).\n")
            return "skipped"
        try:
            _row, created = submit_feedback(
                session,
                run_id=run_id,
                job_id=item.job_id,
                label=label.value,
                primary_reason=primary,
                secondary_reasons=secondary,
                note=note,
                expected_revision=item.revision,
            )
        except ValidationError as exc:
            session.rollback()
            attempts += 1
            detail = exc.args[0] if exc.args else "invalid"
            io.write(f"Invalid decision ({detail}). Try again.\n")
            continue
        except FeedbackConflictError:
            session.rollback()
            io.write("Decision changed concurrently; kept the stored revision.\n")
            return "conflict"
        session.commit()
        io.write("Decision accepted.\n")
        return "decided" if created else "replayed"
    session.rollback()
    io.write("Skipped after repeated invalid input.\n")
    return "skipped"


__all__ = ["ReviewReport", "run_review"]
