"""Durable limits for one explicitly selected canary run."""

from collections.abc import Callable
from contextvars import ContextVar, Token
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from role_radar.db.models import JobSearchRun

CANARY_LIMITS = {
    "source_http_attempts": 2,
    "accepted_items": 2,
    "broker_calls": 4,
    "broker_attempts": 4,
    "notification_batches": 1,
}
CANARY_BUDGET = {"version": 1, "limits": CANARY_LIMITS}
CANARY_CHECKPOINT_STAGES = frozenset(
    {
        "discovery",
        "collection",
        "extraction",
        "scoring",
        "deep_evaluation",
        "notifications",
        "complete",
    }
)


def validate_canary_checkpoint(value: object) -> tuple[str, int]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise CanaryAmbiguousAttempt("canary_checkpoint_invalid")
    version = value.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version != 1:
        raise CanaryAmbiguousAttempt("canary_checkpoint_invalid")
    stage = value.get("stage")
    if not isinstance(stage, str) or stage not in CANARY_CHECKPOINT_STAGES:
        raise CanaryAmbiguousAttempt("canary_checkpoint_invalid")
    cursor = value.get("cursor")
    if not isinstance(cursor, int) or isinstance(cursor, bool) or cursor < 0:
        raise CanaryAmbiguousAttempt("canary_checkpoint_invalid")
    try:
        checkpoint_counts(value)
        reservations = _checkpoint_records(value.get("reservations", []))
        logical_reservations = _checkpoint_records(value.get("logical_reservations", []))
    except CanaryAmbiguousAttempt as exc:
        raise CanaryAmbiguousAttempt("canary_checkpoint_invalid") from exc
    if reservations or logical_reservations:
        raise CanaryAmbiguousAttempt("canary_side_effect_unresolved")
    return stage, cursor


def checkpoint_counts(checkpoint: dict[str, object]) -> dict[str, int]:
    value = checkpoint.get("counts", {})
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise CanaryAmbiguousAttempt("canary_checkpoint_counts_invalid")
    if any(
        not isinstance(count, int) or isinstance(count, bool) or count < 0
        for count in value.values()
    ):
        raise CanaryAmbiguousAttempt("canary_checkpoint_counts_invalid")
    return value


def _checkpoint_records(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise CanaryAmbiguousAttempt("canary_checkpoint_reservations_invalid")
    records: list[dict[str, object]] = []
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"token", "kind"}
            or not isinstance(item.get("token"), str)
            or not isinstance(item.get("kind"), str)
        ):
            raise CanaryAmbiguousAttempt("canary_checkpoint_reservations_invalid")
        token = item["token"]
        kind = item["kind"]
        try:
            parsed_token = UUID(token)
        except ValueError as exc:
            raise CanaryAmbiguousAttempt(
                "canary_checkpoint_reservations_invalid"
            ) from exc
        if str(parsed_token) != token or parsed_token.version != 4 or kind not in CANARY_LIMITS:
            raise CanaryAmbiguousAttempt("canary_checkpoint_reservations_invalid")
        records.append(item)
    return records


class CanaryDeferred(RuntimeError):
    """A canary ceiling was reached before the next bounded operation."""


class CanaryAmbiguousAttempt(RuntimeError):
    """A prior reserved side effect has no durable completion record."""


class CanaryExecutionBudget:
    def __init__(self, session_factory: Callable[[], Session], run_id: str) -> None:
        self._session_factory = session_factory
        self.run_id = run_id

    def reserve(self, kind: str) -> str | None:
        if kind not in CANARY_LIMITS:
            raise ValueError("canary_budget_kind_invalid")
        with self._session_factory() as session:
            run = session.get(JobSearchRun, self.run_id)
            if run is None or run.canary_budget_json != CANARY_BUDGET:
                raise RuntimeError("canary_budget_missing_or_changed")
            checkpoint = dict(run.canary_checkpoint_json or {})
            checkpoint.setdefault("version", 1)
            checkpoint.setdefault("stage", "discovery")
            checkpoint.setdefault("cursor", 0)
            counts = checkpoint_counts(checkpoint)
            reservations = _checkpoint_records(checkpoint.setdefault("reservations", []))
            if reservations:
                raise CanaryAmbiguousAttempt("canary_side_effect_unresolved")
            if counts.get(kind, 0) >= CANARY_LIMITS[kind]:
                return None
            token = str(uuid4())
            counts[kind] = counts.get(kind, 0) + 1
            reservations.append({"token": token, "kind": kind})
            checkpoint["counts"] = counts
            checkpoint["reservations"] = reservations
            run.canary_checkpoint_json = checkpoint
            session.commit()
            return token

    def consume(self, kind: str) -> str | None:
        """Reserve a logical call before I/O and keep it ambiguous until completion."""
        if kind not in CANARY_LIMITS:
            raise ValueError("canary_budget_kind_invalid")
        with self._session_factory() as session:
            run = session.get(JobSearchRun, self.run_id)
            if run is None or run.canary_budget_json != CANARY_BUDGET:
                raise RuntimeError("canary_budget_missing_or_changed")
            checkpoint = dict(run.canary_checkpoint_json or {})
            if checkpoint.get("reservations") or checkpoint.get("logical_reservations"):
                raise CanaryAmbiguousAttempt("canary_side_effect_unresolved")
            counts = checkpoint_counts(checkpoint)
            if counts.get(kind, 0) >= CANARY_LIMITS[kind]:
                return None
            counts[kind] = counts.get(kind, 0) + 1
            logical = _checkpoint_records(checkpoint.get("logical_reservations", []))
            token = str(uuid4())
            logical.append({"token": token, "kind": kind})
            checkpoint["version"] = 1
            checkpoint.setdefault("stage", "discovery")
            checkpoint.setdefault("cursor", 0)
            checkpoint["counts"] = counts
            checkpoint["logical_reservations"] = logical
            checkpoint.setdefault("reservations", [])
            run.canary_checkpoint_json = checkpoint
            session.commit()
            return token

    def settle(self, token: str) -> None:
        with self._session_factory() as session:
            run = session.get(JobSearchRun, self.run_id)
            if run is None:
                raise LookupError("run not found")
            checkpoint = dict(run.canary_checkpoint_json or {})
            reservations = _checkpoint_records(checkpoint.get("reservations", []))
            logical = _checkpoint_records(checkpoint.get("logical_reservations", []))
            if any(item.get("token") == token for item in reservations):
                checkpoint["reservations"] = [
                    item for item in reservations if item.get("token") != token
                ]
            elif any(item.get("token") == token for item in logical):
                checkpoint["logical_reservations"] = [
                    item for item in logical if item.get("token") != token
                ]
            else:
                raise CanaryAmbiguousAttempt("canary_reservation_not_found")
            run.canary_checkpoint_json = checkpoint
            session.commit()

    def checkpoint(self, *, stage: str, cursor: int) -> None:
        if cursor < 0:
            raise ValueError("canary_cursor_invalid")
        with self._session_factory() as session:
            run = session.get(JobSearchRun, self.run_id)
            if run is None:
                raise LookupError("run not found")
            checkpoint = dict(run.canary_checkpoint_json or {})
            checkpoint["version"] = 1
            checkpoint["stage"] = stage
            checkpoint["cursor"] = cursor
            checkpoint.setdefault("counts", {})
            checkpoint.setdefault("reservations", [])
            run.canary_checkpoint_json = checkpoint
            session.commit()


_ACTIVE_BUDGET: ContextVar[CanaryExecutionBudget | None] = ContextVar(
    "role_radar_canary_budget", default=None
)


def activate_canary_budget(budget: CanaryExecutionBudget) -> Token[CanaryExecutionBudget | None]:
    return _ACTIVE_BUDGET.set(budget)


def reset_canary_budget(token: Token[CanaryExecutionBudget | None]) -> None:
    _ACTIVE_BUDGET.reset(token)


def reserve_network_attempt(kind: str = "source_http_attempts") -> str | None:
    budget = _ACTIVE_BUDGET.get()
    if budget is None:
        return None
    token = budget.reserve(kind)
    if token is None:
        raise CanaryDeferred(f"canary_budget_exhausted:{kind}")
    return token


def settle_network_attempt(token: str | None) -> None:
    if token is not None:
        budget = _ACTIVE_BUDGET.get()
        if budget is None:
            raise CanaryAmbiguousAttempt("canary_budget_context_missing")
        budget.settle(token)


def reserve_logical_call(kind: str) -> str | None:
    budget = _ACTIVE_BUDGET.get()
    if budget is None:
        return None
    token = budget.consume(kind)
    if token is None:
        raise CanaryDeferred(f"canary_budget_exhausted:{kind}")
    return token
