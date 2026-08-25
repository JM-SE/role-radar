"""Bounded F10.1D report artifacts and private no-replace storage seams.

The storage helpers take their root explicitly.  They are suitable for an
offline test directory and do not know the production data location.  They
only persist already-authorized report data; they do not create a provider,
credential, or network client.
"""

from __future__ import annotations

import errno
import json
import os
import stat
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, cast
from uuid import UUID

from role_radar.discovery.authorization_v2 import (
    AUTHORIZATION_SCHEMA_VERSION,
    MAX_ARTIFACT_TTL_SECONDS,
    DiscoveryOperationV2,
    OperationChallengeV2,
    OperationKind,
    ProviderQuotaContextV1,
    canonical_json_bytes,
    challenge_sha256,
    operation_sha256,
    profile_binding_v2,
    validate_report_only_challenge,
    validate_report_only_operation,
)

# Conversion accepts small injected DTO protocols without importing their
# domain modules; this is bounded and does not expose filesystem data.
# ruff: noqa: B009


DISCOVERY_ARTIFACT_SCHEMA_VERSION: Final = "f10.1d-discovery-artifact-v2"
DISCOVERY_REPORT_SCHEMA_VERSION: Final = "f10.1d-discovery-report-v2"
MAX_PRIVATE_ARTIFACT_BYTES: Final = 64 * 1024
MAX_PRIVATE_ARTIFACT_DEPTH: Final = 16
MAX_PRIVATE_ARTIFACT_NODES: Final = 2048
MAX_ARTIFACT_NAME_CHARS: Final = 128
MAX_QUERY_REPORTS: Final = 4
MAX_CANDIDATES: Final = 10
MAX_VERIFICATIONS: Final = 8
MAX_PLAN_ARTIFACT_BYTES: Final = 65_536
MAX_OPERATION_ARTIFACT_BYTES: Final = 32_768
MAX_START_MARKER_BYTES: Final = 8_192
MAX_TERMINAL_REPORT_BYTES: Final = 262_144
MAX_TERMINAL_REQUESTS: Final = 108
MAX_TERMINAL_VERIFIED_SOURCES: Final = 8
TERMINAL_COUNT_KEYS: Final = (
    "search_requests_attempted",
    "search_requests_completed",
    "classified_hits",
    "unique_board_candidates_seen",
    "unique_board_candidates_retained",
    "board_verifications_attempted",
    "boards_verified",
    "verification_wire_attempts_consumed",
)
TERMINAL_TRUNCATION_KEYS: Final = (
    "unique_board_candidates",
    "board_verifications",
    "verification_wire_attempts",
)
TERMINAL_CODES: Final = frozenset(
    {
        "provider_search_failed",
        "official_verification_failed",
        "provider_quota_exhausted",
        "authorization_window_invalid",
        "authorization_expired",
        "quota_month_stale",
        "quota_context_stale",
        "quota_evidence_invalid",
        "unique_board_candidates_exhausted",
        "board_verifications_exhausted",
        "verification_wire_attempts_exhausted",
        "multiple_budgets_exhausted",
        "transmission_indeterminate",
    }
)
REQUEST_ERROR_CODES: Final = frozenset(
    {
        "provider_failed",
        "provider_malformed",
        "provider_timeout",
        "pretransport_failed",
        "transmission_indeterminate",
    }
)


def _require_exact_keys(value: Mapping[str, object], expected: tuple[str, ...], code: str) -> None:
    if set(value) != set(expected):
        raise DiscoveryArtifactError(code)


class DiscoveryArtifactError(ValueError):
    """Stable, path-free error for artifact and private storage failures."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


ArtifactError = DiscoveryArtifactError


class DiscoveryReportStatus(StrEnum):
    EMPTY = "empty"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    BLOCKED = "blocked"


def _utc(value: object, *, field: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise DiscoveryArtifactError(f"{field}_invalid")
    return value.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _sha(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise DiscoveryArtifactError(f"{field}_invalid")
    return value


def _canonical_uuid(value: object) -> str:
    if not isinstance(value, str):
        raise DiscoveryArtifactError("operation_id_invalid")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise DiscoveryArtifactError("operation_id_invalid") from exc
    if str(parsed) != value or value != value.casefold():
        raise DiscoveryArtifactError("operation_id_invalid")
    return value


def _jsonable(value: object) -> object:
    if isinstance(value, DiscoveryArtifactV2):
        return _jsonable(value.payload())
    if hasattr(value, "as_dict"):
        return _jsonable(getattr(value, "as_dict")())
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise DiscoveryArtifactError("json_key_invalid")
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, datetime):
        return _iso(_utc(value, field="timestamp"))
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise DiscoveryArtifactError("json_value_invalid")


def _validate_tree(value: object, *, max_depth: int, max_nodes: int) -> None:
    nodes = 0

    def visit(item: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            raise DiscoveryArtifactError("artifact_json_bounds")
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise DiscoveryArtifactError("json_key_invalid")
                nodes += 1
                if nodes > max_nodes:
                    raise DiscoveryArtifactError("artifact_json_bounds")
                visit(child, depth + 1)
        elif isinstance(item, (list, tuple)):
            for child in item:
                visit(child, depth + 1)
        elif not (item is None or isinstance(item, (str, int, float, bool))):
            raise DiscoveryArtifactError("json_value_invalid")

    visit(value, 0)


def _freeze_json(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def canonical_artifact_json(value: object) -> bytes:
    """Return bounded canonical JSON bytes for a generated artifact payload."""

    converted = _jsonable(value)
    _validate_tree(
        converted, max_depth=MAX_PRIVATE_ARTIFACT_DEPTH, max_nodes=MAX_PRIVATE_ARTIFACT_NODES
    )
    try:
        payload = canonical_json_bytes(converted)
    except ValueError as exc:
        raise DiscoveryArtifactError("artifact_json_invalid") from exc
    if len(payload) > MAX_PRIVATE_ARTIFACT_BYTES:
        raise DiscoveryArtifactError("artifact_too_large")
    return payload


def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DiscoveryArtifactError("artifact_duplicate_key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise DiscoveryArtifactError("artifact_nonfinite_number")


def loads_bounded_artifact(
    payload: bytes,
    *,
    max_bytes: int = MAX_PRIVATE_ARTIFACT_BYTES,
    max_depth: int = MAX_PRIVATE_ARTIFACT_DEPTH,
    max_nodes: int = MAX_PRIVATE_ARTIFACT_NODES,
) -> Mapping[str, object]:
    if type(payload) is not bytes or len(payload) > max_bytes:
        raise DiscoveryArtifactError("artifact_too_large")
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
    except DiscoveryArtifactError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        raise DiscoveryArtifactError("artifact_json_invalid") from exc
    if not isinstance(value, dict):
        raise DiscoveryArtifactError("artifact_object_required")
    _validate_tree(value, max_depth=max_depth, max_nodes=max_nodes)
    return value


decode_bounded_artifact = loads_bounded_artifact


@dataclass(frozen=True, slots=True)
class DiscoveryQueryReportV2:
    ordinal: int
    provider: str
    status: str
    result_count: int = 0
    candidate_count: int = 0
    verified_count: int = 0
    error_code: str | None = None

    def __post_init__(self) -> None:
        if type(self.ordinal) is not int or not 1 <= self.ordinal <= MAX_QUERY_REPORTS:
            raise DiscoveryArtifactError("query_ordinal_invalid")
        if self.provider not in {"brave", "tavily"}:
            raise DiscoveryArtifactError("query_provider_invalid")
        if self.status not in {"succeeded", "empty", "failed", "malformed", "indeterminate"}:
            raise DiscoveryArtifactError("query_status_invalid")
        for name, value, maximum in (
            ("result_count", self.result_count, 10),
            ("candidate_count", self.candidate_count, MAX_CANDIDATES),
            ("verified_count", self.verified_count, MAX_VERIFICATIONS),
        ):
            if type(value) is not int or not 0 <= value <= maximum:
                raise DiscoveryArtifactError(f"{name}_invalid")
        if self.error_code is not None and (
            type(self.error_code) is not str or not 1 <= len(self.error_code) <= 64
        ):
            raise DiscoveryArtifactError("error_code_invalid")

    def as_dict(self) -> dict[str, object]:
        return {
            "ordinal": self.ordinal,
            "provider": self.provider,
            "status": self.status,
            "result_count": self.result_count,
            "candidate_count": self.candidate_count,
            "verified_count": self.verified_count,
            "error_code": self.error_code,
        }


QueryReportV2 = DiscoveryQueryReportV2


def _binding_dict(value: object) -> dict[str, object]:
    try:
        return profile_binding_v2(value).as_dict()
    except (TypeError, ValueError) as exc:
        raise DiscoveryArtifactError("profile_binding_invalid") from exc


def _quota_dicts(value: object) -> list[dict[str, object]]:
    if type(value) is not tuple or any(
        not isinstance(item, ProviderQuotaContextV1) for item in value
    ):
        raise DiscoveryArtifactError("quota_contexts_invalid")
    return [item.as_dict() for item in value]


def _artifact_hash(payload: Mapping[str, object], field: str) -> str:
    unsigned = dict(payload)
    unsigned.pop(field, None)
    return sha256(canonical_artifact_json(unsigned)).hexdigest()


@dataclass(frozen=True, slots=True)
class ReportOnlyStartMarkerV1:
    """Immutable marker published immediately before future transport."""

    operation_id: str
    operation_sha256: str
    challenge_sha256: str
    authorization_sha256: str
    profile_binding: object
    policy_sha256: str
    plan_sha256: str
    quota_contexts: tuple[ProviderQuotaContextV1, ...]
    authorization_max_ttl_seconds: int
    authorization_expires_at_utc: datetime
    started_at_utc: datetime
    start_marker_sha256: str = "0" * 64

    def as_dict(self, *, include_hash: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": "report-only-start-marker-v1",
            "operation_id": self.operation_id,
            "operation_sha256": self.operation_sha256,
            "challenge_sha256": self.challenge_sha256,
            "authorization_sha256": self.authorization_sha256,
            "profile_binding": _binding_dict(self.profile_binding),
            "policy_sha256": self.policy_sha256,
            "plan_sha256": self.plan_sha256,
            "quota_contexts": _quota_dicts(self.quota_contexts),
            "authorization_max_ttl_seconds": self.authorization_max_ttl_seconds,
            "authorization_expires_at_utc": _iso(self.authorization_expires_at_utc),
            "started_at_utc": _iso(self.started_at_utc),
        }
        if include_hash:
            payload["start_marker_sha256"] = self.start_marker_sha256
        return payload

    def __post_init__(self) -> None:
        _canonical_uuid(self.operation_id)
        for value, field in (
            (self.operation_sha256, "operation_sha256"),
            (self.challenge_sha256, "challenge_sha256"),
            (self.authorization_sha256, "authorization_sha256"),
            (self.policy_sha256, "policy_sha256"),
            (self.plan_sha256, "plan_sha256"),
            (self.start_marker_sha256, "start_marker_sha256"),
        ):
            _sha(value, field=field)
        _binding_dict(self.profile_binding)
        _quota_dicts(self.quota_contexts)
        if self.authorization_max_ttl_seconds != 86_400:
            raise DiscoveryArtifactError("authorization_window_invalid")
        expires = _utc(self.authorization_expires_at_utc, field="authorization_expires_at_utc")
        started = _utc(self.started_at_utc, field="started_at_utc")
        if started >= expires:
            raise DiscoveryArtifactError("start_marker_invalid")
        object.__setattr__(self, "authorization_expires_at_utc", expires)
        object.__setattr__(self, "started_at_utc", started)
        if self.start_marker_sha256 != "0" * 64 and self.start_marker_sha256 != _artifact_hash(
            self.as_dict(include_hash=False), "start_marker_sha256"
        ):
            raise DiscoveryArtifactError("start_marker_hash_mismatch")


def build_start_marker(**kwargs: object) -> ReportOnlyStartMarkerV1:
    constructor = cast(Any, ReportOnlyStartMarkerV1)
    unsigned = constructor(**kwargs, start_marker_sha256="0" * 64)
    return cast(
        ReportOnlyStartMarkerV1,
        constructor(
            **kwargs,
            start_marker_sha256=_artifact_hash(
                unsigned.as_dict(include_hash=False), "start_marker_sha256"
            ),
        ),
    )


def parse_start_marker(value: bytes | Mapping[str, object]) -> ReportOnlyStartMarkerV1:
    """Decode and validate one complete immutable start marker."""

    payload = (
        loads_bounded_artifact(value, max_bytes=MAX_START_MARKER_BYTES)
        if isinstance(value, bytes)
        else value
    )
    try:
        _require_exact_keys(
            payload,
            (
                "schema_version",
                "operation_id",
                "operation_sha256",
                "challenge_sha256",
                "authorization_sha256",
                "profile_binding",
                "policy_sha256",
                "plan_sha256",
                "quota_contexts",
                "authorization_max_ttl_seconds",
                "authorization_expires_at_utc",
                "started_at_utc",
                "start_marker_sha256",
            ),
            "start_marker_invalid",
        )
        if payload["schema_version"] != "report-only-start-marker-v1":
            raise DiscoveryArtifactError("start_marker_invalid")
        raw_contexts = payload["quota_contexts"]
        if not isinstance(raw_contexts, list):
            raise DiscoveryArtifactError("quota_contexts_invalid")
        contexts = tuple(ProviderQuotaContextV1(**item) for item in raw_contexts)
        return ReportOnlyStartMarkerV1(
            operation_id=cast(str, payload["operation_id"]),
            operation_sha256=cast(str, payload["operation_sha256"]),
            challenge_sha256=cast(str, payload["challenge_sha256"]),
            authorization_sha256=cast(str, payload["authorization_sha256"]),
            profile_binding=payload["profile_binding"],
            policy_sha256=cast(str, payload["policy_sha256"]),
            plan_sha256=cast(str, payload["plan_sha256"]),
            quota_contexts=contexts,
            authorization_max_ttl_seconds=cast(int, payload["authorization_max_ttl_seconds"]),
            authorization_expires_at_utc=datetime.fromisoformat(
                cast(str, payload["authorization_expires_at_utc"]).replace("Z", "+00:00")
            ),
            started_at_utc=datetime.fromisoformat(
                cast(str, payload["started_at_utc"]).replace("Z", "+00:00")
            ),
            start_marker_sha256=cast(str, payload["start_marker_sha256"]),
        )
    except DiscoveryArtifactError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise DiscoveryArtifactError("start_marker_invalid") from exc


@dataclass(frozen=True, slots=True)
class ReportOnlyVerifiedSourceV1:
    source_type: str
    source_key: str
    configuration: Mapping[str, str]
    configuration_sha256: str
    postings_count: int
    board_candidate_ordinal: int
    request_identity_sha256: str

    def __post_init__(self) -> None:
        if self.source_type not in {"greenhouse", "lever"}:
            raise DiscoveryArtifactError("terminal_source_invalid")
        if not isinstance(self.source_key, str) or not 1 <= len(self.source_key) <= 255:
            raise DiscoveryArtifactError("terminal_source_invalid")
        expected_keys = {"board_token"} if self.source_type == "greenhouse" else {"site", "region"}
        if set(self.configuration) != expected_keys or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in self.configuration.items()
        ):
            raise DiscoveryArtifactError("terminal_source_invalid")
        if self.source_type == "lever" and self.configuration.get("region") not in {"global", "eu"}:
            raise DiscoveryArtifactError("terminal_source_invalid")
        for value in (self.configuration_sha256, self.request_identity_sha256):
            _sha(value, field="terminal_source_hash")
        if type(self.postings_count) is not int or self.postings_count < 0:
            raise DiscoveryArtifactError("terminal_source_invalid")
        if (
            type(self.board_candidate_ordinal) is not int
            or not 1 <= self.board_candidate_ordinal <= 10
        ):
            raise DiscoveryArtifactError("terminal_source_invalid")

    def as_dict(self) -> dict[str, object]:
        return {
            "source_type": self.source_type,
            "source_key": self.source_key,
            "configuration": dict(self.configuration),
            "configuration_sha256": self.configuration_sha256,
            "postings_count": self.postings_count,
            "board_candidate_ordinal": self.board_candidate_ordinal,
            "request_identity_sha256": self.request_identity_sha256,
        }


@dataclass(frozen=True, slots=True)
class ReportOnlyRequestEvidenceV1:
    request_ordinal: int
    kind: str
    provider: str
    destination: str
    query_ordinal: int | None = None
    board_candidate_ordinal: int | None = None
    collector_request_ordinal: int | None = None
    operation_key_sha256: str = "0" * 64
    request_identity_sha256: str = "0" * 64
    transmission: str = "not_sent"
    outcome: str = "not_sent"
    result_count: int = 0
    known_count: int = 0
    unknown_count: int = 0
    rejected_count: int = 0
    postings_count: int = 0
    duration_ms: int = 0
    error_code: str | None = None
    wire_attempt_ordinal: int | None = None

    def __post_init__(self) -> None:
        if type(self.request_ordinal) is not int or self.request_ordinal < 1:
            raise DiscoveryArtifactError("terminal_request_invalid")
        if self.kind not in {"search", "official_verification"}:
            raise DiscoveryArtifactError("terminal_request_invalid")
        if self.provider not in {"brave", "tavily", "greenhouse", "lever"}:
            raise DiscoveryArtifactError("terminal_request_invalid")
        if not isinstance(self.destination, str) or not self.destination:
            raise DiscoveryArtifactError("terminal_request_invalid")
        for hash_value in (self.operation_key_sha256, self.request_identity_sha256):
            _sha(hash_value, field="terminal_request_hash")
        if self.transmission not in {"not_sent", "sent", "indeterminate"}:
            raise DiscoveryArtifactError("terminal_request_invalid")
        if self.outcome not in {
            "succeeded",
            "empty",
            "failed",
            "malformed",
            "indeterminate",
            "not_sent",
        }:
            raise DiscoveryArtifactError("terminal_request_invalid")
        if self.outcome == "indeterminate" and self.transmission != "indeterminate":
            raise DiscoveryArtifactError("terminal_request_invalid")
        if self.transmission == "not_sent" and self.outcome != "not_sent":
            raise DiscoveryArtifactError("terminal_request_invalid")
        if self.error_code is not None and self.error_code not in REQUEST_ERROR_CODES:
            raise DiscoveryArtifactError("terminal_request_invalid")
        for count in (
            self.result_count,
            self.known_count,
            self.unknown_count,
            self.rejected_count,
            self.postings_count,
            self.duration_ms,
        ):
            if type(count) is not int or count < 0:
                raise DiscoveryArtifactError("terminal_request_invalid")
        if self.query_ordinal is not None and not 1 <= self.query_ordinal <= 4:
            raise DiscoveryArtifactError("terminal_request_invalid")
        if self.board_candidate_ordinal is not None and not 1 <= self.board_candidate_ordinal <= 10:
            raise DiscoveryArtifactError("terminal_request_invalid")
        if self.collector_request_ordinal is not None and self.collector_request_ordinal < 1:
            raise DiscoveryArtifactError("terminal_request_invalid")
        if self.wire_attempt_ordinal is not None and not 1 <= self.wire_attempt_ordinal <= 100:
            raise DiscoveryArtifactError("terminal_request_invalid")
        if self.kind == "search" and self.board_candidate_ordinal is not None:
            raise DiscoveryArtifactError("terminal_request_invalid")
        if self.kind == "official_verification" and self.board_candidate_ordinal is None:
            raise DiscoveryArtifactError("terminal_request_invalid")

    def as_dict(self) -> dict[str, object]:
        return {
            "request_ordinal": self.request_ordinal,
            "kind": self.kind,
            "provider": self.provider,
            "destination": self.destination,
            "query_ordinal": self.query_ordinal,
            "board_candidate_ordinal": self.board_candidate_ordinal,
            "collector_request_ordinal": self.collector_request_ordinal,
            "operation_key_sha256": self.operation_key_sha256,
            "request_identity_sha256": self.request_identity_sha256,
            "transmission": self.transmission,
            "outcome": self.outcome,
            "result_count": self.result_count,
            "known_count": self.known_count,
            "unknown_count": self.unknown_count,
            "rejected_count": self.rejected_count,
            "postings_count": self.postings_count,
            "duration_ms": self.duration_ms,
            "error_code": self.error_code,
            "wire_attempt_ordinal": self.wire_attempt_ordinal,
        }


@dataclass(frozen=True, slots=True)
class ReportOnlyTerminalReportV1:
    """Allowlisted terminal report; it contains hashes and counts only."""

    operation_id: str
    operation_sha256: str
    challenge_sha256: str
    start_marker_sha256: str
    authorization_sha256: str
    profile_binding: object
    policy_sha256: str
    plan_sha256: str
    quota_contexts: tuple[ProviderQuotaContextV1, ...]
    authorization_max_ttl_seconds: int
    authorization_expires_at_utc: datetime
    state: str
    started_at_utc: datetime
    completed_at_utc: datetime
    counts: Mapping[str, int]
    truncation: Mapping[str, bool]
    requests: tuple[ReportOnlyRequestEvidenceV1, ...]
    verified_sources: tuple[ReportOnlyVerifiedSourceV1, ...]
    terminal_code: str | None = None
    report_sha256: str = "0" * 64

    def as_dict(self, *, include_hash: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": "report-only-terminal-report-v1",
            "operation_id": self.operation_id,
            "operation_sha256": self.operation_sha256,
            "challenge_sha256": self.challenge_sha256,
            "start_marker_sha256": self.start_marker_sha256,
            "authorization_sha256": self.authorization_sha256,
            "profile_binding": _binding_dict(self.profile_binding),
            "policy_sha256": self.policy_sha256,
            "plan_sha256": self.plan_sha256,
            "quota_contexts": _quota_dicts(self.quota_contexts),
            "authorization_max_ttl_seconds": self.authorization_max_ttl_seconds,
            "authorization_expires_at_utc": _iso(self.authorization_expires_at_utc),
            "state": self.state,
            "started_at_utc": _iso(self.started_at_utc),
            "completed_at_utc": _iso(self.completed_at_utc),
            "counts": dict(self.counts),
            "truncation": dict(self.truncation),
            "requests": [item.as_dict() for item in self.requests],
            "verified_sources": [item.as_dict() for item in self.verified_sources],
            "terminal_code": self.terminal_code,
        }
        if include_hash:
            payload["report_sha256"] = self.report_sha256
        return payload

    def __post_init__(self) -> None:
        if self.state not in {
            "completed",
            "completed_empty",
            "completed_partial",
            "failed",
            "indeterminate",
        }:
            raise DiscoveryArtifactError("terminal_state_invalid")
        if (
            len(self.requests) > MAX_TERMINAL_REQUESTS
            or len(self.verified_sources) > MAX_TERMINAL_VERIFIED_SOURCES
        ):
            raise DiscoveryArtifactError("terminal_report_bounds")
        for value, field in (
            (self.operation_sha256, "operation_sha256"),
            (self.challenge_sha256, "challenge_sha256"),
            (self.start_marker_sha256, "start_marker_sha256"),
            (self.authorization_sha256, "authorization_sha256"),
            (self.policy_sha256, "policy_sha256"),
            (self.plan_sha256, "plan_sha256"),
            (self.report_sha256, "report_sha256"),
        ):
            _sha(value, field=field)
        _canonical_uuid(self.operation_id)
        _binding_dict(self.profile_binding)
        _quota_dicts(self.quota_contexts)
        if self.authorization_max_ttl_seconds != 86_400:
            raise DiscoveryArtifactError("authorization_window_invalid")
        expires = _utc(self.authorization_expires_at_utc, field="authorization_expires_at_utc")
        started = _utc(self.started_at_utc, field="started_at_utc")
        completed = _utc(self.completed_at_utc, field="completed_at_utc")
        if not started < completed or expires <= started:
            raise DiscoveryArtifactError("terminal_report_invalid")
        if expires.month != started.month or expires.year != started.year:
            raise DiscoveryArtifactError("authorization_window_invalid")
        if type(self.counts) is not dict and not isinstance(self.counts, Mapping):
            raise DiscoveryArtifactError("terminal_counts_invalid")
        if set(self.counts) != set(TERMINAL_COUNT_KEYS) or any(
            type(value) is not int or value < 0 for value in self.counts.values()
        ):
            raise DiscoveryArtifactError("terminal_counts_invalid")
        if type(self.truncation) is not dict and not isinstance(self.truncation, Mapping):
            raise DiscoveryArtifactError("terminal_truncation_invalid")
        if set(self.truncation) != set(TERMINAL_TRUNCATION_KEYS) or any(
            type(value) is not bool for value in self.truncation.values()
        ):
            raise DiscoveryArtifactError("terminal_truncation_invalid")
        if self.terminal_code is not None and self.terminal_code not in TERMINAL_CODES:
            raise DiscoveryArtifactError("terminal_code_invalid")
        if type(self.requests) is not tuple or any(
            not isinstance(item, ReportOnlyRequestEvidenceV1) for item in self.requests
        ):
            raise DiscoveryArtifactError("terminal_requests_invalid")
        if type(self.verified_sources) is not tuple or any(
            not isinstance(item, ReportOnlyVerifiedSourceV1) for item in self.verified_sources
        ):
            raise DiscoveryArtifactError("terminal_sources_invalid")
        object.__setattr__(self, "authorization_expires_at_utc", expires)
        object.__setattr__(self, "started_at_utc", started)
        object.__setattr__(self, "completed_at_utc", completed)
        if self.report_sha256 != "0" * 64 and self.report_sha256 != _artifact_hash(
            self.as_dict(include_hash=False), "report_sha256"
        ):
            raise DiscoveryArtifactError("report_hash_mismatch")


def build_terminal_report(**kwargs: object) -> ReportOnlyTerminalReportV1:
    constructor = cast(Any, ReportOnlyTerminalReportV1)
    unsigned = constructor(**kwargs, report_sha256="0" * 64)
    return cast(
        ReportOnlyTerminalReportV1,
        constructor(
            **kwargs,
            report_sha256=_artifact_hash(unsigned.as_dict(include_hash=False), "report_sha256"),
        ),
    )


def parse_terminal_report(value: bytes | Mapping[str, object]) -> ReportOnlyTerminalReportV1:
    """Decode and validate one complete immutable terminal report."""

    payload = (
        loads_bounded_artifact(value, max_bytes=MAX_TERMINAL_REPORT_BYTES)
        if isinstance(value, bytes)
        else value
    )
    try:
        _require_exact_keys(
            payload,
            (
                "schema_version",
                "operation_id",
                "operation_sha256",
                "challenge_sha256",
                "start_marker_sha256",
                "authorization_sha256",
                "profile_binding",
                "policy_sha256",
                "plan_sha256",
                "quota_contexts",
                "authorization_max_ttl_seconds",
                "authorization_expires_at_utc",
                "state",
                "started_at_utc",
                "completed_at_utc",
                "counts",
                "truncation",
                "requests",
                "verified_sources",
                "terminal_code",
                "report_sha256",
            ),
            "terminal_report_invalid",
        )
        if payload["schema_version"] != "report-only-terminal-report-v1":
            raise DiscoveryArtifactError("terminal_report_invalid")
        raw_contexts = payload["quota_contexts"]
        raw_requests = payload["requests"]
        raw_sources = payload["verified_sources"]
        if (
            not isinstance(raw_contexts, list)
            or not isinstance(raw_requests, list)
            or not isinstance(raw_sources, list)
        ):
            raise DiscoveryArtifactError("terminal_report_invalid")
        contexts = tuple(ProviderQuotaContextV1(**item) for item in raw_contexts)
        requests = tuple(
            ReportOnlyRequestEvidenceV1(**item)
            for item in raw_requests
            if isinstance(item, Mapping)
        )
        sources = tuple(
            ReportOnlyVerifiedSourceV1(**item) for item in raw_sources if isinstance(item, Mapping)
        )
        if len(requests) != len(raw_requests) or len(sources) != len(raw_sources):
            raise DiscoveryArtifactError("terminal_report_invalid")
        return ReportOnlyTerminalReportV1(
            operation_id=cast(str, payload["operation_id"]),
            operation_sha256=cast(str, payload["operation_sha256"]),
            challenge_sha256=cast(str, payload["challenge_sha256"]),
            start_marker_sha256=cast(str, payload["start_marker_sha256"]),
            authorization_sha256=cast(str, payload["authorization_sha256"]),
            profile_binding=payload["profile_binding"],
            policy_sha256=cast(str, payload["policy_sha256"]),
            plan_sha256=cast(str, payload["plan_sha256"]),
            quota_contexts=contexts,
            authorization_max_ttl_seconds=cast(int, payload["authorization_max_ttl_seconds"]),
            authorization_expires_at_utc=datetime.fromisoformat(
                cast(str, payload["authorization_expires_at_utc"]).replace("Z", "+00:00")
            ),
            state=cast(str, payload["state"]),
            started_at_utc=datetime.fromisoformat(
                cast(str, payload["started_at_utc"]).replace("Z", "+00:00")
            ),
            completed_at_utc=datetime.fromisoformat(
                cast(str, payload["completed_at_utc"]).replace("Z", "+00:00")
            ),
            counts=cast(Mapping[str, int], payload["counts"]),
            truncation=cast(Mapping[str, bool], payload["truncation"]),
            requests=requests,
            verified_sources=sources,
            terminal_code=cast(str | None, payload["terminal_code"]),
            report_sha256=cast(str, payload["report_sha256"]),
        )
    except DiscoveryArtifactError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise DiscoveryArtifactError("terminal_report_invalid") from exc


def read_start_marker(root: Path, *, name: str = "started-v1.json") -> ReportOnlyStartMarkerV1:
    return parse_start_marker(
        read_private_artifact_bytes(root, name, max_bytes=MAX_START_MARKER_BYTES)
    )


def read_terminal_report(
    root: Path, *, name: str = "terminal-report-v1.json"
) -> ReportOnlyTerminalReportV1:
    return parse_terminal_report(
        read_private_artifact_bytes(root, name, max_bytes=MAX_TERMINAL_REPORT_BYTES)
    )


@dataclass(frozen=True, slots=True)
class DiscoveryReportV2:
    """Sanitized report metadata plus no registration side effect."""

    operation_id: str
    operation_kind: OperationKind
    profile_binding: object
    policy_version: str
    policy_sha256: str
    plan_sha256: str
    challenge_sha256: str
    created_at: datetime
    expires_at: datetime
    status: DiscoveryReportStatus
    query_reports: tuple[DiscoveryQueryReportV2, ...] = ()
    candidate_count: int = 0
    verified_count: int = 0
    registration_count: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.operation_kind, OperationKind):
            try:
                object.__setattr__(self, "operation_kind", OperationKind(self.operation_kind))
            except (TypeError, ValueError) as exc:
                raise DiscoveryArtifactError("operation_kind_invalid") from exc
        if not isinstance(self.status, DiscoveryReportStatus):
            try:
                object.__setattr__(self, "status", DiscoveryReportStatus(self.status))
            except (TypeError, ValueError) as exc:
                raise DiscoveryArtifactError("report_status_invalid") from exc
        if self.operation_kind is not OperationKind.REPORT_ONLY:
            raise DiscoveryArtifactError("gate_a_blocked")
        binding = profile_binding_v2(self.profile_binding)
        object.__setattr__(self, "profile_binding", binding)
        if type(self.operation_id) is not str or not self.operation_id:
            raise DiscoveryArtifactError("operation_id_invalid")
        if type(self.policy_version) is not str or not self.policy_version:
            raise DiscoveryArtifactError("policy_version_invalid")
        _sha(self.policy_sha256, field="policy_sha256")
        _sha(self.plan_sha256, field="plan_sha256")
        _sha(self.challenge_sha256, field="challenge_sha256")
        created = _utc(self.created_at, field="created_at")
        expires = _utc(self.expires_at, field="expires_at")
        if expires <= created:
            raise DiscoveryArtifactError("expiry_invalid")
        if expires - created > timedelta(seconds=MAX_ARTIFACT_TTL_SECONDS):
            raise DiscoveryArtifactError("expiry_invalid")
        object.__setattr__(self, "created_at", created)
        object.__setattr__(self, "expires_at", expires)
        if type(self.query_reports) is not tuple or any(
            not isinstance(item, DiscoveryQueryReportV2) for item in self.query_reports
        ):
            raise DiscoveryArtifactError("query_reports_invalid")
        if len(self.query_reports) > MAX_QUERY_REPORTS:
            raise DiscoveryArtifactError("query_reports_limit")
        if len({item.ordinal for item in self.query_reports}) != len(self.query_reports):
            raise DiscoveryArtifactError("query_ordinals_duplicate")
        for name, value, maximum in (
            ("candidate_count", self.candidate_count, MAX_CANDIDATES),
            ("verified_count", self.verified_count, MAX_VERIFICATIONS),
        ):
            if type(value) is not int or not 0 <= value <= maximum:
                raise DiscoveryArtifactError(f"{name}_invalid")
        if type(self.registration_count) is not int or self.registration_count != 0:
            raise DiscoveryArtifactError("gate_a_blocked")

    @property
    def profile(self) -> object:
        return self.profile_binding

    @property
    def kind(self) -> OperationKind:
        return self.operation_kind

    @property
    def mode(self) -> str:
        return "report_only"

    def expired(self, now: datetime) -> bool:
        return _utc(now, field="now") >= self.expires_at

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": DISCOVERY_REPORT_SCHEMA_VERSION,
            "authorization_schema_version": AUTHORIZATION_SCHEMA_VERSION,
            "operation_id": self.operation_id,
            "operation_kind": self.operation_kind.value,
            "profile_binding": profile_binding_v2(self.profile_binding).as_dict(),
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "plan_sha256": self.plan_sha256,
            "challenge_sha256": self.challenge_sha256,
            "created_at": _iso(self.created_at),
            "expires_at": _iso(self.expires_at),
            "status": self.status.value,
            "query_reports": [item.as_dict() for item in self.query_reports],
            "query_count": len(self.query_reports),
            "candidate_count": self.candidate_count,
            "verified_count": self.verified_count,
            "registration_count": self.registration_count,
        }


ReportV2 = DiscoveryReportV2


def build_discovery_report(
    operation: DiscoveryOperationV2,
    challenge: OperationChallengeV2,
    *,
    status: DiscoveryReportStatus,
    query_reports: tuple[DiscoveryQueryReportV2, ...] = (),
    candidate_count: int = 0,
    verified_count: int = 0,
    now: datetime | None = None,
) -> DiscoveryReportV2:
    """Build report metadata only after the report-only challenge is valid."""

    check_at = operation.created_at if now is None else now
    try:
        validate_report_only_challenge(operation, challenge, now=check_at)
    except ValueError as exc:
        raise DiscoveryArtifactError("challenge_invalid") from exc
    return DiscoveryReportV2(
        operation_id=operation.operation_id,
        operation_kind=operation.kind,
        profile_binding=operation.profile_binding,
        policy_version=operation.policy_version,
        policy_sha256=operation.policy_sha256,
        plan_sha256=operation.plan_sha256,
        challenge_sha256=challenge.challenge_sha256,
        created_at=operation.created_at,
        expires_at=min(operation.expires_at, challenge.expires_at),
        status=status,
        query_reports=query_reports,
        candidate_count=candidate_count,
        verified_count=verified_count,
    )


@dataclass(frozen=True, slots=True)
class DiscoveryArtifactV2:
    """A private, bounded JSON artifact whose content is hash-addressed."""

    report: DiscoveryReportV2
    private_payload: Mapping[str, object] = MappingProxyType({})
    artifact_sha256: str = "0" * 64

    def __post_init__(self) -> None:
        if not isinstance(self.report, DiscoveryReportV2):
            raise DiscoveryArtifactError("report_invalid")
        if not isinstance(self.private_payload, Mapping):
            raise DiscoveryArtifactError("private_payload_invalid")
        converted = _jsonable(self.private_payload)
        if not isinstance(converted, dict):
            raise DiscoveryArtifactError("private_payload_invalid")
        _validate_tree(
            converted,
            max_depth=MAX_PRIVATE_ARTIFACT_DEPTH,
            max_nodes=MAX_PRIVATE_ARTIFACT_NODES,
        )
        object.__setattr__(self, "private_payload", _freeze_json(converted))
        _sha(self.artifact_sha256, field="artifact_sha256")

    def payload(self, *, include_hash: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema_version": DISCOVERY_ARTIFACT_SCHEMA_VERSION,
            "report": self.report.as_dict(),
            "private_payload": dict(self.private_payload),
        }
        if include_hash:
            value["artifact_sha256"] = self.artifact_sha256
        return value

    def private_dict(self) -> dict[str, object]:
        return self.payload()

    def sanitized_dict(self) -> dict[str, object]:
        return {
            "schema_version": DISCOVERY_ARTIFACT_SCHEMA_VERSION,
            "report": self.report.as_dict(),
        }

    as_dict = private_dict


PrivateDiscoveryArtifactV2 = DiscoveryArtifactV2
DiscoveryReportArtifactV2 = DiscoveryArtifactV2
ArtifactJsonV2 = DiscoveryArtifactV2
PrivateArtifactV2 = DiscoveryArtifactV2


def canonical_artifact_payload(
    artifact: DiscoveryArtifactV2, *, include_hash: bool = True
) -> dict[str, object]:
    if not isinstance(artifact, DiscoveryArtifactV2):
        raise TypeError("canonical_artifact_payload requires DiscoveryArtifactV2")
    return artifact.payload(include_hash=include_hash)


def canonical_artifact_bytes(artifact: DiscoveryArtifactV2, *, include_hash: bool = True) -> bytes:
    return canonical_artifact_json(canonical_artifact_payload(artifact, include_hash=include_hash))


def artifact_sha256(artifact: DiscoveryArtifactV2) -> str:
    return sha256(canonical_artifact_bytes(artifact, include_hash=False)).hexdigest()


canonical_discovery_artifact_payload = canonical_artifact_payload
canonical_discovery_artifact_bytes = canonical_artifact_bytes
canonical_discovery_artifact_sha256 = artifact_sha256
canonical_artifact_sha256 = artifact_sha256
canonical_private_artifact_bytes = canonical_artifact_bytes
canonical_private_artifact_sha256 = artifact_sha256


def build_discovery_artifact(
    report: DiscoveryReportV2, private_payload: Mapping[str, object] | None = None
) -> DiscoveryArtifactV2:
    unsigned = DiscoveryArtifactV2(report, private_payload or {}, "0" * 64)
    return DiscoveryArtifactV2(report, private_payload or {}, artifact_sha256(unsigned))


create_discovery_artifact = build_discovery_artifact


def validate_discovery_artifact(
    artifact: DiscoveryArtifactV2, *, now: datetime | None = None
) -> DiscoveryArtifactV2:
    if not isinstance(artifact, DiscoveryArtifactV2):
        raise TypeError("validate_discovery_artifact requires DiscoveryArtifactV2")
    if artifact.artifact_sha256 != artifact_sha256(artifact):
        raise DiscoveryArtifactError("artifact_hash_mismatch")
    if now is not None and artifact.report.expired(now):
        raise DiscoveryArtifactError("artifact_expired")
    return artifact


def validate_report_artifact_binding(
    artifact: DiscoveryArtifactV2,
    operation: DiscoveryOperationV2,
    challenge: OperationChallengeV2,
    *,
    now: datetime,
) -> DiscoveryArtifactV2:
    validate_discovery_artifact(artifact, now=now)
    if artifact.report.operation_id != operation.operation_id:
        raise DiscoveryArtifactError("operation_binding_mismatch")
    if artifact.report.challenge_sha256 != challenge.challenge_sha256:
        raise DiscoveryArtifactError("challenge_binding_mismatch")
    validate_report_only_operation(
        operation,
        profile_binding=artifact.report.profile_binding,
        policy_version=artifact.report.policy_version,
        policy_sha256=artifact.report.policy_sha256,
        plan_sha256=artifact.report.plan_sha256,
        now=now,
    )
    validate_report_only_challenge(operation, challenge, now=now)
    if operation_sha256(operation) != challenge.operation_sha256:
        raise DiscoveryArtifactError("operation_binding_mismatch")
    if challenge_sha256(operation) != artifact.report.challenge_sha256:
        raise DiscoveryArtifactError("challenge_binding_mismatch")
    return artifact


def _artifact_name(name: object) -> str:
    if type(name) is not str or not 1 <= len(name) <= MAX_ARTIFACT_NAME_CHARS:
        raise DiscoveryArtifactError("artifact_name_invalid")
    if name in {".", ".."} or any(char in name for char in "/\\\0"):
        raise DiscoveryArtifactError("artifact_name_invalid")
    if any(ord(char) < 32 for char in name):
        raise DiscoveryArtifactError("artifact_name_invalid")
    return name


def _root_path(root: Path) -> Path:
    if not isinstance(root, Path) or not root.is_absolute() or root == Path(root.anchor):
        raise DiscoveryArtifactError("artifact_root_invalid")
    return root


def ensure_private_artifact_root(root: Path, *, create: bool = True) -> Path:
    """Create/validate only the caller-injected root, with mode 0700."""

    path = _root_path(root)
    try:
        for parent in reversed(path.parents):
            metadata = parent.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise DiscoveryArtifactError("artifact_root_not_private")
        if not path.exists():
            if not create:
                raise DiscoveryArtifactError("artifact_root_missing")
            path.mkdir(parents=True, mode=0o700)
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != os.geteuid()
            or path.is_symlink()
        ):
            raise DiscoveryArtifactError("artifact_root_not_private")
    except DiscoveryArtifactError:
        raise
    except OSError as exc:
        raise DiscoveryArtifactError("artifact_root_invalid") from exc
    return path


def artifact_path(root: Path, name: str) -> Path:
    return ensure_private_artifact_root(root) / _artifact_name(name)


def _validate_private_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise DiscoveryArtifactError("artifact_missing") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or path.is_symlink()
    ):
        raise DiscoveryArtifactError("artifact_not_private")


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise DiscoveryArtifactError("artifact_write_failed")
        view = view[written:]


def stage_private_artifact(root: Path, name: str, payload: bytes) -> Path:
    """Write a private staging file; publication remains an explicit step."""

    directory = ensure_private_artifact_root(root)
    _artifact_name(name)
    if type(payload) is not bytes or len(payload) > MAX_PRIVATE_ARTIFACT_BYTES:
        raise DiscoveryArtifactError("artifact_too_large")
    descriptor = -1
    staging: Path | None = None
    completed = False
    try:
        descriptor, raw_name = tempfile.mkstemp(prefix=f".{name}.", dir=directory)
        staging = directory / raw_name
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        _validate_private_file(staging)
        completed = True
        return staging
    except DiscoveryArtifactError:
        raise
    except OSError as exc:
        raise DiscoveryArtifactError("artifact_stage_failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not completed and staging is not None:
            with suppress(FileNotFoundError):
                staging.unlink()


def publish_no_replace(staging: Path, target: Path) -> Path:
    """Publish with an atomic hard-link, never replacing an existing target."""

    if not isinstance(staging, Path) or not isinstance(target, Path):
        raise DiscoveryArtifactError("publish_path_invalid")
    if staging.parent != target.parent or staging.name == target.name:
        raise DiscoveryArtifactError("publish_path_invalid")
    ensure_private_artifact_root(target.parent)
    _artifact_name(target.name)
    _validate_private_file(staging)
    parent_fd = -1
    linked = False
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        parent_fd = os.open(target.parent, flags | getattr(os, "O_CLOEXEC", 0))
        try:
            os.link(
                staging.name,
                target.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
            linked = True
        except FileExistsError as exc:
            raise DiscoveryArtifactError("artifact_exists") from exc
        os.fsync(parent_fd)
        os.unlink(staging.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        return target
    except DiscoveryArtifactError:
        raise
    except OSError as exc:
        code = "artifact_exists" if exc.errno == errno.EEXIST else "publish_failed"
        raise DiscoveryArtifactError(code) from exc
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)
        if not linked and staging.exists():
            # The caller can retry or inspect the staging artifact after a
            # conflict; write_private_artifact removes it in its own cleanup.
            pass


def write_private_artifact(
    root: Path,
    name: str,
    artifact: DiscoveryArtifactV2 | Mapping[str, object] | bytes,
) -> Path:
    """Encode, stage, and no-replace publish one bounded private artifact."""

    if isinstance(artifact, bytes):
        loads_bounded_artifact(artifact)
        payload = artifact
    else:
        payload = canonical_artifact_json(artifact)
    staging = stage_private_artifact(root, name, payload)
    target = artifact_path(root, name)
    try:
        return publish_no_replace(staging, target)
    finally:
        with suppress(FileNotFoundError):
            staging.unlink()


write_artifact_no_replace = write_private_artifact
write_bounded_private_artifact = write_private_artifact


def read_private_artifact_bytes(
    root: Path, name: str, *, max_bytes: int = MAX_PRIVATE_ARTIFACT_BYTES
) -> bytes:
    path = artifact_path(root, name)
    _validate_private_file(path)
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
        ):
            raise DiscoveryArtifactError("artifact_not_private")
        payload = os.read(descriptor, max_bytes + 1)
        if len(payload) > max_bytes:
            raise DiscoveryArtifactError("artifact_too_large")
        return payload
    except DiscoveryArtifactError:
        raise
    except OSError as exc:
        raise DiscoveryArtifactError("artifact_read_failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def read_private_artifact(
    root: Path, name: str, *, max_bytes: int = MAX_PRIVATE_ARTIFACT_BYTES
) -> Mapping[str, object]:
    return loads_bounded_artifact(read_private_artifact_bytes(root, name, max_bytes=max_bytes))


read_private_json = read_private_artifact


class PrivateArtifactStore:
    """Small injected-root facade useful to offline callers and tests."""

    def __init__(self, root: Path, *, max_bytes: int = MAX_PRIVATE_ARTIFACT_BYTES) -> None:
        self.root = _root_path(root)
        if type(max_bytes) is not int or max_bytes <= 0 or max_bytes > MAX_PRIVATE_ARTIFACT_BYTES:
            raise DiscoveryArtifactError("artifact_limit_invalid")
        self.max_bytes = max_bytes

    def ensure(self) -> Path:
        return ensure_private_artifact_root(self.root)

    def write(
        self, name: str, artifact: DiscoveryArtifactV2 | Mapping[str, object] | bytes
    ) -> Path:
        payload = artifact if isinstance(artifact, bytes) else canonical_artifact_json(artifact)
        if len(payload) > self.max_bytes:
            raise DiscoveryArtifactError("artifact_too_large")
        return write_private_artifact(self.root, name, payload)

    def read(self, name: str) -> Mapping[str, object]:
        return read_private_artifact(self.root, name, max_bytes=self.max_bytes)


ArtifactStoreV2 = PrivateArtifactStore
DiscoveryArtifactStoreV2 = PrivateArtifactStore


__all__ = [  # noqa: RUF022
    "ArtifactError",
    "ArtifactJsonV2",
    "ArtifactStoreV2",
    "DISCOVERY_ARTIFACT_SCHEMA_VERSION",
    "DISCOVERY_REPORT_SCHEMA_VERSION",
    "DiscoveryArtifactError",
    "DiscoveryArtifactV2",
    "DiscoveryArtifactStoreV2",
    "DiscoveryQueryReportV2",
    "DiscoveryReportArtifactV2",
    "DiscoveryReportStatus",
    "DiscoveryReportV2",
    "MAX_ARTIFACT_NAME_CHARS",
    "MAX_ARTIFACT_TTL_SECONDS",
    "MAX_CANDIDATES",
    "MAX_PRIVATE_ARTIFACT_BYTES",
    "MAX_PRIVATE_ARTIFACT_DEPTH",
    "MAX_PRIVATE_ARTIFACT_NODES",
    "MAX_QUERY_REPORTS",
    "MAX_OPERATION_ARTIFACT_BYTES",
    "MAX_PLAN_ARTIFACT_BYTES",
    "MAX_START_MARKER_BYTES",
    "MAX_TERMINAL_REPORT_BYTES",
    "MAX_TERMINAL_REQUESTS",
    "MAX_TERMINAL_VERIFIED_SOURCES",
    "MAX_VERIFICATIONS",
    "PrivateArtifactStore",
    "PrivateDiscoveryArtifactV2",
    "PrivateArtifactV2",
    "QueryReportV2",
    "ReportV2",
    "ReportOnlyRequestEvidenceV1",
    "ReportOnlyStartMarkerV1",
    "ReportOnlyTerminalReportV1",
    "ReportOnlyVerifiedSourceV1",
    "canonical_artifact_bytes",
    "canonical_artifact_json",
    "canonical_artifact_payload",
    "canonical_artifact_sha256",
    "canonical_discovery_artifact_bytes",
    "canonical_discovery_artifact_payload",
    "canonical_discovery_artifact_sha256",
    "canonical_private_artifact_bytes",
    "canonical_private_artifact_sha256",
    "create_discovery_artifact",
    "decode_bounded_artifact",
    "ensure_private_artifact_root",
    "artifact_path",
    "artifact_sha256",
    "build_discovery_artifact",
    "build_discovery_report",
    "build_start_marker",
    "build_terminal_report",
    "loads_bounded_artifact",
    "parse_start_marker",
    "parse_terminal_report",
    "publish_no_replace",
    "read_private_artifact",
    "read_private_artifact_bytes",
    "read_private_json",
    "read_start_marker",
    "read_terminal_report",
    "stage_private_artifact",
    "validate_discovery_artifact",
    "validate_report_artifact_binding",
    "write_artifact_no_replace",
    "write_bounded_private_artifact",
    "write_private_artifact",
]
