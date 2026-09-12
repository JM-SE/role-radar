"""Recovered-only bounded synthetic Gate D execution seam."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from .recovered_gate_d_adaptation import RecoveredGateDAdaptationBinding
from .recovered_gate_d_adaptation_authorization import (
    RecoveredGateDAdaptationAuthorization,
)
from .recovered_gate_d_adaptation_service import authorize_recovered_gate_d
from .recovered_gate_d_execution_authorization import (
    RecoveredGateDExecutionAuthorization,
    RecoveredGateDExecutionAuthorizationError,
)


class RecoveredGateDExecutionError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class RecoveredGateDSyntheticRequest:
    binding: RecoveredGateDAdaptationBinding
    namespace: str
    selection_seed: str
    partition_seed: str
    budget_units: int
    max_parent_pool: int
    max_journal_entries: int

    @property
    def source_count(self) -> int:
        return self.binding.source_count


@runtime_checkable
class RecoveredGateDSyntheticAdapter(Protocol):
    def run(self, request: RecoveredGateDSyntheticRequest) -> Mapping[str, object]: ...


class RecoveredGateDExecutionWriter(Protocol):
    root: object

    def publish(self, name: str, payload: bytes) -> None: ...

    def read(self, name: str) -> bytes | None: ...

    def list_names(self) -> tuple[str, ...]: ...


@dataclass(frozen=True, slots=True)
class RecoveredGateDExecutionResult:
    operation_id: str
    result: str
    artifact_sha256: str
    budget_units: int
    source_count: int

    def as_dict(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "result": self.result,
            "artifact_sha256": self.artifact_sha256,
            "budget_units": self.budget_units,
            "source_count": self.source_count,
            "effect": "synthetic_only",
            "downstream": "disabled",
        }


def _authorization_identity(auth: RecoveredGateDExecutionAuthorization) -> dict[str, object]:
    return {
        "action": auth.action,
        "approval_reference": auth.approval_reference,
        "operator_id": auth.operator_id,
        "candidate_commit_sha256": auth.candidate_commit_sha256,
        "window_start_utc": auth.window_start_utc,
        "expires_at_utc": auth.expires_at_utc,
        "historical_root": auth.historical_root,
        "recovery_root": auth.recovery_root,
        "post_c_root": auth.post_c_root,
        "output_root": auth.output_root,
        "operation_id": auth.operation_id,
        "seal_sha256": auth.seal_sha256,
        "source_plan_sha256": auth.source_plan_sha256,
        "report_sha256": auth.report_sha256,
        "post_c_authorization_sha256": auth.post_c_authorization_sha256,
        "source_keys": auth.source_keys,
        "namespace": auth.namespace,
        "selection_seed": auth.selection_seed,
        "partition_seed": auth.partition_seed,
        "budget_units": auth.budget_units,
        "max_parent_pool": auth.max_parent_pool,
        "max_journal_entries": auth.max_journal_entries,
    }


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _artifact_payloads(
    auth: RecoveredGateDExecutionAuthorization,
    request: RecoveredGateDSyntheticRequest,
    outcome: Mapping[str, object],
) -> dict[str, bytes]:
    if (
        not set(outcome) <= {"fixture", "journal", "parent_pool"}
        or outcome.get("fixture") != "bounded"
    ):
        raise RecoveredGateDExecutionError("gate_d_execution_fixture_invalid")
    journal = outcome.get("journal", [{"event": "synthetic_complete"}])
    parent_pool = outcome.get("parent_pool", [])
    if not isinstance(journal, list) or len(journal) > request.max_journal_entries:
        raise RecoveredGateDExecutionError("gate_d_execution_journal_limit")
    if not isinstance(parent_pool, list) or len(parent_pool) > request.max_parent_pool:
        raise RecoveredGateDExecutionError("gate_d_execution_parent_pool_limit")
    consumed_budget = len(journal) + len(parent_pool)
    if consumed_budget > request.budget_units:
        raise RecoveredGateDExecutionError("gate_d_execution_budget_exhausted")
    budget_status = "exhausted" if consumed_budget == request.budget_units else "completed"
    checkpoint = {
        "operation_id": auth.operation_id,
        "namespace": auth.namespace,
        "selection_seed": auth.selection_seed,
        "partition_seed": auth.partition_seed,
        "budget_units": auth.budget_units,
        "parent_pool_count": len(parent_pool),
        "journal_entry_count": len(journal),
        "budget_units_consumed": consumed_budget,
        "budget_status": budget_status,
    }
    identity = _authorization_identity(auth)
    payloads = {
        "journal.json": _canonical(journal),
        "checkpoint.json": _canonical(checkpoint),
        "evidence.json": _canonical(
            {
                "authorization": identity,
                "fixture": {"fixture": "bounded"},
                "source_count": request.source_count,
            }
        ),
        "parent-pool.json": _canonical(parent_pool),
    }
    manifest = {
        "schema_version": "f10.1f-gate-d-recovered-synthetic-manifest-v1",
        "operation_id": auth.operation_id,
        "authorization": identity,
        "authorization_sha256": hashlib.sha256(_canonical(identity)).hexdigest(),
        "candidate_commit_sha256": auth.candidate_commit_sha256,
        "source_plan_sha256": auth.source_plan_sha256,
        "report_sha256": auth.report_sha256,
        "source_keys": auth.source_keys,
        "namespace": auth.namespace,
        "selection_seed": auth.selection_seed,
        "partition_seed": auth.partition_seed,
        "budget_units": auth.budget_units,
        "budget_units_consumed": consumed_budget,
        "budget_status": budget_status,
        "max_parent_pool": auth.max_parent_pool,
        "max_journal_entries": auth.max_journal_entries,
        "artifact_sha256": {
            name: hashlib.sha256(value).hexdigest() for name, value in payloads.items()
        },
        "result": "sealed",
    }
    payloads["manifest.json"] = _canonical(manifest)
    return payloads


def _replay_manifest(
    authorization: RecoveredGateDExecutionAuthorization,
    writer: RecoveredGateDExecutionWriter,
) -> RecoveredGateDExecutionResult | None:
    raw_manifest = writer.read("manifest.json")
    if raw_manifest is None:
        return None
    try:
        manifest = json.loads(raw_manifest.decode("utf-8"))
        identity = _authorization_identity(authorization)
        persisted_identity = {**identity, "source_keys": list(authorization.source_keys)}
        hashes = manifest["artifact_sha256"]
        if raw_manifest != _canonical(manifest):
            raise ValueError
        expected_fields = {
            "schema_version",
            "operation_id",
            "authorization",
            "authorization_sha256",
            "candidate_commit_sha256",
            "source_plan_sha256",
            "report_sha256",
            "source_keys",
            "namespace",
            "selection_seed",
            "partition_seed",
            "budget_units",
            "max_parent_pool",
            "max_journal_entries",
            "artifact_sha256",
            "result",
            "budget_units_consumed",
            "budget_status",
        }
        if (
            not isinstance(manifest, dict)
            or set(manifest) != expected_fields
            or manifest["schema_version"] != "f10.1f-gate-d-recovered-synthetic-manifest-v1"
            or manifest.get("operation_id") != authorization.operation_id
            or manifest.get("authorization") != persisted_identity
            or manifest.get("authorization_sha256")
            != hashlib.sha256(_canonical(identity)).hexdigest()
            or manifest.get("candidate_commit_sha256") != authorization.candidate_commit_sha256
            or manifest.get("source_plan_sha256") != authorization.source_plan_sha256
            or manifest.get("report_sha256") != authorization.report_sha256
            or manifest.get("source_keys") != list(authorization.source_keys)
            or manifest.get("namespace") != authorization.namespace
            or manifest.get("selection_seed") != authorization.selection_seed
            or manifest.get("partition_seed") != authorization.partition_seed
            or manifest.get("budget_units") != authorization.budget_units
            or manifest.get("max_parent_pool") != authorization.max_parent_pool
            or manifest.get("max_journal_entries") != authorization.max_journal_entries
            or manifest.get("result") != "sealed"
            or not isinstance(hashes, dict)
            or set(hashes)
            != {"journal.json", "checkpoint.json", "evidence.json", "parent-pool.json"}
        ):
            raise ValueError
        if set(writer.list_names()) != set(hashes) | {"manifest.json"}:
            raise ValueError
        if (
            type(manifest["budget_units_consumed"]) is not int
            or manifest["budget_units_consumed"] > authorization.budget_units
        ):
            raise ValueError
        checkpoint_raw = writer.read("checkpoint.json")
        journal_raw = writer.read("journal.json")
        parent_pool_raw = writer.read("parent-pool.json")
        if checkpoint_raw is None or journal_raw is None or parent_pool_raw is None:
            raise ValueError
        checkpoint = json.loads(checkpoint_raw.decode("utf-8"))
        journal = json.loads(journal_raw.decode("utf-8"))
        parent_pool = json.loads(parent_pool_raw.decode("utf-8"))
        evidence_raw = writer.read("evidence.json")
        if evidence_raw is None:
            raise ValueError
        evidence = json.loads(evidence_raw.decode("utf-8"))
        checkpoint_fields = {
            "operation_id",
            "namespace",
            "selection_seed",
            "partition_seed",
            "budget_units",
            "parent_pool_count",
            "journal_entry_count",
            "budget_units_consumed",
            "budget_status",
        }
        evidence_fields = {"authorization", "fixture", "source_count"}
        if (
            not isinstance(checkpoint, dict)
            or set(checkpoint) != checkpoint_fields
            or not isinstance(evidence, dict)
            or set(evidence) != evidence_fields
            or checkpoint["operation_id"] != authorization.operation_id
            or checkpoint["namespace"] != authorization.namespace
            or checkpoint["selection_seed"] != authorization.selection_seed
            or checkpoint["partition_seed"] != authorization.partition_seed
            or checkpoint["budget_units"] != authorization.budget_units
            or checkpoint["parent_pool_count"] != len(parent_pool)
            or checkpoint["journal_entry_count"] != len(journal)
            or checkpoint["budget_units_consumed"] != manifest["budget_units_consumed"]
            or checkpoint["budget_status"] != manifest["budget_status"]
            or not isinstance(journal, list)
            or not isinstance(parent_pool, list)
            or journal_raw != _canonical(journal)
            or parent_pool_raw != _canonical(parent_pool)
            or evidence_raw != _canonical(evidence)
            or checkpoint["budget_units_consumed"] != len(journal) + len(parent_pool)
            or checkpoint["budget_status"]
            != (
                "exhausted"
                if checkpoint["budget_units_consumed"] == authorization.budget_units
                else "completed"
            )
            or evidence["authorization"] != persisted_identity
            or evidence["source_count"] != 6
            or evidence["fixture"] != {"fixture": "bounded"}
            or checkpoint_raw != _canonical(checkpoint)
        ):
            raise ValueError
        if manifest["budget_status"] not in {"completed", "exhausted"}:
            raise ValueError
        for name, expected_hash in hashes.items():
            artifact = writer.read(name)
            if artifact is None or hashlib.sha256(artifact).hexdigest() != expected_hash:
                raise ValueError
        return RecoveredGateDExecutionResult(
            authorization.operation_id,
            "sealed",
            hashlib.sha256(raw_manifest).hexdigest(),
            authorization.budget_units,
            6,
        )
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise RecoveredGateDExecutionError("gate_d_execution_output_conflict") from exc


def run_recovered_gate_d_bounded_synthetic(
    authorization: RecoveredGateDExecutionAuthorization,
    adapter: RecoveredGateDSyntheticAdapter,
    writer: RecoveredGateDExecutionWriter,
    *,
    clock: Callable[[], datetime] | None = None,
) -> RecoveredGateDExecutionResult:
    """Run one bounded fixture seam; never dispatches to ordinary Gate D."""
    if type(authorization) is not RecoveredGateDExecutionAuthorization:
        raise RecoveredGateDExecutionError("gate_d_execution_authorization_invalid")
    if not isinstance(adapter, RecoveredGateDSyntheticAdapter):
        raise RecoveredGateDExecutionError("gate_d_execution_adapter_invalid")
    if not all(callable(getattr(writer, name, None)) for name in ("publish", "read", "list_names")):
        raise RecoveredGateDExecutionError("gate_d_execution_writer_invalid")
    if str(getattr(writer, "root", "")) != authorization.output_root:
        raise RecoveredGateDExecutionError("gate_d_execution_output_root_invalid")
    trusted_clock = authorization.clock if clock is None else clock
    try:
        authorization.validate_current(trusted_clock())
        binding = authorize_recovered_gate_d(
            _adaptation_authorization(authorization), clock=trusted_clock
        )
        request = RecoveredGateDSyntheticRequest(
            binding,
            authorization.namespace,
            authorization.selection_seed,
            authorization.partition_seed,
            authorization.budget_units,
            authorization.max_parent_pool,
            authorization.max_journal_entries,
        )
        names = set(writer.list_names())
        expected_names = {
            "journal.json",
            "checkpoint.json",
            "evidence.json",
            "parent-pool.json",
            "manifest.json",
        }
        if names not in (set(), expected_names):
            raise RecoveredGateDExecutionError("gate_d_execution_output_conflict")
        replay = _replay_manifest(authorization, writer)
        if replay is not None:
            return replay
        if any(
            writer.read(name) is not None
            for name in ("journal.json", "checkpoint.json", "evidence.json", "parent-pool.json")
        ):
            raise RecoveredGateDExecutionError("gate_d_execution_output_conflict")
        authorization.validate_current(trusted_clock())
        outcome = adapter.run(request)
        if not isinstance(outcome, Mapping):
            raise RecoveredGateDExecutionError("gate_d_execution_fixture_invalid")
        payloads = _artifact_payloads(authorization, request, outcome)
        expected = tuple(payloads.items())
        existing = {name: writer.read(name) for name in payloads}
        if any(value is not None for value in existing.values()):
            if all(existing[name] == payload for name, payload in expected):
                manifest_sha = hashlib.sha256(payloads["manifest.json"]).hexdigest()
                return RecoveredGateDExecutionResult(
                    authorization.operation_id,
                    "sealed",
                    manifest_sha,
                    authorization.budget_units,
                    binding.source_count,
                )
            raise RecoveredGateDExecutionError("gate_d_execution_output_conflict")
        for name, payload in expected:
            authorization.validate_current(trusted_clock())
            writer.publish(name, payload)
        return RecoveredGateDExecutionResult(
            authorization.operation_id,
            "sealed",
            hashlib.sha256(payloads["manifest.json"]).hexdigest(),
            authorization.budget_units,
            binding.source_count,
        )
    except RecoveredGateDExecutionError:
        raise
    except (RecoveredGateDExecutionAuthorizationError, ValueError, TypeError) as exc:
        raise RecoveredGateDExecutionError(getattr(exc, "code", "gate_d_execution_failed")) from exc


def _adaptation_authorization(
    authorization: RecoveredGateDExecutionAuthorization,
) -> RecoveredGateDAdaptationAuthorization:
    from .recovered_gate_d_adaptation_authorization import ACTION

    return RecoveredGateDAdaptationAuthorization(
        action=ACTION,
        approval_reference=authorization.approval_reference,
        operator_id=authorization.operator_id,
        window_start_utc=authorization.window_start_utc,
        expires_at_utc=authorization.expires_at_utc,
        historical_root=authorization.historical_root,
        recovery_root=authorization.recovery_root,
        post_c_root=authorization.post_c_root,
        operation_id=authorization.operation_id,
        seal_sha256=authorization.seal_sha256,
        source_plan_sha256=authorization.source_plan_sha256,
        report_sha256=authorization.report_sha256,
        post_c_authorization_sha256=authorization.post_c_authorization_sha256,
        source_keys=authorization.source_keys,
        clock=authorization.clock,
    )


__all__ = [
    "RecoveredGateDExecutionError",
    "RecoveredGateDExecutionResult",
    "RecoveredGateDExecutionWriter",
    "RecoveredGateDSyntheticAdapter",
    "RecoveredGateDSyntheticRequest",
    "run_recovered_gate_d_bounded_synthetic",
]
