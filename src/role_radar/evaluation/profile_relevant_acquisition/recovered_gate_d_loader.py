"""Dependency-light, read-only loader for the recovered Gate D preflight."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from .post_c_recovery_filesystem import (
    MAX_SEAL_BYTES,
    pinned_root,
    read_json,
)
from .recovered_gate_d_authorization import (
    EXPECTED_EVIDENCE_SHA256,
    EXPECTED_EXPIRES_AT_UTC,
    EXPECTED_HISTORICAL_APPROVAL,
    EXPECTED_OPERATION_SHA256,
    EXPECTED_PLAN_SHA256,
    EXPECTED_POLICY_SHA256,
    EXPECTED_POST_C_APPROVAL,
    EXPECTED_PROFILE_ID,
    EXPECTED_PROFILE_SHA256,
    EXPECTED_PROFILE_VERSION,
    EXPECTED_SOURCE_KEYS,
    EXPECTED_STATE,
    EXPECTED_TERMINAL_CODE,
    EXPECTED_WINDOW_START_UTC,
    RecoveredGateDPreflightAuthorization,
)


class RecoveredGateDLoadError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _require_fields(value: dict[str, object], fields: set[str]) -> None:
    if set(value) != fields:
        raise RecoveredGateDLoadError("gate_d_preflight_artifact_schema_invalid")


def load_recovered_gate_d_preflight(
    authorization: RecoveredGateDPreflightAuthorization,
    *,
    clock: Callable[[], datetime],
) -> tuple[str, str, int]:
    """Validate all local recovery outputs without constructing live Gate D types."""
    try:
        authorization.validate_current(clock())
        recovery = Path(authorization.recovery_root)
        post_c = Path(authorization.post_c_root)
        with (
            pinned_root(Path(authorization.historical_root)),
            pinned_root(recovery) as recovery_fd,
            pinned_root(post_c) as post_c_fd,
        ):
            manifest_path = recovery / "recovery-manifest.json"
            verdict_path = recovery / "recovery-verdict.json"
            evidence_path = (
                recovery
                / "gate-c"
                / "e7ea8287e7cb1d1d4f2f32ffb8c0db84b1889bf70be404a96778b34a9afc2b95"
                / "real_discovery_evidence.json"
            )
            manifest, _ = read_json(
                recovery_fd,
                recovery,
                manifest_path,
                approved_raw_sha256="a4f273f59015c00580509d0c697eb7a4d5f131fb46d1e237b21cbf1a93a58d1b",
            )
            verdict, _ = read_json(
                recovery_fd,
                recovery,
                verdict_path,
                approved_raw_sha256="a4ec7f1d35a28dd21df7cd118092a70b501a38f69696664a8967a82cf5ef4c0d",
            )
            evidence, evidence_raw = read_json(recovery_fd, recovery, evidence_path)
            seal_path = post_c / "post-c" / f"{authorization.operation_id}.json"
            seal, seal_raw = read_json(post_c_fd, post_c, seal_path, maximum=MAX_SEAL_BYTES)
        _require_fields(
            manifest,
            {
                "approval_reference",
                "evidence_sha256",
                "operation_id",
                "operation_sha256",
                "plan_sha256",
                "report_sha256",
                "schema_version",
                "source_plan_sha256",
                "state",
                "terminal_code",
                "verified_source_count",
            },
        )
        _require_fields(
            verdict,
            {
                "checks",
                "credentials",
                "downstream",
                "network",
                "operation_id",
                "operation_sha256",
                "plan_sha256",
                "quota",
                "report_sha256",
                "result",
                "schema_version",
                "source_plan_sha256",
                "verified_source_count",
            },
        )
        _require_fields(
            evidence,
            {"plan_sha256", "report_sha256", "source_plan_sha256", "verified_sources"},
        )
        if hashlib.sha256(seal_raw).hexdigest() != authorization.seal_sha256:
            raise RecoveredGateDLoadError("gate_d_preflight_seal_hash_mismatch")
        expected_seal_fields = {
            "action",
            "approval_reference",
            "authorization_sha256",
            "evidence_sha256",
            "expires_at_utc",
            "operation_id",
            "operation_sha256",
            "plan_sha256",
            "policy_sha256",
            "profile_id",
            "profile_sha256",
            "profile_version",
            "report_sha256",
            "schema_version",
            "source_plan_sha256",
            "state",
            "terminal_code",
            "verified_source_count",
            "window_start_utc",
        }
        _require_fields(seal, expected_seal_fields)
        if (
            seal["action"] != "offline_preregistration"
            or seal["approval_reference"] != EXPECTED_POST_C_APPROVAL
            or seal["authorization_sha256"] != authorization.post_c_authorization_sha256
            or seal["evidence_sha256"] != EXPECTED_EVIDENCE_SHA256
            or seal["operation_id"] != authorization.operation_id
            or seal["operation_sha256"] != EXPECTED_OPERATION_SHA256
            or seal["plan_sha256"] != EXPECTED_PLAN_SHA256
            or seal["policy_sha256"] != EXPECTED_POLICY_SHA256
            or seal["profile_id"] != EXPECTED_PROFILE_ID
            or seal["profile_sha256"] != EXPECTED_PROFILE_SHA256
            or seal["profile_version"] != EXPECTED_PROFILE_VERSION
            or seal["source_plan_sha256"] != authorization.source_plan_sha256
            or seal["report_sha256"] != authorization.report_sha256
            or seal["expires_at_utc"] != EXPECTED_EXPIRES_AT_UTC
            or seal["window_start_utc"] != EXPECTED_WINDOW_START_UTC
            or seal["state"] != EXPECTED_STATE
            or seal["terminal_code"] != EXPECTED_TERMINAL_CODE
            or seal["verified_source_count"] != 6
        ):
            raise RecoveredGateDLoadError("gate_d_preflight_seal_binding_mismatch")
        common = (
            authorization.operation_id,
            authorization.source_plan_sha256,
            authorization.report_sha256,
        )
        if (
            tuple(
                manifest[name] for name in ("operation_id", "source_plan_sha256", "report_sha256")
            )
            != common
            or tuple(
                verdict[name] for name in ("operation_id", "source_plan_sha256", "report_sha256")
            )
            != common
            or tuple(evidence[name] for name in ("source_plan_sha256", "report_sha256"))
            != common[1:]
            or manifest["approval_reference"] != EXPECTED_HISTORICAL_APPROVAL
            or manifest["operation_sha256"] != EXPECTED_OPERATION_SHA256
            or manifest["plan_sha256"] != EXPECTED_PLAN_SHA256
            or manifest["evidence_sha256"] != EXPECTED_EVIDENCE_SHA256
            or manifest["state"] != EXPECTED_STATE
            or manifest["terminal_code"] != EXPECTED_TERMINAL_CODE
            or manifest["verified_source_count"] != 6
            or verdict["operation_sha256"] != EXPECTED_OPERATION_SHA256
            or verdict["plan_sha256"] != EXPECTED_PLAN_SHA256
            or verdict["result"] != "passed"
            or verdict["verified_source_count"] != 6
            or hashlib.sha256(evidence_raw).hexdigest() != EXPECTED_EVIDENCE_SHA256
            or not isinstance(evidence["verified_sources"], list)
            or len(evidence["verified_sources"]) != 6
        ):
            raise RecoveredGateDLoadError("gate_d_preflight_provenance_mismatch")
        source_keys: list[str] = []
        expected_source_fields = {
            "board_candidate_ordinal",
            "configuration",
            "configuration_sha256",
            "family",
            "postings_count",
            "request_identity_sha256",
            "source_key",
        }
        for source in evidence["verified_sources"]:
            if not isinstance(source, dict) or set(source) != expected_source_fields:
                raise RecoveredGateDLoadError("gate_d_preflight_artifact_schema_invalid")
            if (
                not isinstance(source["source_key"], str)
                or source["source_key"] not in EXPECTED_SOURCE_KEYS
                or not isinstance(source["configuration"], dict)
                or type(source["postings_count"]) is not int
                or source["postings_count"] < 0
                or any(
                    not isinstance(source[name], str) or len(source[name]) != 64
                    for name in ("configuration_sha256", "request_identity_sha256")
                )
            ):
                raise RecoveredGateDLoadError("gate_d_preflight_provenance_mismatch")
            source_keys.append(source["source_key"])
        if tuple(source_keys) != authorization.source_keys:
            raise RecoveredGateDLoadError("gate_d_preflight_source_keys_mismatch")
        authorization.validate_current(clock())
        return "completed_partial", "multiple_budgets_exhausted", 6
    except RecoveredGateDLoadError:
        raise
    except Exception as exc:
        raise RecoveredGateDLoadError(
            getattr(exc, "code", "gate_d_preflight_artifact_invalid")
        ) from exc


__all__ = ["RecoveredGateDLoadError", "load_recovered_gate_d_preflight"]
