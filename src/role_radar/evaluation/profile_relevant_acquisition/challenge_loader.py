"""Strict, side-effect-free loader for one F10.1F challenge artifact."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Final

from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    ArtifactClass,
    ChallengeArtifact,
    ExternalApprovalBinding,
    ExternalApprovalVerifier,
    SeedInputs,
    _approved_artifact_token,
    require_execution_boundary,
)

MAX_CHALLENGE_BYTES: Final[int] = 64 * 1024
CHALLENGE_DOMAIN: Final[str] = "role-radar:f10.1f:challenge:v1"
CHALLENGE_SCHEMA: Final[str] = "f10.1f-challenge-v1"
CHALLENGE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "artifact_class",
        "challenge_sha256",
        "gate",
        "lineage_id",
        "operation_id",
        "payload_sha256",
        "policy_sha256",
        "prerequisite_status",
        "schema_version",
        "seed_inputs",
    }
)


class ChallengeLoadError(ValueError):
    """Stable detail-free challenge parsing/verification failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ChallengeLoadError("challenge_canonical_invalid") from exc


def challenge_hash(canonical_bytes: bytes) -> str:
    if not isinstance(canonical_bytes, bytes):
        raise ChallengeLoadError("challenge_bytes_invalid")
    digest = hashlib.sha256()
    digest.update(CHALLENGE_DOMAIN.encode("ascii"))
    digest.update(b"\x00")
    digest.update(canonical_bytes)
    return digest.hexdigest()


def _object(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) > MAX_CHALLENGE_BYTES:
        raise ChallengeLoadError("challenge_bounds_exceeded")
    if not raw.endswith(b"\n") or raw[:-1].count(b"\n") != 0:
        raise ChallengeLoadError("challenge_record_invalid")
    try:
        value = json.loads(raw[:-1].decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ChallengeLoadError("challenge_json_invalid") from exc
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ChallengeLoadError("challenge_object_invalid")
    if set(value) != CHALLENGE_KEYS:
        raise ChallengeLoadError("challenge_fields_invalid")
    if _canonical(value) != raw[:-1]:
        raise ChallengeLoadError("challenge_noncanonical")
    return value


def load_challenge_bytes(
    raw: bytes,
    *,
    expected_gate: str | None = None,
    approval: ExternalApprovalBinding | None = None,
    approval_verifier: ExternalApprovalVerifier | None = None,
) -> ChallengeArtifact:
    """Parse exactly one canonical challenge and verify its domain hash.

    The optional gate argument is an assertion, not a conversion mechanism:
    a challenge for another gate is rejected before a DTO is returned.
    """

    value = _object(raw)
    gate = value["gate"]
    if not isinstance(gate, str) or gate not in {"C", "post-C", "D", "E", "F"}:
        raise ChallengeLoadError("challenge_gate_invalid")
    if expected_gate is not None and gate != expected_gate:
        raise ChallengeLoadError("challenge_wrong_gate")
    if value["schema_version"] != CHALLENGE_SCHEMA:
        raise ChallengeLoadError("challenge_schema_invalid")
    seed_data = value["seed_inputs"]
    if not isinstance(seed_data, dict) or set(seed_data) != {"selection_seed", "partition_seed"}:
        raise ChallengeLoadError("challenge_seed_inputs_invalid")
    try:
        seeds = SeedInputs(
            selection_seed=seed_data["selection_seed"],
            partition_seed=seed_data["partition_seed"],
        )
    except (TypeError, ValueError) as exc:
        raise ChallengeLoadError("challenge_seed_inputs_invalid") from exc
    artifact_name = value["artifact_class"]
    try:
        artifact_class = ArtifactClass(artifact_name)
    except (TypeError, ValueError) as exc:
        raise ChallengeLoadError("challenge_artifact_class_invalid") from exc
    for field in ("policy_sha256", "payload_sha256"):
        candidate = value[field]
        if (
            not isinstance(candidate, str)
            or len(candidate) != 64
            or any(char not in "0123456789abcdef" for char in candidate)
        ):
            raise ChallengeLoadError(f"challenge_{field.removesuffix('_sha256')}_invalid")
    operation_id = value["operation_id"]
    lineage_id = value["lineage_id"]
    prerequisite = value["prerequisite_status"]
    if not isinstance(operation_id, str) or not operation_id.strip():
        raise ChallengeLoadError("challenge_operation_invalid")
    if not isinstance(lineage_id, str) or not lineage_id.strip():
        raise ChallengeLoadError("challenge_lineage_invalid")
    if prerequisite != "passed":
        raise ChallengeLoadError("challenge_prerequisite_invalid")
    supplied_digest = value["challenge_sha256"]
    if (
        not isinstance(supplied_digest, str)
        or len(supplied_digest) != 64
        or any(char not in "0123456789abcdef" for char in supplied_digest)
    ):
        raise ChallengeLoadError("challenge_hash_invalid")
    unsigned = dict(value)
    del unsigned["challenge_sha256"]
    digest = challenge_hash(_canonical(unsigned))
    if supplied_digest != digest:
        raise ChallengeLoadError("challenge_hash_mismatch")
    if artifact_class is ArtifactClass.APPROVED_PRODUCTION:
        try:
            require_execution_boundary(
                artifact_sha256=supplied_digest,
                test_only_adapter=None,
                approval=approval,
                approval_verifier=approval_verifier,
                code="challenge_external_approval_required",
            )
        except ValueError as exc:
            raise ChallengeLoadError(
                getattr(exc, "code", "challenge_external_approval_required")
            ) from exc
    try:
        return ChallengeArtifact(
            schema_version=CHALLENGE_SCHEMA,
            gate=gate,
            operation_id=operation_id,
            lineage_id=lineage_id,
            prerequisite_status=prerequisite,
            artifact_class=artifact_class,
            seed_inputs=seeds,
            policy_sha256=value["policy_sha256"],
            payload_sha256=value["payload_sha256"],
            challenge_sha256=supplied_digest,
            canonical_bytes=raw,
            _approval_token=(
                _approved_artifact_token()
                if artifact_class is ArtifactClass.APPROVED_PRODUCTION
                else None
            ),
        )
    except (TypeError, ValueError) as exc:
        raise ChallengeLoadError("challenge_contract_invalid") from exc


def build_challenge_bytes(
    *,
    gate: str,
    operation_id: str,
    lineage_id: str,
    artifact_class: ArtifactClass,
    selection_seed: str,
    partition_seed: str,
    policy_sha256: str,
    payload_sha256: str,
) -> bytes:
    """Build explicit synthetic/test bytes without any runtime defaults."""

    if artifact_class is ArtifactClass.APPROVED_PRODUCTION:
        raise ChallengeLoadError("challenge_approved_class_builder_forbidden")

    value = {
        "artifact_class": artifact_class.value,
        "gate": gate,
        "lineage_id": lineage_id,
        "operation_id": operation_id,
        "payload_sha256": payload_sha256,
        "policy_sha256": policy_sha256,
        "prerequisite_status": "passed",
        "schema_version": CHALLENGE_SCHEMA,
        "seed_inputs": {
            "partition_seed": partition_seed,
            "selection_seed": selection_seed,
        },
    }
    value["challenge_sha256"] = challenge_hash(_canonical(value))
    raw = _canonical(value) + b"\n"
    load_challenge_bytes(raw, expected_gate=gate)
    return raw


def load_challenge(
    value: Mapping[str, object],
    *,
    expected_gate: str | None = None,
    approval: ExternalApprovalBinding | None = None,
    approval_verifier: ExternalApprovalVerifier | None = None,
) -> ChallengeArtifact:
    """Strict mapping adapter; it never fills missing fields or coerces gates."""

    if not isinstance(value, Mapping):
        raise ChallengeLoadError("challenge_object_invalid")
    return load_challenge_bytes(
        _canonical(dict(value)) + b"\n",
        expected_gate=expected_gate,
        approval=approval,
        approval_verifier=approval_verifier,
    )


__all__ = [
    "CHALLENGE_DOMAIN",
    "CHALLENGE_SCHEMA",
    "ChallengeLoadError",
    "build_challenge_bytes",
    "challenge_hash",
    "load_challenge",
    "load_challenge_bytes",
]
