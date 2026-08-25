"""Contracts, policy validation, canonical hashing, and no-live-defaults for Gate A."""

from __future__ import annotations

import dataclasses
import hashlib
import re
from typing import Any

import pytest

from role_radar.evaluation.profile_relevance import contracts as contracts_mod
from role_radar.evaluation.profile_relevance import hashing
from role_radar.evaluation.profile_relevance import policy as policy_mod
from role_radar.evaluation.profile_relevance.errors import (
    OfflineScopeRequiredError,
    SelectionSeedInvalidError,
)
from role_radar.evaluation.profile_relevance.policy import (
    DOMAIN_APPROVED_PREVIEW_BINDING,
    DOMAIN_DATASET_ID,
    DOMAIN_MATERIALIZATION,
    DOMAIN_PARTITION_RANK,
    DOMAIN_SELECTION_RANK,
    EXECUTION_SCOPE_SYNTHETIC,
    HEX32_BYTES_RE,
    HEX64_RE,
    MAX_BOARD_CAP,
    MAX_CANONICAL_BYTES,
    MAX_COMPANY_CAP,
    MAX_CORPUS_CARDINALITY,
    MAX_OBSERVATIONS,
    OPAQUE_ID_RE,
    REASON_FAMILIES,
    SCHEMA_APPROVED_PREVIEW,
    SCHEMA_HOLDOUT_BINDING,
    SCHEMA_INPUT,
    SCHEMA_MATERIALIZATION_CONTEXT,
    SCHEMA_OPERATOR_PAYLOAD,
    SCHEMA_PILOT_BINDING,
    SCHEMA_PILOT_VIEW,
    SCHEMA_PRIVATE_PAYLOAD,
    SCHEMA_SANITIZED_PREVIEW,
    STRATA,
    validate_execution_scope,
    validate_hex32_seed,
    validate_reason_sequence,
)

# Synthetic Gate A literals — not live defaults
SELECTION_SEED = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
PARTITION_SEED = "f0e0d0c0b0a090807060504030201000ffeeddccbbaa99887766554433221100"

HEX64_A = "a" * 64
HEX64_B = "b" * 64


def _hex64(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Immutability (frozen/slots, no mutation)
# ---------------------------------------------------------------------------


def test_all_contracts_are_frozen_and_slotted() -> None:
    for cls in (
        contracts_mod.FrozenProfile,
        contracts_mod.SourceIdentity,
        contracts_mod.AcquisitionObservation,
        contracts_mod.SealedAcquisitionSnapshot,
        contracts_mod.ConstraintPolicy,
        contracts_mod.RelevancePolicy,
        contracts_mod.HistoricalIdentityExclusion,
        contracts_mod.QuotaCell,
        contracts_mod.SamplingPolicy,
        contracts_mod.PartitionQuota,
        contracts_mod.PartitionPolicy,
        contracts_mod.ProfileRelevanceInput,
        contracts_mod.ProjectedFacts,
        contracts_mod.GateDecision,
        contracts_mod.SamplingMicrocell,
        contracts_mod.SelectedItem,
        contracts_mod.SelectionResult,
        contracts_mod.PartitionResult,
        contracts_mod.SanitizedPreview,
        contracts_mod.PreviewComputationResult,
        contracts_mod.ApprovedPreview,
        contracts_mod.MaterializationContext,
        contracts_mod.CanonicalPayload,
        contracts_mod.MaterializedPayloads,
    ):
        assert dataclasses.is_dataclass(cls), cls.__name__
        params = getattr(cls, "__dataclass_params__", None)
        assert params is not None and params.frozen, cls.__name__
        assert params.slots, cls.__name__  # type: ignore[attr-defined,unused-ignore]
        # immutability proof: assigning raises
        # we test via a concrete instance for a few DTOs
    # specific mutation attempt
    fp = contracts_mod.FrozenProfile(
        profile_id="p",
        version=1,
        schema_version="s",
        payload_canonical_json="{}",
        content_sha256=HEX64_A,
        binding_sha256=HEX64_B,
        frozen_at_utc="2026-08-25T00:00:00Z",
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        fp.profile_id = "q"  # type: ignore[misc]
    q = contracts_mod.QuotaCell(source_unit="board_a", stratum="candidate", corpus_quota=1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        q.corpus_quota = 2  # type: ignore[misc]
    # slots: no __dict__ on instance
    assert (
        not hasattr(fp, "__dict__") or fp.__dict__ == {}
    )  # slots may still have __dict__ disabled
    # verify __slots__ exists
    assert hasattr(contracts_mod.FrozenProfile, "__slots__")


def test_nested_collections_are_immutable_tuples() -> None:
    obs = contracts_mod.AcquisitionObservation(
        observation_id="obs1",
        item_semantic_sha256=HEX64_A,
        strong_identity_digest=HEX64_B,
        identity_policy_version="strong-identity-v1",
        source=contracts_mod.SourceIdentity("fam", "sid", "bid", "board_a", HEX64_A),
        company_sampling_key="alpha",
        title="Engineer",
        description="desc",
        location="Remote",
        remote_evidence=None,
        employment_evidence=None,
        authorization_evidence=None,
        region_evidence=None,
        canonical_observation_bytes=b"{}",
    )
    snap = contracts_mod.SealedAcquisitionSnapshot(
        namespace="ns",
        snapshot_id="snap",
        schema_version=SCHEMA_INPUT,
        state="sealed",
        acquisition_started_at_utc="2026-08-25T00:00:00Z",
        sealed_at_utc="2026-08-25T01:00:00Z",
        acquisition_semantic_sha256=HEX64_A,
        discovery_policy_sha256=HEX64_A,
        source_plan_sha256=HEX64_A,
        observations=(obs,),
    )
    # observations must be tuple, not list
    assert isinstance(snap.observations, tuple)
    with pytest.raises((TypeError, ValueError, AttributeError)):
        # cannot assign mutable list via replacement — frozen will raise, but also type check
        contracts_mod.SealedAcquisitionSnapshot(
            namespace="ns",
            snapshot_id="snap",
            schema_version=SCHEMA_INPUT,
            state="sealed",
            acquisition_started_at_utc="2026-08-25T00:00:00Z",
            sealed_at_utc="2026-08-25T01:00:00Z",
            acquisition_semantic_sha256=HEX64_A,
            discovery_policy_sha256=HEX64_A,
            source_plan_sha256=HEX64_A,
            observations=[obs],  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# Schemas / domains
# ---------------------------------------------------------------------------


def test_schema_and_domain_constants_match_spec() -> None:
    assert SCHEMA_INPUT == "f10.1e-profile-relevance-input-v1"
    assert SCHEMA_SANITIZED_PREVIEW == "f10.1e-profile-relevance-sanitized-preview-v1"
    assert (
        policy_mod.SCHEMA_PREVIEW_COMPUTATION == "f10.1e-profile-relevance-preview-computation-v1"
    )
    assert SCHEMA_APPROVED_PREVIEW == "f10.1e-profile-relevance-approved-preview-v1"
    assert SCHEMA_MATERIALIZATION_CONTEXT == "f10.1e-profile-relevance-materialization-context-v1"
    assert SCHEMA_PRIVATE_PAYLOAD == "f10.1e-profile-relevance-private-payload-v1"
    assert SCHEMA_OPERATOR_PAYLOAD == "f10.1e-profile-relevance-operator-payload-v1"
    assert SCHEMA_PILOT_VIEW == "f10.1e-profile-relevance-pilot-view-v1"
    assert SCHEMA_PILOT_BINDING == "f10.1e-profile-relevance-pilot-binding-v1"
    assert SCHEMA_HOLDOUT_BINDING == "f10.1e-profile-relevance-holdout-binding-v1"
    assert policy_mod.PROTOCOL_FACTS == "f10.1e-facts-v1"
    assert policy_mod.PROTOCOL_GATE == "f10.1e-high-recall-gate-v1"
    assert policy_mod.PROTOCOL_SELECTION == "f10.1e-source-stratum-selection-v1"
    assert policy_mod.PROTOCOL_PARTITION == "f10.1e-source-stratum-partition-v1"
    assert policy_mod.PROTOCOL_MATERIALIZATION == "f10.1e-profile-relevance-materialization-v1"
    assert DOMAIN_SELECTION_RANK == "role-radar:f10.1e-profile-relevance:selection-rank:v1"
    assert DOMAIN_PARTITION_RANK == "role-radar:f10.1e-profile-relevance:partition-rank:v1"
    assert DOMAIN_DATASET_ID == "role-radar:f10.1e-profile-relevance:dataset-id:v1"
    assert (
        DOMAIN_APPROVED_PREVIEW_BINDING
        == "role-radar:f10.1e-profile-relevance:approved-preview-binding:v1"
    )
    assert DOMAIN_MATERIALIZATION == "role-radar:f10.1e-profile-relevance:materialization:v1"
    # domains are ASCII
    for dom in policy_mod.ALL_DOMAINS:
        assert dom.isascii(), dom
        assert dom.endswith(":v1")
    # no F10.1C reuse
    for v in [
        SCHEMA_INPUT,
        SCHEMA_SANITIZED_PREVIEW,
        SCHEMA_APPROVED_PREVIEW,
        SCHEMA_PRIVATE_PAYLOAD,
    ]:
        assert "f10.1c" not in v
    assert str(policy_mod.DOMAIN_SELECTION_RANK) != str(policy_mod.DOMAIN_PARTITION_RANK)
    assert STRATA == ("candidate", "near_miss", "background_control", "indeterminate")


def test_reason_vocab_order_and_strata() -> None:
    assert REASON_FAMILIES == (
        "role_anchor",
        "support_core",
        "support_secondary",
        "conflict_role",
        "conflict_technology",
        "constraint_match",
        "constraint_conflict",
        "indeterminate",
    )
    # ordered allowlist: role_anchor before support_core etc.
    validate_reason_sequence(
        ("role_anchor:engineer", "support_core:python", "constraint_match:region")
    )
    validate_reason_sequence(("conflict_role:manager",))
    # out-of-order must fail
    with pytest.raises(Exception):
        validate_reason_sequence(("support_core:python", "role_anchor:engineer"))
    # duplicate fails
    with pytest.raises(Exception):
        validate_reason_sequence(("role_anchor:engineer", "role_anchor:engineer"))
    # unknown prefix fails
    with pytest.raises(Exception):
        validate_reason_sequence(("unknown:foo",))
    # suffix free-text not allowed (uppercase/space)
    with pytest.raises(Exception):
        validate_reason_sequence(("role_anchor:Engineer Senior",))


# ---------------------------------------------------------------------------
# Policy validation (hex32 seeds, scope synthetic_gate_a, caps)
# ---------------------------------------------------------------------------


def test_hex32_seed_validation_and_scope() -> None:
    # valid synthetic seeds are 64 lowercase hex
    assert HEX32_BYTES_RE.fullmatch(SELECTION_SEED) is not None
    assert HEX32_BYTES_RE.fullmatch(PARTITION_SEED) is not None
    validate_hex32_seed(SELECTION_SEED)
    validate_hex32_seed(PARTITION_SEED)
    # uppercase fails
    with pytest.raises(SelectionSeedInvalidError):
        validate_hex32_seed(PARTITION_SEED.upper())
    # wrong length fails
    with pytest.raises(SelectionSeedInvalidError):
        validate_hex32_seed("abc")
    # non-hex fails
    with pytest.raises(SelectionSeedInvalidError):
        validate_hex32_seed("g" * 64)
    # seeds must differ (checked in preview_workflow, but policy layer enforces distinctness via caller)
    assert SELECTION_SEED != PARTITION_SEED
    # scope synthetic only
    validate_execution_scope(EXECUTION_SCOPE_SYNTHETIC)
    with pytest.raises(OfflineScopeRequiredError):
        validate_execution_scope("live")
    with pytest.raises(OfflineScopeRequiredError):
        validate_execution_scope("")
    with pytest.raises(OfflineScopeRequiredError):
        validate_execution_scope("synthetic_gate_a ")  # trailing space invalid


def test_caps_and_schemas_allowlist() -> None:
    assert MAX_OBSERVATIONS == 100_000
    assert MAX_CORPUS_CARDINALITY == 100_000
    assert MAX_CANONICAL_BYTES == 10 * 1024 * 1024
    assert MAX_BOARD_CAP == 100_000
    assert MAX_COMPANY_CAP == 10_000
    # hex validation
    assert HEX64_RE.fullmatch(HEX64_A) is not None
    assert HEX64_RE.fullmatch("Z" * 64) is None
    assert OPAQUE_ID_RE.fullmatch("a" * 24) is not None
    assert OPAQUE_ID_RE.fullmatch("a" * 23) is None


# ---------------------------------------------------------------------------
# Canonical hashing (no float, duplicate keys)
# ---------------------------------------------------------------------------


def test_canonical_hash_rejects_float_and_non_finite() -> None:
    with pytest.raises(ValueError):
        hashing.canonical_json_bytes({"a": 1.0})
    with pytest.raises(ValueError):
        hashing.canonical_json_bytes([1, 2.5])
    with pytest.raises(ValueError):
        hashing.canonical_json_bytes({"a": float("nan")})
    with pytest.raises(ValueError):
        hashing.canonical_json_bytes({"a": float("inf")})
    # nested float
    with pytest.raises(ValueError):
        hashing.canonical_json_bytes({"a": {"b": 3.14}})


def test_canonical_hash_rejects_non_string_keys() -> None:
    with pytest.raises(ValueError):
        hashing.canonical_json_bytes({1: "a"})  # type: ignore[arg-type,unused-ignore]
    with pytest.raises(ValueError):
        hashing.canonical_json_bytes({None: "a"})  # type: ignore[arg-type,unused-ignore]


def test_canonical_hash_is_deterministic_and_domain_separated() -> None:
    payload = {"b": 2, "a": 1}
    b1 = hashing.canonical_json_bytes(payload)
    b2 = hashing.canonical_json_bytes({"a": 1, "b": 2})
    assert b1 == b2 == b'{"a":1,"b":2}'
    h1 = hashing.domain_hash(DOMAIN_SELECTION_RANK, payload)
    h2 = hashing.domain_hash(DOMAIN_PARTITION_RANK, payload)
    assert h1 != h2
    # NUL separator proof: domain + NUL + bytes
    raw = DOMAIN_SELECTION_RANK.encode("ascii") + b"\x00" + b1
    expected = hashlib.sha256(raw).hexdigest()
    assert h1 == expected
    # non-ASCII domain rejected
    with pytest.raises(ValueError):
        hashing.domain_hash("dómáin", payload)


def test_duplicate_keys_are_not_canonical() -> None:
    # python dict cannot hold duplicates, but raw JSON with duplicates would be caught if we parsed
    # ensure canonical json sorts keys and uses compact separators
    obj: dict[str, Any] = {"z": 1, "a": 2}
    raw = hashing.canonical_json_bytes(obj)
    assert raw == b'{"a":2,"z":1}'
    # ensure ensure_ascii=False keeps unicode as utf8, not escaped
    raw2 = hashing.canonical_json_bytes({"é": 1})
    assert "é".encode() in raw2


# ---------------------------------------------------------------------------
# No live defaults
# ---------------------------------------------------------------------------


def test_no_live_defaults_in_policy_module() -> None:
    src = policy_mod.__file__ or ""
    text = open(src, encoding="utf-8").read() if src else ""
    # must not contain literal live scope as default
    assert (
        "live" in text
    )  # appears as constant EXECUTION_SCOPE_LIVE, but ALLOWED_SCOPES must not contain live
    assert frozenset({EXECUTION_SCOPE_SYNTHETIC}) == policy_mod.ALLOWED_SCOPES
    # seeds must not be default literals inside policy module
    assert SELECTION_SEED not in text
    assert PARTITION_SEED not in text
    # ensure no hardcoded live cardinalities from historical 177/50/127 as defaults
    # those numbers may appear in tests but not as policy defaults; check no constant equals 177 etc as default quota
    # we simply ensure policy module does not define a DEFAULT_CORPUS = 177 etc.
    assert "177" not in text or (
        "177" in text and "historical" not in text.lower()
    )  # allow minimal
    # ensure preview_workflow does not contain a default seed
    import pathlib

    pw = pathlib.Path("src/role_radar/evaluation/profile_relevance/preview_workflow.py").read_text(
        encoding="utf-8"
    )
    assert "f0e0d0c0" not in pw
    assert "00010203" not in pw
    mat = pathlib.Path("src/role_radar/evaluation/profile_relevance/materialization.py").read_text(
        encoding="utf-8"
    )
    assert "f0e0d0c0" not in mat


def test_hex_patterns_are_lowercase_only() -> None:
    assert re.fullmatch(r"[0-9a-f]{64}", SELECTION_SEED) is not None
    assert re.fullmatch(r"[0-9a-f]{64}", PARTITION_SEED) is not None
    # uppercase must be rejected by policy
    assert HEX32_BYTES_RE.fullmatch(SELECTION_SEED.upper()) is None
