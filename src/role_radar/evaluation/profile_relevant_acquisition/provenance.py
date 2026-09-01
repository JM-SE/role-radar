"""Pre-Gate-C provenance bundle — immutable, validated before any Gate C request.

Binds exact commit/diff/status, lock identity, Alembic head, profile/policy/plan
hashes, source-independent formulas, explicit caps/cardinalities, window,
namespace, root, inventory hash, and proof old hashes unchanged.

No defaults for unresolved values; source-specific matrices remain not-yet-applicable.
No live network, no historical holdout read.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

HEX64_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
HEX40_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{40}$")
NAMESPACE_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9\-]+[a-z0-9]$")

SCHEMA_PROVENANCE: Final[str] = "f10.1f-provenance-pre-gate-c-v1"
DOMAIN_PROVENANCE: Final[str] = "role-radar:f10.1f:provenance:pre-gate-c:v1"
ALEMBIC_HEAD_F10_1B: Final[str] = "f101b_continuous"


class ProvenanceError(ValueError):
    def __init__(self, code: str) -> None:
        self.code: str = code
        super().__init__(code)


def _require_hex64(value: str, code: str) -> None:
    if not isinstance(value, str) or HEX64_RE.fullmatch(value) is None:
        raise ProvenanceError(code)


def _require_hex40(value: str, code: str) -> None:
    if not isinstance(value, str) or HEX40_RE.fullmatch(value) is None:
        raise ProvenanceError(code)


def _canonical_bytes(value: Any) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (ValueError, TypeError) as exc:
        raise ProvenanceError("provenance_canonical_invalid") from exc
    return text.encode("utf-8")


def _domain_hash(domain: str, canonical: bytes) -> str:
    if not domain.isascii():
        raise ProvenanceError("provenance_domain_invalid")
    h = hashlib.sha256()
    h.update(domain.encode("ascii"))
    h.update(b"\x00")
    h.update(canonical)
    return h.hexdigest()


@dataclass(frozen=True, slots=True)
class ProvenanceBundle:
    """Immutable pre-Gate-C bundle; no source-specific plan/matrix."""

    schema_version: str
    provenance_sha256: str
    commit_sha: str
    diff_sha256: str
    status_sha256: str
    lock_sha256: str
    alembic_head: str
    profile_binding_sha256: str
    discovery_policy_sha256: str
    relevance_policy_sha256: str
    display_contract_sha256: str
    planner_sha256: str
    query_plan_sha256: str
    sampling_formula_sha256: str
    partition_formula_sha256: str
    per_board_cap: int
    per_company_cap: int
    corpus_total: int
    pilot_count: int
    holdout_count: int
    window_start_utc: str
    window_end_utc: str
    cutoff_utc: str
    namespace: str
    root: str
    inventory_sha256: str
    old_artifact_hashes: tuple[tuple[str, str], ...]
    selection_seed_sha256: str
    partition_seed_sha256: str
    source_plan_hash: str | None
    canonical_bytes: bytes

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_PROVENANCE:
            raise ProvenanceError("provenance_schema_invalid")
        for name in (
            "corpus_total",
            "pilot_count",
            "holdout_count",
            "per_board_cap",
            "per_company_cap",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ProvenanceError("provenance_cardinality_invalid")
        if self.corpus_total != self.pilot_count + self.holdout_count:
            raise ProvenanceError("provenance_cardinality_mismatch")
        if self.source_plan_hash is not None:
            raise ProvenanceError("provenance_source_plan_must_be_null_pre_gate_c")
        if NAMESPACE_RE.fullmatch(self.namespace) is None:
            raise ProvenanceError("provenance_namespace_invalid")
        if not isinstance(self.root, str) or not self.root.startswith("/"):
            raise ProvenanceError("provenance_root_invalid")
        _validate_root_not_historical(self.root)
        if not isinstance(self.canonical_bytes, bytes):
            raise ProvenanceError("provenance_bytes_invalid")


def _validate_root_not_historical(root: str) -> None:
    hist = (
        "/opt/role-radar/data/evaluation/snapshot",
        "/opt/role-radar/data/evaluation/f10.1",
        "/opt/role-radar/data/evaluation/f10.1c",
        "/opt/role-radar/data/evaluation/f10.1e",
    )
    for h in hist:
        if root == h or root.startswith(h + "/"):
            raise ProvenanceError("provenance_root_historical_alias")


def build_provenance_bundle(
    *,
    commit_sha: str,
    diff_sha256: str,
    status_sha256: str,
    lock_sha256: str,
    alembic_head: str,
    profile_binding_sha256: str,
    discovery_policy_sha256: str,
    relevance_policy_sha256: str,
    display_contract_sha256: str,
    planner_sha256: str,
    query_plan_sha256: str,
    sampling_formula_sha256: str,
    partition_formula_sha256: str,
    window_start_utc: str,
    window_end_utc: str,
    cutoff_utc: str,
    inventory_sha256: str,
    old_artifact_hashes: Mapping[str, str],
    selection_seed: str,
    partition_seed: str,
    per_board_cap: int,
    per_company_cap: int,
    corpus_total: int,
    pilot_count: int,
    holdout_count: int,
    namespace: str,
    root: str,
) -> ProvenanceBundle:
    """Construct and hash bundle; fails closed if any binding invalid."""

    _require_hex40(commit_sha, "provenance_commit_invalid")
    _require_hex64(diff_sha256, "provenance_diff_invalid")
    _require_hex64(status_sha256, "provenance_status_invalid")
    _require_hex64(lock_sha256, "provenance_lock_invalid")
    if alembic_head != ALEMBIC_HEAD_F10_1B:
        raise ProvenanceError("provenance_alembic_head_mismatch")
    _require_hex64(profile_binding_sha256, "provenance_profile_invalid")
    _require_hex64(discovery_policy_sha256, "provenance_discovery_policy_invalid")
    _require_hex64(relevance_policy_sha256, "provenance_relevance_policy_invalid")
    _require_hex64(display_contract_sha256, "provenance_display_contract_invalid")
    _require_hex64(planner_sha256, "provenance_planner_invalid")
    _require_hex64(query_plan_sha256, "provenance_query_plan_invalid")
    _require_hex64(sampling_formula_sha256, "provenance_sampling_formula_invalid")
    _require_hex64(partition_formula_sha256, "provenance_partition_formula_invalid")
    _require_hex64(inventory_sha256, "provenance_inventory_invalid")
    _require_hex64(selection_seed, "provenance_selection_seed_invalid")
    _require_hex64(partition_seed, "provenance_partition_seed_invalid")
    if not isinstance(namespace, str) or NAMESPACE_RE.fullmatch(namespace) is None:
        raise ProvenanceError("provenance_namespace_invalid")
    if not isinstance(root, str) or not root.startswith("/"):
        raise ProvenanceError("provenance_root_invalid")
    _validate_root_not_historical(root)
    for value in (per_board_cap, per_company_cap, corpus_total, pilot_count, holdout_count):
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ProvenanceError("provenance_cardinality_invalid")
    if corpus_total != pilot_count + holdout_count:
        raise ProvenanceError("provenance_cardinality_mismatch")
    sel_hash = hashlib.sha256(selection_seed.encode("ascii")).hexdigest()
    par_hash = hashlib.sha256(partition_seed.encode("ascii")).hexdigest()
    _require_hex64(sel_hash, "provenance_seed_invalid")
    _require_hex64(par_hash, "provenance_seed_invalid")
    if selection_seed == partition_seed:
        raise ProvenanceError("provenance_seeds_must_differ")
    for k, v in old_artifact_hashes.items():
        if not isinstance(k, str) or not k.strip():
            raise ProvenanceError("provenance_old_artifact_key_invalid")
        _require_hex64(v, "provenance_old_artifact_hash_invalid")
    if window_start_utc >= window_end_utc:
        raise ProvenanceError("provenance_window_invalid")
    if cutoff_utc < window_start_utc or cutoff_utc > window_end_utc:
        raise ProvenanceError("provenance_cutoff_invalid")
    old_sorted = tuple(sorted(old_artifact_hashes.items()))
    payload: dict[str, Any] = {
        "alembic_head": alembic_head,
        "commit_sha": commit_sha,
        "corpus_total": corpus_total,
        "cutoff_utc": cutoff_utc,
        "diff_sha256": diff_sha256,
        "discovery_policy_sha256": discovery_policy_sha256,
        "display_contract_sha256": display_contract_sha256,
        "holdout_count": holdout_count,
        "inventory_sha256": inventory_sha256,
        "lock_sha256": lock_sha256,
        "namespace": namespace,
        "old_artifact_hashes": [[k, v] for k, v in old_sorted],
        "partition_formula_sha256": partition_formula_sha256,
        "partition_seed_sha256": hashlib.sha256(partition_seed.encode("ascii")).hexdigest(),
        "per_board_cap": per_board_cap,
        "per_company_cap": per_company_cap,
        "pilot_count": pilot_count,
        "planner_sha256": planner_sha256,
        "profile_binding_sha256": profile_binding_sha256,
        "query_plan_sha256": query_plan_sha256,
        "relevance_policy_sha256": relevance_policy_sha256,
        "root": root,
        "sampling_formula_sha256": sampling_formula_sha256,
        "schema_version": SCHEMA_PROVENANCE,
        "selection_seed": selection_seed,
        "selection_seed_sha256": hashlib.sha256(selection_seed.encode("ascii")).hexdigest(),
        "source_plan_hash": None,
        "status_sha256": status_sha256,
        "window_end_utc": window_end_utc,
        "window_start_utc": window_start_utc,
        "partition_seed": partition_seed,
    }
    canonical = _canonical_bytes(payload)
    digest = _domain_hash(DOMAIN_PROVENANCE, canonical)
    return ProvenanceBundle(
        schema_version=SCHEMA_PROVENANCE,
        provenance_sha256=digest,
        commit_sha=commit_sha,
        diff_sha256=diff_sha256,
        status_sha256=status_sha256,
        lock_sha256=lock_sha256,
        alembic_head=alembic_head,
        profile_binding_sha256=profile_binding_sha256,
        discovery_policy_sha256=discovery_policy_sha256,
        relevance_policy_sha256=relevance_policy_sha256,
        display_contract_sha256=display_contract_sha256,
        planner_sha256=planner_sha256,
        query_plan_sha256=query_plan_sha256,
        sampling_formula_sha256=sampling_formula_sha256,
        partition_formula_sha256=partition_formula_sha256,
        per_board_cap=per_board_cap,
        per_company_cap=per_company_cap,
        corpus_total=corpus_total,
        pilot_count=pilot_count,
        holdout_count=holdout_count,
        window_start_utc=window_start_utc,
        window_end_utc=window_end_utc,
        cutoff_utc=cutoff_utc,
        namespace=namespace,
        root=root,
        inventory_sha256=inventory_sha256,
        old_artifact_hashes=old_sorted,
        selection_seed_sha256=hashlib.sha256(selection_seed.encode("ascii")).hexdigest(),
        partition_seed_sha256=hashlib.sha256(partition_seed.encode("ascii")).hexdigest(),
        source_plan_hash=None,
        canonical_bytes=canonical,
    )


def validate_provenance(bundle: ProvenanceBundle) -> None:
    """Recompute hash and re-validate invariants before Gate C."""

    if not isinstance(bundle, ProvenanceBundle):
        raise ProvenanceError("provenance_bundle_invalid")
    # ``dataclasses.replace`` bypasses ``__post_init__``; rerun the complete
    # explicit-value validation before accepting a replayed bundle.
    try:
        bundle.__post_init__()
    except ProvenanceError:
        raise
    except (TypeError, ValueError) as exc:
        raise ProvenanceError("provenance_bundle_invalid") from exc
    # recompute canonical and hash
    try:
        payload: dict[str, Any] = json.loads(bundle.canonical_bytes.decode("utf-8"))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ProvenanceError("provenance_canonical_invalid") from exc
    if not isinstance(payload, dict):
        raise ProvenanceError("provenance_canonical_invalid")
    recomputed = _canonical_bytes(payload)
    if recomputed != bundle.canonical_bytes:
        raise ProvenanceError("provenance_canonical_mismatch")
    expected = _domain_hash(DOMAIN_PROVENANCE, bundle.canonical_bytes)
    if expected != bundle.provenance_sha256:
        raise ProvenanceError("provenance_hash_mismatch")
    for key, expected_value in (
        ("namespace", bundle.namespace),
        ("root", bundle.root),
        ("corpus_total", bundle.corpus_total),
        ("pilot_count", bundle.pilot_count),
        ("holdout_count", bundle.holdout_count),
        ("per_board_cap", bundle.per_board_cap),
        ("per_company_cap", bundle.per_company_cap),
        ("source_plan_hash", bundle.source_plan_hash),
    ):
        if payload.get(key) != expected_value:
            raise ProvenanceError("provenance_binding_mismatch")
    # re-check no source plan pre-Gate-C
    if bundle.source_plan_hash is not None:
        raise ProvenanceError("provenance_source_plan_must_be_null_pre_gate_c")
    # old hashes unchanged proof: ensure still hex64
    for _, v in bundle.old_artifact_hashes:
        _require_hex64(v, "provenance_old_artifact_hash_invalid")
    # caps / cardinalities already checked in __post_init__
    # window already validated during build; re-validate ordering
    if bundle.window_start_utc >= bundle.window_end_utc:
        raise ProvenanceError("provenance_window_invalid")


def load_provenance_bytes(path: Path) -> ProvenanceBundle:
    """Strict loader for persisted provenance file (bounded, no symlink)."""

    from role_radar.evaluation.filesystem import bounded_read

    raw = bounded_read(path)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ProvenanceError("provenance_json_invalid") from exc
    # rebuild via build_ to enforce validation
    required = [
        "commit_sha",
        "diff_sha256",
        "status_sha256",
        "lock_sha256",
        "alembic_head",
        "profile_binding_sha256",
        "discovery_policy_sha256",
        "relevance_policy_sha256",
        "display_contract_sha256",
        "planner_sha256",
        "query_plan_sha256",
        "sampling_formula_sha256",
        "partition_formula_sha256",
        "window_start_utc",
        "window_end_utc",
        "cutoff_utc",
        "inventory_sha256",
        "old_artifact_hashes",
        "selection_seed",
        "partition_seed",
        "per_board_cap",
        "per_company_cap",
        "corpus_total",
        "pilot_count",
        "holdout_count",
        "namespace",
        "root",
    ]
    for key in required:
        if key not in data:
            raise ProvenanceError("provenance_missing_field")
    old = {str(k): str(v) for k, v in data["old_artifact_hashes"]}
    bundle = build_provenance_bundle(
        commit_sha=str(data["commit_sha"]),
        diff_sha256=str(data["diff_sha256"]),
        status_sha256=str(data["status_sha256"]),
        lock_sha256=str(data["lock_sha256"]),
        alembic_head=str(data["alembic_head"]),
        profile_binding_sha256=str(data["profile_binding_sha256"]),
        discovery_policy_sha256=str(data["discovery_policy_sha256"]),
        relevance_policy_sha256=str(data["relevance_policy_sha256"]),
        display_contract_sha256=str(data["display_contract_sha256"]),
        planner_sha256=str(data["planner_sha256"]),
        query_plan_sha256=str(data["query_plan_sha256"]),
        sampling_formula_sha256=str(data["sampling_formula_sha256"]),
        partition_formula_sha256=str(data["partition_formula_sha256"]),
        window_start_utc=str(data["window_start_utc"]),
        window_end_utc=str(data["window_end_utc"]),
        cutoff_utc=str(data["cutoff_utc"]),
        inventory_sha256=str(data["inventory_sha256"]),
        old_artifact_hashes=old,
        selection_seed=str(data["selection_seed"]),
        partition_seed=str(data["partition_seed"]),
        per_board_cap=int(data["per_board_cap"]),
        per_company_cap=int(data["per_company_cap"]),
        corpus_total=int(data["corpus_total"]),
        pilot_count=int(data["pilot_count"]),
        holdout_count=int(data["holdout_count"]),
        namespace=str(data["namespace"]),
        root=str(data["root"]),
    )
    # verify canonical matches persisted provenance_sha256 if present
    if data.get("provenance_sha256") and data["provenance_sha256"] != bundle.provenance_sha256:
        raise ProvenanceError("provenance_hash_mismatch")
    return bundle


__all__ = [
    "ALEMBIC_HEAD_F10_1B",
    "DOMAIN_PROVENANCE",
    "SCHEMA_PROVENANCE",
    "ProvenanceBundle",
    "ProvenanceError",
    "build_provenance_bundle",
    "load_provenance_bytes",
    "validate_provenance",
]
