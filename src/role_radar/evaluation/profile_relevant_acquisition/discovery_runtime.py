"""Gate C report-only discovery runtime — wraps F10.1D planner, no Source/Job mutation.

Composition only; no live network. Wraps the product discovery plan via the
approved F10.1D seam and emits private request/destination/budget evidence.

Zero product DB mutation proof is provided by before/after projection hooks
injected by caller; runtime itself never imports ORM, Source, Job, or job runs.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from role_radar.discovery.planner_v2 import DiscoveryQueryPlanV2

DOMAIN_REQUEST: Final[str] = "role-radar:f10.1f:gate-c:request:v1"
DOMAIN_REPORT: Final[str] = "role-radar:f10.1f:gate-c:report:v1"


class ReportOnlyError(ValueError):
    def __init__(self, code: str) -> None:
        self.code: str = code
        super().__init__(code)


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (ValueError, TypeError) as exc:
        raise ReportOnlyError("report_only_canonical_invalid") from exc


def _domain_hash(domain: str, canonical: bytes) -> str:
    h = hashlib.sha256()
    h.update(domain.encode("ascii"))
    h.update(b"\x00")
    h.update(canonical)
    return h.hexdigest()


@dataclass(frozen=True, slots=True)
class PrivateRequestEvidence:
    """Opaque per-query destination/budget evidence; no raw query leakage."""

    ordinal: int
    host: str
    family: str
    destination_fingerprint: str
    budget_key: str
    request_sha256: str


@dataclass(frozen=True, slots=True)
class BudgetEvidence:
    max_brave_requests_per_run: int
    max_tavily_requests_per_run: int
    max_unique_board_candidates_per_run: int
    max_unique_board_verifications_per_run: int
    max_verification_wire_attempts_per_run: int
    consumed_brave: int
    consumed_tavily: int
    consumed_candidates: int
    consumed_verifications: int
    consumed_wire_attempts: int


@dataclass(frozen=True, slots=True)
class ReportOnlyResult:
    """Result of report-only discovery; no Source/Job, no registration."""

    plan_sha256: str
    query_count: int
    private_requests: tuple[PrivateRequestEvidence, ...]
    budget: BudgetEvidence
    sanitized_counts: dict[str, int]
    ledger_transitions: tuple[dict[str, Any], ...]
    report_sha256: str
    private_evidence_sha256: str
    private_evidence_path: Path | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.private_requests, tuple):
            raise ReportOnlyError("report_only_requests_invalid")
        if len(self.private_requests) != self.query_count:
            raise ReportOnlyError("report_only_count_mismatch")


BeforeAfter = Callable[[], tuple[dict[str, Any], dict[str, Any]]]
LedgerReconcile = Callable[[tuple[dict[str, Any], ...]], None]


@dataclass(frozen=True, slots=True)
class ReportOnlyRuntimeConfig:
    evidence_root: Path
    before_after: BeforeAfter | None = None
    ledger_reconcile: LedgerReconcile | None = None


def _private_request_for_query(
    ordinal: int, host: str, family: str, canonical_query: str
) -> PrivateRequestEvidence:
    # Opaque fingerprint: hash of ordinal+host+canonical, no raw leakage beyond fingerprint
    preimage = _canonical_bytes([ordinal, host, canonical_query])
    fp = hashlib.sha256(preimage).hexdigest()
    req_pre = _canonical_bytes({"ordinal": ordinal, "host": host, "fingerprint": fp})
    req_hash = _domain_hash(DOMAIN_REQUEST, req_pre)
    return PrivateRequestEvidence(
        ordinal=ordinal,
        host=host,
        family=family,
        destination_fingerprint=fp[:16],
        budget_key=f"{family}:{host}",
        request_sha256=req_hash,
    )


def _verify_plan(
    plan: DiscoveryQueryPlanV2,
    expected_sha: str | None = None,
) -> DiscoveryQueryPlanV2:
    # Use approved verification seam without constructing new planner.
    from role_radar.evaluation.profile_aware_discovery import verify_discovery_plan

    try:
        verified = verify_discovery_plan(plan)
    except Exception as exc:
        raise ReportOnlyError(getattr(exc, "code", "discovery_plan_invalid")) from exc
    if expected_sha is not None and verified.plan_sha256 != expected_sha:
        raise ReportOnlyError("discovery_plan_binding_mismatch")
    return verified


def run_report_only_discovery(
    *,
    plan: DiscoveryQueryPlanV2,
    config: ReportOnlyRuntimeConfig,
    expected_plan_sha256: str | None = None,
) -> ReportOnlyResult:
    """Run planner in report-only mode; emit private evidence + sanitized counts.

    - Verifies plan via F10.1D seam, never recreates planner.
    - Captures per-query private request/destination/budget evidence.
    - Calls before_after + ledger_reconcile hooks to prove zero Source/Job mutation.
    - Persists no product rows, creates no Source/Job/run/registration.
    """

    # Capture the pre-operation projection.  The post-operation projection is
    # deliberately captured only after all report work and reconciliation.
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    if config.before_after is not None:
        before, _ = (dict(item) for item in config.before_after())

    verified = _verify_plan(plan, expected_plan_sha256)
    # Build private evidence per query without network
    private_reqs: list[PrivateRequestEvidence] = []
    for q in verified.queries:
        private_reqs.append(
            _private_request_for_query(q.ordinal, q.host, q.family, q.canonical_query)
        )
    # Budget evidence: in report-only, consumed == 0, limits from plan
    budget = BudgetEvidence(
        max_brave_requests_per_run=verified.max_brave_requests_per_run,
        max_tavily_requests_per_run=verified.max_tavily_requests_per_run,
        max_unique_board_candidates_per_run=verified.max_unique_board_candidates_per_run,
        max_unique_board_verifications_per_run=verified.max_unique_board_verifications_per_run,
        max_verification_wire_attempts_per_run=verified.max_verification_wire_attempts_per_run,
        consumed_brave=0,
        consumed_tavily=0,
        consumed_candidates=0,
        consumed_verifications=0,
        consumed_wire_attempts=0,
    )
    sanitized_counts: dict[str, int] = {
        "query_count": len(private_reqs),
        "host_count": len({r.host for r in private_reqs}),
        "family_greenhouse": sum(1 for r in private_reqs if r.family == "greenhouse"),
        "family_lever": sum(1 for r in private_reqs if r.family == "lever"),
    }
    # Ledger transitions: empty in report-only scaffold (no live ledger mutation).
    # Real Gate C will provide reconciled transitions via hook.
    ledger_transitions: tuple[dict[str, Any], ...] = ()
    if config.ledger_reconcile is not None:
        try:
            config.ledger_reconcile(ledger_transitions)
        except Exception as exc:
            raise ReportOnlyError("report_only_ledger_reconcile_failed") from exc
    # Report hashes
    private_payload = _canonical_bytes(
        [r.request_sha256 for r in sorted(private_reqs, key=lambda x: x.ordinal)]
    )
    private_hash = _domain_hash(DOMAIN_REPORT, private_payload)
    report_payload = _canonical_bytes(
        {
            "plan_sha256": verified.plan_sha256,
            "sanitized_counts": sanitized_counts,
            "budget": {
                "max_brave": budget.max_brave_requests_per_run,
                "max_tavily": budget.max_tavily_requests_per_run,
            },
        }
    )
    report_hash = _domain_hash(DOMAIN_REPORT, report_payload)
    # No mutation proof: capture state after the operation, not the second
    # value returned by the pre-operation callback.
    if config.before_after is not None:
        _, current_after = config.before_after()
        after = dict(current_after)
    if before is not None and after is not None:
        # In scaffold, we require exact equality to prove zero mutation
        if before != after:
            raise ReportOnlyError("report_only_product_mutation_detected")
        # Ensure no Source/Job keys mutated (allowlist only ledger transitions)
        forbidden = {"Source", "Job", "discovery_run", "acquisition_run", "job_run", "registration"}
        for key in forbidden:
            if key in before and key in after and before[key] != after[key]:
                raise ReportOnlyError("report_only_forbidden_mutation")

    return ReportOnlyResult(
        plan_sha256=verified.plan_sha256,
        query_count=len(private_reqs),
        private_requests=tuple(private_reqs),
        budget=budget,
        sanitized_counts=dict(sanitized_counts),
        ledger_transitions=ledger_transitions,
        report_sha256=report_hash,
        private_evidence_sha256=private_hash,
        private_evidence_path=None,
    )


def persist_private_evidence(
    result: ReportOnlyResult,
    root: Path,
) -> Path:
    """Persist private evidence under isolated root using filesystem primitive."""

    from role_radar.evaluation.filesystem import (
        atomic_write,
        ensure_private_root,
    )

    ensure_private_root(root)
    evidence_dir = root / "gate-c" / result.plan_sha256
    evidence_dir.mkdir(parents=True, exist_ok=True)
    try:
        evidence_dir.chmod(0o700)
    except OSError as exc:
        raise ReportOnlyError("report_only_chmod_failed") from exc
    payload = _canonical_bytes(
        {
            "plan_sha256": result.plan_sha256,
            "private_requests": [
                {
                    "ordinal": r.ordinal,
                    "host": r.host,
                    "family": r.family,
                    "destination_fingerprint": r.destination_fingerprint,
                    "budget_key": r.budget_key,
                    "request_sha256": r.request_sha256,
                }
                for r in result.private_requests
            ],
            "budget": {
                "max_brave": result.budget.max_brave_requests_per_run,
                "max_tavily": result.budget.max_tavily_requests_per_run,
            },
            "report_sha256": result.report_sha256,
            "private_evidence_sha256": result.private_evidence_sha256,
        }
    )
    target = evidence_dir / "private_evidence.json"
    try:
        atomic_write(target, payload)
    except Exception as exc:
        raise ReportOnlyError("report_only_persist_failed") from exc
    return target


__all__ = [
    "BudgetEvidence",
    "PrivateRequestEvidence",
    "ReportOnlyError",
    "ReportOnlyResult",
    "ReportOnlyRuntimeConfig",
    "persist_private_evidence",
    "run_report_only_discovery",
]
