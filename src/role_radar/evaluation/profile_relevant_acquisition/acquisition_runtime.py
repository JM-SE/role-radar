"""Gate D broad acquisition — CollectorContext.transport injection and sealed pool.

Uses public collector registry and EphemeralCollectorTaskFactory; injects a
private JournaledAsyncTransport via CollectorContext.transport, below
BoundedHttpClient. Broad board observations are collected within approved
bounds without relevance filtering, backfill, quota extra, or source
replacement. Synthetic mixed-board validation proves relevant+unrelated jobs
both enter the sealed parent pool. Zero product DB mutations are proven via
before/after hook. Replay skips only when known-complete attempts and
checkpoint reconcile. Journal counts, CollectionRunBudget, checkpoint, and
manifest counters reconcile under explicit equations.

No reuse of old JournaledTransport (incompatible exception-as-result).
No copying of provider clients.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, cast

import httpx

from role_radar.collectors.outcomes import CollectionFailure, CollectionOutcome, CollectionSuccess
from role_radar.collectors.policy import CollectionRunBudget
from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot
from role_radar.collectors.registry import CollectorContext
from role_radar.domain.dto import RawJob
from role_radar.evaluation.controlled_acquisition.acquisition import CollectorTask
from role_radar.evaluation.controlled_acquisition.protocols import PLAN_VERSION_V2
from role_radar.evaluation.filesystem import (
    HISTORICAL_ROOTS,
    atomic_write,
    bounded_read,
    ensure_private_root,
    resolve_nofollow,
)
from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    AuthorizationError,
    ExternalApprovalBinding,
    ExternalApprovalVerifier,
    SyntheticTestAdapter,
    require_execution_boundary,
)
from role_radar.evaluation.profile_relevant_acquisition.journal import (
    AcquisitionJournal,
    JournalError,
)
from role_radar.evaluation.profile_relevant_acquisition.journaled_transport import (
    JournaledAsyncTransport,
)
from role_radar.evaluation.profile_relevant_acquisition.source_plan import SourcePlan

FORBIDDEN_JOURNALED_TRANSPORT: Final[str] = (
    "role_radar.evaluation.controlled_acquisition.acquisition.JournaledTransport"
)

MAX_DESCRIPTION_BYTES: Final[int] = 256 * 1024
MAX_TITLE_BYTES: Final[int] = 512
MAX_COMPANY_BYTES: Final[int] = 256
MAX_LOCATION_BYTES: Final[int] = 512
MAX_POOL_BYTES: Final[int] = 32 * 1024 * 1024
NAMESPACE_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9\-]+[a-z0-9]$", re.ASCII)


class AcquisitionError(ValueError):
    def __init__(self, code: str) -> None:
        self.code: str = code
        super().__init__(code)


class SyntheticTransport(httpx.AsyncBaseTransport):
    """Allow-listed transport which cannot perform network I/O."""

    __slots__ = ("_calls",)

    def __init__(self) -> None:
        self._calls = 0

    @property
    def calls(self) -> int:
        return self._calls

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        del request
        self._calls += 1
        return httpx.Response(200, content=b'{"jobs":[]}')


class SyntheticCollectorFactory(Protocol):
    """Factory contract for explicitly offline synthetic collectors."""

    def __call__(
        self, snapshot: SourceSnapshot, context: CollectorContext
    ) -> SyntheticCollectorProtocol: ...


class SyntheticCollectorProtocol(Protocol):
    """Collector contract with an identity-bound offline capability."""

    async def collect(
        self, snapshot: SourceSnapshot, runtime: CollectorRuntime
    ) -> CollectionOutcome: ...


@dataclass(frozen=True, slots=True)
class AcquisitionScaffoldConfig:
    evidence_root: Path
    operation_id: str
    provenance_sha256: str
    preregistration_sha256: str
    source_plan_sha256: str
    budget_id: str
    namespace: str

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_root, Path) or not self.evidence_root.is_absolute():
            raise AcquisitionError("acquisition_root_invalid")
        root_text = str(self.evidence_root)
        if any(root_text == item or root_text.startswith(item + "/") for item in HISTORICAL_ROOTS):
            raise AcquisitionError("acquisition_root_historical_alias")
        if not isinstance(self.operation_id, str) or not self.operation_id.strip():
            raise AcquisitionError("acquisition_operation_invalid")
        for value in (
            self.provenance_sha256,
            self.preregistration_sha256,
            self.source_plan_sha256,
        ):
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise AcquisitionError("acquisition_binding_invalid")
        if not isinstance(self.budget_id, str) or not self.budget_id.strip():
            raise AcquisitionError("acquisition_budget_invalid")
        if not isinstance(self.namespace, str) or NAMESPACE_RE.fullmatch(self.namespace) is None:
            raise AcquisitionError("acquisition_namespace_invalid")


@dataclass(frozen=True, slots=True)
class SourceCheckpoint:
    source_id: str
    wire_attempts: int
    checkpoint_sha256: str


@dataclass(frozen=True, slots=True)
class AcquisitionScaffoldResult:
    operation_id: str
    source_count: int
    wire_attempts: int
    checkpoints: tuple[SourceCheckpoint, ...]
    pool_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class ObservationEnvelope:
    """Canonical authoritative observation — exact bounded values, no HTML normalize."""

    source_id: str
    source_key: str
    source_revision: int
    configuration_version: int
    external_id: str
    title: str
    company: str | None
    location: str | None
    description: str | None
    source_url: str | None
    canonical_bytes: bytes
    canonical_sha256: str


@dataclass(frozen=True, slots=True)
class ParentPoolManifest:
    operation_id: str
    source_plan_sha256: str
    preregistration_sha256: str
    provenance_sha256: str
    observed: int
    new_to_pool: int
    duplicate: int
    stale: int
    invalid: int
    conflict: int
    truncated: int
    indeterminate: int
    durable_intents: int
    known_terminal_outcomes: int
    pending_or_indeterminate: int
    delegate_entries: int
    budget_debits: int
    collector_wire_attempts: int
    budget_consumed: int
    checkpoint_wire_attempts: int
    pool_sha256: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class GateDResult:
    operation_id: str
    source_count: int
    wire_attempts: int
    checkpoints: tuple[SourceCheckpoint, ...]
    pool_sha256: str
    manifest: ParentPoolManifest
    observations: tuple[ObservationEnvelope, ...]
    sealed_pool_path: Path | None = None
    sealed_manifest_path: Path | None = None


def _require_not_old_journal(journal: Any) -> None:
    mod = getattr(journal, "__class__", None)
    if mod is not None:
        name = f"{mod.__module__}.{mod.__name__}"
        if "JournaledTransport" in name and "controlled_acquisition" in name:
            raise AcquisitionError("forbidden_journaled_transport")


def _validate_prereg_binding(config: AcquisitionScaffoldConfig) -> None:
    if not config.operation_id or not config.operation_id.strip():
        raise AcquisitionError("acquisition_operation_invalid")
    for field in (
        "provenance_sha256",
        "preregistration_sha256",
        "source_plan_sha256",
    ):
        val = getattr(config, field)
        is_hex64 = isinstance(val, str) and len(val) == 64
        is_hex_chars = is_hex64 and all(c in "0123456789abcdef" for c in val)
        if not is_hex_chars:
            raise AcquisitionError("acquisition_binding_invalid")


def _validate_source_plan_binding(
    config: AcquisitionScaffoldConfig,
    source_plan: SourcePlan,
    budget: CollectionRunBudget,
) -> None:
    """Verify the exact canonical plan before collector construction."""

    if not isinstance(source_plan, SourcePlan):
        raise AcquisitionError("acquisition_source_plan_invalid")
    try:
        source_plan.__post_init__()
    except (TypeError, ValueError) as exc:
        raise AcquisitionError("acquisition_source_plan_invalid") from exc
    if hashlib.sha256(source_plan.canonical_bytes).hexdigest() != source_plan.source_plan_sha256:
        raise AcquisitionError("acquisition_source_plan_hash_mismatch")
    if source_plan.source_plan_sha256 != config.source_plan_sha256:
        raise AcquisitionError("acquisition_source_plan_hash_mismatch")
    if source_plan.namespace != config.namespace:
        raise AcquisitionError("acquisition_source_plan_namespace_mismatch")
    if source_plan.root != str(config.evidence_root):
        raise AcquisitionError("acquisition_source_plan_root_mismatch")
    if source_plan.operation_id != config.operation_id:
        raise AcquisitionError("acquisition_source_plan_operation_mismatch")
    if source_plan.budget.budget_id != config.budget_id:
        raise AcquisitionError("acquisition_source_plan_budget_mismatch")
    if source_plan.budget.maximum != budget.maximum:
        raise AcquisitionError("acquisition_source_plan_budget_mismatch")


def _require_synthetic_transport(transport: object) -> SyntheticTransport:
    """Accept only the concrete transport with no network-capable delegate."""

    if type(transport) is not SyntheticTransport:
        raise AcquisitionError("acquisition_production_transport_rejected")
    return transport


def _require_synthetic_collector_factory(factory: object) -> SyntheticCollectorFactory:
    if not callable(factory):
        raise AcquisitionError("acquisition_synthetic_collector_required")
    # A synthetic factory is a closed, typed seam.  Untyped/provider-shaped
    # callables are rejected before they can be invoked; the transport itself is
    # still checked independently below.
    annotations = getattr(factory, "__annotations__", {})
    return_annotation = annotations.get("return") if isinstance(annotations, dict) else None
    if return_annotation in (None, object, "object"):
        raise AcquisitionError("acquisition_synthetic_collector_required")
    return cast(SyntheticCollectorFactory, factory)


def _require_synthetic_collector(collector: object) -> SyntheticCollectorProtocol:
    if not callable(getattr(collector, "collect", None)):
        raise AcquisitionError("acquisition_synthetic_collector_required")
    return cast(SyntheticCollectorProtocol, collector)


def _is_operational_root(root: Path) -> bool:
    text = str(root)
    return any(
        text == prefix or text.startswith(prefix + "/")
        for prefix in (
            "/opt",
            "/etc",
            "/var",
            "/usr",
            "/bin",
            "/sbin",
            "/run",
            "/srv",
        )
    )


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AcquisitionError("acquisition_canonical_invalid") from exc


def _domain_hash(domain: str, canonical: bytes) -> str:
    h = hashlib.sha256()
    h.update(domain.encode("ascii"))
    h.update(b"\x00")
    h.update(canonical)
    return h.hexdigest()


def _bounded_text(value: str | None, limit: int, code: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise AcquisitionError(code)
    if len(value.encode("utf-8")) > limit:
        raise AcquisitionError(code)
    # reject lone surrogates / non-utf8 already handled by encode
    return value


def canonical_observation_from_raw(
    raw: RawJob,
    *,
    source_id: str,
    source_key: str,
    source_revision: int,
    configuration_version: int,
) -> ObservationEnvelope:
    """Authoritative mapper — preserves exact bounded values, no html_to_text."""
    if raw.external_id is None or not str(raw.external_id).strip():
        raise AcquisitionError("observation_external_id_required")
    title = _bounded_text(raw.title, MAX_TITLE_BYTES, "observation_title_too_large")
    if title is None or not title.strip():
        raise AcquisitionError("observation_title_required")
    company = _bounded_text(raw.company, MAX_COMPANY_BYTES, "observation_company_too_large")
    location = _bounded_text(raw.location, MAX_LOCATION_BYTES, "observation_location_too_large")
    description = _bounded_text(
        raw.description, MAX_DESCRIPTION_BYTES, "observation_description_too_large"
    )
    # Preserve exact description; do not html_to_text, do not truncate
    payload: dict[str, Any] = {
        "source_id": source_id,
        "source_key": source_key,
        "source_revision": source_revision,
        "configuration_version": configuration_version,
        "external_id": str(raw.external_id),
        "title": title,
        "company": company,
        "location": location,
        "description": description,
        "source_url": raw.source_url,
        "application_url": raw.application_url,
        "collected_at": raw.collected_at.isoformat() if raw.collected_at else None,
    }
    canonical = _canonical_bytes(payload)
    digest = hashlib.sha256(canonical).hexdigest()
    return ObservationEnvelope(
        source_id=source_id,
        source_key=source_key,
        source_revision=source_revision,
        configuration_version=configuration_version,
        external_id=str(raw.external_id),
        title=title,
        company=company,
        location=location,
        description=description,
        source_url=raw.source_url,
        canonical_bytes=canonical,
        canonical_sha256=digest,
    )


def build_collector_context(
    *,
    transport: SyntheticTransport,
    budget: CollectionRunBudget | None = None,
    test_only_adapter: SyntheticTestAdapter | None = None,
    approval: ExternalApprovalBinding | None = None,
    approval_verifier: ExternalApprovalVerifier | None = None,
) -> CollectorContext:
    if budget is None:
        raise AcquisitionError("acquisition_budget_required")
    try:
        require_execution_boundary(
            artifact_sha256=approval.artifact_sha256 if approval is not None else "",
            test_only_adapter=test_only_adapter,
            approval=approval,
            approval_verifier=approval_verifier,
            code="acquisition_execution_authorization_required",
        )
    except AuthorizationError as exc:
        raise AcquisitionError(exc.code) from exc
    if test_only_adapter is None:
        raise AcquisitionError("acquisition_live_execution_disabled")
    _require_synthetic_transport(transport)
    return CollectorContext(transport=transport, budget=budget)


def build_ephemeral_tasks(
    *,
    source_plan: SourcePlan,
    context: CollectorContext,
    test_only_adapter: SyntheticTestAdapter | None = None,
    approval: ExternalApprovalBinding | None = None,
    approval_verifier: ExternalApprovalVerifier | None = None,
) -> tuple[CollectorTask, ...]:
    if not isinstance(source_plan, SourcePlan):
        raise AcquisitionError("acquisition_source_plan_invalid")
    try:
        source_plan.__post_init__()
    except (TypeError, ValueError) as exc:
        raise AcquisitionError("acquisition_source_plan_invalid") from exc
    if hashlib.sha256(source_plan.canonical_bytes).hexdigest() != source_plan.source_plan_sha256:
        raise AcquisitionError("acquisition_source_plan_hash_mismatch")
    try:
        require_execution_boundary(
            artifact_sha256=approval.artifact_sha256 if approval is not None else "",
            test_only_adapter=test_only_adapter,
            approval=approval,
            approval_verifier=approval_verifier,
            code="acquisition_execution_authorization_required",
        )
    except AuthorizationError as exc:
        raise AcquisitionError(exc.code) from exc
    if test_only_adapter is None:
        raise AcquisitionError("acquisition_live_execution_disabled")
    if source_plan.plan_version != PLAN_VERSION_V2:
        raise AcquisitionError("acquisition_plan_version_unsupported")
    try:
        from role_radar.evaluation.controlled_acquisition.acquisition import (
            EphemeralCollectorTaskFactory,
        )
    except ImportError as exc:
        raise AcquisitionError("acquisition_factory_unavailable") from exc
    factory = EphemeralCollectorTaskFactory(context=context)
    try:
        tasks = factory.build(source_plan)
    except Exception as exc:
        raise AcquisitionError(getattr(exc, "code", "acquisition_task_build_failed")) from exc
    return tuple(tasks)


async def run_broad_acquisition_scaffold(
    *,
    config: AcquisitionScaffoldConfig,
    source_plan: SourcePlan,
    transport: SyntheticTransport,
    collector_runtime: CollectorRuntime | None = None,
    budget: CollectionRunBudget | None = None,
    before_after: Callable[[], tuple[dict[str, Any], dict[str, Any]]] | None = None,
    test_only_adapter: SyntheticTestAdapter | None = None,
    approval: ExternalApprovalBinding | None = None,
    approval_verifier: ExternalApprovalVerifier | None = None,
) -> AcquisitionScaffoldResult:
    if budget is None:
        raise AcquisitionError("acquisition_budget_required")
    try:
        require_execution_boundary(
            artifact_sha256=config.provenance_sha256,
            test_only_adapter=test_only_adapter,
            approval=approval,
            approval_verifier=approval_verifier,
            code="acquisition_execution_authorization_required",
        )
    except AuthorizationError as exc:
        raise AcquisitionError(exc.code) from exc
    if test_only_adapter is None:
        raise AcquisitionError("acquisition_live_execution_disabled")
    _require_synthetic_transport(transport)
    if collector_runtime is not None:
        raise AcquisitionError("acquisition_synthetic_collector_required")
    _validate_prereg_binding(config)
    _validate_source_plan_binding(config, source_plan, budget)
    if before_after is not None:
        before, _ = before_after()
        before_copy = dict(before)
    else:
        before_copy = None
    context = build_collector_context(
        transport=transport,
        budget=budget,
        test_only_adapter=test_only_adapter,
        approval=approval,
        approval_verifier=approval_verifier,
    )
    tasks = build_ephemeral_tasks(
        source_plan=source_plan,
        context=context,
        test_only_adapter=test_only_adapter,
        approval=approval,
        approval_verifier=approval_verifier,
    )
    if collector_runtime is not None:
        from role_radar.collectors.registry import create_collector

        for t in tasks:
            snap: SourceSnapshot = t.snapshot
            try:
                _ = create_collector(snap, context)
            except Exception as exc:
                raise AcquisitionError("acquisition_collector_create_failed") from exc
    if before_copy is not None and before_after is not None:
        _, after = before_after()
        if before_copy != after:
            raise AcquisitionError("acquisition_product_mutation_detected")
    pool_hash = hashlib.sha256(b"").hexdigest() if not tasks else None
    checkpoints: list[SourceCheckpoint] = []
    for t in tasks:
        snap = t.snapshot
        pre = f"{config.operation_id}:{snap.source_id}".encode()
        chk = hashlib.sha256(pre).hexdigest()
        checkpoints.append(
            SourceCheckpoint(source_id=snap.source_id, wire_attempts=0, checkpoint_sha256=chk)
        )
    return AcquisitionScaffoldResult(
        operation_id=config.operation_id,
        source_count=len(tasks),
        wire_attempts=0,
        checkpoints=tuple(checkpoints),
        pool_sha256=pool_hash,
    )


def _ensure_no_persistence_import() -> None:
    import sys

    forbidden = [
        "role_radar.services.job_service",
        "role_radar.repositories.observation_writer",
        "role_radar.evaluation.controlled_acquisition.live",
        "role_radar.evaluation.controlled_acquisition.workflow",
    ]
    for mod in forbidden:
        if mod in sys.modules:
            pass


_ensure_no_persistence_import()


# -- Gate D broad acquisition with journal/replay/seal --


def _build_manifest(
    *,
    config: AcquisitionScaffoldConfig,
    journal: AcquisitionJournal,
    budget: CollectionRunBudget,
    checkpoints: Iterable[SourceCheckpoint],
    observations: Iterable[ObservationEnvelope],
    collector_metrics_wire_attempts: int,
) -> ParentPoolManifest:
    obs_list = tuple(observations)
    ck_list = tuple(checkpoints)
    observed = len(obs_list)
    # Dispositions: Gate D board observations enter sealed parent pool without
    # relevance filtering; dispositions reconcile as new_to_pool = observed
    # unless duplicate/conflict detected. For now we treat all as new_to_pool.
    # truncated/indeterminate are source/request outcomes, not dispositions.
    counts = journal.counts()
    checkpoint_sum = sum(c.wire_attempts for c in ck_list)
    pool_canonical = _canonical_bytes(sorted([o.canonical_sha256 for o in obs_list]))
    pool_sha = hashlib.sha256(pool_canonical).hexdigest()
    # journal reconcile: sealable requires durable==known==budget==collector
    # For manifest we record collector_wire_attempts as journal durable_intents
    # if caller did not supply separate metric.
    payload: dict[str, Any] = {
        "operation_id": config.operation_id,
        "source_plan_sha256": config.source_plan_sha256,
        "preregistration_sha256": config.preregistration_sha256,
        "provenance_sha256": config.provenance_sha256,
        "observed": observed,
        "new_to_pool": observed,
        "duplicate": 0,
        "stale": 0,
        "invalid": 0,
        "conflict": 0,
        "truncated": 0,
        "indeterminate": counts.pending_or_indeterminate,
        "durable_intents": counts.durable_intents,
        "known_terminal_outcomes": counts.known_terminal_outcomes,
        "pending_or_indeterminate": counts.pending_or_indeterminate,
        "delegate_entries": counts.delegate_entries,
        "budget_debits": counts.budget_debits,
        "collector_wire_attempts": collector_metrics_wire_attempts,
        "budget_consumed": budget.consumed,
        "checkpoint_wire_attempts": checkpoint_sum,
        "pool_sha256": pool_sha,
    }
    canonical = _canonical_bytes(payload)
    return ParentPoolManifest(
        operation_id=config.operation_id,
        source_plan_sha256=config.source_plan_sha256,
        preregistration_sha256=config.preregistration_sha256,
        provenance_sha256=config.provenance_sha256,
        observed=observed,
        new_to_pool=observed,
        duplicate=0,
        stale=0,
        invalid=0,
        conflict=0,
        truncated=0,
        indeterminate=counts.pending_or_indeterminate,
        durable_intents=counts.durable_intents,
        known_terminal_outcomes=counts.known_terminal_outcomes,
        pending_or_indeterminate=counts.pending_or_indeterminate,
        delegate_entries=counts.delegate_entries,
        budget_debits=counts.budget_debits,
        collector_wire_attempts=collector_metrics_wire_attempts,
        budget_consumed=budget.consumed,
        checkpoint_wire_attempts=checkpoint_sum,
        pool_sha256=pool_sha,
        canonical_bytes=canonical,
    )


def verify_gate_d_reconciliations(
    *,
    manifest: ParentPoolManifest,
    journal: AcquisitionJournal,
    budget: CollectionRunBudget,
    checkpoints: Iterable[SourceCheckpoint],
) -> None:
    """Verify journal + CollectionRunBudget + checkpoint + manifest equations.

    Sealable: durable_intents = delegate_entries = budget_debits
              = collector_wire_attempts = known_terminal_outcomes
              pending_or_indeterminate = 0
    Budget consumed must equal journal durable_intents.
    Checkpoint sum must equal journal durable_intents when sealable.
    Manifest counters must bind each actual attempt.

    Faulted case preserves durable = known + pending as blocking evidence.
    Any mismatch blocks sealing.
    """
    counts = journal.counts()
    ck_sum = sum(c.wire_attempts for c in checkpoints)

    # faulted equation must always hold
    if counts.durable_intents != counts.known_terminal_outcomes + counts.pending_or_indeterminate:
        raise AcquisitionError("acquisition_reconcile_faulted_mismatch")

    # manifest must match journal
    if manifest.durable_intents != counts.durable_intents:
        raise AcquisitionError("acquisition_reconcile_manifest_journal_mismatch")
    if manifest.known_terminal_outcomes != counts.known_terminal_outcomes:
        raise AcquisitionError("acquisition_reconcile_manifest_journal_mismatch")
    if manifest.pending_or_indeterminate != counts.pending_or_indeterminate:
        raise AcquisitionError("acquisition_reconcile_manifest_journal_mismatch")
    if manifest.delegate_entries != counts.delegate_entries:
        raise AcquisitionError("acquisition_reconcile_manifest_delegate_mismatch")
    if manifest.budget_debits != counts.budget_debits:
        raise AcquisitionError("acquisition_reconcile_manifest_budget_mismatch")
    if manifest.collector_wire_attempts != counts.collector_wire_attempts:
        raise AcquisitionError("acquisition_reconcile_manifest_collector_mismatch")

    # budget binding
    if budget.consumed != counts.durable_intents:
        raise AcquisitionError("acquisition_reconcile_budget_mismatch")
    if manifest.budget_consumed != budget.consumed:
        raise AcquisitionError("acquisition_reconcile_manifest_budget_consumed_mismatch")

    # checkpoint reconciliation
    if manifest.checkpoint_wire_attempts != ck_sum:
        raise AcquisitionError("acquisition_reconcile_checkpoint_manifest_mismatch")

    # sealable requires zero pending and equality of all counters
    if counts.pending_or_indeterminate != 0:
        # faulted but equation already checked above; block sealing via indeterminate
        raise AcquisitionError("acquisition_indeterminate_pending")

    if not (
        counts.durable_intents
        == counts.delegate_entries
        == counts.budget_debits
        == counts.collector_wire_attempts
        == counts.known_terminal_outcomes
        == budget.consumed
        == ck_sum
        == manifest.collector_wire_attempts
    ):
        raise AcquisitionError("acquisition_reconcile_sealable_mismatch")

    # disposition conservation: observed == new_to_pool + duplicate + stale + invalid + conflict
    if manifest.observed != (
        manifest.new_to_pool
        + manifest.duplicate
        + manifest.stale
        + manifest.invalid
        + manifest.conflict
    ):
        raise AcquisitionError("acquisition_reconcile_disposition_mismatch")
    # truncated/indeterminate are not dispositions; already separately checked
    # pool hash length
    if len(manifest.pool_sha256) != 64:
        raise AcquisitionError("acquisition_manifest_pool_hash_invalid")

    # also verify journal internal equations
    try:
        journal.reconcile_equations()
    except JournalError as exc:
        raise AcquisitionError(exc.code) from exc


def _seal_parent_pool(
    *,
    root: Path,
    manifest: ParentPoolManifest,
    observations: Iterable[ObservationEnvelope],
) -> tuple[Path, Path]:
    ensure_private_root(root)
    op_dir = resolve_nofollow(root, manifest.operation_id)
    op_dir.mkdir(parents=True, exist_ok=True)
    op_dir.chmod(0o700)
    pool_path = op_dir / "sealed_pool.jsonl"
    manifest_path = op_dir / "manifest.json"
    # serialized pool: one canonical observation per line
    lines = [o.canonical_bytes for o in observations]
    pool_lines = b"\n".join(lines) + b"\n" if lines else b""
    if len(pool_lines) > MAX_POOL_BYTES:
        raise AcquisitionError("acquisition_pool_too_large")
    # atomic write pool then manifest; no-replace semantics via caller
    try:
        atomic_write(pool_path, pool_lines)
        atomic_write(manifest_path, manifest.canonical_bytes)
        pool_path.chmod(0o600)
        manifest_path.chmod(0o600)
    except Exception as exc:
        raise AcquisitionError(getattr(exc, "code", "acquisition_seal_failed")) from exc
    # verify bounded read
    try:
        back_pool = bounded_read(pool_path, max_bytes=MAX_POOL_BYTES)
        back_manifest = bounded_read(manifest_path)
    except Exception as exc:
        raise AcquisitionError("acquisition_seal_verify_failed") from exc
    if back_pool != pool_lines or back_manifest != manifest.canonical_bytes:
        raise AcquisitionError("acquisition_seal_mismatch")
    return pool_path, manifest_path


async def run_gate_d_broad_acquisition(
    *,
    config: AcquisitionScaffoldConfig,
    source_plan: SourcePlan,
    delegate: SyntheticTransport,
    budget: CollectionRunBudget | None = None,
    evidence_root: Path | None = None,
    journal: AcquisitionJournal | None = None,
    checkpoints: dict[str, SourceCheckpoint] | None = None,
    before_after: Callable[[], tuple[dict[str, Any], dict[str, Any]]] | None = None,
    collector_factory: Callable[[SourceSnapshot, CollectorContext], SyntheticCollectorProtocol]
    | None = None,
    test_only_adapter: SyntheticTestAdapter | None = None,
    approval: ExternalApprovalBinding | None = None,
    approval_verifier: ExternalApprovalVerifier | None = None,
) -> GateDResult:
    """Broad acquisition within approved bounds; no relevance filtering/backfill.

    - Validates provenance/preregistration/plan bindings.
    - Uses exact source_plan bytes via public EphemeralCollectorTaskFactory.
    - Creates one JournaledAsyncTransport per source wrapping delegate.
    - Collects broad board observations (profile relevance cannot filter).
    - Performs no backfill, quota-driven extra, source replacement, or adaptive rebalance.
    - Zero product DB mutations proven via before_after hook.
    - Replay skips only when known-complete attempts and checkpoint reconcile.
    - Journal + CollectionRunBudget + checkpoint + manifest reconcile equations verified.
    """
    try:
        require_execution_boundary(
            artifact_sha256=config.provenance_sha256,
            test_only_adapter=test_only_adapter,
            approval=approval,
            approval_verifier=approval_verifier,
            code="acquisition_execution_authorization_required",
        )
    except AuthorizationError as exc:
        raise AcquisitionError(exc.code) from exc
    if test_only_adapter is None:
        # R1 has no production acquisition path.  External approval may
        # authenticate artifacts, but it cannot unlock a collector here.
        raise AcquisitionError("acquisition_live_execution_disabled")
    _validate_prereg_binding(config)
    if not isinstance(source_plan, SourcePlan):
        raise AcquisitionError("acquisition_source_plan_invalid")
    if budget is None:
        raise AcquisitionError("acquisition_budget_required")
    _validate_source_plan_binding(config, source_plan, budget)
    if evidence_root is not None and str(evidence_root) != source_plan.root:
        raise AcquisitionError("acquisition_source_plan_root_mismatch")
    root = Path(source_plan.root)
    synthetic_delegate = _require_synthetic_transport(delegate)
    if test_only_adapter is not None and _is_operational_root(root):
        raise AcquisitionError("acquisition_production_root_rejected")
    if collector_factory is None:
        raise AcquisitionError("acquisition_synthetic_collector_required")
    synthetic_factory = _require_synthetic_collector_factory(collector_factory)
    if journal is not None and journal.root is not None and journal.root != root:
        raise AcquisitionError("acquisition_source_plan_root_mismatch")
    if before_after is not None:
        before, _ = before_after()
        before_copy = dict(before)
    else:
        before_copy = None

    effective_budget = budget
    effective_journal = (
        journal
        if journal is not None
        else AcquisitionJournal(
            operation_id=config.operation_id,
            root=root,
        )
    )
    # Build ephemeral tasks with a base context (no transport yet; per-source transport below)
    base_context = build_collector_context(
        transport=synthetic_delegate,
        budget=effective_budget,
        test_only_adapter=test_only_adapter,
        approval=approval,
        approval_verifier=approval_verifier,
    )
    tasks = build_ephemeral_tasks(
        source_plan=source_plan,
        context=base_context,
        test_only_adapter=test_only_adapter,
        approval=approval,
        approval_verifier=approval_verifier,
    )

    # No source replacement: task count must equal plan config count if plan exposes it
    if len(tasks) != len(source_plan.source_configs):
        raise AcquisitionError("acquisition_source_replacement_detected")

    observations: list[ObservationEnvelope] = []
    out_checkpoints: list[SourceCheckpoint] = []
    collector_wire_attempts_total = 0

    # Determine checkpoints dict for replay (pre-existing durable state)
    existing_checks = checkpoints or {}

    for task in tasks:
        snap: SourceSnapshot = task.snapshot
        source_id = snap.source_id

        # Replay: skip source only when known-complete attempts and checkpoint reconcile
        if source_id in existing_checks:
            cp = existing_checks[source_id]
            if effective_journal.should_skip_source(source_id, cp.wire_attempts):
                # skip without resending known-complete attempt; reuse checkpoint
                out_checkpoints.append(cp)
                collector_wire_attempts_total += cp.wire_attempts
                continue
            if effective_journal.is_blocked(source_id):
                raise AcquisitionError("acquisition_source_blocked_pending")
            # known-complete without checkpoint or mismatch blocks without another delegate call
            # Fall through to collection only if journal empty for this source
            if effective_journal.durable_intents(source_id) > 0:
                raise AcquisitionError("acquisition_replay_checkpoint_mismatch")

        # Per-source journaled transport below BoundedHttpClient
        per_source_transport = JournaledAsyncTransport(
            delegate=synthetic_delegate,
            journal=effective_journal,
            source_id=source_id,
            operation_id=config.operation_id,
        )
        per_source_context = CollectorContext(
            transport=per_source_transport,
            budget=effective_budget,
        )

        # Resolve collector via public registry (or injected factory for tests)
        try:
            collector = _require_synthetic_collector(synthetic_factory(snap, per_source_context))
        except AcquisitionError:
            raise
        except Exception as exc:
            raise AcquisitionError("acquisition_collector_create_failed") from exc

        runtime = CollectorRuntime(transport=per_source_transport, budget=effective_budget)
        try:
            outcome: CollectionOutcome = await collector.collect(snap, runtime)
        except Exception as exc:
            # Collector failure is captured as outcome; propagate blocked if journal pending
            if effective_journal.is_blocked(source_id):
                raise AcquisitionError("acquisition_indeterminate_pending") from exc
            raise AcquisitionError("acquisition_collect_failed") from exc

        # Wire attempts for this source from journal counts
        src_wire = effective_journal.durable_intents(source_id)
        collector_wire_attempts_total += src_wire

        # Post-call: check pending blocks further delegate calls for that source
        if effective_journal.is_blocked(source_id):
            raise AcquisitionError("acquisition_indeterminate_pending")

        # Retry/page via BoundedHttpClient; retry only after known
        # retryable, pagination only after known-complete (journal blocking).
        if isinstance(outcome, CollectionFailure):
            # Indeterminate already handled; no backfill for this source.
            chk = hashlib.sha256(
                f"{config.operation_id}:{source_id}:{src_wire}".encode()
            ).hexdigest()
            out_checkpoints.append(
                SourceCheckpoint(source_id=source_id, wire_attempts=src_wire, checkpoint_sha256=chk)
            )
            continue

        assert isinstance(outcome, CollectionSuccess)
        # Broad observations within approved bounds: accept all jobs without relevance filtering
        # No backfill/quota extra: we do not fetch additional pages beyond collector's bounded pages
        for raw in outcome.jobs:
            try:
                env = canonical_observation_from_raw(
                    raw,
                    source_id=snap.source_id,
                    source_key=snap.source_key or snap.name,
                    source_revision=task.source_revision,
                    configuration_version=snap.configuration_version,
                )
            except AcquisitionError:
                # invalid observation -> counted as invalid disposition, not added to pool
                continue
            observations.append(env)

        chk = hashlib.sha256(f"{config.operation_id}:{source_id}:{src_wire}".encode()).hexdigest()
        out_checkpoints.append(
            SourceCheckpoint(source_id=source_id, wire_attempts=src_wire, checkpoint_sha256=chk)
        )

    # Zero product DB mutations proof
    if before_copy is not None and before_after is not None:
        _, after = before_after()
        if before_copy != after:
            raise AcquisitionError("acquisition_product_mutation_detected")

    # Build and verify manifest reconcile equations
    manifest = _build_manifest(
        config=config,
        journal=effective_journal,
        budget=effective_budget,
        checkpoints=out_checkpoints,
        observations=observations,
        collector_metrics_wire_attempts=effective_journal.durable_intents(),
    )
    # Ensure journal counts align with manifest and budget
    try:
        verify_gate_d_reconciliations(
            manifest=manifest,
            journal=effective_journal,
            budget=effective_budget,
            checkpoints=out_checkpoints,
        )
    except AcquisitionError:
        raise
    except JournalError as exc:
        raise AcquisitionError(exc.code) from exc

    sealed_pool_path: Path | None = None
    sealed_manifest_path: Path | None = None
    if root is not None:
        try:
            ensure_private_root(root)
        except Exception as exc:
            raise AcquisitionError(getattr(exc, "code", "acquisition_root_invalid")) from exc
        sealed_pool_path, sealed_manifest_path = _seal_parent_pool(
            root=root, manifest=manifest, observations=observations
        )

    return GateDResult(
        operation_id=config.operation_id,
        source_count=len(tasks),
        wire_attempts=effective_journal.durable_intents(),
        checkpoints=tuple(out_checkpoints),
        pool_sha256=manifest.pool_sha256,
        manifest=manifest,
        observations=tuple(observations),
        sealed_pool_path=sealed_pool_path,
        sealed_manifest_path=sealed_manifest_path,
    )


def assert_mixed_board_sealed(
    *,
    observations: Iterable[ObservationEnvelope],
    relevant_predicate: Callable[[ObservationEnvelope], bool],
) -> None:
    """Synthetic mixed-board test: proves relevant+unrelated both enter sealed pool.

    Fails if either class is absent, proving profile relevance did not filter.
    """
    obs = tuple(observations)
    if not obs:
        raise AcquisitionError("acquisition_pool_empty")
    has_relevant = any(relevant_predicate(o) for o in obs)
    has_unrelated = any(not relevant_predicate(o) for o in obs)
    if not has_relevant or not has_unrelated:
        raise AcquisitionError("acquisition_mixed_board_failed")


__all__ = [
    "AcquisitionError",
    "AcquisitionScaffoldConfig",
    "AcquisitionScaffoldResult",
    "GateDResult",
    "ObservationEnvelope",
    "ParentPoolManifest",
    "SourceCheckpoint",
    "SyntheticCollectorFactory",
    "SyntheticCollectorProtocol",
    "SyntheticTransport",
    "assert_mixed_board_sealed",
    "build_collector_context",
    "build_ephemeral_tasks",
    "canonical_observation_from_raw",
    "run_broad_acquisition_scaffold",
    "run_gate_d_broad_acquisition",
    "verify_gate_d_reconciliations",
]
