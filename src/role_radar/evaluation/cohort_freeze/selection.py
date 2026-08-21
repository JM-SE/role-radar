"""Pure deterministic F10.1C eligibility, ordering and hashing."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from role_radar.evaluation.cohort_freeze.contracts import (
    CandidateEvidence,
    CohortStatus,
    CorpusItem,
    CorpusResult,
    SelectionResult,
)
from role_radar.evaluation.cohort_freeze.policy import (
    CORPUS_COUNT,
    TARGET_COUNT,
    V2_CORPUS_DOMAIN,
    acquisition_snapshot_hash,
    canonical_hash,
    canonical_time,
    content_reason,
    source_snapshot_valid,
)
from role_radar.evaluation.snapshot_store import canonical_line, sha256_bytes


def _domain_hash(domain: str, values: Iterable[Any]) -> str:
    payload = bytearray(domain.encode("ascii") + b"\0")
    for value in values:
        payload.extend(canonical_line(value))
    return sha256_bytes(bytes(payload))


def _identity_reason(
    candidate: CandidateEvidence, identity_owners: dict[tuple[str, str, str], set[str]]
) -> str | None:
    matches = [
        item
        for item in candidate.identity_keys
        if item.version == candidate.identity_policy_version
    ]
    if not matches:
        return "strong_identity_missing"
    for item in matches:
        if item.owner_job_id != candidate.job_id:
            return "strong_identity_inconsistent"
        try:
            digest = sha256_bytes(item.value.encode("utf-8"))
        except UnicodeEncodeError:
            return "strong_identity_inconsistent"
        if digest != item.value_digest:
            return "strong_identity_inconsistent"
        if len(identity_owners.get((item.version, item.kind, item.value), set())) > 1:
            return "strong_identity_inconsistent"
    # The same strong identity may appear more than once for one job only when
    # the value is identical; an ambiguous value is not silently selected.
    ownership = {(item.kind, item.version, item.value, item.owner_job_id) for item in matches}
    if len(ownership) != len(matches):
        return "strong_identity_inconsistent"
    return None


def _reason(
    candidate: CandidateEvidence,
    created_by_operation: MappingCounts,
    identity_owners: dict[tuple[str, str, str], set[str]],
) -> str | None:
    if candidate.run_state not in {"completed", "completed_partial"}:
        return "run_not_terminal"
    if (
        candidate.operation_run_id is None
        or candidate.operation_run_id != candidate.run_id
        or candidate.operation_source_id is None
        or candidate.operation_created_count < created_by_operation.get(candidate.operation_id, 0)
        or candidate.operation_observed_count < created_by_operation.get(candidate.operation_id, 0)
        or candidate.run_created_count < created_by_operation.run_created.get(candidate.run_id, 0)
        or candidate.run_observed_count < created_by_operation.run_created.get(candidate.run_id, 0)
    ):
        return "run_operation_inconsistent"
    if (
        candidate.operation_result_state not in {"succeeded", "truncated"}
        or not candidate.operation_finished_at
    ):
        return "operation_not_accepted"
    if not source_snapshot_valid(candidate.source_snapshot_json):
        return "source_snapshot_invalid"
    if candidate.operation_source_id != candidate.source_snapshot_json["source_id"]:
        return "run_operation_inconsistent"
    try:
        expected_run_hash = acquisition_snapshot_hash(candidate.run_snapshot_json)
        source_belongs = isinstance(candidate.run_snapshot_json, list) and any(
            item == candidate.source_snapshot_json for item in candidate.run_snapshot_json
        )
    except (TypeError, ValueError):
        expected_run_hash, source_belongs = "", False
    if (
        not source_belongs
        or not candidate.run_snapshot_hash
        or candidate.run_snapshot_hash != expected_run_hash
    ):
        return "run_snapshot_inconsistent"
    if any(
        value in (None, "")
        for value in (
            candidate.provider_recency_at,
            candidate.recency_semantic,
            candidate.freshness_policy_version,
            candidate.identity_policy_version,
            candidate.provenance_hash,
        )
    ):
        return "freshness_provenance_missing"
    try:
        canonical_time(candidate.provider_recency_at)  # type: ignore[arg-type]
        canonical_time(candidate.accepted_observation_at)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return "freshness_provenance_invalid"
    if (
        not candidate.recency_semantic
        or not candidate.freshness_policy_version
        or not candidate.identity_policy_version
        or not isinstance(candidate.provenance_hash, str)
        or not re.fullmatch(r"[0-9a-f]{64}", candidate.provenance_hash)
    ):
        return "freshness_provenance_invalid"
    if not candidate.job_exists:
        return "job_missing"
    identity_reason = _identity_reason(candidate, identity_owners)
    if identity_reason is not None:
        return identity_reason
    return content_reason(candidate)


class MappingCounts(dict[str, int]):
    """Tiny typed carrier for operation/run link counts."""

    def __init__(self, operation: dict[str, int], run: dict[str, int]) -> None:
        super().__init__(operation)
        self.run_created = run


def item_semantic_sha256(candidate: CandidateEvidence) -> str:
    if candidate.provider_recency_at is None:
        raise ValueError("semantic_timestamp_missing")
    payload = {
        "content": {
            "title": candidate.title,
            "company": candidate.company,
            "location": candidate.location,
            "description": candidate.description,
            "application_url": candidate.application_url,
        },
        "provenance": {
            "provider_recency_at": canonical_time(candidate.provider_recency_at),
            "recency_semantic": candidate.recency_semantic,
            "freshness_policy_version": candidate.freshness_policy_version,
            "identity_policy_version": candidate.identity_policy_version,
            "provenance_hash": candidate.provenance_hash,
            "provenance_scope": "source_key+external_id",
            "source_snapshot_hash": canonical_hash(candidate.source_snapshot_json),
        },
    }
    return sha256_bytes(b"f10.1c:item-semantic-v1\0" + canonical_line(payload))


def _sort_key(candidate: CandidateEvidence) -> tuple[str, bytes, bytes, bytes]:
    if candidate.accepted_observation_at is None:
        timestamp = ""
        return (
            timestamp,
            candidate.run_id.encode(),
            candidate.link_id.encode(),
            candidate.job_id.encode(),
        )
    try:
        timestamp = canonical_time(candidate.accepted_observation_at)
    except (TypeError, ValueError, OverflowError):
        timestamp = ""
    return (
        timestamp,
        candidate.run_id.encode(),
        candidate.link_id.encode(),
        candidate.job_id.encode(),
    )


def _record(candidate: CandidateEvidence, reason: str | None) -> dict[str, Any]:
    return {
        "key": [*_sort_key(candidate)[:1], candidate.run_id, candidate.link_id, candidate.job_id],
        "run_id": candidate.run_id,
        "link_id": candidate.link_id,
        "job_id": candidate.job_id,
        "disposition": candidate.disposition,
        "terminal_code": reason,
        "semantic_sha256": item_semantic_sha256(candidate) if reason is None else None,
        "ignored_link_ids": sorted(candidate.ignored_link_ids),
    }


def select_candidates(
    candidates: Iterable[CandidateEvidence],
    *,
    target_count: int = TARGET_COUNT,
) -> SelectionResult:
    """Select a prefix of the total order; input order has no effect."""

    source = tuple(candidates)
    identity_owners: defaultdict[tuple[str, str, str], set[str]] = defaultdict(set)
    for candidate in source:
        for identity_item in candidate.identity_keys:
            identity_owners[(identity_item.version, identity_item.kind, identity_item.value)].add(
                identity_item.owner_job_id
            )
    operation_counts: Counter[str] = Counter(
        item.operation_id for item in source if item.disposition == "created"
    )
    run_counts: Counter[str] = Counter(
        item.run_id for item in source if item.disposition == "created"
    )
    counts = MappingCounts(dict(operation_counts), dict(run_counts))
    ignored: Counter[str] = Counter()
    ignored_ids: defaultdict[str, list[str]] = defaultdict(list)
    created = [item for item in source if item.disposition == "created"]
    for item in source:
        if item.disposition == "duplicate":
            ignored["duplicate_link_ignored"] += 1
            ignored_ids["duplicate_link_ignored"].append(item.link_id)
    by_job: defaultdict[str, list[CandidateEvidence]] = defaultdict(list)
    for item in created:
        by_job[item.job_id].append(item)
    considered: list[CandidateEvidence] = []
    for _job_id, links in by_job.items():
        ordered = sorted(links, key=_sort_key)
        considered.append(ordered[0])
        ignored["non_first_created_link_ignored"] += max(0, len(ordered) - 1)
        ignored_ids["non_first_created_link_ignored"].extend(item.link_id for item in ordered[1:])
    rejected: Counter[str] = Counter()
    eligible: list[CandidateEvidence] = []
    records: list[dict[str, Any]] = []
    for item in sorted(considered, key=_sort_key):
        reason = _reason(item, counts, identity_owners)
        records.append(_record(item, reason))
        if reason is None:
            eligible.append(item)
        else:
            rejected[reason] += 1
    eligible = sorted(eligible, key=_sort_key)
    selected = tuple(eligible[:target_count]) if len(eligible) >= target_count else ()
    if len(eligible) > target_count:
        rejected["eligible_after_first_50"] = len(eligible) - target_count
    for item in eligible[target_count:]:
        records.append(_record(item, "eligible_after_first_50"))
    records.sort(key=lambda row: (row["key"], row["link_id"], row["job_id"]))
    # Ignored links are included as stable aggregate evidence, even though
    # their private identifiers never leave the internal hash.
    records.append(
        {
            "ignored_counts": dict(sorted(ignored.items())),
            "ignored_link_ids": {key: sorted(value) for key, value in sorted(ignored_ids.items())},
        }
    )
    cohort_hash = _domain_hash("f10.1c:candidate-cohort-v1", records)
    semantic_hashes = tuple(item_semantic_sha256(item) for item in selected)
    selection_hash = (
        _domain_hash("f10.1c:selection-v1", semantic_hashes)
        if len(selected) == target_count
        else None
    )
    return SelectionResult(
        status=CohortStatus.READY if len(eligible) >= target_count else CohortStatus.WAITING,
        eligible_count=len(eligible),
        selected_count=len(selected),
        rejection_counts=dict(sorted(rejected.items())),
        candidates=tuple(eligible),
        selected=selected,
        candidate_cohort_sha256=cohort_hash,
        selection_sha256=selection_hash,
        item_semantic_sha256=semantic_hashes,
        ignored_link_counts=dict(sorted(ignored.items())),
    )


def strong_identity_digest(candidate: CandidateEvidence) -> str:
    """Canonical digest used by v2, never a raw identity value in public data."""

    matches = [
        item
        for item in candidate.identity_keys
        if item.version == candidate.identity_policy_version
    ]
    if not matches:
        raise ValueError("strong_identity_missing")
    ordered = sorted((item.kind, item.version, item.value_digest) for item in matches)
    return sha256_bytes(b"f10.1c:strong-identity-v2\0" + canonical_line(ordered))


def source_stratum(candidate: CandidateEvidence) -> str:
    source = candidate.source_snapshot_json
    if not isinstance(source, dict):
        raise ValueError("source_snapshot_invalid")
    source_id = source.get("source_id")
    source_key = source.get("source_key")
    if not isinstance(source_id, str) or not source_id.strip():
        raise ValueError("source_snapshot_invalid")
    if not isinstance(source_key, str) or not source_key.strip():
        raise ValueError("source_snapshot_invalid")
    return f"{source_id.strip()}\x00{source_key.strip()}"


def item_semantic_sha256_v2(candidate: CandidateEvidence) -> str:
    if candidate.provider_recency_at is None:
        raise ValueError("semantic_timestamp_missing")
    payload = {
        "content": {
            "title": candidate.title,
            "company": candidate.company,
            "location": candidate.location,
            "description": candidate.description,
            "application_url": candidate.application_url,
        },
        "provenance": {
            "provider_recency_at": canonical_time(candidate.provider_recency_at),
            "recency_semantic": candidate.recency_semantic,
            "freshness_policy_version": candidate.freshness_policy_version,
            "identity_policy_version": candidate.identity_policy_version,
            "provenance_hash": candidate.provenance_hash,
            "provenance_scope": "source_key+external_id",
            "source_snapshot_hash": canonical_hash(candidate.source_snapshot_json),
        },
    }
    return sha256_bytes(b"f10.1c:item-semantic-v2\0" + canonical_line(payload))


def build_bounded_corpus(
    candidates: Iterable[CandidateEvidence],
    *,
    expected_count: int = CORPUS_COUNT,
    boundaries: Mapping[str, object] | None = None,
    bounded_fingerprint_sha256: str = "",
) -> CorpusResult:
    """Build the complete bounded parent corpus; never truncates or backfills."""

    source = tuple(candidates)
    identity_owners: defaultdict[tuple[str, str, str], set[str]] = defaultdict(set)
    for candidate in source:
        for identity in candidate.identity_keys:
            identity_owners[(identity.version, identity.kind, identity.value)].add(
                identity.owner_job_id
            )
    operation_counts: Counter[str] = Counter(
        item.operation_id for item in source if item.disposition == "created"
    )
    run_counts: Counter[str] = Counter(
        item.run_id for item in source if item.disposition == "created"
    )
    counts = MappingCounts(dict(operation_counts), dict(run_counts))
    ignored: Counter[str] = Counter()
    by_job: defaultdict[str, list[CandidateEvidence]] = defaultdict(list)
    for item in source:
        if item.disposition == "duplicate":
            ignored["duplicate_link_ignored"] += 1
        elif item.disposition == "created":
            by_job[item.job_id].append(item)
    considered: list[CandidateEvidence] = []
    for links in by_job.values():
        ordered = sorted(links, key=_sort_key)
        considered.append(ordered[0])
        ignored["non_first_created_link_ignored"] += max(0, len(ordered) - 1)
    rejection: Counter[str] = Counter()
    eligible: list[CorpusItem] = []
    for candidate in sorted(considered, key=_sort_key):
        reason = _reason(candidate, counts, identity_owners)
        if reason is not None:
            rejection[reason] += 1
            continue
        try:
            eligible.append(
                CorpusItem(
                    evidence=candidate,
                    source_stratum=source_stratum(candidate),
                    strong_identity_digest=strong_identity_digest(candidate),
                    item_semantic_sha256=item_semantic_sha256_v2(candidate),
                )
            )
        except ValueError as exc:
            rejection[str(exc)] += 1
    eligible.sort(key=lambda item: (item.item_semantic_sha256, item.strong_identity_digest))
    if len({item.item_semantic_sha256 for item in eligible}) != len(eligible):
        rejection["item_semantic_collision"] += 1
    if len({item.strong_identity_digest for item in eligible}) != len(eligible):
        rejection["strong_identity_collision"] += 1
    if (
        len(eligible) != expected_count
        or rejection.get("item_semantic_collision")
        or rejection.get("strong_identity_collision")
    ):
        return CorpusResult(
            status="blocked",
            items=(),
            eligible_count=len(eligible),
            rejection_counts=dict(sorted(rejection.items())),
            ignored_link_counts=dict(sorted(ignored.items())),
            corpus_sha256=None,
        )
    corpus_hash = _domain_hash(
        V2_CORPUS_DOMAIN,
        (
            {
                "schema_version": "f10.1c-preview-v2",
                "corpus_protocol": "f10.1c-bounded-corpus-v2",
                "boundaries": dict(boundaries or {}),
                "bounded_fingerprint_sha256": bounded_fingerprint_sha256,
            },
            *(
                {"semantic": item.item_semantic_sha256, "identity": item.strong_identity_digest}
                for item in eligible
            ),
        ),
    )
    return CorpusResult(
        status="ready",
        items=tuple(eligible),
        eligible_count=len(eligible),
        rejection_counts=dict(sorted(rejection.items())),
        ignored_link_counts=dict(sorted(ignored.items())),
        corpus_sha256=corpus_hash,
    )


select = select_candidates
select_cohort = select_candidates
evaluate_candidates = select_candidates

__all__ = [
    "build_bounded_corpus",
    "evaluate_candidates",
    "item_semantic_sha256",
    "item_semantic_sha256_v2",
    "select",
    "select_candidates",
    "select_cohort",
    "source_stratum",
    "strong_identity_digest",
]
