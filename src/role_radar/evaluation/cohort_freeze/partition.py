"""Pure v2 Source-stratified Hamilton partitioning."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from fractions import Fraction

from role_radar.evaluation.cohort_freeze.contracts import (
    CorpusItem,
    CorpusResult,
    PartitionResult,
    SourceQuota,
)
from role_radar.evaluation.cohort_freeze.policy import (
    CORPUS_COUNT,
    HOLDOUT_COUNT,
    PARTITION_PROTOCOL,
    PILOT_COUNT,
    V2_PARTITION_DOMAIN,
    V2_RANK_DOMAIN,
)
from role_radar.evaluation.snapshot_store import canonical_line, sha256_bytes


def _lp(*values: str) -> bytes:
    result = bytearray()
    for value in values:
        encoded = value.encode("utf-8")
        result.extend(len(encoded).to_bytes(4, "big"))
        result.extend(encoded)
    return bytes(result)


def partition_rank_sha256(corpus_sha256: str, item: CorpusItem) -> str:
    return hashlib.sha256(
        _lp(V2_RANK_DOMAIN, corpus_sha256, item.item_semantic_sha256, item.strong_identity_digest)
    ).hexdigest()


def _tie_break(source: str) -> str:
    return hashlib.sha256(_lp("f10.1c:quota-tie-v2", source)).hexdigest()


def _quotas(groups: dict[str, list[CorpusItem]]) -> tuple[SourceQuota, ...]:
    names = sorted(groups)
    total = sum(len(items) for items in groups.values())
    if total != CORPUS_COUNT:
        raise ValueError("corpus_cardinality_invalid")
    if len(names) <= PILOT_COUNT:
        minimums = {name: 1 for name in names}
        remaining_seats = PILOT_COUNT - len(names)
        capacities = {name: len(groups[name]) - 1 for name in names}
        capacity_total = sum(capacities.values())
        ideals = {
            name: Fraction(remaining_seats * capacities[name], capacity_total)
            if capacity_total
            else Fraction(0)
            for name in names
        }
    else:
        minimums = {name: 0 for name in names}
        remaining_seats = PILOT_COUNT
        ideals = {name: Fraction(PILOT_COUNT * len(groups[name]), total) for name in names}
    floors = {name: ideals[name].numerator // ideals[name].denominator for name in names}
    assigned = sum(minimums[name] + floors[name] for name in names)
    left = PILOT_COUNT - assigned
    if left < 0:
        raise ValueError("quota_negative")
    order = sorted(
        names,
        key=lambda name: (
            -(ideals[name] - floors[name]),
            _tie_break(name),
            name.encode("utf-8"),
        ),
    )
    extras = {name: 0 for name in names}
    for name in order[:left]:
        extras[name] += 1
    result: list[SourceQuota] = []
    for name in names:
        ideal = ideals[name]
        result.append(
            SourceQuota(
                source_stratum=name,
                population=len(groups[name]),
                minimum_applied=minimums[name],
                ideal_numerator=ideal.numerator,
                ideal_denominator=ideal.denominator,
                floor=floors[name],
                remainder_numerator=(ideal - floors[name]).numerator,
                remainder_denominator=(ideal - floors[name]).denominator,
                tie_break_sha256=_tie_break(name),
                quota=minimums[name] + floors[name] + extras[name],
            )
        )
    if sum(item.quota for item in result) != PILOT_COUNT or any(
        item.quota < 0 or item.quota > item.population for item in result
    ):
        raise ValueError("quota_cardinality_invalid")
    return tuple(result)


def _membership_hash(
    domain: str,
    corpus_sha256: str,
    items: Iterable[CorpusItem],
    quotas: tuple[SourceQuota, ...],
) -> str:
    ordered = sorted(
        (
            item.item_semantic_sha256,
            item.strong_identity_digest,
        )
        for item in items
    )
    return sha256_bytes(
        _lp(V2_PARTITION_DOMAIN, domain, corpus_sha256, PARTITION_PROTOCOL)
        + canonical_line(
            [{"semantic": semantic, "identity": identity} for semantic, identity in ordered]
        )
        + canonical_line(
            [
                quota.__dict__
                if hasattr(quota, "__dict__")
                else {
                    "source": quota.source_stratum,
                    "population": quota.population,
                    "minimum": quota.minimum_applied,
                    "ideal": [quota.ideal_numerator, quota.ideal_denominator],
                    "floor": quota.floor,
                    "remainder": [quota.remainder_numerator, quota.remainder_denominator],
                    "tie": quota.tie_break_sha256,
                    "quota": quota.quota,
                }
                for quota in quotas
            ]
        ),
    )


def partition_corpus(corpus: CorpusResult) -> PartitionResult:
    if corpus.status != "ready" or corpus.corpus_sha256 is None:
        raise ValueError("corpus_not_ready")
    if len(corpus.items) != CORPUS_COUNT:
        raise ValueError("corpus_cardinality_invalid")
    groups: defaultdict[str, list[CorpusItem]] = defaultdict(list)
    for item in corpus.items:
        groups[item.source_stratum].append(item)
    quotas = _quotas(dict(groups))
    ranks = {id(item): partition_rank_sha256(corpus.corpus_sha256, item) for item in corpus.items}
    pilot: list[CorpusItem] = []
    for quota in quotas:
        members = sorted(
            groups[quota.source_stratum],
            key=lambda item: (
                ranks[id(item)],
                item.strong_identity_digest,
                item.item_semantic_sha256,
            ),
        )
        pilot.extend(members[: quota.quota])
    pilot_tuple = tuple(
        sorted(pilot, key=lambda item: (item.item_semantic_sha256, item.strong_identity_digest))
    )
    pilot_keys = {(item.item_semantic_sha256, item.strong_identity_digest) for item in pilot_tuple}
    holdout_tuple = tuple(
        item
        for item in corpus.items
        if (item.item_semantic_sha256, item.strong_identity_digest) not in pilot_keys
    )
    holdout_tuple = tuple(
        sorted(
            holdout_tuple,
            key=lambda item: (item.item_semantic_sha256, item.strong_identity_digest),
        )
    )
    if (
        len(pilot_tuple) != PILOT_COUNT
        or len(holdout_tuple) != HOLDOUT_COUNT
        or pilot_keys
        & {(item.item_semantic_sha256, item.strong_identity_digest) for item in holdout_tuple}
    ):
        raise ValueError("partition_membership_invalid")
    quota_hash = sha256_bytes(
        canonical_line(
            [
                {
                    "source": quota.source_stratum,
                    "population": quota.population,
                    "quota": quota.quota,
                    "tie": quota.tie_break_sha256,
                }
                for quota in quotas
            ]
        )
    )
    return PartitionResult(
        pilot=pilot_tuple,
        holdout=holdout_tuple,
        quotas=quotas,
        pilot_sha256=_membership_hash("pilot", corpus.corpus_sha256, pilot_tuple, quotas),
        holdout_sha256=_membership_hash("holdout", corpus.corpus_sha256, holdout_tuple, quotas),
        quota_sha256=quota_hash,
        algorithm_version=PARTITION_PROTOCOL,
    )


partition = partition_corpus

__all__ = ["partition", "partition_corpus", "partition_rank_sha256"]
