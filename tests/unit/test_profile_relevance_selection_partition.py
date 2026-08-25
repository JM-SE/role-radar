"""Selection, Hamilton allocation, probabilities, ties, ranks, partition membership."""

from __future__ import annotations

import hashlib

import pytest

from role_radar.evaluation.profile_relevance.contracts import (
    HistoricalIdentityExclusion,
    PartitionPolicy,
    PartitionQuota,
    QuotaCell,
    SamplingPolicy,
)
from role_radar.evaluation.profile_relevance.hashing import (
    domain_hash,
    domain_hash_bytes,
    membership_root,
    partition_rank_hash,
    selection_rank_hash,
)
from role_radar.evaluation.profile_relevance.partition import run_partition
from role_radar.evaluation.profile_relevance.policy import (
    DOMAIN_EXCLUSION,
    DOMAIN_HOLDOUT_MEMBERSHIP,
    DOMAIN_PARTITION_POLICY,
    DOMAIN_PARTITION_RANK,
    DOMAIN_PILOT_MEMBERSHIP,
    DOMAIN_SAMPLING_POLICY,
    DOMAIN_SELECTION_RANK,
    PROTOCOL_PARTITION,
    PROTOCOL_SELECTION,
)
from role_radar.evaluation.profile_relevance.selection import run_selection

# Golden literals approved prereg
SELECTION_SEED = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
PARTITION_SEED = "f0e0d0c0b0a090807060504030201000ffeeddccbbaa99887766554433221100"
SELECTION_RANK_DOMAIN = "role-radar:f10.1e-profile-relevance:selection-rank:v1"
PARTITION_RANK_DOMAIN = "role-radar:f10.1e-profile-relevance:partition-rank:v1"

# 8 rows golden vector
SEMANTICS = [
    "1111111111111111111111111111111111111111111111111111111111111111",
    "2222222222222222222222222222222222222222222222222222222222222222",
    "3333333333333333333333333333333333333333333333333333333333333333",
    "4444444444444444444444444444444444444444444444444444444444444444",
    "5555555555555555555555555555555555555555555555555555555555555555",
    "6666666666666666666666666666666666666666666666666666666666666666",
    "7777777777777777777777777777777777777777777777777777777777777777",
    "8888888888888888888888888888888888888888888888888888888888888888",
]
STRONG = [
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "9999999999999999999999999999999999999999999999999999999999999999",
    "8888888888888888888888888888888888888888888888888888888888888888",
]
COMPANY = ["alpha", "alpha", "alpha", "alpha", "beta", "beta", "beta", "gamma"]
# Independently hard-coded expected selection ranks (do not derive via production helpers)
EXPECTED_SELECTION_RANKS = {
    SEMANTICS[0]: "59b2ef42f3861da8d961edcaa2523a19f771b6a3acbcef91960d73bf2457643b",
    SEMANTICS[1]: "b06a14dc95fe1bbe5ac53c1480dc5cb96f9292f8da3c7be118475715128d589c",
    SEMANTICS[2]: "adaa564c70698161552c2a4f25506a27564f6789a81c456bf1a22210d61eca97",
    SEMANTICS[3]: "8d4e609c5f59742df7aaf118502be66bd8f124dca560abaaee560580cc6419f7",
    SEMANTICS[4]: "736c6ae05d5580d09400946063ca605d3e68dc4df23b08439aa7056460699999",
    SEMANTICS[5]: "5128de472d76773c6bff58c401ac8882e592589059da205ce031fe98f384eba2",
    SEMANTICS[6]: "7a8e2ab43ef8a1da0d4b6be10042a6913d26234354b243c074ca31528b977c4e",
    SEMANTICS[7]: "457836c26b976d6b4af57f883c9e9191ec1f37ce82d415b7326df905987029de",
}
# Independently hard-coded partition ranks for selected set
EXPECTED_PARTITION_RANKS = {
    "1111111111111111111111111111111111111111111111111111111111111111": "c611aaab7105703cc1e153c33aefe8f1362ff8b0efee1225ff4155cda6c5b915",
    "4444444444444444444444444444444444444444444444444444444444444444": "1499b7de21f8f34131c7ded8e4bba78359cb27e12ab19c1ae93da7aed50bfa94",
    "5555555555555555555555555555555555555555555555555555555555555555": "925a51dcf4229c8bf72e8402f99ff861194e6e0b839e0e58fc961ae53a4a9861",
    "6666666666666666666666666666666666666666666666666666666666666666": "5b581dede6d722dc13db188c8af74ea158db577782191a4941e4e3f2c900f30e",
}
PILOT_MEMBERSHIP_EXPECTED = "e94cdd76dba624e94ba9229bf5ca396435d7e05fc30e80e9235034a5cc210ee3"
HOLDOUT_MEMBERSHIP_EXPECTED = "0d74fb4cc056440eb5f65698ee49c5852547e85b7918d9e29d877fae031fd6d9"


def _hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _make_exclusion(
    *, digests: tuple[str, ...] = (), created_at: str = "2026-08-24T00:00:00Z"
) -> HistoricalIdentityExclusion:
    dig = tuple(sorted(digests))
    payload = {
        "count": len(dig),
        "created_at_utc": created_at,
        "digests": list(dig),
        "exclusion_id": "excl",
        "identity_policy_version": "strong-identity-v1",
        "kind": "complete_inventory_digest_set",
        "policy_version": "v1",
        "schema_version": "v1",
        "scope": "complete",
    }
    h = domain_hash(DOMAIN_EXCLUSION, payload)
    return HistoricalIdentityExclusion(
        exclusion_id="excl",
        schema_version="v1",
        policy_version="v1",
        kind="complete_inventory_digest_set",
        identity_policy_version="strong-identity-v1",
        scope="complete",
        created_at_utc=created_at,
        digests=dig,
        count=len(dig),
        exclusion_sha256=h,
    )


def _make_sampling_policy(*, selection_input_sha256: str = "a" * 64) -> SamplingPolicy:
    quotas = (
        QuotaCell("board_a", "candidate", 4),
        QuotaCell("board_a", "near_miss", 0),
        QuotaCell("board_a", "background_control", 0),
        QuotaCell("board_a", "indeterminate", 0),
    )
    canon_dict = {
        "corpus_cardinality": 4,
        "partition": "x",
        "quotas": [[q.source_unit, q.stratum, q.corpus_quota] for q in quotas],
        "selection_seed": SELECTION_SEED,
    }
    # provide canonical bytes deterministic
    from role_radar.evaluation.profile_relevance.hashing import canonical_json_bytes

    canon = canonical_json_bytes(canon_dict)
    h = domain_hash_bytes(DOMAIN_SAMPLING_POLICY, canon)
    return SamplingPolicy(
        policy_id="sp",
        policy_version="v1",
        schema_version="v1",
        selection_input_sha256=selection_input_sha256,
        relevance_policy_sha256="b" * 64,
        corpus_cardinality=4,
        quotas=quotas,
        per_board_cap=4,
        global_per_company_cap=2,
        allocation_protocol=PROTOCOL_SELECTION,
        selection_seed=SELECTION_SEED,
        selection_rank_domain=DOMAIN_SELECTION_RANK,
        rank_protocol=PROTOCOL_SELECTION,
        insufficient_inventory_behavior="fail_closed",
        execution_scope="synthetic_gate_a",
        canonical_bytes=canon,
        sampling_policy_sha256=h,
    )


def _make_partition_policy(selection: object | None = None) -> PartitionPolicy:
    _ = getattr(selection, "selection_sha256", "e" * 64) if selection else "e" * 64
    pilot_quotas = (
        PartitionQuota("board_a", "candidate", 2),
        PartitionQuota("board_a", "near_miss", 0),
        PartitionQuota("board_a", "background_control", 0),
        PartitionQuota("board_a", "indeterminate", 0),
    )
    from role_radar.evaluation.profile_relevance.hashing import canonical_json_bytes

    canon_dict = {
        "pilot_count": 2,
        "total_count": 4,
        "partition_seed": PARTITION_SEED,
        "pilot_quotas": [[q.source_unit, q.stratum, q.pilot_quota] for q in pilot_quotas],
    }
    canon = canonical_json_bytes(canon_dict)
    h = domain_hash_bytes(DOMAIN_PARTITION_POLICY, canon)
    return PartitionPolicy(
        policy_id="pp",
        policy_version="v1",
        schema_version="v1",
        sampling_policy_sha256="f" * 64,
        pilot_quotas=pilot_quotas,
        total_count=4,
        pilot_count=2,
        holdout_count=2,
        partition_seed=PARTITION_SEED,
        partition_rank_domain=DOMAIN_PARTITION_RANK,
        rank_protocol=PROTOCOL_PARTITION,
        execution_scope="synthetic_gate_a",
        canonical_bytes=canon,
        partition_policy_sha256=h,
    )


def _eligible_items() -> tuple[tuple[str, str, str, str, str], ...]:
    items: list[tuple[str, str, str, str, str]] = []
    for sem, st, comp in zip(SEMANTICS, STRONG, COMPANY, strict=False):
        items.append(("board_a", "candidate", comp, sem, st))
    return tuple(items)


# ---------------------------------------------------------------------------
# Historical exclusion
# ---------------------------------------------------------------------------


def test_historical_exclusion_missing_and_stale() -> None:
    _ = _make_exclusion(digests=())
    policy = _make_sampling_policy()
    # missing -> create type error path via None
    with pytest.raises(Exception) as ei:
        run_selection(
            decisions=tuple(),
            observations=tuple(),
            sampling_policy=policy,
            historical_exclusion=None,  # type: ignore[arg-type]
            acquisition_started_at_utc="2026-08-25T00:00:00Z",
            eligible_items=_eligible_items(),
        )
    assert "historical_exclusion_missing" in str(ei.value)
    # stale: created after acquisition start
    excl_stale = _make_exclusion(digests=(), created_at="2026-08-26T00:00:00Z")
    with pytest.raises(Exception) as ei2:
        run_selection(
            decisions=tuple(),
            observations=tuple(),
            sampling_policy=policy,
            historical_exclusion=excl_stale,
            acquisition_started_at_utc="2026-08-25T00:00:00Z",
            eligible_items=_eligible_items(),
        )
    assert "historical_exclusion_stale" in str(ei2.value)
    # identity_policy mismatch via observations path
    from role_radar.evaluation.profile_relevance.contracts import (
        AcquisitionObservation,
        SourceIdentity,
    )

    obs = AcquisitionObservation(
        observation_id="obs1",
        item_semantic_sha256=SEMANTICS[0],
        strong_identity_digest=STRONG[0],
        identity_policy_version="mismatch-version",
        source=SourceIdentity("fam", "sid", "bid", "board_a", _hex("snap")),
        company_sampling_key="alpha",
        title="Engineer",
        description="desc",
        location="loc",
        remote_evidence=None,
        employment_evidence=None,
        authorization_evidence=None,
        region_evidence=None,
        canonical_observation_bytes=b"{}",
    )
    from role_radar.evaluation.profile_relevance.contracts import GateDecision

    dec = GateDecision(
        item_semantic_sha256=SEMANTICS[0],
        stratum="candidate",
        reason_codes=("role_anchor:engineer",),
        input_sha256="a" * 64,
        profile_sha256="b" * 64,
        policy_sha256="c" * 64,
        acquisition_sha256="d" * 64,
        fact_sha256="e" * 64,
        gate_protocol=PROTOCOL_SELECTION,
        decision_sha256="f" * 64,
    )
    # Use observations with mismatched policy version should raise identity_policy_mismatch
    with pytest.raises(Exception) as ei3:
        run_selection(
            decisions=(dec,),
            observations=(obs,),
            sampling_policy=_make_sampling_policy(),
            historical_exclusion=_make_exclusion(digests=()),
            acquisition_started_at_utc="2026-08-25T00:00:00Z",
        )
    assert "identity_policy_mismatch" in str(ei3.value)
    # historical identity selected -> fail
    excl_match = _make_exclusion(digests=(STRONG[0],))
    with pytest.raises(Exception) as ei4:
        run_selection(
            decisions=tuple(),
            observations=tuple(),
            sampling_policy=policy,
            historical_exclusion=excl_match,
            acquisition_started_at_utc="2026-08-25T00:00:00Z",
            eligible_items=_eligible_items(),
        )
    assert "historical_identity_selected" in str(ei4.value)


def test_quota_and_board_cap_validation() -> None:
    excl = _make_exclusion()
    # quota matrix incomplete: missing indeterminate
    bad_quotas = (QuotaCell("board_a", "candidate", 4),)
    from role_radar.evaluation.profile_relevance.hashing import canonical_json_bytes

    canon = canonical_json_bytes({"x": 1})
    h = domain_hash_bytes(DOMAIN_SAMPLING_POLICY, canon)
    bad_policy = SamplingPolicy(
        policy_id="sp",
        policy_version="v1",
        schema_version="v1",
        selection_input_sha256="a" * 64,
        relevance_policy_sha256="b" * 64,
        corpus_cardinality=4,
        quotas=bad_quotas,
        per_board_cap=4,
        global_per_company_cap=2,
        allocation_protocol=PROTOCOL_SELECTION,
        selection_seed=SELECTION_SEED,
        selection_rank_domain=DOMAIN_SELECTION_RANK,
        rank_protocol=PROTOCOL_SELECTION,
        insufficient_inventory_behavior="fail_closed",
        execution_scope="synthetic_gate_a",
        canonical_bytes=canon,
        sampling_policy_sha256=h,
    )
    with pytest.raises(Exception) as ei:
        run_selection(
            decisions=tuple(),
            observations=tuple(),
            sampling_policy=bad_policy,
            historical_exclusion=excl,
            acquisition_started_at_utc="2026-08-25T00:00:00Z",
            eligible_items=_eligible_items(),
        )
    assert "quota_matrix_incomplete" in str(ei.value) or "quota_cardinality_invalid" in str(
        ei.value
    )
    # board cap exceeded
    quotas_ok = (
        QuotaCell("board_a", "candidate", 4),
        QuotaCell("board_a", "near_miss", 0),
        QuotaCell("board_a", "background_control", 0),
        QuotaCell("board_a", "indeterminate", 0),
    )
    canon2 = canonical_json_bytes({"y": 2})
    h2 = domain_hash_bytes(DOMAIN_SAMPLING_POLICY, canon2)
    small_board = SamplingPolicy(
        policy_id="sp",
        policy_version="v1",
        schema_version="v1",
        selection_input_sha256="a" * 64,
        relevance_policy_sha256="b" * 64,
        corpus_cardinality=4,
        quotas=quotas_ok,
        per_board_cap=3,  # less than quota 4
        global_per_company_cap=10,
        allocation_protocol=PROTOCOL_SELECTION,
        selection_seed=SELECTION_SEED,
        selection_rank_domain=DOMAIN_SELECTION_RANK,
        rank_protocol=PROTOCOL_SELECTION,
        insufficient_inventory_behavior="fail_closed",
        execution_scope="synthetic_gate_a",
        canonical_bytes=canon2,
        sampling_policy_sha256=h2,
    )
    with pytest.raises(Exception) as ei2:
        run_selection(
            decisions=tuple(),
            observations=tuple(),
            sampling_policy=small_board,
            historical_exclusion=excl,
            acquisition_started_at_utc="2026-08-25T00:00:00Z",
            eligible_items=_eligible_items(),
        )
    assert "board_cap_exceeded" in str(ei2.value)


# ---------------------------------------------------------------------------
# Hamilton allocation exact golden vector, seed-independent
# ---------------------------------------------------------------------------


def test_hamilton_allocation_exact_vector_and_probabilities() -> None:
    excl = _make_exclusion()
    policy = _make_sampling_policy()
    result = run_selection(
        decisions=tuple(),
        observations=tuple(),
        sampling_policy=policy,
        historical_exclusion=excl,
        acquisition_started_at_utc="2026-08-25T00:00:00Z",
        eligible_items=_eligible_items(),
    )
    # microcell summaries: alpha 4->2, beta 3->2, gamma 1->0
    by_company = {
        mc.company_sampling_key: mc
        for mc in result.microcell_summaries
        if mc.source_unit == "board_a" and mc.stratum == "candidate"
    }
    assert by_company["alpha"].population_count == 4
    assert by_company["alpha"].allocated_count == 2
    assert by_company["beta"].population_count == 3
    assert by_company["beta"].allocated_count == 2
    assert by_company["gamma"].population_count == 1
    assert by_company["gamma"].allocated_count == 0
    # reduced probabilities
    assert (
        by_company["alpha"].probability_numerator,
        by_company["alpha"].probability_denominator,
    ) == (1, 2)
    assert (
        by_company["beta"].probability_numerator,
        by_company["beta"].probability_denominator,
    ) == (2, 3)
    assert (
        by_company["gamma"].probability_numerator,
        by_company["gamma"].probability_denominator,
    ) == (0, 1)
    # selected count
    assert result.selected_count == 4
    assert result.corpus_count == 4
    # Hamilton shares before integer: alpha 2, beta 1.5, gamma 0.5 ; floors 2,1,0 ; tie 0.5 -> beta gets extra => 2,2,0
    # seed independence: changing seed must not affect allocations
    from role_radar.evaluation.profile_relevance.hashing import canonical_json_bytes as cjb

    alt_seed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    canon_alt = cjb({"alt": 1})
    h_alt = domain_hash_bytes(DOMAIN_SAMPLING_POLICY, canon_alt)
    alt_policy = SamplingPolicy(
        policy_id="sp",
        policy_version="v1",
        schema_version="v1",
        selection_input_sha256="a" * 64,
        relevance_policy_sha256="b" * 64,
        corpus_cardinality=4,
        quotas=policy.quotas,
        per_board_cap=4,
        global_per_company_cap=2,
        allocation_protocol=PROTOCOL_SELECTION,
        selection_seed=alt_seed,
        selection_rank_domain=DOMAIN_SELECTION_RANK,
        rank_protocol=PROTOCOL_SELECTION,
        insufficient_inventory_behavior="fail_closed",
        execution_scope="synthetic_gate_a",
        canonical_bytes=canon_alt,
        sampling_policy_sha256=h_alt,
    )
    result_alt = run_selection(
        decisions=tuple(),
        observations=tuple(),
        sampling_policy=alt_policy,
        historical_exclusion=excl,
        acquisition_started_at_utc="2026-08-25T00:00:00Z",
        eligible_items=_eligible_items(),
    )
    by_alt = {mc.company_sampling_key: mc.allocated_count for mc in result_alt.microcell_summaries}
    by_orig = {mc.company_sampling_key: mc.allocated_count for mc in result.microcell_summaries}
    assert by_alt == by_orig


def test_probability_inverse_weights_and_ties() -> None:
    excl = _make_exclusion()
    policy = _make_sampling_policy()
    result = run_selection(
        decisions=tuple(),
        observations=tuple(),
        sampling_policy=policy,
        historical_exclusion=excl,
        acquisition_started_at_utc="2026-08-25T00:00:00Z",
        eligible_items=_eligible_items(),
    )
    # selected items inverse weights
    for sel in result.selected:
        comp = sel.microcell.company_sampling_key
        if comp == "alpha":
            assert (sel.inclusion_probability_numerator, sel.inclusion_probability_denominator) == (
                1,
                2,
            )
            assert (sel.inverse_weight_numerator, sel.inverse_weight_denominator) == (2, 1)
        elif comp == "beta":
            assert (sel.inclusion_probability_numerator, sel.inclusion_probability_denominator) == (
                2,
                3,
            )
            assert (sel.inverse_weight_numerator, sel.inverse_weight_denominator) == (3, 2)
        else:
            pytest.fail("gamma should not be selected")
    # equal remainder tie 1/2 -> canonical company key beta wins over gamma (alpha floor already 2)
    # already verified above; ensure gamma not selected
    assert all(s.microcell.company_sampling_key != "gamma" for s in result.selected)


# ---------------------------------------------------------------------------
# Selection ranks golden vector (8 rows) and selection set
# ---------------------------------------------------------------------------


def test_selection_ranks_golden_vector_via_pure_hash() -> None:
    # directly verify partition_rank/selection_rank pure hashes match hard-coded literals (no production helper to derive oracle)
    # use hashlib directly as oracle
    def _rank_via_hashlib(seed: str, source: str, stratum: str, company: str, semantic: str) -> str:
        h = hashlib.sha256()
        h.update(SELECTION_RANK_DOMAIN.encode("ascii"))
        h.update(b"\x00")
        h.update(seed.encode("ascii"))
        h.update(b"\x00")
        h.update(source.encode("utf-8"))
        h.update(b"\x00")
        h.update(stratum.encode("utf-8"))
        h.update(b"\x00")
        h.update(company.encode("utf-8"))
        h.update(b"\x00")
        h.update(semantic.encode("ascii"))
        return h.hexdigest()

    for idx, sem in enumerate(SEMANTICS):
        comp = COMPANY[idx]
        raw = _rank_via_hashlib(SELECTION_SEED, "board_a", "candidate", comp, sem)
        assert raw == EXPECTED_SELECTION_RANKS[sem], f"mismatch rank for {sem}"
        # also verify production helper agrees (but oracle is hashlib, not helper)
        via_helper = selection_rank_hash(
            SELECTION_RANK_DOMAIN, SELECTION_SEED, "board_a", "candidate", comp, sem
        )
        assert via_helper == raw


def test_selected_set_and_within_company_order() -> None:
    excl = _make_exclusion()
    policy = _make_sampling_policy()
    result = run_selection(
        decisions=tuple(),
        observations=tuple(),
        sampling_policy=policy,
        historical_exclusion=excl,
        acquisition_started_at_utc="2026-08-25T00:00:00Z",
        eligible_items=_eligible_items(),
    )
    selected_sems = sorted(s.decision.item_semantic_sha256 for s in result.selected)
    expected_selected = sorted([SEMANTICS[0], SEMANTICS[3], SEMANTICS[4], SEMANTICS[5]])
    assert selected_sems == expected_selected
    # within-company ranks order
    # alpha: 111 < 444 < 333 < 222
    alpha_order = sorted(
        [SEMANTICS[0], SEMANTICS[1], SEMANTICS[2], SEMANTICS[3]],
        key=lambda s: EXPECTED_SELECTION_RANKS[s],
    )
    assert alpha_order == [SEMANTICS[0], SEMANTICS[3], SEMANTICS[2], SEMANTICS[1]]
    beta_order = sorted(
        [SEMANTICS[4], SEMANTICS[5], SEMANTICS[6]], key=lambda s: EXPECTED_SELECTION_RANKS[s]
    )
    assert beta_order == [SEMANTICS[5], SEMANTICS[4], SEMANTICS[6]]


# ---------------------------------------------------------------------------
# Partition pilot/holdout membership hashes and ranks
# ---------------------------------------------------------------------------


def test_partition_ranks_and_membership_hashes() -> None:
    def _part_rank_via_hashlib(seed: str, source: str, stratum: str, semantic: str) -> str:
        h = hashlib.sha256()
        h.update(PARTITION_RANK_DOMAIN.encode("ascii"))
        h.update(b"\x00")
        h.update(seed.encode("ascii"))
        h.update(b"\x00")
        h.update(source.encode("utf-8"))
        h.update(b"\x00")
        h.update(stratum.encode("utf-8"))
        h.update(b"\x00")
        h.update(semantic.encode("ascii"))
        return h.hexdigest()

    selected_for_partition = [SEMANTICS[0], SEMANTICS[3], SEMANTICS[4], SEMANTICS[5]]
    for sem in selected_for_partition:
        raw = _part_rank_via_hashlib(PARTITION_SEED, "board_a", "candidate", sem)
        assert raw == EXPECTED_PARTITION_RANKS[sem]
        via_helper = partition_rank_hash(
            PARTITION_RANK_DOMAIN, PARTITION_SEED, "board_a", "candidate", sem
        )
        assert via_helper == raw
    # order 444 < 666 < 555 < 111
    ordered = sorted(selected_for_partition, key=lambda s: EXPECTED_PARTITION_RANKS[s])
    assert ordered == [SEMANTICS[3], SEMANTICS[5], SEMANTICS[4], SEMANTICS[0]]
    # membership hashes via canonical sorted pairs (pure membership_root)
    pilot_pairs = tuple(sorted([(SEMANTICS[3], STRONG[3]), (SEMANTICS[5], STRONG[5])]))
    holdout_pairs = tuple(sorted([(SEMANTICS[0], STRONG[0]), (SEMANTICS[4], STRONG[4])]))
    _, pilot_h = membership_root(DOMAIN_PILOT_MEMBERSHIP, pilot_pairs)
    _, holdout_h = membership_root(DOMAIN_HOLDOUT_MEMBERSHIP, holdout_pairs)
    assert pilot_h == PILOT_MEMBERSHIP_EXPECTED
    assert holdout_h == HOLDOUT_MEMBERSHIP_EXPECTED


def test_partition_disjoint_exhaustive_and_deterministic() -> None:
    excl = _make_exclusion()
    samp_policy = _make_sampling_policy()
    sel = run_selection(
        decisions=tuple(),
        observations=tuple(),
        sampling_policy=samp_policy,
        historical_exclusion=excl,
        acquisition_started_at_utc="2026-08-25T00:00:00Z",
        eligible_items=_eligible_items(),
    )
    semantic_to_strong = {sem: st for sem, st in zip(SEMANTICS, STRONG, strict=False)}
    part_policy = _make_partition_policy(sel)
    # monkey fix sampling_policy_sha: align with actual
    # need to recreate with correct sampling hash
    from role_radar.evaluation.profile_relevance.hashing import canonical_json_bytes as cjb

    # Rebuild partition policy with correct sampling hash
    canon_dict = {
        "pilot_count": 2,
        "total_count": 4,
        "partition_seed": PARTITION_SEED,
        "pilot_quotas": [
            ["board_a", "candidate", 2],
            ["board_a", "near_miss", 0],
            ["board_a", "background_control", 0],
            ["board_a", "indeterminate", 0],
        ],
    }
    canon = cjb(canon_dict)
    h = domain_hash_bytes(DOMAIN_PARTITION_POLICY, canon)
    part_policy2 = PartitionPolicy(
        policy_id="pp",
        policy_version="v1",
        schema_version="v1",
        sampling_policy_sha256=sel.policy_sha256,
        pilot_quotas=part_policy.pilot_quotas,
        total_count=4,
        pilot_count=2,
        holdout_count=2,
        partition_seed=PARTITION_SEED,
        partition_rank_domain=DOMAIN_PARTITION_RANK,
        rank_protocol=PROTOCOL_PARTITION,
        execution_scope="synthetic_gate_a",
        canonical_bytes=canon,
        partition_policy_sha256=h,
    )
    part = run_partition(
        selection=sel, partition_policy=part_policy2, semantic_to_strong=semantic_to_strong
    )
    assert part.pilot_membership_sha256 == PILOT_MEMBERSHIP_EXPECTED
    assert part.holdout_membership_sha256 == HOLDOUT_MEMBERSHIP_EXPECTED
    # disjoint exhaustive
    pilot_set = set(part.pilot_item_hashes)
    holdout_set = set(part.holdout_item_hashes)
    assert pilot_set.isdisjoint(holdout_set)
    assert pilot_set | holdout_set == set(s.decision.item_semantic_sha256 for s in sel.selected)
    assert len(part.pilot_item_hashes) == 2
    assert len(part.holdout_item_hashes) == 2
    assert set(part.pilot_item_hashes) == {SEMANTICS[3], SEMANTICS[5]}
    assert set(part.holdout_item_hashes) == {SEMANTICS[0], SEMANTICS[4]}
    # deterministic rerun
    part2 = run_partition(
        selection=sel, partition_policy=part_policy2, semantic_to_strong=semantic_to_strong
    )
    assert part2.pilot_membership_sha256 == part.pilot_membership_sha256
    assert part2.holdout_membership_sha256 == part.holdout_membership_sha256
    assert part2.partition_sha256 == part.partition_sha256
