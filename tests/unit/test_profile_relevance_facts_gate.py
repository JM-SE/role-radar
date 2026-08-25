"""Facts normalization, alias matching, truth table, reason ordering, hash binding."""

from __future__ import annotations

import hashlib

from role_radar.evaluation.profile_relevance.contracts import (
    AcquisitionObservation,
    ConstraintPolicy,
    RelevancePolicy,
    SourceIdentity,
)
from role_radar.evaluation.profile_relevance.facts import (
    normalize_text,
    normalized_tokens,
    project_facts,
)
from role_radar.evaluation.profile_relevance.gate import decide_gate
from role_radar.evaluation.profile_relevance.hashing import domain_hash
from role_radar.evaluation.profile_relevance.policy import (
    PROTOCOL_FACTS,
    PROTOCOL_GATE,
)

HEX64_A = "a" * 64
HEX64_B = "b" * 64
HEX64_C = "c" * 64


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _source(board_key: str = "board_a") -> SourceIdentity:
    return SourceIdentity("fam", "sid", "bid", board_key, _h("snapshot"))


def _obs(
    *,
    title: str,
    description: str = "desc",
    company: str = "alpha",
    authorizations: str | None = None,
    remote: str | None = None,
    employment: str | None = None,
    region: str | None = None,
    semantic: str | None = None,
    strong: str | None = None,
) -> AcquisitionObservation:
    sem = semantic or _h(title + company)
    strong_d = strong or _h(sem)  # ensure 64 hex distinct
    # make strong digest distinct from semantic: use hex of sem string
    strong_d = hashlib.sha256((sem + "strong").encode()).hexdigest()
    return AcquisitionObservation(
        observation_id=f"obs-{sem[:8]}",
        item_semantic_sha256=sem if len(sem) == 64 else _h(sem),
        strong_identity_digest=strong_d,
        identity_policy_version="strong-identity-v1",
        source=_source(),
        company_sampling_key=company,
        title=title,
        description=description,
        location="loc",
        remote_evidence=remote,
        employment_evidence=employment,
        authorization_evidence=authorizations,
        region_evidence=region,
        canonical_observation_bytes=b"{}",
    )


def _policy(
    *,
    approved: tuple[str, ...] = ("senior engineer",),
    excluded_roles: tuple[str, ...] = ("manager",),
    core: tuple[str, ...] = ("python",),
    secondary: tuple[str, ...] = ("aws",),
    excluded_tech: tuple[str, ...] = ("cobol",),
    constraints: ConstraintPolicy | None = None,
) -> RelevancePolicy:
    if constraints is None:
        constraints = ConstraintPolicy()
    # canonical bytes arbitrary, hash derived via domain
    from role_radar.evaluation.profile_relevance.policy import DOMAIN_POLICY

    canon = b'{"policy":"synthetic"}'
    ph = domain_hash(DOMAIN_POLICY, {"policy": "synthetic"})
    # use stable hash helper: domain_hash(DOMAIN_POLICY, {"policy":...})
    # but need domain_hash_bytes variant: compute same as preview workflow expects
    from role_radar.evaluation.profile_relevance.hashing import domain_hash_bytes

    ph2 = domain_hash_bytes(DOMAIN_POLICY, canon)
    # use ph2 as policy hash
    policy_hash = ph2
    return RelevancePolicy(
        policy_id="synth",
        policy_version="v1",
        schema_version="f10.1e-profile-relevance-input-v1",
        profile_binding_sha256=_h("binding"),
        normalization_version="nfkc-casefold-v1",
        facts_version=PROTOCOL_FACTS,
        gate_version=PROTOCOL_GATE,
        reason_version="v1",
        stratum_version="v1",
        approved_role_aliases=approved,
        core_skills=core,
        secondary_skills=secondary,
        excluded_role_aliases=excluded_roles,
        excluded_technologies=excluded_tech,
        constraints=constraints,
        execution_scope="synthetic_gate_a",
        canonical_bytes=canon,
        policy_sha256=policy_hash,
    )


SHARED_INPUT_SHA = _h("input")
SHARED_PROFILE_SHA = _h("binding")
SHARED_ACQ_SHA = _h("acq")

# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def test_normalize_nfkc_casefold_punctuation_whitespace() -> None:
    # punctuation to boundary, whitespace collapse
    assert normalize_text("Senior-Engineer!!") == "senior engineer"
    assert normalize_text("  Hello   World  ") == "hello world"
    # casefold
    assert normalize_text("PYTHON") == "python"
    # NFKC: ligature ﬁ -> fi
    assert normalize_text("\ufb01") == "fi"
    # symbols become space
    assert normalize_text("a/b") == "a b"
    assert normalize_text("a\u2014b") == "a b"  # em dash


def test_normalized_tokens_split() -> None:
    assert normalized_tokens("Senior Engineer") == ("senior", "engineer")
    assert normalized_tokens("") == ()
    assert normalized_tokens("   ") == ()


# ---------------------------------------------------------------------------
# Alias matching - complete token sequence only, no substring/fuzzy
# ---------------------------------------------------------------------------


def test_alias_matching_complete_sequence_no_substring() -> None:
    policy = _policy(
        approved=("senior engineer",), excluded_roles=(), core=(), secondary=(), excluded_tech=()
    )
    obs = _obs(title="Senior Engineer")
    facts = project_facts(
        obs,
        policy,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    assert "senior engineer" in facts.matched_approved_aliases
    # substring must not match: "senior" alone should not match "senior engineer"
    policy2 = _policy(
        approved=("senior engineer",), excluded_roles=(), core=(), secondary=(), excluded_tech=()
    )
    obs2 = _obs(title="Senior")  # only one token
    facts2 = project_facts(
        obs2,
        policy2,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    assert facts2.matched_approved_aliases == ()
    # fuzzy not allowed
    obs3 = _obs(title="Sr Engineer")
    facts3 = project_facts(
        obs3,
        policy2,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    assert facts3.matched_approved_aliases == ()
    # punctuation boundary counts as token separator, not substring
    obs4 = _obs(title="Senior, Engineer!")
    facts4 = project_facts(
        obs4,
        policy2,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    assert "senior engineer" in facts4.matched_approved_aliases


def test_skills_match_title_or_description_but_never_anchor() -> None:
    policy = _policy(
        approved=("engineer",),
        core=("python",),
        secondary=("aws",),
        excluded_roles=(),
        excluded_tech=(),
    )
    obs = _obs(title="Engineer", description="we use python and aws")
    facts = project_facts(
        obs,
        policy,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    assert "python" in facts.supporting_core_matches
    assert "aws" in facts.supporting_secondary_matches
    # skills do not affect anchor count
    assert "engineer" in facts.matched_approved_aliases
    # skill in description only
    obs2 = _obs(title="Random", description="python")
    facts2 = project_facts(
        obs2,
        policy,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    assert "python" in facts2.supporting_core_matches
    assert facts2.matched_approved_aliases == ()


def test_excluded_technologies_exact_token_sequence() -> None:
    policy = _policy(approved=("engineer",), excluded_tech=("cobol",))
    obs = _obs(title="Engineer", description="Cobol system")
    facts = project_facts(
        obs,
        policy,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    assert "cobol" in facts.excluded_technology_matches
    # substring not match
    obs2 = _obs(title="Engineer", description="cobol123")
    facts2 = project_facts(
        obs2,
        policy,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    assert facts2.excluded_technology_matches == ()


# ---------------------------------------------------------------------------
# Evidence handling
# ---------------------------------------------------------------------------


def test_missing_evidence_is_indeterminate() -> None:
    # configured constraint without evidence -> indeterminate
    constraints = ConstraintPolicy(approved_regions=("us",), approved_remote=("remote",))
    policy = _policy(approved=("engineer",), constraints=constraints)
    obs = _obs(title="Engineer", region=None, remote=None)  # missing evidence
    facts = project_facts(
        obs,
        policy,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    # constraint_states ordered: region, remote, employment, authorization
    states = dict(facts.constraint_states)
    assert states["region"] == "indeterminate"
    assert states["remote"] == "indeterminate"
    assert states["employment"] == "not_applicable"
    # not_applicable when not configured
    constraints2 = ConstraintPolicy()
    policy2 = _policy(approved=("engineer",), constraints=constraints2)
    facts2 = project_facts(
        obs,
        policy2,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    assert dict(facts2.constraint_states)["region"] == "not_applicable"


# ---------------------------------------------------------------------------
# Gate truth table all strata
# ---------------------------------------------------------------------------


def test_gate_candidate_requires_anchor_no_conflict_all_match() -> None:
    constraints = ConstraintPolicy(approved_regions=("us",))
    policy = _policy(approved=("engineer",), constraints=constraints)
    # evidence matches approved region
    obs = _obs(title="Engineer", region="us")
    facts = project_facts(
        obs,
        policy,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    dec = decide_gate(facts)
    assert dec.stratum == "candidate"
    assert any(c.startswith("role_anchor:") for c in dec.reason_codes)
    assert any(c.startswith("constraint_match:") for c in dec.reason_codes)
    # ensure no conflict reasons
    assert not any(c.startswith("conflict_") for c in dec.reason_codes)
    assert not any(c.startswith("indeterminate") for c in dec.reason_codes)


def test_gate_near_miss_with_tech_conflict() -> None:
    policy = _policy(approved=("engineer",), excluded_tech=("cobol",))
    obs = _obs(title="Engineer", description="cobol")
    facts = project_facts(
        obs,
        policy,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    dec = decide_gate(facts)
    assert dec.stratum == "near_miss"
    assert any(c.startswith("role_anchor:") for c in dec.reason_codes)
    assert any(c.startswith("conflict_technology:") for c in dec.reason_codes)


def test_gate_near_miss_with_constraint_conflict_no_indeterminate() -> None:
    constraints = ConstraintPolicy(approved_regions=("us",))
    policy = _policy(approved=("engineer",), constraints=constraints)
    obs = _obs(title="Engineer", region="eu")  # conflict, not indeterminate
    facts = project_facts(
        obs,
        policy,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    dec = decide_gate(facts)
    assert dec.stratum == "near_miss"
    assert any(c.startswith("constraint_conflict:") for c in dec.reason_codes)


def test_gate_background_control_only_excluded_anchor() -> None:
    policy = _policy(approved=("engineer",), excluded_roles=("manager",))
    obs = _obs(title="Manager")
    facts = project_facts(
        obs,
        policy,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    dec = decide_gate(facts)
    assert dec.stratum == "background_control"
    assert any(c.startswith("conflict_role:") for c in dec.reason_codes)
    # skills cannot alter background_control
    policy2 = _policy(approved=("engineer",), excluded_roles=("manager",), core=("python",))
    obs2 = _obs(title="Manager", description="python")
    facts2 = project_facts(
        obs2,
        policy2,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    dec2 = decide_gate(facts2)
    assert dec2.stratum == "background_control"


def test_gate_indeterminate_no_anchor() -> None:
    policy = _policy(approved=("engineer",), excluded_roles=("manager",))
    obs = _obs(title="Random Title")
    facts = project_facts(
        obs,
        policy,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    dec = decide_gate(facts)
    assert dec.stratum == "indeterminate"
    assert any(c.startswith("indeterminate:") for c in dec.reason_codes)


def test_gate_indeterminate_both_anchors() -> None:
    policy = _policy(approved=("engineer",), excluded_roles=("manager",))
    # tricky: need title that contains both aliases as token sequences
    # alias "engineer" and "manager" are single tokens, so title "Engineer Manager" contains both
    obs = _obs(title="Engineer Manager")
    facts = project_facts(
        obs,
        policy,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    # verify facts have both
    assert len(facts.matched_approved_aliases) > 0
    assert len(facts.matched_excluded_aliases) > 0
    dec = decide_gate(facts)
    assert dec.stratum == "indeterminate"
    assert "indeterminate:ambiguous_role" in dec.reason_codes


def test_gate_indeterminate_missing_constraint() -> None:
    constraints = ConstraintPolicy(approved_regions=("us",))
    policy = _policy(approved=("engineer",), constraints=constraints)
    obs = _obs(title="Engineer", region=None)  # missing
    facts = project_facts(
        obs,
        policy,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    dec = decide_gate(facts)
    assert dec.stratum == "indeterminate"
    assert any("constraint_indeterminate" in c for c in dec.reason_codes)


# ---------------------------------------------------------------------------
# Reason ordering
# ---------------------------------------------------------------------------


def test_reasons_are_ordered_by_family_and_unique() -> None:
    # Use a candidate with core + secondary + constraint match to get multiple families
    constraints = ConstraintPolicy(approved_regions=("us",), approved_remote=("remote",))
    policy = _policy(
        approved=("engineer",),
        core=("python", "java"),
        secondary=("aws",),
        constraints=constraints,
    )
    obs = _obs(title="Engineer", description="python java aws", region="us", remote="remote")
    facts = project_facts(
        obs,
        policy,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    dec = decide_gate(facts)
    assert dec.stratum == "candidate"
    # check family order non-decreasing
    from role_radar.evaluation.profile_relevance.policy import REASON_FAMILIES

    order = {fam: i for i, fam in enumerate(REASON_FAMILIES)}
    last = -1
    seen: set[str] = set()
    for rc in dec.reason_codes:
        fam = rc.split(":", 1)[0]
        idx = order[fam]
        assert idx >= last, f"out of order {rc}"
        last = idx
        assert rc not in seen, "duplicate reason"
        seen.add(rc)
    # duplicate reason codes must fail validation if manually passed (tested elsewhere)


# ---------------------------------------------------------------------------
# Hash binding and permutation invariance
# ---------------------------------------------------------------------------


def test_facts_and_gate_hash_bindings() -> None:
    policy = _policy()
    obs = _obs(title="Engineer", company="alpha")
    facts = project_facts(
        obs,
        policy,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    # fact hash must be domain hash over expected payload — check non-empty hex
    assert len(facts.fact_sha256) == 64
    assert facts.input_sha256 == SHARED_INPUT_SHA
    assert facts.policy_sha256 == policy.policy_sha256
    dec = decide_gate(facts)
    assert len(dec.decision_sha256) == 64
    assert dec.input_sha256 == facts.input_sha256
    assert dec.fact_sha256 == facts.fact_sha256
    assert dec.policy_sha256 == facts.policy_sha256
    # no label/score/rank/split in GateDecision
    assert not hasattr(dec, "label") and not hasattr(dec, "score")


def test_permutation_stable_fact_matching() -> None:
    # alias order permutation should not affect sorted matched aliases
    policy_a = _policy(
        approved=("b", "a", "c"), core=(), secondary=(), excluded_roles=(), excluded_tech=()
    )
    policy_b = _policy(
        approved=("c", "a", "b"), core=(), secondary=(), excluded_roles=(), excluded_tech=()
    )
    obs = _obs(title="a b c")
    f_a = project_facts(
        obs,
        policy_a,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    f_b = project_facts(
        obs,
        policy_b,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    # despite policy alias order differing, matched list is sorted lexicographically deterministic
    assert f_a.matched_approved_aliases == f_b.matched_approved_aliases


# ---------------------------------------------------------------------------
# Evidence handling edge: empty title -> indeterminate
# ---------------------------------------------------------------------------


def test_empty_title_is_indeterminate() -> None:
    policy = _policy()
    obs = _obs(title="   ")
    facts = project_facts(
        obs,
        policy,
        input_sha256=SHARED_INPUT_SHA,
        profile_sha256=SHARED_PROFILE_SHA,
        acquisition_sha256=SHARED_ACQ_SHA,
    )
    dec = decide_gate(facts)
    assert dec.stratum == "indeterminate"
