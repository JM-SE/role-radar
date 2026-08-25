"""Pure high-recall truth table — no score, no threshold, no I/O."""

from __future__ import annotations

import re
import unicodedata

from role_radar.evaluation.profile_relevance.contracts import GateDecision, ProjectedFacts
from role_radar.evaluation.profile_relevance.hashing import domain_hash
from role_radar.evaluation.profile_relevance.policy import (
    DOMAIN_GATE_DECISION,
    PROTOCOL_GATE,
    REASON_FAMILIES,
    validate_reason_sequence,
)

_FAMILY_ORDER: dict[str, int] = {fam: idx for idx, fam in enumerate(REASON_FAMILIES)}
_SUFFIX_RE = re.compile(r"^[a-z0-9_\-\.]+$")


def _slug(value: str) -> str:
    # Convert normalized value to valid suffix: NFKC, casefold already done in facts,
    # but ensure slug passes validate_reason_code.
    # Normalize again, replace spaces with underscore, collapse invalid chars.
    if not isinstance(value, str):
        return "invalid"
    nfkc = unicodedata.normalize("NFKC", value)
    folded = nfkc.casefold()
    # keep alphanum, underscore, hyphen, dot; others -> underscore
    # First normalize punctuation to space then to underscore
    chars: list[str] = []
    for ch in folded:
        if ch.isspace():
            chars.append("_")
            continue
        cat = unicodedata.category(ch)
        if cat.startswith(("L", "N")) or ch in ("_", "-", "."):
            chars.append(ch)
        else:
            chars.append("_")
    slug = "".join(chars)
    # collapse multiple underscores
    slug = re.sub(r"_+", "_", slug).strip("_.")
    if not slug:
        slug = "unknown"
    # ensure regex
    if not _SUFFIX_RE.fullmatch(slug):
        # fallback: hash? but keep simple
        slug = re.sub(r"[^a-z0-9_\-\.]", "_", slug)
        slug = re.sub(r"_+", "_", slug).strip("_.") or "unknown"
    # truncate to reasonable length
    if len(slug) > 64:
        slug = slug[:64].strip("_.") or "unknown"
    return slug


def _ordered_unique(codes: list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    uniq: list[str] = []
    for c in codes:
        if c not in seen:
            seen.add(c)
            uniq.append(c)

    # sort by family order, then lexicographically within family for determinism
    def sort_key(code: str) -> tuple[int, str]:
        fam = code.split(":", 1)[0] if ":" in code else ""
        return (_FAMILY_ORDER.get(fam, 999), code)

    uniq_sorted = sorted(uniq, key=sort_key)
    # validate ordering non-decreasing family order already via sorted
    # Also need to enforce that validate_reason_sequence will pass
    # Ensure uniqueness and valid prefix already
    validate_reason_sequence(tuple(uniq_sorted))
    return tuple(uniq_sorted)


def _decision_hash(
    *,
    item_semantic_sha256: str,
    stratum: str,
    reason_codes: tuple[str, ...],
    input_sha256: str,
    profile_sha256: str,
    policy_sha256: str,
    acquisition_sha256: str,
    fact_sha256: str,
) -> str:
    payload = {
        "acquisition_sha256": acquisition_sha256,
        "fact_sha256": fact_sha256,
        "gate_protocol": PROTOCOL_GATE,
        "input_sha256": input_sha256,
        "item_semantic_sha256": item_semantic_sha256,
        "policy_sha256": policy_sha256,
        "profile_sha256": profile_sha256,
        "reason_codes": list(reason_codes),
        "stratum": stratum,
    }
    return domain_hash(DOMAIN_GATE_DECISION, payload)


def decide_gate(
    facts: ProjectedFacts, policy: object | None = None, *_args: object, **_kwargs: object
) -> GateDecision:
    """Pure truth table per spec. No score/threshold.

    Candidate: approved anchor, no excluded ambiguity, no tech/constraint
        conflict, all configured constraints match.
    Near_miss: anchor, >=1 tech/constraint conflict, no indeterminate.
    Background_control: no anchor, >=1 excluded anchor.
    Indeterminate: missing/unsupported/ambiguous/both anchors/
        indeterminate constraint.
    """
    if not isinstance(facts, ProjectedFacts):
        raise TypeError("facts invalid")

    has_approved = len(facts.matched_approved_aliases) > 0
    has_excluded = len(facts.matched_excluded_aliases) > 0
    has_both = has_approved and has_excluded
    has_tech_conflict = len(facts.excluded_technology_matches) > 0

    # constraint analysis
    has_constraint_conflict = False
    has_constraint_indeterminate = False
    has_configured = False
    all_match = True
    indeterminate_constraints: list[str] = []
    conflict_constraints: list[str] = []
    match_constraints: list[str] = []

    for name, state in facts.constraint_states:
        if state == "not_applicable":
            continue
        has_configured = True
        if state == "indeterminate":
            has_constraint_indeterminate = True
            indeterminate_constraints.append(name)
            all_match = False
        elif state == "conflict":
            has_constraint_conflict = True
            conflict_constraints.append(name)
            all_match = False
        elif state == "match":
            match_constraints.append(name)
        else:
            # unknown state -> treat as indeterminate
            has_constraint_indeterminate = True
            indeterminate_constraints.append(name)
            all_match = False

    # if no configured constraints, all_match should be True (vacuous)
    if not has_configured:
        all_match = True

    has_tech_or_constraint_conflict = has_tech_conflict or has_constraint_conflict
    # title empty already yields no anchor -> indeterminate

    # Determine stratum via ordered checks
    stratum: str
    reason_codes: tuple[str, ...]

    if has_constraint_indeterminate:
        stratum = "indeterminate"
        codes: list[str] = []
        # precise reasons for indeterminate constraints
        for c in sorted(set(indeterminate_constraints)):
            codes.append(f"indeterminate:constraint_indeterminate_{_slug(c)}")
        if not codes:
            codes.append("indeterminate:constraint_indeterminate")
        # also include ambiguous if both anchors present
        if has_both:
            codes.append("indeterminate:ambiguous_role")
        if not has_approved and not has_excluded:
            codes.append("indeterminate:no_anchor")
        reason_codes = _ordered_unique(codes)
    elif has_both:
        stratum = "indeterminate"
        reason_codes = _ordered_unique(["indeterminate:ambiguous_role"])
    elif not has_approved and not has_excluded:
        stratum = "indeterminate"
        reason_codes = _ordered_unique(["indeterminate:no_anchor"])
    elif has_approved and not has_excluded:
        if has_tech_or_constraint_conflict:
            # near_miss requires no indeterminate (already ensured)
            stratum = "near_miss"
            codes = []
            for alias in facts.matched_approved_aliases:
                codes.append(f"role_anchor:{_slug(alias)}")
            # only anchor + conflicts for near_miss
            for tech in facts.excluded_technology_matches:
                codes.append(f"conflict_technology:{_slug(tech)}")
            for c in sorted(set(conflict_constraints)):
                codes.append(f"constraint_conflict:{_slug(c)}")
            # ensure at least one conflict (guaranteed by condition)
            reason_codes = _ordered_unique(codes)
        else:
            # candidate path: requires all configured constraints match (if any)
            if all_match:
                stratum = "candidate"
                codes = []
                for alias in facts.matched_approved_aliases:
                    codes.append(f"role_anchor:{_slug(alias)}")
                for skill in facts.supporting_core_matches:
                    codes.append(f"support_core:{_slug(skill)}")
                for skill in facts.supporting_secondary_matches:
                    codes.append(f"support_secondary:{_slug(skill)}")
                for c in sorted(set(match_constraints)):
                    codes.append(f"constraint_match:{_slug(c)}")
                # if no support/match, still at least anchor
                reason_codes = _ordered_unique(codes)
            else:
                # Should not happen without conflict/indeterminate, but fallback to indeterminate
                stratum = "indeterminate"
                reason_codes = _ordered_unique(["indeterminate:constraint_mismatch"])
    elif not has_approved and has_excluded:
        stratum = "background_control"
        codes = []
        for alias in facts.matched_excluded_aliases:
            codes.append(f"conflict_role:{_slug(alias)}")
        reason_codes = _ordered_unique(codes)
    else:
        stratum = "indeterminate"
        reason_codes = _ordered_unique(["indeterminate:unknown"])

    # Build decision with hash binding
    decision_sha = _decision_hash(
        item_semantic_sha256=facts.item_semantic_sha256,
        stratum=stratum,
        reason_codes=reason_codes,
        input_sha256=facts.input_sha256,
        profile_sha256=facts.profile_sha256,
        policy_sha256=facts.policy_sha256,
        acquisition_sha256=facts.acquisition_sha256,
        fact_sha256=facts.fact_sha256,
    )
    # Validate reason sequence (will raise if invalid)
    validate_reason_sequence(reason_codes)

    return GateDecision(
        item_semantic_sha256=facts.item_semantic_sha256,
        stratum=stratum,  # type: ignore[arg-type]
        reason_codes=reason_codes,
        input_sha256=facts.input_sha256,
        profile_sha256=facts.profile_sha256,
        policy_sha256=facts.policy_sha256,
        acquisition_sha256=facts.acquisition_sha256,
        fact_sha256=facts.fact_sha256,
        gate_protocol=PROTOCOL_GATE,
        decision_sha256=decision_sha,
    )


# Aliases for test compatibility
gate_decision = decide_gate
classify = decide_gate
evaluate_gate = decide_gate
decide = decide_gate

__all__ = [
    "classify",
    "decide",
    "decide_gate",
    "evaluate_gate",
    "gate_decision",
]
