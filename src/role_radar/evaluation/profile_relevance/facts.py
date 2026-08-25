"""Pure normalization and projection — no I/O, no store, no seed use."""

from __future__ import annotations

import unicodedata
from typing import Final

from role_radar.evaluation.profile_relevance.contracts import (
    AcquisitionObservation,
    ProjectedFacts,
    RelevancePolicy,
)
from role_radar.evaluation.profile_relevance.hashing import domain_hash
from role_radar.evaluation.profile_relevance.policy import DOMAIN_FACT, PROTOCOL_FACTS

_CONSTRAINT_ORDER: Final = ("region", "remote", "employment", "authorization")
_DEFAULT_EVIDENCE_MAP: Final = {
    "region": "region_evidence",
    "remote": "remote_evidence",
    "employment": "employment_evidence",
    "authorization": "authorization_evidence",
}


def normalize_text(value: str) -> str:
    """UTF-8, NFKC, casefold, punctuation-to-boundary, whitespace collapse."""
    if not isinstance(value, str):
        raise TypeError("normalize_text expects str")
    # NFKC
    nfkc = unicodedata.normalize("NFKC", value)
    # casefold
    folded = nfkc.casefold()
    # punctuation/symbol to boundary: any char whose category is not L/M/N and not space
    # Keep letters, marks, numbers, and Zs space; everything else becomes space.
    # Use isspace to treat all whitespace as boundary.
    chars: list[str] = []
    for ch in folded:
        if ch.isspace():
            chars.append(" ")
            continue
        cat = unicodedata.category(ch)
        # L* letter, M* mark, N* number keep; Zs space already handled
        if cat.startswith(("L", "M", "N")):
            chars.append(ch)
        elif cat == "Zs":
            chars.append(" ")
        else:
            # P* punctuation, S* symbol, C* control/other -> boundary
            chars.append(" ")
    joined = "".join(chars)
    # whitespace collapse
    collapsed = " ".join(joined.split())
    return collapsed


def tokenize_normalized(normalized: str) -> tuple[str, ...]:
    if not normalized:
        return ()
    return tuple(normalized.split(" "))


def normalized_tokens(value: str) -> tuple[str, ...]:
    return tokenize_normalized(normalize_text(value))


def _contains_sequence(haystack: tuple[str, ...], needle: tuple[str, ...]) -> bool:
    if not needle:
        return False
    if len(needle) > len(haystack):
        return False
    # contiguous exact match
    for i in range(len(haystack) - len(needle) + 1):
        if haystack[i : i + len(needle)] == needle:
            return True
    return False


def _collect_title_matches(
    title_tokens: tuple[str, ...], aliases: tuple[str, ...]
) -> tuple[str, ...]:
    matched: list[str] = []
    seen: set[str] = set()
    for alias in aliases:
        if not isinstance(alias, str) or not alias.strip():
            continue
        needle = normalized_tokens(alias)
        if not needle:
            continue
        if _contains_sequence(title_tokens, needle) and alias not in seen:
            seen.add(alias)
            matched.append(alias)
    # Deterministic ordering: preserve policy order but caller may sort; keep policy order for now
    # To guarantee permutation stability, sort lexicographically.
    # Use sorted to be deterministic against policy reorder.
    matched_sorted = tuple(sorted(matched))
    return matched_sorted


def _collect_support_matches(
    title_tokens: tuple[str, ...],
    desc_tokens: tuple[str, ...],
    skills: tuple[str, ...],
) -> tuple[str, ...]:
    matched: list[str] = []
    seen: set[str] = set()
    for skill in skills:
        if not isinstance(skill, str) or not skill.strip():
            continue
        needle = normalized_tokens(skill)
        if not needle:
            continue
        if (
            _contains_sequence(title_tokens, needle) or _contains_sequence(desc_tokens, needle)
        ) and skill not in seen:
            seen.add(skill)
            matched.append(skill)
    return tuple(sorted(matched))


def _collect_technology_matches(
    title_tokens: tuple[str, ...],
    desc_tokens: tuple[str, ...],
    techs: tuple[str, ...],
) -> tuple[str, ...]:
    matched: list[str] = []
    seen: set[str] = set()
    for tech in techs:
        if not isinstance(tech, str) or not tech.strip():
            continue
        needle = normalized_tokens(tech)
        if not needle:
            continue
        if (
            _contains_sequence(title_tokens, needle) or _contains_sequence(desc_tokens, needle)
        ) and tech not in seen:
            seen.add(tech)
            matched.append(tech)
    return tuple(sorted(matched))


def _constraint_states(
    observation: AcquisitionObservation, policy: RelevancePolicy
) -> tuple[tuple[str, str], ...]:
    # Build evidence field map
    evidence_map: dict[str, str] = dict(_DEFAULT_EVIDENCE_MAP)
    if policy.constraints.evidence_map:
        for pair in policy.constraints.evidence_map:
            if not isinstance(pair, tuple) or len(pair) != 2:
                continue
            k, v = pair
            if not isinstance(k, str) or not isinstance(v, str):
                continue
            k_n = k.strip()
            v_n = v.strip()
            if not k_n or not v_n:
                continue
            # only accept known constraint names and known evidence attrs
            if k_n in _CONSTRAINT_ORDER and v_n in (
                "region_evidence",
                "remote_evidence",
                "employment_evidence",
                "authorization_evidence",
                "location",
                "title",
                "description",
            ):
                evidence_map[k_n] = v_n
    states: list[tuple[str, str]] = []
    # Map constraint name to approved tuple
    approved_map: dict[str, tuple[str, ...] | None] = {
        "region": policy.constraints.approved_regions,
        "remote": policy.constraints.approved_remote,
        "employment": policy.constraints.approved_employment,
        "authorization": policy.constraints.approved_authorizations,
    }
    for name in _CONSTRAINT_ORDER:
        approved = approved_map[name]
        if approved is None:
            states.append((name, "not_applicable"))
            continue
        # configured but need evidence
        field = evidence_map.get(name, _DEFAULT_EVIDENCE_MAP[name])
        raw: str | None = getattr(observation, field, None)
        # location is not evidence field but string; remote_evidence etc may be str|None
        if raw is None:
            states.append((name, "indeterminate"))
            continue
        if not isinstance(raw, str):
            states.append((name, "indeterminate"))
            continue
        if not raw.strip():
            states.append((name, "indeterminate"))
            continue
        norm_ev = normalize_text(raw)
        if not norm_ev:
            states.append((name, "indeterminate"))
            continue
        # Build normalized approved set
        norm_approved: set[str] = set()
        for a in approved:
            if not isinstance(a, str) or not a.strip():
                continue
            na = normalize_text(a)
            if na:
                norm_approved.add(na)
        if not norm_approved:
            states.append((name, "indeterminate"))
            continue
        if norm_ev in norm_approved:
            states.append((name, "match"))
        else:
            # explicit mismatch; evidence present so conflict not indeterminate
            states.append((name, "conflict"))
    return tuple(states)


def _source_unit(observation: AcquisitionObservation) -> str:
    # Deterministic source unit: use board_key as primary, fallback to board_id, then source_id
    # Include source_family for uniqueness when board_key collision across families
    key = observation.source.board_key.strip()
    if key:
        # board_key alone is unique; keep source_unit deterministic
        return key
    bid = observation.source.board_id.strip()
    if bid:
        return bid
    return observation.source.source_id.strip()


def _fact_hash(
    *,
    item_semantic_sha256: str,
    source_unit: str,
    company_sampling_key: str,
    strong_identity_digest: str,
    matched_approved_aliases: tuple[str, ...],
    matched_excluded_aliases: tuple[str, ...],
    supporting_core_matches: tuple[str, ...],
    supporting_secondary_matches: tuple[str, ...],
    excluded_technology_matches: tuple[str, ...],
    constraint_states: tuple[tuple[str, str], ...],
    input_sha256: str,
    profile_sha256: str,
    policy_sha256: str,
    acquisition_sha256: str,
    normalization_version: str,
    facts_version: str,
) -> str:
    payload = {
        "acquisition_sha256": acquisition_sha256,
        "company_sampling_key": company_sampling_key,
        "constraint_states": [list(p) for p in constraint_states],
        "excluded_technology_matches": list(excluded_technology_matches),
        "facts_version": facts_version,
        "input_sha256": input_sha256,
        "item_semantic_sha256": item_semantic_sha256,
        "matched_approved_aliases": list(matched_approved_aliases),
        "matched_excluded_aliases": list(matched_excluded_aliases),
        "normalization_version": normalization_version,
        "policy_sha256": policy_sha256,
        "profile_sha256": profile_sha256,
        "protocol": PROTOCOL_FACTS,
        "source_unit": source_unit,
        "strong_identity_digest": strong_identity_digest,
        "supporting_core_matches": list(supporting_core_matches),
        "supporting_secondary_matches": list(supporting_secondary_matches),
    }
    return domain_hash(DOMAIN_FACT, payload)


def project_facts(
    observation: AcquisitionObservation,
    policy: RelevancePolicy,
    input_sha256: str | None = None,
    profile_sha256: str | None = None,
    acquisition_sha256: str | None = None,
    input_hash: str | None = None,
    profile_hash: str | None = None,
    acquisition_hash: str | None = None,
) -> ProjectedFacts:
    """Pure projection from observation + policy to facts with hash binding."""
    # Resolve alias compat
    if input_sha256 is None:
        input_sha256 = input_hash
    if profile_sha256 is None:
        profile_sha256 = profile_hash
    if acquisition_sha256 is None:
        acquisition_sha256 = acquisition_hash
    # Fallback to policy/observation derived hashes if not provided
    if input_sha256 is None:
        input_sha256 = policy.policy_sha256
    if profile_sha256 is None:
        profile_sha256 = policy.profile_binding_sha256
    if acquisition_sha256 is None:
        acquisition_sha256 = observation.item_semantic_sha256
    if not isinstance(observation, AcquisitionObservation):
        raise TypeError("observation invalid")
    if not isinstance(policy, RelevancePolicy):
        raise TypeError("policy invalid")
    for name, val in (
        ("input_sha256", input_sha256),
        ("profile_sha256", profile_sha256),
        ("acquisition_sha256", acquisition_sha256),
    ):
        if not isinstance(val, str) or not val.strip():
            raise ValueError(f"{name} invalid")
    title_tokens = normalized_tokens(observation.title)
    desc_tokens = normalized_tokens(observation.description)
    matched_approved = _collect_title_matches(title_tokens, policy.approved_role_aliases)
    matched_excluded = _collect_title_matches(title_tokens, policy.excluded_role_aliases)
    supporting_core = _collect_support_matches(title_tokens, desc_tokens, policy.core_skills)
    supporting_secondary = _collect_support_matches(
        title_tokens, desc_tokens, policy.secondary_skills
    )
    excluded_tech = _collect_technology_matches(
        title_tokens, desc_tokens, policy.excluded_technologies
    )
    constraint_states = _constraint_states(observation, policy)
    source_unit = _source_unit(observation)
    fact_sha = _fact_hash(
        item_semantic_sha256=observation.item_semantic_sha256,
        source_unit=source_unit,
        company_sampling_key=observation.company_sampling_key,
        strong_identity_digest=observation.strong_identity_digest,
        matched_approved_aliases=matched_approved,
        matched_excluded_aliases=matched_excluded,
        supporting_core_matches=supporting_core,
        supporting_secondary_matches=supporting_secondary,
        excluded_technology_matches=excluded_tech,
        constraint_states=constraint_states,
        input_sha256=input_sha256,
        profile_sha256=profile_sha256,
        policy_sha256=policy.policy_sha256,
        acquisition_sha256=acquisition_sha256,
        normalization_version=policy.normalization_version,
        facts_version=policy.facts_version,
    )
    return ProjectedFacts(
        item_semantic_sha256=observation.item_semantic_sha256,
        source_unit=source_unit,
        company_sampling_key=observation.company_sampling_key,
        strong_identity_digest=observation.strong_identity_digest,
        matched_approved_aliases=matched_approved,
        matched_excluded_aliases=matched_excluded,
        supporting_core_matches=supporting_core,
        supporting_secondary_matches=supporting_secondary,
        excluded_technology_matches=excluded_tech,
        constraint_states=constraint_states,
        input_sha256=input_sha256,
        profile_sha256=profile_sha256,
        policy_sha256=policy.policy_sha256,
        acquisition_sha256=acquisition_sha256,
        fact_sha256=fact_sha,
    )


def project_from_inputs(
    observation: AcquisitionObservation,
    policy: RelevancePolicy,
    profile_sha256: str,
    acquisition_sha256: str,
    input_sha256: str,
) -> ProjectedFacts:
    return project_facts(
        observation,
        policy,
        input_sha256=input_sha256,
        profile_sha256=profile_sha256,
        acquisition_sha256=acquisition_sha256,
    )


# Aliases for potential test imports
project_observation = project_facts
build_projected_facts = project_facts
facts_for_observation = project_facts
normalize = normalize_text
project = project_facts

__all__ = [
    "build_projected_facts",
    "facts_for_observation",
    "normalize",
    "normalize_text",
    "normalized_tokens",
    "project",
    "project_facts",
    "project_from_inputs",
    "project_observation",
    "tokenize_normalized",
]
