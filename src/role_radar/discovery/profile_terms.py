"""Pure compilation of approved discovery phrases from a frozen profile.

This module deliberately knows about profile fields and policy groups only.  It
does not know provider syntax, hosts, URLs, or any persistence/runtime seam.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from role_radar.discovery.policy import (
    MAX_APPROVED_PHRASE_CHARS,
    DiscoveryPolicyV1,
    ProfileBindingV1,
    canonical_policy_sha256,
)
from role_radar.domain.profile import CandidateProfileV1

MAX_DISCOVERY_PHRASES = 8
PROFILE_TERMS_COMPILER_VERSION = "profile-terms-compiler-v1"


class DiscoveryTermsError(ValueError):
    """Sanitized, stable error for deterministic term compilation."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class FrozenCandidateProfileV1:
    """Validated profile value paired with the exact selected-row binding."""

    binding: ProfileBindingV1
    profile: CandidateProfileV1

    def __post_init__(self) -> None:
        if not isinstance(self.binding, ProfileBindingV1):
            raise TypeError("FrozenCandidateProfileV1 requires ProfileBindingV1")
        if not isinstance(self.profile, CandidateProfileV1):
            raise TypeError("FrozenCandidateProfileV1 requires CandidateProfileV1")

    @property
    def profile_binding(self) -> ProfileBindingV1:
        return self.binding

    @property
    def value(self) -> CandidateProfileV1:
        return self.profile


@dataclass(frozen=True, slots=True)
class DiscoveryTermProvenanceV1:
    """One stable policy/profile path which approved a compiled phrase."""

    profile_field: Literal["target_roles", "target_titles"]
    profile_key: str
    group_id: str
    coverage: bool

    @property
    def kind(self) -> Literal["target_role", "target_title"]:
        return "target_role" if self.profile_field == "target_roles" else "target_title"


@dataclass(frozen=True, slots=True)
class CompiledDiscoveryPhraseV1:
    """A complete phrase and all deterministic provenance paths for it."""

    phrase: str
    provenance: tuple[DiscoveryTermProvenanceV1, ...]

    @property
    def text(self) -> str:
        return self.phrase


@dataclass(frozen=True, slots=True)
class CompiledDiscoveryTermsV1:
    """Immutable compiler output consumed by the v2 planner."""

    profile_binding: ProfileBindingV1
    policy_version: str
    policy_sha256: str
    phrases: tuple[CompiledDiscoveryPhraseV1, ...]
    compiler_version: str = PROFILE_TERMS_COMPILER_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.profile_binding, ProfileBindingV1):
            raise TypeError("compiled terms require ProfileBindingV1")
        if self.compiler_version != PROFILE_TERMS_COMPILER_VERSION:
            raise ValueError("compiled terms compiler version is invalid")
        if not 1 <= len(self.phrases) <= MAX_DISCOVERY_PHRASES:
            raise ValueError("compiled terms phrase count is out of bounds")
        if any(
            not isinstance(item, CompiledDiscoveryPhraseV1)
            or not 1 <= len(item.phrase) <= MAX_APPROVED_PHRASE_CHARS
            or not item.provenance
            for item in self.phrases
        ):
            raise ValueError("compiled terms are invalid")

    @property
    def approved_phrases(self) -> tuple[str, ...]:
        return tuple(item.phrase for item in self.phrases)

    @property
    def phrase_texts(self) -> tuple[str, ...]:
        return self.approved_phrases

    @property
    def approved(self) -> tuple[CompiledDiscoveryPhraseV1, ...]:
        return self.phrases

    @property
    def terms(self) -> tuple[CompiledDiscoveryPhraseV1, ...]:
        return self.phrases


def _profile_value(profile: CandidateProfileV1 | FrozenCandidateProfileV1) -> CandidateProfileV1:
    if isinstance(profile, FrozenCandidateProfileV1):
        return profile.profile
    if isinstance(profile, CandidateProfileV1):
        return profile
    raise TypeError("compile_profile_terms requires CandidateProfileV1")


def _check_binding(
    profile: CandidateProfileV1 | FrozenCandidateProfileV1,
    policy: DiscoveryPolicyV1,
) -> None:
    if isinstance(profile, FrozenCandidateProfileV1) and profile.binding != policy.profile_binding:
        raise DiscoveryTermsError("discovery_profile_binding_mismatch")


def compile_profile_terms(
    profile: CandidateProfileV1 | FrozenCandidateProfileV1,
    policy: DiscoveryPolicyV1,
) -> CompiledDiscoveryTermsV1:
    """Compile only policy-mapped target roles and titles.

    Profile values are already canonicalized by ``CandidateProfileV1``.  The
    compiler sorts the selected keys, follows the policy's ordered primary
    then coverage groups, and uses first-wins casefolded phrase deduplication.
    A duplicate phrase keeps every provenance path in encounter order.
    """

    if not isinstance(policy, DiscoveryPolicyV1):
        raise TypeError("compile_profile_terms requires DiscoveryPolicyV1")
    candidate = _profile_value(profile)
    _check_binding(profile, policy)

    compiled: dict[str, tuple[str, list[DiscoveryTermProvenanceV1]]] = {}

    def append_for(
        field: Literal["target_roles", "target_titles"],
        keys: tuple[str, ...],
        bindings: Mapping[str, object],
    ) -> None:
        for key in sorted(set(keys)):
            binding = bindings.get(key)
            if binding is None:
                continue
            # The policy DTO guarantees this type; the explicit check keeps a
            # malformed object from crossing this pure boundary if constructed
            # by an untyped caller.
            primary = getattr(binding, "primary_groups", None)
            coverage = getattr(binding, "coverage_groups", None)
            if not isinstance(primary, tuple) or not isinstance(coverage, tuple):
                raise DiscoveryTermsError("discovery_terms_invalid")
            for is_coverage, group_ids in ((False, primary), (True, coverage)):
                for group_id in group_ids:
                    phrases = policy.groups.get(group_id)
                    if phrases is None:
                        raise DiscoveryTermsError("discovery_terms_invalid")
                    for phrase in phrases:
                        folded = phrase.casefold()
                        provenance = DiscoveryTermProvenanceV1(
                            profile_field=field,
                            profile_key=key,
                            group_id=group_id,
                            coverage=is_coverage,
                        )
                        if folded not in compiled:
                            compiled[folded] = (phrase, [provenance])
                        else:
                            compiled[folded][1].append(provenance)
                        if len(compiled) > MAX_DISCOVERY_PHRASES:
                            raise DiscoveryTermsError("discovery_terms_limit_exceeded")

    append_for("target_roles", candidate.target_roles, policy.target_roles)
    append_for("target_titles", candidate.target_titles, policy.target_titles)

    if not compiled:
        raise DiscoveryTermsError("discovery_terms_unavailable")
    phrases = tuple(
        CompiledDiscoveryPhraseV1(phrase, tuple(provenance))
        for phrase, provenance in compiled.values()
    )
    return CompiledDiscoveryTermsV1(
        profile_binding=policy.profile_binding,
        policy_version=policy.policy_version,
        policy_sha256=canonical_policy_sha256(policy),
        phrases=phrases,
    )


# A read-only mapping is useful to callers that want keyed phrase access while
# retaining the tuple as the canonical serialization/order representation.
def phrase_provenance(
    compiled: CompiledDiscoveryTermsV1,
) -> Mapping[str, tuple[DiscoveryTermProvenanceV1, ...]]:
    """Return phrase-to-provenance data without exposing mutable state."""

    return MappingProxyType({item.phrase: item.provenance for item in compiled.phrases})
