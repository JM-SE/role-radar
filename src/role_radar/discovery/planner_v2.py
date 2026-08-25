"""Pure, profile-driven v2 discovery plan and provider request adapter."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Literal
from uuid import UUID

from role_radar.discovery.contracts import ProviderIntent, SearchRequest
from role_radar.discovery.policy import DiscoveryPolicyV1, ProfileBindingV1
from role_radar.discovery.profile_terms import (
    PROFILE_TERMS_COMPILER_VERSION,
    CompiledDiscoveryTermsV1,
)

MAX_DISCOVERY_PHRASES = 8

DISCOVERY_PLAN_SCHEMA_VERSION = "discovery-query-plan-v2"
DISCOVERY_PLANNER_VERSION = "discovery-planner-v2"
DISCOVERY_QUERY_VERSION = DISCOVERY_PLANNER_VERSION

MAX_DISCOVERY_QUERIES = 4
MAX_APPROVED_PHRASE_CHARS = 128
MAX_DISCOVERY_QUERY_CHARS = 2048
MAX_DISCOVERY_RESULTS_PER_QUERY = 10
MAX_BRAVE_REQUESTS_PER_RUN = 4
MAX_TAVILY_REQUESTS_PER_RUN = 4
MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN = 10
MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN = 8
MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN = 100

_LIMIT_NAMES = (
    "MAX_DISCOVERY_QUERIES",
    "MAX_DISCOVERY_PHRASES",
    "MAX_APPROVED_PHRASE_CHARS",
    "MAX_DISCOVERY_QUERY_CHARS",
    "MAX_DISCOVERY_RESULTS_PER_QUERY",
    "MAX_BRAVE_REQUESTS_PER_RUN",
    "MAX_TAVILY_REQUESTS_PER_RUN",
    "MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN",
    "MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN",
    "MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN",
)
DISCOVERY_LIMIT_NAMES = _LIMIT_NAMES


@dataclass(frozen=True, slots=True)
class DiscoveryHostV2:
    ordinal: int
    family: Literal["greenhouse", "lever"]
    host: str


DISCOVERY_HOST_REGISTRY = (
    DiscoveryHostV2(1, "greenhouse", "boards.greenhouse.io"),
    DiscoveryHostV2(2, "greenhouse", "job-boards.greenhouse.io"),
    DiscoveryHostV2(3, "lever", "jobs.lever.co"),
    DiscoveryHostV2(4, "lever", "jobs.eu.lever.co"),
)
# Short aliases make the code-owned registry easy to discover without creating
# a second source of truth.
DISCOVERY_HOSTS = tuple(item.host for item in DISCOVERY_HOST_REGISTRY)


class DiscoveryPlanError(ValueError):
    """Sanitized, stable error for invalid v2 plans or adapters."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class PlannedQueryV2:
    """One exact, one-based query in the code-owned four-host registry."""

    ordinal: int
    family: Literal["greenhouse", "lever"]
    host: str
    provider_intent: ProviderIntent
    canonical_query: str

    @property
    def query(self) -> str:
        return self.canonical_query


@dataclass(frozen=True, slots=True)
class DiscoveryQueryPlanV2:
    """Complete immutable plan identity and all frozen execution bounds."""

    schema_version: str
    planner_version: str
    compiler_version: str
    profile_binding: ProfileBindingV1
    policy_schema_version: int
    policy_version: str
    policy_sha256: str
    source_registry: tuple[DiscoveryHostV2, ...]
    max_discovery_queries: int
    max_discovery_phrases: int
    max_approved_phrase_chars: int
    max_discovery_query_chars: int
    max_discovery_results_per_query: int
    max_brave_requests_per_run: int
    max_tavily_requests_per_run: int
    max_unique_board_candidates_per_run: int
    max_unique_board_verifications_per_run: int
    max_verification_wire_attempts_per_run: int
    queries: tuple[PlannedQueryV2, ...]
    plan_sha256: str

    @property
    def hosts(self) -> tuple[str, ...]:
        return tuple(item.host for item in self.source_registry)

    @property
    def families(self) -> tuple[str, ...]:
        return tuple(item.family for item in self.source_registry)

    @property
    def limits(self) -> dict[str, int]:
        return _limit_values(self)

    @property
    def sha256(self) -> str:
        return self.plan_sha256


def _limit_values(plan: DiscoveryQueryPlanV2 | None = None) -> dict[str, int]:
    if plan is None:
        return {
            "MAX_DISCOVERY_QUERIES": MAX_DISCOVERY_QUERIES,
            "MAX_DISCOVERY_PHRASES": MAX_DISCOVERY_PHRASES,
            "MAX_APPROVED_PHRASE_CHARS": MAX_APPROVED_PHRASE_CHARS,
            "MAX_DISCOVERY_QUERY_CHARS": MAX_DISCOVERY_QUERY_CHARS,
            "MAX_DISCOVERY_RESULTS_PER_QUERY": MAX_DISCOVERY_RESULTS_PER_QUERY,
            "MAX_BRAVE_REQUESTS_PER_RUN": MAX_BRAVE_REQUESTS_PER_RUN,
            "MAX_TAVILY_REQUESTS_PER_RUN": MAX_TAVILY_REQUESTS_PER_RUN,
            "MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN": MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN,
            "MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN": MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN,
            "MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN": MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN,
        }
    return {
        "MAX_DISCOVERY_QUERIES": plan.max_discovery_queries,
        "MAX_DISCOVERY_PHRASES": plan.max_discovery_phrases,
        "MAX_APPROVED_PHRASE_CHARS": plan.max_approved_phrase_chars,
        "MAX_DISCOVERY_QUERY_CHARS": plan.max_discovery_query_chars,
        "MAX_DISCOVERY_RESULTS_PER_QUERY": plan.max_discovery_results_per_query,
        "MAX_BRAVE_REQUESTS_PER_RUN": plan.max_brave_requests_per_run,
        "MAX_TAVILY_REQUESTS_PER_RUN": plan.max_tavily_requests_per_run,
        "MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN": plan.max_unique_board_candidates_per_run,
        "MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN": plan.max_unique_board_verifications_per_run,
        "MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN": plan.max_verification_wire_attempts_per_run,
    }


def _binding_payload(binding: ProfileBindingV1) -> dict[str, object]:
    return {
        "profile_id": binding.profile_id,
        "row_version": binding.row_version,
        "schema_version": binding.schema_version,
        "canonical_profile_sha256": binding.canonical_profile_sha256,
    }


def _plan_payload(plan: DiscoveryQueryPlanV2, *, include_hash: bool) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": plan.schema_version,
        "planner_version": plan.planner_version,
        "compiler_version": plan.compiler_version,
        "profile_binding": _binding_payload(plan.profile_binding),
        "policy_schema_version": plan.policy_schema_version,
        "policy_version": plan.policy_version,
        "policy_sha256": plan.policy_sha256,
        "source_registry": [
            {"ordinal": item.ordinal, "family": item.family, "host": item.host}
            for item in plan.source_registry
        ],
        "limits": _limit_values(plan),
        "queries": [
            {
                "ordinal": item.ordinal,
                "family": item.family,
                "host": item.host,
                "provider_intent": item.provider_intent.value,
                "canonical_query": item.canonical_query,
            }
            for item in plan.queries
        ],
    }
    if include_hash:
        payload["plan_sha256"] = plan.plan_sha256
    return payload


def canonical_plan_payload(
    plan: DiscoveryQueryPlanV2, *, include_hash: bool = True
) -> dict[str, object]:
    """Return the complete canonical JSON payload for a plan artifact."""

    if not isinstance(plan, DiscoveryQueryPlanV2):
        raise TypeError("canonical_plan_payload requires DiscoveryQueryPlanV2")
    return _plan_payload(plan, include_hash=include_hash)


def canonical_plan_bytes(plan: DiscoveryQueryPlanV2, *, include_hash: bool = True) -> bytes:
    return json.dumps(
        canonical_plan_payload(plan, include_hash=include_hash),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def plan_sha256(plan: DiscoveryQueryPlanV2) -> str:
    """Hash every plan field except the plan hash itself."""

    return sha256(canonical_plan_bytes(plan, include_hash=False)).hexdigest()


def _validate_query(query: PlannedQueryV2, expected: DiscoveryHostV2) -> None:
    if (
        query.ordinal != expected.ordinal
        or query.family != expected.family
        or query.host != expected.host
        or query.provider_intent is not ProviderIntent.EXACT
    ):
        raise DiscoveryPlanError("discovery_plan_invalid")
    if not 1 <= len(query.canonical_query) <= MAX_DISCOVERY_QUERY_CHARS:
        raise DiscoveryPlanError("discovery_plan_invalid")
    expected_prefix = f"site:{expected.host} ("
    if not query.canonical_query.startswith(expected_prefix) or not query.canonical_query.endswith(
        ")"
    ):
        raise DiscoveryPlanError("discovery_plan_invalid")
    phrase_text = query.canonical_query[len(expected_prefix) : -1]
    phrases = phrase_text.split(" OR ")
    if not 1 <= len(phrases) <= MAX_DISCOVERY_PHRASES or any(
        len(phrase) < 2
        or not phrase.startswith('"')
        or not phrase.endswith('"')
        or '"' in phrase[1:-1]
        or len(phrase[1:-1]) > MAX_APPROVED_PHRASE_CHARS
        for phrase in phrases
    ):
        raise DiscoveryPlanError("discovery_plan_invalid")


def validate_discovery_query_plan(plan: DiscoveryQueryPlanV2) -> DiscoveryQueryPlanV2:
    """Validate code-owned identities and the canonical hash before transport."""

    if not isinstance(plan, DiscoveryQueryPlanV2):
        raise TypeError("validate_discovery_query_plan requires DiscoveryQueryPlanV2")
    if (
        plan.schema_version != DISCOVERY_PLAN_SCHEMA_VERSION
        or plan.planner_version != DISCOVERY_PLANNER_VERSION
        or plan.compiler_version != PROFILE_TERMS_COMPILER_VERSION
        or plan.policy_schema_version != 1
        or plan.max_discovery_queries != MAX_DISCOVERY_QUERIES
        or plan.max_discovery_phrases != MAX_DISCOVERY_PHRASES
        or plan.max_approved_phrase_chars != MAX_APPROVED_PHRASE_CHARS
        or plan.max_discovery_query_chars != MAX_DISCOVERY_QUERY_CHARS
        or plan.max_discovery_results_per_query != MAX_DISCOVERY_RESULTS_PER_QUERY
        or plan.max_brave_requests_per_run != MAX_BRAVE_REQUESTS_PER_RUN
        or plan.max_tavily_requests_per_run != MAX_TAVILY_REQUESTS_PER_RUN
        or plan.max_unique_board_candidates_per_run != MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN
        or plan.max_unique_board_verifications_per_run != MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN
        or plan.max_verification_wire_attempts_per_run != MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN
    ):
        raise DiscoveryPlanError("discovery_plan_invalid")
    if (
        plan.source_registry != DISCOVERY_HOST_REGISTRY
        or len(plan.queries) != MAX_DISCOVERY_QUERIES
    ):
        raise DiscoveryPlanError("discovery_plan_invalid")
    if tuple(item.ordinal for item in plan.queries) != (1, 2, 3, 4):
        raise DiscoveryPlanError("discovery_plan_invalid")
    for query, host in zip(plan.queries, DISCOVERY_HOST_REGISTRY, strict=True):
        _validate_query(query, host)
    first_suffix = plan.queries[0].canonical_query.removeprefix(
        f"site:{DISCOVERY_HOST_REGISTRY[0].host} "
    )
    if any(
        query.canonical_query.removeprefix(f"site:{host.host} ") != first_suffix
        for query, host in zip(plan.queries, DISCOVERY_HOST_REGISTRY, strict=True)
    ):
        raise DiscoveryPlanError("discovery_plan_invalid")
    if plan.plan_sha256 != plan_sha256(plan):
        raise DiscoveryPlanError("discovery_plan_hash_mismatch")
    return plan


def plan_profile_discovery(
    compiled: CompiledDiscoveryTermsV1,
    policy: DiscoveryPolicyV1,
) -> DiscoveryQueryPlanV2:
    """Compile output into exactly four bounded, host-owned queries."""

    if not isinstance(compiled, CompiledDiscoveryTermsV1):
        raise TypeError("plan_profile_discovery requires CompiledDiscoveryTermsV1")
    if not isinstance(policy, DiscoveryPolicyV1):
        raise TypeError("plan_profile_discovery requires DiscoveryPolicyV1")
    from role_radar.discovery.policy import canonical_policy_sha256

    if compiled.profile_binding != policy.profile_binding:
        raise DiscoveryPlanError("discovery_profile_binding_mismatch")
    if compiled.policy_version != policy.policy_version:
        raise DiscoveryPlanError("discovery_plan_policy_mismatch")
    if compiled.policy_sha256 != canonical_policy_sha256(policy):
        raise DiscoveryPlanError("discovery_plan_policy_mismatch")
    phrases = compiled.approved_phrases
    if not 1 <= len(phrases) <= MAX_DISCOVERY_PHRASES:
        raise DiscoveryPlanError("discovery_terms_invalid")
    if any(len(phrase) > MAX_APPROVED_PHRASE_CHARS for phrase in phrases):
        raise DiscoveryPlanError("discovery_terms_invalid")

    phrase_text = " OR ".join(f'"{phrase}"' for phrase in phrases)
    queries = tuple(
        PlannedQueryV2(
            ordinal=host.ordinal,
            family=host.family,
            host=host.host,
            provider_intent=ProviderIntent.EXACT,
            canonical_query=f"site:{host.host} ({phrase_text})",
        )
        for host in DISCOVERY_HOST_REGISTRY
    )
    if any(len(query.canonical_query) > MAX_DISCOVERY_QUERY_CHARS for query in queries):
        raise DiscoveryPlanError("discovery_query_limit_exceeded")

    unsigned = DiscoveryQueryPlanV2(
        schema_version=DISCOVERY_PLAN_SCHEMA_VERSION,
        planner_version=DISCOVERY_PLANNER_VERSION,
        compiler_version=compiled.compiler_version,
        profile_binding=compiled.profile_binding,
        policy_schema_version=policy.schema_version,
        policy_version=policy.policy_version,
        policy_sha256=compiled.policy_sha256,
        source_registry=DISCOVERY_HOST_REGISTRY,
        max_discovery_queries=MAX_DISCOVERY_QUERIES,
        max_discovery_phrases=MAX_DISCOVERY_PHRASES,
        max_approved_phrase_chars=MAX_APPROVED_PHRASE_CHARS,
        max_discovery_query_chars=MAX_DISCOVERY_QUERY_CHARS,
        max_discovery_results_per_query=MAX_DISCOVERY_RESULTS_PER_QUERY,
        max_brave_requests_per_run=MAX_BRAVE_REQUESTS_PER_RUN,
        max_tavily_requests_per_run=MAX_TAVILY_REQUESTS_PER_RUN,
        max_unique_board_candidates_per_run=MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN,
        max_unique_board_verifications_per_run=MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN,
        max_verification_wire_attempts_per_run=MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN,
        queries=queries,
        plan_sha256="0" * 64,
    )
    return DiscoveryQueryPlanV2(
        schema_version=unsigned.schema_version,
        planner_version=unsigned.planner_version,
        compiler_version=unsigned.compiler_version,
        profile_binding=unsigned.profile_binding,
        policy_schema_version=unsigned.policy_schema_version,
        policy_version=unsigned.policy_version,
        policy_sha256=unsigned.policy_sha256,
        source_registry=unsigned.source_registry,
        max_discovery_queries=unsigned.max_discovery_queries,
        max_discovery_phrases=unsigned.max_discovery_phrases,
        max_approved_phrase_chars=unsigned.max_approved_phrase_chars,
        max_discovery_query_chars=unsigned.max_discovery_query_chars,
        max_discovery_results_per_query=unsigned.max_discovery_results_per_query,
        max_brave_requests_per_run=unsigned.max_brave_requests_per_run,
        max_tavily_requests_per_run=unsigned.max_tavily_requests_per_run,
        max_unique_board_candidates_per_run=unsigned.max_unique_board_candidates_per_run,
        max_unique_board_verifications_per_run=unsigned.max_unique_board_verifications_per_run,
        max_verification_wire_attempts_per_run=unsigned.max_verification_wire_attempts_per_run,
        queries=unsigned.queries,
        plan_sha256=plan_sha256(unsigned),
    )


def _canonical_operation_id(operation: str) -> str:
    try:
        parsed = UUID(operation)
    except ValueError as exc:
        raise DiscoveryPlanError("discovery_operation_invalid") from exc
    if str(parsed) != operation or operation != operation.casefold():
        raise DiscoveryPlanError("discovery_operation_invalid")
    return operation


def planned_query_v2_to_search_request(
    query: PlannedQueryV2,
    plan: DiscoveryQueryPlanV2,
    operation: str,
) -> SearchRequest:
    """Adapt one verified v2 query to the existing provider-neutral DTO."""

    validate_discovery_query_plan(plan)
    if query not in plan.queries:
        raise DiscoveryPlanError("discovery_query_not_in_plan")
    operation_id = _canonical_operation_id(operation)
    operation_key = f"cdv2:{operation_id}:{plan.plan_sha256}:q{query.ordinal:02d}"
    query_key_payload = {
        "plan_sha256": plan.plan_sha256,
        "query_ordinal": query.ordinal,
        "exact_query": query.canonical_query,
    }
    query_key = sha256(
        json.dumps(
            query_key_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return SearchRequest(
        operation_key=operation_key,
        query=query.canonical_query,
        query_key=query_key,
        planner_version=plan.planner_version,
        query_version=DISCOVERY_QUERY_VERSION,
        max_results=MAX_DISCOVERY_RESULTS_PER_QUERY,
        provider_intent=ProviderIntent.EXACT,
        cycle_query_count=MAX_DISCOVERY_QUERIES,
    )


# Explicitly named aliases for callers that use the shorter validation/hash
# vocabulary.  No v1 PlannedQuery is imported or aliased here.
verify_plan = validate_discovery_query_plan
canonical_plan_sha256 = plan_sha256
