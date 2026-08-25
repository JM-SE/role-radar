"""Gate A four-host planner and provider-neutral adapter checks."""

from __future__ import annotations

import hashlib
import json

import pytest

from role_radar.discovery.contracts import ProviderIntent
from role_radar.discovery.planner_v2 import (
    DISCOVERY_HOST_REGISTRY,
    DiscoveryPlanError,
    PlannedQueryV2,
    canonical_plan_bytes,
    plan_profile_discovery,
    planned_query_v2_to_search_request,
    validate_discovery_query_plan,
)
from role_radar.discovery.policy import (
    DiscoveryPhraseGrammarV1,
    DiscoveryPolicyV1,
    policy_sha256,
)
from role_radar.discovery.profile_terms import (
    CompiledDiscoveryPhraseV1,
    CompiledDiscoveryTermsV1,
    DiscoveryTermProvenanceV1,
)

GOLDEN_PLAN_SHA256 = "486dddc0c0ce31b457beaeb2b7e4a5c3a7c70251a708e322bf88c37973b27468"
GOLDEN_PLAN_HASH_PREIMAGE_BYTES = (
    b'{"compiler_version":"profile-terms-compiler-v1","limits":{"MAX_APPROVED_PHRASE_CHARS":12'
    b'8,"MAX_BRAVE_REQUESTS_PER_RUN":4,"MAX_DISCOVERY_PHRASES":8,"MAX_DISCOVERY_QUERIES":4,"MA'
    b'X_DISCOVERY_QUERY_CHARS":2048,"MAX_DISCOVERY_RESULTS_PER_QUERY":10,"MAX_TAVILY_REQUESTS_'
    b'PER_RUN":4,"MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN":10,"MAX_UNIQUE_BOARD_VERIFICATIONS_PER_'
    b'RUN":8,"MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN":100},"planner_version":"discovery-planne'
    b'r-v2","policy_schema_version":1,"policy_sha256":"9b323f25e8d20695d01b3789fd480894c04a3eb'
    b'8072603b56e5beeac1e093fcb","policy_version":"gate-a-v1","profile_binding":{"canonical_pr'
    b'ofile_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profil'
    b'e_id":"00000000-0000-0000-0000-000000000001","row_version":1,"schema_version":1},"querie'
    b's":[{"canonical_query":"site:boards.greenhouse.io (\\"Backend Engineer\\")","family":"gree'
    b'nhouse","host":"boards.greenhouse.io","ordinal":1,"provider_intent":"exact"},{"canonical'
    b'_query":"site:job-boards.greenhouse.io (\\"Backend Engineer\\")","family":"greenhouse","ho'
    b'st":"job-boards.greenhouse.io","ordinal":2,"provider_intent":"exact"},{"canonical_query"'
    b':"site:jobs.lever.co (\\"Backend Engineer\\")","family":"lever","host":"jobs.lever.co","or'
    b'dinal":3,"provider_intent":"exact"},{"canonical_query":"site:jobs.eu.lever.co (\\"Backend'
    b' Engineer\\")","family":"lever","host":"jobs.eu.lever.co","ordinal":4,"provider_intent":"'
    b'exact"}],"schema_version":"discovery-query-plan-v2","source_registry":[{"family":"greenh'
    b'ouse","host":"boards.greenhouse.io","ordinal":1},{"family":"greenhouse","host":"job-boar'
    b'ds.greenhouse.io","ordinal":2},{"family":"lever","host":"jobs.lever.co","ordinal":3},{"f'
    b'amily":"lever","host":"jobs.eu.lever.co","ordinal":4}]}'
)
GOLDEN_PLAN_ARTIFACT_BYTES = (
    b'{"compiler_version":"profile-terms-compiler-v1","limits":{"MAX_APPROVED_PHRASE_CHARS":12'
    b'8,"MAX_BRAVE_REQUESTS_PER_RUN":4,"MAX_DISCOVERY_PHRASES":8,"MAX_DISCOVERY_QUERIES":4,"MA'
    b'X_DISCOVERY_QUERY_CHARS":2048,"MAX_DISCOVERY_RESULTS_PER_QUERY":10,"MAX_TAVILY_REQUESTS_'
    b'PER_RUN":4,"MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN":10,"MAX_UNIQUE_BOARD_VERIFICATIONS_PER_'
    b'RUN":8,"MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN":100},"plan_sha256":"486dddc0c0ce31b457be'
    b'aeb2b7e4a5c3a7c70251a708e322bf88c37973b27468","planner_version":"discovery-planner-v2","'
    b'policy_schema_version":1,"policy_sha256":"9b323f25e8d20695d01b3789fd480894c04a3eb8072603'
    b'b56e5beeac1e093fcb","policy_version":"gate-a-v1","profile_binding":{"canonical_profile_s'
    b'ha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profile_id":"'
    b'00000000-0000-0000-0000-000000000001","row_version":1,"schema_version":1},"queries":[{"c'
    b'anonical_query":"site:boards.greenhouse.io (\\"Backend Engineer\\")","family":"greenhouse"'
    b',"host":"boards.greenhouse.io","ordinal":1,"provider_intent":"exact"},{"canonical_query"'
    b':"site:job-boards.greenhouse.io (\\"Backend Engineer\\")","family":"greenhouse","host":"jo'
    b'b-boards.greenhouse.io","ordinal":2,"provider_intent":"exact"},{"canonical_query":"site:'
    b'jobs.lever.co (\\"Backend Engineer\\")","family":"lever","host":"jobs.lever.co","ordinal":'
    b'3,"provider_intent":"exact"},{"canonical_query":"site:jobs.eu.lever.co (\\"Backend Engine'
    b'er\\")","family":"lever","host":"jobs.eu.lever.co","ordinal":4,"provider_intent":"exact"'
    b'}],"schema_version":"discovery-query-plan-v2","source_registry":[{"family":"greenhouse","'
    b'host":"boards.greenhouse.io","ordinal":1},{"family":"greenhouse","host":"job-boards.gree'
    b'nhouse.io","ordinal":2},{"family":"lever","host":"jobs.lever.co","ordinal":3},{"family":'
    b'"lever","host":"jobs.eu.lever.co","ordinal":4}]}'
)


def policy() -> DiscoveryPolicyV1:
    return DiscoveryPolicyV1.model_validate(
        {
            "schema_version": 1,
            "policy_version": "gate-a-v1",
            "profile_binding": {
                "profile_id": "00000000-0000-0000-0000-000000000001",
                "row_version": 1,
                "schema_version": 1,
                "canonical_profile_sha256": "a" * 64,
            },
            "phrase_grammar": DiscoveryPhraseGrammarV1().model_dump(mode="json"),
            "groups": {"primary": ["Backend Engineer"]},
            "target_roles": {"backend": {"primary_groups": ["primary"]}},
            "target_titles": {},
        }
    )


def terms(policy_value: DiscoveryPolicyV1, count: int = 1) -> CompiledDiscoveryTermsV1:
    provenance = DiscoveryTermProvenanceV1("target_roles", "backend", "primary", False)
    phrases = tuple(
        CompiledDiscoveryPhraseV1(
            f"Backend Engineer {index}" if count > 1 else "Backend Engineer",
            (provenance,),
        )
        for index in range(count)
    )
    return CompiledDiscoveryTermsV1(
        profile_binding=policy_value.profile_binding,
        policy_version=policy_value.policy_version,
        policy_sha256=policy_sha256(policy_value),
        phrases=phrases,
    )


@pytest.mark.parametrize("count", range(1, 9))
def test_one_to_eight_phrases_always_emit_four_code_owned_queries(count: int) -> None:
    plan = plan_profile_discovery(terms(policy(), count), policy())
    assert len(plan.queries) == 4
    assert tuple(query.ordinal for query in plan.queries) == (1, 2, 3, 4)
    assert tuple(query.host for query in plan.queries) == tuple(
        item.host for item in DISCOVERY_HOST_REGISTRY
    )
    assert all(query.provider_intent is ProviderIntent.EXACT for query in plan.queries)
    assert validate_discovery_query_plan(plan) == plan


def test_fixed_plan_matches_independent_canonical_oracles() -> None:
    value = plan_profile_discovery(terms(policy()), policy())
    preimage = canonical_plan_bytes(value, include_hash=False)
    artifact = canonical_plan_bytes(value)
    assert preimage == GOLDEN_PLAN_HASH_PREIMAGE_BYTES
    assert artifact == GOLDEN_PLAN_ARTIFACT_BYTES
    assert hashlib.sha256(preimage).hexdigest() == GOLDEN_PLAN_SHA256


def test_adapter_binds_operation_plan_ordinal_and_exact_query() -> None:
    plan = plan_profile_discovery(terms(policy()), policy())
    operation_id = "00000000-0000-0000-0000-000000000002"
    request = planned_query_v2_to_search_request(plan.queries[0], plan, operation_id)
    expected = json.dumps(
        {
            "plan_sha256": plan.plan_sha256,
            "query_ordinal": 1,
            "exact_query": plan.queries[0].canonical_query,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert request.operation_key == f"cdv2:{operation_id}:{plan.plan_sha256}:q01"
    assert request.query == plan.queries[0].canonical_query
    assert request.query_key == hashlib.sha256(expected).hexdigest()
    assert request.cycle_query_count == 4
    assert request.max_results == 10


def test_adapter_rejects_query_not_in_verified_plan() -> None:
    plan = plan_profile_discovery(terms(policy()), policy())
    query = PlannedQueryV2(1, "greenhouse", "boards.greenhouse.io", ProviderIntent.EXACT, "site:x")
    with pytest.raises(DiscoveryPlanError) as error:
        planned_query_v2_to_search_request(query, plan, "00000000-0000-0000-0000-000000000002")
    assert error.value.code == "discovery_query_not_in_plan"
