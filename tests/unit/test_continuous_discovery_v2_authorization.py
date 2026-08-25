"""Gate A operation, challenge, budget, and authorization-boundary checks."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from role_radar.continuous_acquisition.report_only_v2 import (
    prepare_report_only_operation,
    verify_report_only_authorization,
)
from role_radar.discovery.authorization_v2 import (
    EXACT_BUDGET_NAMES,
    AuthorizationError,
    build_register_operation,
    canonical_challenge_bytes,
    canonical_json_bytes,
    challenge_sha256,
    validate_report_only_challenge,
)
from role_radar.discovery.planner_v2 import DiscoveryQueryPlanV2, plan_profile_discovery
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


def plan() -> DiscoveryQueryPlanV2:
    policy = DiscoveryPolicyV1.model_validate(
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
    provenance = DiscoveryTermProvenanceV1("target_roles", "backend", "primary", False)
    terms = CompiledDiscoveryTermsV1(
        profile_binding=policy.profile_binding,
        policy_version=policy.policy_version,
        policy_sha256=policy_sha256(policy),
        phrases=(CompiledDiscoveryPhraseV1("Backend Engineer", (provenance,)),),
    )
    return plan_profile_discovery(terms, policy)


class Quota:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self.units_limit = 4


class Config:
    config_version = "config-v1"
    brave_free = Quota(True)
    tavily_free = Quota(True)


GOLDEN_CHALLENGE_SHA256 = "4b9ad3dab602ca538407c4313a5b0a257dd0538f6aff96befe85ead582bea278"
GOLDEN_CHALLENGE_HASH_PREIMAGE_BYTES = (
    b'f10.1d:report-only-challenge-v2\x00{"domain":"f10.1d:report-only-challenge-v2","operation":'
    b'{"authorization_max_ttl_seconds":86400,"budgets":{"MAX_APPROVED_PHRASE_CHARS":128,"MAX_B'
    b'RAVE_REQUESTS_PER_RUN":4,"MAX_DISCOVERY_PHRASES":8,"MAX_DISCOVERY_QUERIES":4,"MAX_DISCOV'
    b'ERY_QUERY_CHARS":2048,"MAX_DISCOVERY_RESULTS_PER_QUERY":10,"MAX_TAVILY_REQUESTS_PER_RUN"'
    b':4,"MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN":10,"MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN":8,"'
    b'MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN":100},"challenge_nonce":"bm5ubm5ubm5ubm5ubm5ubm5u'
    b'bm5ubm5ubm5ubm5ubm4","created_at":"2026-08-24T12:00:00.000000Z","expires_at":"2026-08-25'
    b'T12:00:00.000000Z","kind":"continuous_discovery_v2_report_only","operation_id":"00000000'
    b'-0000-0000-0000-000000000002","plan_sha256":"486dddc0c0ce31b457beaeb2b7e4a5c3a7c70251a70'
    b'8e322bf88c37973b27468","policy_sha256":"9b323f25e8d20695d01b3789fd480894c04a3eb8072603b5'
    b'6e5beeac1e093fcb","policy_version":"gate-a-v1","profile_binding":{"canonical_profile_sha'
    b'256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profile_id":"00'
    b'000000-0000-0000-0000-000000000001","row_version":1,"schema_version":1},"protocol_versio'
    b'n":"f10.1d-report-only-v2","quota_contexts":[{"config_version":"config-v1","micro_usd_li'
    b'mit":0,"operation_max_calls":4,"provider":"brave","reservation_micro_usd_per_call":0,"re'
    b'servation_units_per_call":1,"tier":"free","unit_limit":4,"utc_month":"2026-08"},{"config'
    b'_version":"config-v1","micro_usd_limit":0,"operation_max_calls":4,"provider":"tavily","r'
    b'eservation_micro_usd_per_call":0,"reservation_units_per_call":1,"tier":"free","unit_limi'
    b't":4,"utc_month":"2026-08"}],"schema_version":"f10.1d-authorization-v2"},"operation_sha2'
    b'56":"9815c0554bf5011ab238a82dc710815e09a9284072a8d98e110991364bc74564"}'
)
GOLDEN_OPERATION_SHA256 = "8febe368de80100a9964e26f133ee90fe2cc988b9025fa641d2edd1b86409d01"
GOLDEN_OPERATION_HASH_PREIMAGE_BYTES = (
    b'{"authorization_expires_at_utc":"2026-08-25T12:00:00.000000Z","authorization_max_ttl_sec'
    b'onds":86400,"budgets":{"MAX_APPROVED_PHRASE_CHARS":128,"MAX_BRAVE_REQUESTS_PER_RUN":4,"M'
    b'AX_DISCOVERY_PHRASES":8,"MAX_DISCOVERY_QUERIES":4,"MAX_DISCOVERY_QUERY_CHARS":2048,"MAX_'
    b'DISCOVERY_RESULTS_PER_QUERY":10,"MAX_TAVILY_REQUESTS_PER_RUN":4,"MAX_UNIQUE_BOARD_CANDID'
    b'ATES_PER_RUN":10,"MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN":8,"MAX_VERIFICATION_WIRE_ATTEM'
    b'PTS_PER_RUN":100},"challenge_nonce":"bm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm4","chall'
    b'enge_sha256":"4b9ad3dab602ca538407c4313a5b0a257dd0538f6aff96befe85ead582bea278","created'
    b'_at_utc":"2026-08-24T12:00:00.000000Z","destinations":["brave_search_api","tavily_search'
    b'_api","greenhouse_official_api","lever_global_official_api","lever_eu_official_api"],"op'
    b'eration_id":"00000000-0000-0000-0000-000000000002","operation_kind":"continuous_discover'
    b'y_v2_report_only","plan_identity":{"compiler_version":"profile-terms-compiler-v1","plan_'
    b'sha256":"486dddc0c0ce31b457beaeb2b7e4a5c3a7c70251a708e322bf88c37973b27468","planner_vers'
    b'ion":"discovery-planner-v2","schema_version":"discovery-query-plan-v2"},"policy_identity'
    b'":{"policy_sha256":"9b323f25e8d20695d01b3789fd480894c04a3eb8072603b56e5beeac1e093fcb","p'
    b'olicy_version":"gate-a-v1","schema_version":1},"profile_binding":{"canonical_profile_sha'
    b'256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profile_id":"00'
    b'000000-0000-0000-0000-000000000001","row_version":1,"schema_version":1},"providers":[{"e'
    b'nabled":true,"provider":"brave","tier":"free"},{"enabled":true,"provider":"tavily","tier'
    b'":"free"},{"enabled":true,"provider":"greenhouse","tier":"official"},{"enabled":true,"pr'
    b'ovider":"lever","tier":"official"}],"quota_contexts":[{"config_version":"config-v1","mic'
    b'ro_usd_limit":0,"operation_max_calls":4,"provider":"brave","reservation_micro_usd_per_ca'
    b'll":0,"reservation_units_per_call":1,"tier":"free","unit_limit":4,"utc_month":"2026-08"}'
    b',{"config_version":"config-v1","micro_usd_limit":0,"operation_max_calls":4,"provider":"t'
    b'avily","reservation_micro_usd_per_call":0,"reservation_units_per_call":1,"tier":"free","'
    b'unit_limit":4,"utc_month":"2026-08"}],"schema_version":"report-only-operation-v1"}'
)
GOLDEN_OPERATION_ARTIFACT_BYTES = (
    b'{"authorization_expires_at_utc":"2026-08-25T12:00:00.000000Z","authorization_max_ttl_sec'
    b'onds":86400,"budgets":{"MAX_APPROVED_PHRASE_CHARS":128,"MAX_BRAVE_REQUESTS_PER_RUN":4,"M'
    b'AX_DISCOVERY_PHRASES":8,"MAX_DISCOVERY_QUERIES":4,"MAX_DISCOVERY_QUERY_CHARS":2048,"MAX_'
    b'DISCOVERY_RESULTS_PER_QUERY":10,"MAX_TAVILY_REQUESTS_PER_RUN":4,"MAX_UNIQUE_BOARD_CANDID'
    b'ATES_PER_RUN":10,"MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN":8,"MAX_VERIFICATION_WIRE_ATTEM'
    b'PTS_PER_RUN":100},"challenge_nonce":"bm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm4","chall'
    b'enge_sha256":"4b9ad3dab602ca538407c4313a5b0a257dd0538f6aff96befe85ead582bea278","created'
    b'_at_utc":"2026-08-24T12:00:00.000000Z","destinations":["brave_search_api","tavily_search'
    b'_api","greenhouse_official_api","lever_global_official_api","lever_eu_official_api"],"op'
    b'eration_id":"00000000-0000-0000-0000-000000000002","operation_kind":"continuous_discover'
    b'y_v2_report_only","operation_sha256":"8febe368de80100a9964e26f133ee90fe2cc988b9025fa641d'
    b'2edd1b86409d01","plan_identity":{"compiler_version":"profile-terms-compiler-v1","plan_sh'
    b'a256":"486dddc0c0ce31b457beaeb2b7e4a5c3a7c70251a708e322bf88c37973b27468","planner_versio'
    b'n":"discovery-planner-v2","schema_version":"discovery-query-plan-v2"},"policy_identity":'
    b'{"policy_sha256":"9b323f25e8d20695d01b3789fd480894c04a3eb8072603b56e5beeac1e093fcb","pol'
    b'icy_version":"gate-a-v1","schema_version":1},"profile_binding":{"canonical_profile_sha25'
    b'6":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profile_id":"0000'
    b'0000-0000-0000-0000-000000000001","row_version":1,"schema_version":1},"providers":[{"ena'
    b'bled":true,"provider":"brave","tier":"free"},{"enabled":true,"provider":"tavily","tier":'
    b'"free"},{"enabled":true,"provider":"greenhouse","tier":"official"},{"enabled":true,"prov'
    b'ider":"lever","tier":"official"}],"quota_contexts":[{"config_version":"config-v1","micro'
    b'_usd_limit":0,"operation_max_calls":4,"provider":"brave","reservation_micro_usd_per_call'
    b'":0,"reservation_units_per_call":1,"tier":"free","unit_limit":4,"utc_month":"2026-08"},{'
    b'"config_version":"config-v1","micro_usd_limit":0,"operation_max_calls":4,"provider":"tav'
    b'ily","reservation_micro_usd_per_call":0,"reservation_units_per_call":1,"tier":"free","un'
    b'it_limit":4,"utc_month":"2026-08"}],"schema_version":"report-only-operation-v1"}'
)


def test_operation_contains_exact_ten_budgets_and_nonce() -> None:
    operation = prepare_report_only_operation(
        plan(),
        Config(),
        operation_id="00000000-0000-0000-0000-000000000002",
        clock=datetime(2026, 8, 24, 12, tzinfo=UTC),
        nonce_source=lambda: b"n" * 32,
    )
    assert tuple(operation.budgets) == EXACT_BUDGET_NAMES
    assert operation.operation.challenge_nonce == operation.challenge_nonce
    assert operation.operation.authorization_max_ttl_seconds == 86_400
    assert operation.authorization_expires_at_utc == datetime(2026, 8, 25, 12, tzinfo=UTC)
    assert len(operation.quota_contexts) == 2
    assert operation.quota_contexts[0].provider == "brave"
    assert operation.quota_contexts[1].provider == "tavily"


def test_fixed_operation_matches_independent_canonical_oracles() -> None:
    operation = prepare_report_only_operation(
        plan(),
        Config(),
        operation_id="00000000-0000-0000-0000-000000000002",
        clock=datetime(2026, 8, 24, 12, tzinfo=UTC),
        nonce_source=lambda: b"n" * 32,
    )
    challenge_preimage = canonical_challenge_bytes(operation.operation)
    artifact = canonical_json_bytes(operation.as_dict())
    operation_preimage = dict(operation.as_dict())
    operation_preimage.pop("operation_sha256")
    operation_preimage_bytes = canonical_json_bytes(operation_preimage)
    assert challenge_preimage == GOLDEN_CHALLENGE_HASH_PREIMAGE_BYTES
    assert artifact == GOLDEN_OPERATION_ARTIFACT_BYTES
    assert operation_preimage_bytes == GOLDEN_OPERATION_HASH_PREIMAGE_BYTES
    assert hashlib.sha256(challenge_preimage).hexdigest() == GOLDEN_CHALLENGE_SHA256
    assert hashlib.sha256(operation_preimage_bytes).hexdigest() == GOLDEN_OPERATION_SHA256


def test_authorization_window_clamps_to_utc_month_end() -> None:
    with pytest.raises(Exception) as error:
        prepare_report_only_operation(
            plan(),
            Config(),
            operation_id="00000000-0000-0000-0000-000000000002",
            clock=datetime(2026, 1, 31, 23, 59, 59, 999999, tzinfo=UTC),
            nonce_source=lambda: b"n" * 32,
        )
    assert getattr(error.value, "code", "") == "discovery_v2_authorization_window_invalid"


def test_nonce_mutation_changes_challenge_and_generic_ack_is_not_authorization() -> None:
    operation = prepare_report_only_operation(
        plan(),
        Config(),
        operation_id="00000000-0000-0000-0000-000000000002",
        clock=datetime(2026, 8, 24, 12, tzinfo=UTC),
        nonce_source=lambda: b"n" * 32,
    )
    changed = replace(
        operation.operation,
        challenge_nonce=base64.urlsafe_b64encode(b"m" * 32).decode().rstrip("="),
    )
    assert challenge_sha256(changed) != operation.challenge_sha256
    with pytest.raises(AuthorizationError) as error:
        validate_report_only_challenge(
            operation.operation,
            operation.challenge,
            now=datetime(2026, 8, 24, 12, tzinfo=UTC),
            acknowledgement="I_ACKNOWLEDGE_LIVE_PROVIDER_CALLS",
        )
    assert error.value.code == "acknowledgement_mismatch"


def test_gate_a_does_not_create_register_operation() -> None:
    with pytest.raises(AuthorizationError) as error:
        build_register_operation()
    assert error.value.code == "gate_a_blocked"


def test_prepared_operation_replays_offline() -> None:
    operation = prepare_report_only_operation(
        plan(),
        Config(),
        operation_id="00000000-0000-0000-0000-000000000002",
        clock=datetime(2026, 8, 24, 12, tzinfo=UTC),
        nonce_source=lambda: b"n" * 32,
    )
    evidence = verify_report_only_authorization(
        operation, operation.as_dict(), now=datetime(2026, 8, 24, 12, tzinfo=UTC)
    )
    assert evidence.operation_sha256 == operation.operation_sha256
