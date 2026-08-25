"""Gate A private artifact schemas, hashes, and no-replace storage checks."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from role_radar.continuous_acquisition.discovery_artifacts_v2 import (
    DiscoveryArtifactError,
    ReportOnlyRequestEvidenceV1,
    ReportOnlyStartMarkerV1,
    ReportOnlyTerminalReportV1,
    ReportOnlyVerifiedSourceV1,
    build_start_marker,
    build_terminal_report,
    canonical_artifact_json,
    publish_no_replace,
    read_private_artifact_bytes,
    stage_private_artifact,
)
from role_radar.discovery.authorization_v2 import ProviderQuotaContextV1
from role_radar.discovery.policy import ProfileBindingV1

NOW = datetime(2026, 8, 24, 12, tzinfo=UTC)
BINDING = ProfileBindingV1(
    profile_id="00000000-0000-0000-0000-000000000001",
    row_version=1,
    schema_version=1,
    canonical_profile_sha256="a" * 64,
)
CONTEXT = ProviderQuotaContextV1(
    provider="brave",
    tier="free",
    utc_month="2026-08",
    config_version="config-v1",
    unit_limit=4,
    micro_usd_limit=0,
    reservation_units_per_call=1,
    reservation_micro_usd_per_call=0,
    operation_max_calls=4,
)
GOLDEN_START_MARKER_SHA256 = "ce5378fb9b87784d5da705fd2fa21e298e7a5f945b959247f43be2bb44e54e2c"
GOLDEN_START_MARKER_HASH_PREIMAGE_BYTES = (
    b'{"authorization_expires_at_utc":"2026-08-25T12:00:00.000000Z","authorization_max_ttl_sec'
    b'onds":86400,"authorization_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddd'
    b'dddddddddddd","challenge_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccc'
    b'cccccccccc","operation_id":"00000000-0000-0000-0000-000000000002","operation_sha256":"bb'
    b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","plan_sha256":"fffffffff'
    b'fffffffffffffffffffffffffffffffffffffffffffffffffffffff","policy_sha256":"eeeeeeeeeeeeee'
    b'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","profile_binding":{"canonical_profil'
    b'e_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profile_id'
    b'":"00000000-0000-0000-0000-000000000001","row_version":1,"schema_version":1},"quota_cont'
    b'exts":[{"config_version":"config-v1","micro_usd_limit":0,"operation_max_calls":4,"provid'
    b'er":"brave","reservation_micro_usd_per_call":0,"reservation_units_per_call":1,"tier":"fr'
    b'ee","unit_limit":4,"utc_month":"2026-08"}],"schema_version":"report-only-start-marker-v1'
    b'","started_at_utc":"2026-08-24T12:00:00.000000Z"}'
)
GOLDEN_START_MARKER_ARTIFACT_BYTES = (
    b'{"authorization_expires_at_utc":"2026-08-25T12:00:00.000000Z","authorization_max_ttl_sec'
    b'onds":86400,"authorization_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddd'
    b'dddddddddddd","challenge_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccc'
    b'cccccccccc","operation_id":"00000000-0000-0000-0000-000000000002","operation_sha256":"bb'
    b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","plan_sha256":"fffffffff'
    b'fffffffffffffffffffffffffffffffffffffffffffffffffffffff","policy_sha256":"eeeeeeeeeeeeee'
    b'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","profile_binding":{"canonical_profil'
    b'e_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","profile_id'
    b'":"00000000-0000-0000-0000-000000000001","row_version":1,"schema_version":1},"quota_cont'
    b'exts":[{"config_version":"config-v1","micro_usd_limit":0,"operation_max_calls":4,"provid'
    b'er":"brave","reservation_micro_usd_per_call":0,"reservation_units_per_call":1,"tier":"fr'
    b'ee","unit_limit":4,"utc_month":"2026-08"}],"schema_version":"report-only-start-marker-v1'
    b'","start_marker_sha256":"ce5378fb9b87784d5da705fd2fa21e298e7a5f945b959247f43be2bb44e54e2'
    b'c","started_at_utc":"2026-08-24T12:00:00.000000Z"}'
)
GOLDEN_TERMINAL_REPORT_SHA256 = "657f12b2e50eb4e180e3f632f2b085ad69d4db52f7a02761bd09d296292e5873"
GOLDEN_TERMINAL_REPORT_HASH_PREIMAGE_BYTES = (
    b'{"authorization_expires_at_utc":"2026-08-25T12:00:00.000000Z","authorization_max_ttl_sec'
    b'onds":86400,"authorization_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddd'
    b'dddddddddddd","challenge_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccc'
    b'cccccccccc","completed_at_utc":"2026-08-24T12:00:01.000000Z","counts":{"board_verificati'
    b'ons_attempted":0,"boards_verified":0,"classified_hits":0,"search_requests_attempted":0,"'
    b'search_requests_completed":0,"unique_board_candidates_retained":0,"unique_board_candidat'
    b'es_seen":0,"verification_wire_attempts_consumed":0},"operation_id":"00000000-0000-0000-0'
    b'000-000000000002","operation_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    b'bbbbbbbbbbbbbb","plan_sha256":"fffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    b'fffffff","policy_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
    b'ee","profile_binding":{"canonical_profile_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    b'aaaaaaaaaaaaaaaaaaaaaaaaaaa","profile_id":"00000000-0000-0000-0000-000000000001","row_ve'
    b'rsion":1,"schema_version":1},"quota_contexts":[{"config_version":"config-v1","micro_usd_'
    b'limit":0,"operation_max_calls":4,"provider":"brave","reservation_micro_usd_per_call":0,"'
    b'reservation_units_per_call":1,"tier":"free","unit_limit":4,"utc_month":"2026-08"}],"requ'
    b'ests":[{"board_candidate_ordinal":null,"collector_request_ordinal":null,"destination":"b'
    b'rave_search_api","duration_ms":0,"error_code":null,"kind":"search","known_count":0,"oper'
    b'ation_key_sha256":"0000000000000000000000000000000000000000000000000000000000000000","ou'
    b'tcome":"not_sent","postings_count":0,"provider":"brave","query_ordinal":null,"rejected_c'
    b'ount":0,"request_identity_sha256":"00000000000000000000000000000000000000000000000000000'
    b'00000000000","request_ordinal":1,"result_count":0,"transmission":"not_sent","unknown_cou'
    b'nt":0,"wire_attempt_ordinal":null}],"schema_version":"report-only-terminal-report-v1","s'
    b'tart_marker_sha256":"ce5378fb9b87784d5da705fd2fa21e298e7a5f945b959247f43be2bb44e54e2c","'
    b'started_at_utc":"2026-08-24T12:00:00.000000Z","state":"completed_empty","terminal_code":'
    b'null,"truncation":{"board_verifications":false,"unique_board_candidates":false,"verifica'
    b'tion_wire_attempts":false},"verified_sources":[{"board_candidate_ordinal":1,"configurati'
    b'on":{"board_token":"acme"},"configuration_sha256":"1111111111111111111111111111111111111'
    b'111111111111111111111111111","postings_count":0,"request_identity_sha256":"2222222222222'
    b'222222222222222222222222222222222222222222222222222","source_key":"greenhouse:acme","sou'
    b'rce_type":"greenhouse"}]}'
)
GOLDEN_TERMINAL_REPORT_ARTIFACT_BYTES = (
    b'{"authorization_expires_at_utc":"2026-08-25T12:00:00.000000Z","authorization_max_ttl_sec'
    b'onds":86400,"authorization_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddd'
    b'dddddddddddd","challenge_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccc'
    b'cccccccccc","completed_at_utc":"2026-08-24T12:00:01.000000Z","counts":{"board_verificati'
    b'ons_attempted":0,"boards_verified":0,"classified_hits":0,"search_requests_attempted":0,"'
    b'search_requests_completed":0,"unique_board_candidates_retained":0,"unique_board_candidat'
    b'es_seen":0,"verification_wire_attempts_consumed":0},"operation_id":"00000000-0000-0000-0'
    b'000-000000000002","operation_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    b'bbbbbbbbbbbbbb","plan_sha256":"fffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    b'fffffff","policy_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
    b'ee","profile_binding":{"canonical_profile_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    b'aaaaaaaaaaaaaaaaaaaaaaaaaaa","profile_id":"00000000-0000-0000-0000-000000000001","row_ve'
    b'rsion":1,"schema_version":1},"quota_contexts":[{"config_version":"config-v1","micro_usd_'
    b'limit":0,"operation_max_calls":4,"provider":"brave","reservation_micro_usd_per_call":0,"'
    b'reservation_units_per_call":1,"tier":"free","unit_limit":4,"utc_month":"2026-08"}],"repo'
    b'rt_sha256":"657f12b2e50eb4e180e3f632f2b085ad69d4db52f7a02761bd09d296292e5873","requests"'
    b':[{"board_candidate_ordinal":null,"collector_request_ordinal":null,"destination":"brave_'
    b'search_api","duration_ms":0,"error_code":null,"kind":"search","known_count":0,"operation'
    b'_key_sha256":"0000000000000000000000000000000000000000000000000000000000000000","outcome'
    b'":"not_sent","postings_count":0,"provider":"brave","query_ordinal":null,"rejected_count"'
    b':0,"request_identity_sha256":"0000000000000000000000000000000000000000000000000000000000'
    b'000000","request_ordinal":1,"result_count":0,"transmission":"not_sent","unknown_count":0'
    b',"wire_attempt_ordinal":null}],"schema_version":"report-only-terminal-report-v1","start_'
    b'marker_sha256":"ce5378fb9b87784d5da705fd2fa21e298e7a5f945b959247f43be2bb44e54e2c","start'
    b'ed_at_utc":"2026-08-24T12:00:00.000000Z","state":"completed_empty","terminal_code":null,'
    b'"truncation":{"board_verifications":false,"unique_board_candidates":false,"verification_'
    b'wire_attempts":false},"verified_sources":[{"board_candidate_ordinal":1,"configuration":{'
    b'"board_token":"acme"},"configuration_sha256":"111111111111111111111111111111111111111111'
    b'1111111111111111111111","postings_count":0,"request_identity_sha256":"222222222222222222'
    b'2222222222222222222222222222222222222222222222","source_key":"greenhouse:acme","source_t'
    b'ype":"greenhouse"}]}'
)


def marker() -> ReportOnlyStartMarkerV1:
    return build_start_marker(
        operation_id="00000000-0000-0000-0000-000000000002",
        operation_sha256="b" * 64,
        challenge_sha256="c" * 64,
        authorization_sha256="d" * 64,
        profile_binding=BINDING,
        policy_sha256="e" * 64,
        plan_sha256="f" * 64,
        quota_contexts=(CONTEXT,),
        authorization_max_ttl_seconds=86_400,
        authorization_expires_at_utc=datetime(2026, 8, 25, 12, tzinfo=UTC),
        started_at_utc=NOW,
    )


def test_start_marker_hash_binds_exact_quota_and_window_fields() -> None:
    value = marker()
    payload = value.as_dict()
    assert payload["schema_version"] == "report-only-start-marker-v1"
    assert payload["quota_contexts"] == [CONTEXT.as_dict()]
    assert (
        value.start_marker_sha256
        == hashlib.sha256(canonical_artifact_json(value.as_dict(include_hash=False))).hexdigest()
    )
    assert (
        canonical_artifact_json(value.as_dict(include_hash=False))
        == GOLDEN_START_MARKER_HASH_PREIMAGE_BYTES
    )
    assert canonical_artifact_json(value.as_dict()) == GOLDEN_START_MARKER_ARTIFACT_BYTES
    assert (
        hashlib.sha256(GOLDEN_START_MARKER_HASH_PREIMAGE_BYTES).hexdigest()
        == GOLDEN_START_MARKER_SHA256
    )


def test_terminal_report_has_exact_bounded_arrays() -> None:
    value: ReportOnlyTerminalReportV1 = build_terminal_report(
        operation_id="00000000-0000-0000-0000-000000000002",
        operation_sha256="b" * 64,
        challenge_sha256="c" * 64,
        start_marker_sha256=marker().start_marker_sha256,
        authorization_sha256="d" * 64,
        profile_binding=BINDING,
        policy_sha256="e" * 64,
        plan_sha256="f" * 64,
        quota_contexts=(CONTEXT,),
        authorization_max_ttl_seconds=86_400,
        authorization_expires_at_utc=datetime(2026, 8, 25, 12, tzinfo=UTC),
        state="completed_empty",
        started_at_utc=NOW,
        completed_at_utc=NOW.replace(second=1),
        counts={
            key: 0
            for key in (
                "search_requests_attempted",
                "search_requests_completed",
                "classified_hits",
                "unique_board_candidates_seen",
                "unique_board_candidates_retained",
                "board_verifications_attempted",
                "boards_verified",
                "verification_wire_attempts_consumed",
            )
        },
        truncation={
            "unique_board_candidates": False,
            "board_verifications": False,
            "verification_wire_attempts": False,
        },
        requests=(
            ReportOnlyRequestEvidenceV1(
                request_ordinal=1,
                kind="search",
                provider="brave",
                destination="brave_search_api",
            ),
        ),
        verified_sources=(
            ReportOnlyVerifiedSourceV1(
                source_type="greenhouse",
                source_key="greenhouse:acme",
                configuration={"board_token": "acme"},
                configuration_sha256="1" * 64,
                postings_count=0,
                board_candidate_ordinal=1,
                request_identity_sha256="2" * 64,
            ),
        ),
    )
    assert value.as_dict()["state"] == "completed_empty"
    assert value.report_sha256 != "0" * 64
    assert (
        canonical_artifact_json(value.as_dict(include_hash=False))
        == GOLDEN_TERMINAL_REPORT_HASH_PREIMAGE_BYTES
    )
    assert canonical_artifact_json(value.as_dict()) == GOLDEN_TERMINAL_REPORT_ARTIFACT_BYTES
    assert (
        hashlib.sha256(GOLDEN_TERMINAL_REPORT_HASH_PREIMAGE_BYTES).hexdigest()
        == GOLDEN_TERMINAL_REPORT_SHA256
    )


def test_private_publication_is_no_replace(tmp_path: Path) -> None:
    staging = stage_private_artifact(tmp_path, "operation-v1.json", b"{}")
    target = tmp_path / "operation-v1.json"
    publish_no_replace(staging, target)
    assert read_private_artifact_bytes(tmp_path, "operation-v1.json") == b"{}"
    staging = stage_private_artifact(tmp_path, "operation-v1.json", b"changed")
    with pytest.raises(DiscoveryArtifactError) as error:
        publish_no_replace(staging, target)
    assert error.value.code == "artifact_exists"
