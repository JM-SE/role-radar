"""Normal discovery through the profile-bound v2 compiler/planner."""

from __future__ import annotations

import warnings
from uuid import uuid4

import pytest

from role_radar.db.models import CandidateProfile
from role_radar.discovery.policy import DiscoveryPhraseGrammarV1, DiscoveryPolicyV1
from role_radar.domain.enums import DiscoveryCycleStatus, DiscoveryMode
from role_radar.domain.profile import canonical_profile_sha256
from role_radar.repositories.discovery import DiscoveryRepository
from role_radar.repositories.runs import RunRepository
from role_radar.services.pipeline_discovery import PipelineDiscoveryService

SECRET = b"0123456789abcdef0123456789abcdef"


def fresh_profile_id() -> str:
    return str(uuid4())


def profile_payload(titles: tuple[str, ...]) -> dict:
    return {
        "title": "backend engineer",
        "years_of_experience": 8,
        "target_roles": ["backend"],
        "target_titles": list(titles),
        "core_skills": ["python"],
        "secondary_skills": [],
        "regions": ["europe"],
        "remote_only": True,
        "employment_preferences": ["full_time"],
        "languages": {"english": "professional"},
        "excluded_roles": [],
        "excluded_technologies": [],
        "hard_constraints": {
            "available_work_authorizations": [],
            "unavailable_work_authorizations": [],
            "allowed_employment_types": [],
            "allowed_remote_policies": [],
        },
        "soft_preferences": {"preferred_industries": []},
    }


def policy_for(profile_id: str, payload: dict, version: str) -> DiscoveryPolicyV1:
    return DiscoveryPolicyV1.model_validate(
        {
            "schema_version": 1,
            "policy_version": version,
            "profile_binding": {
                "profile_id": profile_id,
                "row_version": 1,
                "schema_version": 1,
                "canonical_profile_sha256": canonical_profile_sha256(payload),
            },
            "phrase_grammar": DiscoveryPhraseGrammarV1().model_dump(mode="json"),
            "groups": {
                "backend": ("Backend Engineer",),
                "platform": ("Platform Engineer",),
            },
            "target_roles": {"backend": {"primary_groups": ["backend"]}},
            "target_titles": {
                "backend engineer": {"primary_groups": ["backend"]},
                "platform engineer": {"primary_groups": ["platform"]},
            },
        }
    )


def seed_profile(db_session, profile_id: str, payload: dict) -> None:
    db_session.add(
        CandidateProfile(
            id=profile_id,
            name=f"qa-{profile_id[:8]}",
            version=1,
            schema_version=1,
            profile_json=payload,
            is_active=True,
        )
    )
    db_session.flush()


def seed_run(db_session, profile_id: str) -> str:
    run = RunRepository(db_session).create_run(
        "test", profile_id=profile_id, discovery_mode=DiscoveryMode.SCHEDULED_DUE
    )
    db_session.flush()
    return run.id


def test_v2_plan_uses_bound_phrases(db_session) -> None:
    profile_id = fresh_profile_id()
    payload = profile_payload(("backend engineer",))
    seed_profile(db_session, profile_id, payload)
    run_id = seed_run(db_session, profile_id)
    service = PipelineDiscoveryService(
        lambda: db_session,
        query_key_secret=SECRET,
        discovery_policy_v1=policy_for(profile_id, payload, "gate-a-v1"),
    )
    plan = service.prepare(run_id)
    assert plan is not None
    assert plan.planner_version == "discovery-planner-v2"
    assert plan.policy_version == "gate-a-v1"
    assert len(plan.queries) == 4
    assert {query.ordinal for query in plan.queries} == {1, 2, 3, 4}
    assert all("Backend Engineer" in query.canonical_query for query in plan.queries)
    assert len(plan.identities) == 4
    assert plan.planner_hash != "query_key_unavailable"
    assert plan.profile_snapshot["approved_phrases"] == ["Backend Engineer"]
    snapshot = dict(plan.profile_snapshot)
    assert snapshot["discovery_planner"] == "v2"
    assert len(snapshot["plan_sha256"]) == 64
    assert len(snapshot["policy_sha256"]) == 64
    assert snapshot["profile_binding"]["profile_id"] == profile_id
    cycle = DiscoveryRepository(db_session).get_cycle_for_run(run_id)
    assert cycle is not None
    assert cycle.planner_version == "discovery-planner-v2"


def test_title_change_shifts_planned_queries(db_session) -> None:
    profile_a = fresh_profile_id()
    profile_b = fresh_profile_id()
    payload_a = profile_payload(("backend engineer",))
    payload_b = profile_payload(("platform engineer",))
    seed_profile(db_session, profile_a, payload_a)
    seed_profile(db_session, profile_b, payload_b)
    run_a = seed_run(db_session, profile_a)
    run_b = seed_run(db_session, profile_b)
    service_a = PipelineDiscoveryService(
        lambda: db_session,
        query_key_secret=SECRET,
        discovery_policy_v1=policy_for(profile_a, payload_a, "gate-a-v1"),
    )
    service_b = PipelineDiscoveryService(
        lambda: db_session,
        query_key_secret=SECRET,
        discovery_policy_v1=policy_for(profile_b, payload_b, "gate-a-v1"),
    )
    plan_a = service_a.prepare(run_a)
    plan_b = service_b.prepare(run_b)
    assert plan_a is not None and plan_b is not None
    queries_a = {query.canonical_query for query in plan_a.queries}
    queries_b = {query.canonical_query for query in plan_b.queries}
    assert queries_a != queries_b
    assert all("Platform Engineer" in query for query in queries_b)


def test_binding_mismatch_falls_back_to_v1(db_session) -> None:
    profile_id = fresh_profile_id()
    payload = profile_payload(("backend engineer",))
    seed_profile(db_session, profile_id, payload)
    run_id = seed_run(db_session, profile_id)
    foreign = policy_for(fresh_profile_id(), profile_payload(("platform engineer",)), "gate-a-v1")
    service = PipelineDiscoveryService(
        lambda: db_session,
        query_key_secret=SECRET,
        discovery_policy_v1=foreign,
    )
    with pytest.warns(UserWarning, match="discovery_v2_binding_mismatch"):
        plan = service.prepare(run_id)
    assert plan is not None
    assert plan.planner_version == "query-planner-v1"


def test_unconfigured_policy_keeps_v1_without_warning(db_session) -> None:
    profile_id = fresh_profile_id()
    payload = profile_payload(("backend engineer",))
    seed_profile(db_session, profile_id, payload)
    run_id = seed_run(db_session, profile_id)
    service = PipelineDiscoveryService(lambda: db_session, query_key_secret=SECRET)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        plan = service.prepare(run_id)
    assert plan is not None
    assert plan.planner_version == "query-planner-v1"


def test_terminal_cycle_replays_previous_plan(db_session) -> None:
    profile_id = fresh_profile_id()
    payload = profile_payload(("backend engineer",))
    seed_profile(db_session, profile_id, payload)
    run_id = seed_run(db_session, profile_id)
    service = PipelineDiscoveryService(
        lambda: db_session,
        query_key_secret=SECRET,
        discovery_policy_v1=policy_for(profile_id, payload, "gate-a-v1"),
    )
    first = service.prepare(run_id)
    assert first is not None
    cycle = DiscoveryRepository(db_session).get_cycle_for_run(run_id)
    assert cycle is not None
    cycle.status = DiscoveryCycleStatus.COMPLETED
    db_session.commit()
    second = service.prepare(run_id)
    assert second is not None
    assert second.reused is True
    assert second.cycle_id == first.cycle_id
