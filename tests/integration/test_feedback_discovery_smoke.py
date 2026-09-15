"""Offline smoke: v2 prepare, Null-provider execute, terminal finalize."""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy.orm import Session

from role_radar.db.models import CandidateProfile
from role_radar.discovery.policy import DiscoveryPhraseGrammarV1, DiscoveryPolicyV1
from role_radar.domain.enums import DiscoveryCycleStatus, DiscoveryMode
from role_radar.domain.profile import canonical_profile_sha256
from role_radar.repositories.discovery import DiscoveryRepository
from role_radar.repositories.runs import RunRepository
from role_radar.services.pipeline_discovery import PipelineDiscoveryService

PROFILE_PAYLOAD = {
    "title": "backend engineer",
    "years_of_experience": 8,
    "target_roles": ["backend"],
    "target_titles": ["backend engineer"],
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

SECRET = b"0123456789abcdef0123456789abcdef"


async def test_v2_prepare_execute_finalize_reaches_terminal_cycle(
    db_session: Session,
) -> None:
    profile_id = str(uuid4())
    db_session.add(
        CandidateProfile(
            id=profile_id,
            name=f"qa-{profile_id[:8]}",
            version=1,
            schema_version=1,
            profile_json=PROFILE_PAYLOAD,
            is_active=True,
        )
    )
    run = RunRepository(db_session).create_run(
        "test", profile_id=profile_id, discovery_mode=DiscoveryMode.SCHEDULED_DUE
    )
    policy = DiscoveryPolicyV1.model_validate(
        {
            "schema_version": 1,
            "policy_version": "gate-a-v1",
            "profile_binding": {
                "profile_id": profile_id,
                "row_version": 1,
                "schema_version": 1,
                "canonical_profile_sha256": canonical_profile_sha256(PROFILE_PAYLOAD),
            },
            "phrase_grammar": DiscoveryPhraseGrammarV1().model_dump(mode="python"),
            "groups": {"backend": ("Backend Engineer",)},
            "target_roles": {"backend": {"primary_groups": ["backend"]}},
            "target_titles": {"backend engineer": {"primary_groups": ["backend"]}},
        }
    )
    service = PipelineDiscoveryService(
        lambda: db_session, query_key_secret=SECRET, discovery_policy_v1=policy
    )
    run_id = run.id
    plan = service.prepare(run_id)
    assert plan is not None
    assert plan.planner_version == "discovery-planner-v2"
    execution = await service.execute(plan)
    assert execution.plan.cycle_id == plan.cycle_id
    finalization = service.finalize(execution)
    assert finalization.cycle_id == plan.cycle_id
    cycle = DiscoveryRepository(db_session).get_cycle_for_run(run_id)
    assert cycle is not None
    assert cycle.status in {
        DiscoveryCycleStatus.COMPLETED,
        DiscoveryCycleStatus.DEGRADED,
    }
