from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

from role_radar.collectors.outcomes import CollectionMetrics, CollectionSuccess
from role_radar.collectors.protocols import SourceSnapshot
from role_radar.db.models import CandidateProfile
from role_radar.discovery.contracts import (
    DiscoveryExecution,
    DiscoveryPlan,
    GreenhouseOfficialCandidate,
    VerifiedBatch,
)
from role_radar.domain.dto import RawJob
from role_radar.domain.enums import DiscoveryMode, SourceType
from role_radar.repositories.discovery import DiscoveryRepository
from role_radar.repositories.runs import RunRepository
from role_radar.repositories.sources import SourceRepository
from role_radar.services.acquired_job_writer import AcquiredJobWriter, AcquiredWriteResult
from role_radar.services.pipeline_discovery import PipelineDiscoveryService


def _profile() -> dict:
    return {
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


def test_finalize_persists_bounded_writer_diagnostics_across_zero_accept_writes(
    db_session, monkeypatch
) -> None:
    profile_id = str(uuid4())
    db_session.add(
        CandidateProfile(
            id=profile_id,
            name="synthetic",
            version=1,
            schema_version=1,
            profile_json=_profile(),
            is_active=True,
        )
    )
    run = RunRepository(db_session).create_run(
        "test", profile_id=profile_id, discovery_mode=DiscoveryMode.SCHEDULED_DUE
    )
    run_id = run.id
    SourceRepository(db_session).create(
        type=SourceType.GREENHOUSE,
        name="Synthetic board",
        configuration={"board_token": "synthetic-board"},
    )
    cycle = DiscoveryRepository(db_session).create_cycle(
        run_id=run.id,
        profile_snapshot={},
        planner_version="test",
        planner_hash="test",
        policy_version="test",
    )
    db_session.commit()

    candidate = GreenhouseOfficialCandidate(
        "https://boards.greenhouse.io/synthetic-board", "synthetic-board"
    )
    batch = VerifiedBatch(
        candidate=candidate,
        snapshot=SourceSnapshot(
            "synthetic", "greenhouse", "synthetic", {"board_token": "synthetic-board"}
        ),
        outcome=CollectionSuccess("ok", (), CollectionMetrics()),
        jobs=(),
    )
    plan = DiscoveryPlan(run.id, cycle.id, {}, (), (), "test", "test", "test")
    execution = DiscoveryExecution(plan, (), (batch, batch))
    results = iter(
        (
            AcquiredWriteResult(
                accepted=0,
                new_jobs=0,
                duplicates=0,
                prefiltered=1,
                profile_rejected=2,
                clarification_attempts=1,
                profile_reason_counts=(("role_mismatch", 2), ("private-profile-field", 99)),
                job_ids=(),
            ),
            AcquiredWriteResult(
                accepted=0,
                new_jobs=0,
                duplicates=0,
                prefiltered=2,
                profile_rejected=1,
                clarification_attempts=0,
                profile_reason_counts=(("role_mismatch", 1), ("private-profile-field", 99)),
                job_ids=(),
            ),
        )
    )
    monkeypatch.setattr(AcquiredJobWriter, "write", lambda *_args, **_kwargs: next(results))

    PipelineDiscoveryService(lambda: db_session).finalize(execution)

    stats = DiscoveryRepository(db_session).get_cycle_for_run(run_id).stats_json
    assert stats == {
        "queries": 0,
        "candidates": 0,
        "known": 0,
        "unknown": 0,
        "rejected": 0,
        "verified_sources": 2,
        "verified_jobs": 0,
        "blocked": 0,
        "writer_prefiltered": 3,
        "writer_profile_rejected": 3,
        "profile_rejected_role_mismatch": 3,
    }


def test_writer_adds_missing_application_url_reason_once(db_session, monkeypatch) -> None:
    import role_radar.services.acquired_job_writer as writer_module

    profile_id = str(uuid4())
    db_session.add(
        CandidateProfile(
            id=profile_id,
            name="synthetic",
            version=1,
            schema_version=1,
            profile_json=_profile(),
            is_active=True,
        )
    )
    run = RunRepository(db_session).create_run("test", profile_id=profile_id)
    source = SourceRepository(db_session).create(
        type=SourceType.GREENHOUSE,
        name="Synthetic board",
        configuration={"board_token": "synthetic-board"},
    )
    db_session.commit()
    decisions = iter(
        (
            SimpleNamespace(
                eligible=False,
                application_url=None,
                reason_codes=("role_mismatch",),
                intake_evidence=None,
            ),
            SimpleNamespace(
                eligible=False,
                application_url=None,
                reason_codes=("application_url_missing_or_invalid",),
                intake_evidence=None,
            ),
        )
    )
    monkeypatch.setattr(
        writer_module,
        "evaluate_profile_intake",
        lambda *_args, **_kwargs: next(decisions),
    )
    raw_jobs = tuple(
        RawJob(
            source="greenhouse",
            external_id=str(index),
            source_url=f"https://boards.greenhouse.io/synthetic-board/jobs/{index}",
            title="Backend Engineer",
            company="Synthetic",
            description="Synthetic description",
            collected_at=datetime.now(UTC),
        )
        for index in (1, 2)
    )

    result = AcquiredJobWriter(db_session).write(
        run_id=run.id, source_id=source.id, raw_jobs=raw_jobs
    )

    assert result.accepted == 0
    assert result.profile_rejected == 2
    assert result.profile_reason_counts == (
        ("application_url_missing_or_invalid", 2),
        ("role_mismatch", 1),
    )
