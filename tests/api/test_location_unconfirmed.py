from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy.orm import Session

from role_radar.domain.dto import RawJob
from role_radar.domain.enums import SourceType
from role_radar.domain.profile import CandidateProfileV1
from role_radar.execution_budget import CANARY_BUDGET
from role_radar.repositories.profiles import ProfileRepository
from role_radar.repositories.runs import RunRepository
from role_radar.repositories.sources import SourceRepository
from role_radar.services.acquired_job_writer import AcquiredJobWriter


def _profile() -> dict[str, object]:
    return CandidateProfileV1.model_validate(
        {
            "title": None,
            "years_of_experience": None,
            "target_roles": ["frontend"],
            "target_titles": [],
            "core_skills": [],
            "secondary_skills": [],
            "regions": ["argentina"],
            "remote_only": True,
            "employment_preferences": [],
            "languages": {},
            "excluded_roles": [],
            "excluded_technologies": [],
            "hard_constraints": {
                "available_work_authorizations": ["argentina"],
                "unavailable_work_authorizations": [],
                "allowed_employment_types": [],
                "allowed_remote_policies": [],
            },
            "soft_preferences": {},
        }
    ).model_dump(mode="json")


def _context(db_session: Session, *, canary: bool = False):
    profile = ProfileRepository(db_session).create_v1(
        name="review-profile", profile_json=_profile()
    )
    source = SourceRepository(db_session).create(
        type=SourceType.GREENHOUSE,
        name="Acme",
        configuration={"board_token": "acme"},
        enabled=True,
    )
    run = RunRepository(db_session).create_run("location-review", profile_id=profile.id)
    if canary:
        run.canary_budget_json = dict(CANARY_BUDGET)
    db_session.commit()
    return profile, source, run


def _unknown_region_job(external_id: str = "review-me") -> RawJob:
    url = f"https://boards.greenhouse.io/acme/jobs/{external_id}"
    return RawJob(
        source="greenhouse",
        external_id=external_id,
        title="Senior Frontend Engineer",
        company="Acme",
        location="Remote",
        source_url=url,
        application_url=url,
        description="Build frontend products with the Acme team.",
        structured_data={"id": external_id, "remote_policy": "remote"},
        collected_at=datetime.now(UTC),
    )


async def _review_list(client: httpx.AsyncClient, profile_id: str) -> list[dict[str, object]]:
    response = await client.get("/jobs/location-unconfirmed", params={"profile_id": profile_id})
    assert response.status_code == 200
    return response.json()


async def test_review_endpoint_separates_unknown_region_from_eligible_jobs(
    client: httpx.AsyncClient, db_session: Session
) -> None:
    profile, source, run = _context(db_session)
    result = AcquiredJobWriter(db_session).write(
        run_id=run.id,
        source_id=source.id,
        raw_jobs=(_unknown_region_job(),),
        max_clarification_attempts=0,
    )
    db_session.commit()

    assert result.accepted == 0
    assert result.profile_rejected == 1

    ordinary = await client.get("/jobs")
    assert ordinary.status_code == 200
    assert ordinary.json() == []
    eligible = await client.get("/jobs", params={"profile_id": profile.id, "eligible": True})
    assert eligible.status_code == 200
    assert eligible.json() == []

    response = await client.get("/jobs/location-unconfirmed", params={"profile_id": profile.id})
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert set(body[0]) == {
        "id",
        "title",
        "company",
        "location",
        "source_id",
        "external_id",
        "source_url",
        "application_url",
        "reason_code",
        "first_seen_at",
        "last_seen_at",
    }
    assert body[0]["id"]
    assert body[0]["title"] == "Senior Frontend Engineer"
    assert body[0]["company"] == "Acme"
    assert body[0]["location"] == "Remote"
    assert body[0]["source_id"] == source.id
    assert body[0]["external_id"] == "review-me"
    assert body[0]["source_url"] == "https://boards.greenhouse.io/acme/jobs/review-me"
    assert body[0]["application_url"] == "https://boards.greenhouse.io/acme/jobs/review-me"
    assert body[0]["reason_code"] == "region_unknown"
    assert "eligible" not in body[0]
    assert "latest_score" not in body[0]


async def test_review_accepts_only_sole_unknown_region_with_valid_application_url(
    client: httpx.AsyncClient, db_session: Session
) -> None:
    profile, source, run = _context(db_session)
    valid = _unknown_region_job("valid")
    invalid_url = _unknown_region_job("invalid-url").model_copy(
        update={
            "application_url": "javascript:alert(1)",
            "source_url": "javascript:alert(1)",
        }
    )
    role_mismatch = _unknown_region_job("wrong-role").model_copy(
        update={"title": "Senior Backend Engineer"}
    )
    incompatible = _unknown_region_job("us-only").model_copy(
        update={"location": "Remote - United States"}
    )
    result = AcquiredJobWriter(db_session).write(
        run_id=run.id,
        source_id=source.id,
        raw_jobs=(valid, invalid_url, role_mismatch, incompatible),
        max_clarification_attempts=0,
    )
    db_session.commit()

    assert result.accepted == 0
    assert result.profile_rejected == 3
    assert result.prefiltered == 1
    reviews = await _review_list(client, profile.id)
    assert len(reviews) == 1
    assert reviews[0]["external_id"] == "valid"
    assert reviews[0]["reason_code"] == "region_unknown"
    assert reviews[0]["application_url"] == "https://boards.greenhouse.io/acme/jobs/valid"


async def test_review_refreshes_observation_then_removes_it_when_location_is_confirmed(
    client: httpx.AsyncClient, db_session: Session
) -> None:
    profile, source, run = _context(db_session)
    first = _unknown_region_job()
    AcquiredJobWriter(db_session).write(
        run_id=run.id, source_id=source.id, raw_jobs=(first,), max_clarification_attempts=0
    )
    db_session.commit()
    original = (await _review_list(client, profile.id))[0]

    refreshed = first.model_copy(
        update={
            "company": "Acme Updated",
            "collected_at": first.collected_at + timedelta(minutes=1),
        }
    )
    AcquiredJobWriter(db_session).write(
        run_id=run.id, source_id=source.id, raw_jobs=(refreshed,), max_clarification_attempts=0
    )
    db_session.commit()
    current = (await _review_list(client, profile.id))[0]
    assert current["id"] == original["id"]
    assert current["company"] == "Acme Updated"
    assert current["first_seen_at"] == original["first_seen_at"]
    assert current["last_seen_at"] != original["last_seen_at"]

    confirmed = first.model_copy(
        update={
            "location": "Remote - Argentina",
            "collected_at": first.collected_at + timedelta(minutes=2),
        }
    )
    result = AcquiredJobWriter(db_session).write(
        run_id=run.id, source_id=source.id, raw_jobs=(confirmed,), max_clarification_attempts=0
    )
    db_session.commit()
    assert result.accepted == 1
    assert await _review_list(client, profile.id) == []
    ordinary = await client.get("/jobs")
    assert ordinary.status_code == 200
    assert len(ordinary.json()) == 1


async def test_review_hides_rows_bound_to_an_old_profile_version(
    client: httpx.AsyncClient, db_session: Session
) -> None:
    profile, source, run = _context(db_session)
    AcquiredJobWriter(db_session).write(
        run_id=run.id,
        source_id=source.id,
        raw_jobs=(_unknown_region_job(),),
        max_clarification_attempts=0,
    )
    db_session.commit()
    assert len(await _review_list(client, profile.id)) == 1

    profile.version += 1
    changed_profile = dict(profile.profile_json)
    changed_profile["title"] = "Updated profile"
    profile.profile_json = changed_profile
    db_session.commit()

    assert await _review_list(client, profile.id) == []


async def test_canary_does_not_create_update_or_remove_review_observations(
    client: httpx.AsyncClient, db_session: Session
) -> None:
    profile, source, normal_run = _context(db_session)
    original = _unknown_region_job()
    AcquiredJobWriter(db_session).write(
        run_id=normal_run.id,
        source_id=source.id,
        raw_jobs=(original,),
        max_clarification_attempts=0,
    )
    db_session.commit()
    before = (await _review_list(client, profile.id))[0]

    canary_run = RunRepository(db_session).create_run(
        "location-review-canary", profile_id=profile.id
    )
    canary_run.canary_budget_json = dict(CANARY_BUDGET)
    db_session.commit()
    update = original.model_copy(update={"company": "Canary Change"})
    new_unknown = _unknown_region_job("canary-new")
    confirmed = original.model_copy(update={"location": "Remote - Argentina"})
    AcquiredJobWriter(db_session).write(
        run_id=canary_run.id,
        source_id=source.id,
        raw_jobs=(update, new_unknown, confirmed),
        max_clarification_attempts=0,
    )
    db_session.commit()

    after = await _review_list(client, profile.id)
    assert len(after) == 1
    assert after[0] == before
