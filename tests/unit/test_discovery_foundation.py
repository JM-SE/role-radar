"""Pure and persistence seams for the F8.4 discovery foundation."""

from sqlalchemy.orm import Session

from role_radar.discovery.contracts import (
    GreenhouseOfficialCandidate,
    LeverOfficialCandidate,
    RejectedCandidate,
    UnknownCandidate,
)
from role_radar.discovery.planner import MAX_QUERIES_PER_CYCLE, QueryPlannerV1
from role_radar.discovery.policy import MAX_NEW_SOURCES_PER_RUN
from role_radar.discovery.query_keys import QueryKeyFactory
from role_radar.discovery.url_classifier import classify_url
from role_radar.domain.profile import CandidateProfileV1
from role_radar.services.discovered_source_service import DiscoveredSourceService


def _profile(**overrides: object) -> CandidateProfileV1:
    values: dict[str, object] = {
        "title": "backend engineer",
        "years_of_experience": 8,
        "target_roles": ["backend", "platform"],
        "target_titles": ["backend engineer"],
        "core_skills": ["python", "secret-employer-name"],
        "secondary_skills": ["docker"],
        "regions": ["spain", "madrid"],
        "remote_only": True,
        "employment_preferences": ["full_time"],
        "languages": {"english": "professional"},
        "excluded_roles": [],
        "excluded_technologies": [],
        "hard_constraints": {
            "available_work_authorizations": [],
            "unavailable_work_authorizations": [],
            "allowed_employment_types": [],
        },
        "soft_preferences": {"preferred_industries": []},
    }
    values.update(overrides)
    return CandidateProfileV1.model_validate(values)


def test_planner_is_deterministic_bounded_and_excludes_free_text() -> None:
    planner = QueryPlannerV1()

    first = planner.plan(_profile())
    second = planner.plan(
        _profile(
            target_roles=["platform", "backend"],
            regions=["madrid", "spain"],
            core_skills=["secret-employer-name", "python"],
        )
    )

    assert first == second
    assert len(first) <= MAX_QUERIES_PER_CYCLE
    assert [item.ordinal for item in first] == list(range(len(first)))
    assert all("secret-employer-name" not in item.canonical_query for item in first)
    assert all("madrid" not in item.canonical_query for item in first)


def test_query_keys_are_hmac_only_and_stable() -> None:
    planner = QueryPlannerV1()
    query = planner.plan(_profile())[0]
    factory = QueryKeyFactory("test-secret")

    identity = factory.identities((query,), planner_version=planner.version)[0]

    assert len(identity.query_key) == 64
    assert query.canonical_query not in identity.query_key
    assert factory.matches(identity.query_key, identity.query_key)
    assert not factory.matches(identity.query_key, "0" * 64)


def test_classifier_accepts_only_known_official_ats_shapes() -> None:
    greenhouse = classify_url("https://boards.greenhouse.io/acme/jobs/123")
    lever = classify_url("https://jobs.eu.lever.co/acme/abc123/apply")

    assert isinstance(greenhouse, GreenhouseOfficialCandidate)
    assert greenhouse.board_token == "acme"
    assert isinstance(lever, LeverOfficialCandidate)
    assert lever.site == "acme"
    assert lever.region == "eu"

    assert isinstance(classify_url("https://boards.greenhouse.io.evil.test/acme"), UnknownCandidate)
    assert isinstance(
        classify_url("https://boards.greenhouse.io/acme?utm_source=x"), RejectedCandidate
    )
    assert isinstance(classify_url("http://jobs.lever.co/acme"), RejectedCandidate)
    assert isinstance(classify_url("https://jobs.lever.co/acme/../secret"), RejectedCandidate)


def test_discovered_source_registration_is_worker_owned_and_capped(db_session: Session) -> None:
    service = DiscoveredSourceService(db_session, max_new_per_run=1, max_active=1)
    candidate = GreenhouseOfficialCandidate("https://boards.greenhouse.io/acme", "acme")

    registration = service.register_verified(candidate)
    db_session.commit()

    assert registration.created is True
    assert registration.linked is True
    assert registration.blocked is False
    assert registration.source_id is not None

    duplicate = service.register_verified(candidate)
    assert duplicate.created is False
    assert duplicate.source_id == registration.source_id


def test_discovered_source_registration_enforces_per_run_cap(db_session: Session) -> None:
    service = DiscoveredSourceService(db_session)
    registrations = [
        service.register_verified(
            GreenhouseOfficialCandidate(
                f"https://boards.greenhouse.io/board-{index}", f"board-{index}"
            ),
            new_sources_used=index,
        )
        for index in range(MAX_NEW_SOURCES_PER_RUN + 1)
    ]

    assert sum(item.created for item in registrations) == MAX_NEW_SOURCES_PER_RUN
    assert registrations[-1].source_id is None
    assert registrations[-1].created is False
    assert registrations[-1].blocked is True
