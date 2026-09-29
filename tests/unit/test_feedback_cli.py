"""End-to-end coverage of the current product feedback CLI namespace."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from role_radar.cli.main import main
from role_radar.db.base import Base
from role_radar.db.models import CandidateProfile
from role_radar.discovery.policy import DiscoveryPhraseGrammarV1, DiscoveryPolicyV1
from role_radar.domain.enums import DiscoveryMode, RunJobStage, RunJobStatus
from role_radar.domain.profile import canonical_profile_sha256
from role_radar.evaluation.blind_labeling.display_policy import (
    DISPLAY_ERROR_HTML_MALFORMED,
    DisplayError,
)
from role_radar.repositories.discovery import DiscoveryRepository
from role_radar.services.feedback_refinement import emit_policy_toml, policy_payload

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


def make_policy(profile_id: str, version: str) -> DiscoveryPolicyV1:
    return DiscoveryPolicyV1.model_validate(
        {
            "schema_version": 1,
            "policy_version": version,
            "profile_binding": {
                "profile_id": profile_id,
                "row_version": 1,
                "schema_version": 1,
                "canonical_profile_sha256": canonical_profile_sha256(PROFILE_PAYLOAD),
            },
            "phrase_grammar": DiscoveryPhraseGrammarV1().model_dump(mode="python"),
            "groups": {"backend": ("Backend Engineer",), "legacy": ("COBOL",)},
            "target_roles": {"backend": {"primary_groups": ["backend"]}},
            "target_titles": {
                "backend engineer": {
                    "primary_groups": ["backend"],
                    "coverage_groups": ["legacy"],
                }
            },
        }
    )


def seed_database(
    database: Path,
    legacy_jobs: int = 1,
    relevant_description: str = "Backend Engineer with Python daily",
) -> tuple[str, str, tuple[str, ...]]:
    import role_radar.db.models  # noqa: F401
    from role_radar.repositories.jobs import JobRepository
    from role_radar.repositories.run_jobs import RunJobRepository
    from role_radar.repositories.runs import RunRepository

    engine = create_engine(f"sqlite:///{database}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    session = factory()
    profile_id = str(uuid4())
    session.add(
        CandidateProfile(
            id=profile_id,
            name=f"qa-{profile_id[:8]}",
            version=1,
            schema_version=1,
            profile_json={},
            is_active=True,
        )
    )
    run = RunRepository(session).create_run(
        "test", profile_id=profile_id, discovery_mode=DiscoveryMode.SCHEDULED_DUE
    )
    DiscoveryRepository(session).create_cycle(
        run_id=run.id,
        profile_snapshot={
            "approved_phrases": ["Backend Engineer", "COBOL"],
            "profile_binding": {
                "profile_id": profile_id,
                "row_version": 1,
                "schema_version": 1,
                "canonical_profile_sha256": canonical_profile_sha256(PROFILE_PAYLOAD),
            },
        },
        planner_version="discovery-planner-v2",
        planner_hash="0" * 64,
        policy_version="gate-a-v1",
    )
    job_ids = []
    postings = [("Backend Engineer", relevant_description)]
    postings.extend(
        ("Java Developer", f"COBOL maintenance role {index}") for index in range(legacy_jobs)
    )
    for title, description in postings:
        job = JobRepository(session).create(
            title=title,
            company="Acme",
            description=description,
            description_hash=str(uuid4()).replace("-", ""),
        )
        row = RunJobRepository(session).claim_attempt(
            run_id=run.id,
            job_id=job.id,
            stage=RunJobStage.DEDUPLICATED,
            max_attempts=3,
            now=datetime.now(UTC),
        )
        assert row is not None
        RunJobRepository(session).finish(
            row, status=RunJobStatus.SUCCEEDED, outcome={"acquisition": "discovery"}
        )
        scored = RunJobRepository(session).claim_attempt(
            run_id=run.id,
            job_id=job.id,
            stage=RunJobStage.SCORED,
            max_attempts=3,
            now=datetime.now(UTC),
        )
        assert scored is not None
        RunJobRepository(session).finish(
            scored,
            status=RunJobStatus.SUCCEEDED,
            outcome={
                "product_eligibility": {
                    "policy_version": "product-eligibility-v1",
                    "profile_binding": {
                        "profile_id": profile_id,
                        "row_version": 1,
                        "schema_version": 1,
                        "canonical_profile_sha256": canonical_profile_sha256(PROFILE_PAYLOAD),
                    },
                    "input_sha256": "1" * 64,
                    "eligible": True,
                    "reason_codes": ["exact_region_match"],
                    "extraction_id": "fixture-extraction",
                }
            },
        )
        job_ids.append(job.id)
    wanted_run_id = run.id
    wanted_job_ids = tuple(job_ids)
    session.commit()
    session.close()
    engine.dispose()
    return wanted_run_id, wanted_job_ids[0], wanted_job_ids[1:]


def write_policy(tmp_path: Path, profile_id: str) -> Path:
    path = tmp_path / "discovery-policy.toml"
    path.write_text(
        emit_policy_toml(policy_payload(make_policy(profile_id, "gate-a-v1"))),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)
    return path


def run_cli(
    monkeypatch: Any, capsys: Any, database: Path, *argv: str
) -> tuple[int, dict[str, Any]]:
    monkeypatch.setenv("ROLE_RADAR_DATABASE_URL", f"sqlite:///{database}")
    code = main(["feedback", *argv])
    out = capsys.readouterr().out.strip()
    return code, json.loads(out)


def test_status_next_decide_summary(monkeypatch: Any, capsys: Any, tmp_path: Path) -> None:
    database = tmp_path / "feedback.db"
    run_id, relevant, _legacy = seed_database(database)
    code, status = run_cli(monkeypatch, capsys, database, "status", "--run", run_id)
    assert code == 0
    assert status["result"] == "ok"
    assert status["candidates"] == 2

    code, first = run_cli(monkeypatch, capsys, database, "next", "--run", run_id)
    assert code == 0
    assert first["job_id"] == relevant
    assert "Backend Engineer" in first["rendered"]

    code, decided = run_cli(
        monkeypatch,
        capsys,
        database,
        "decide",
        "--run",
        run_id,
        "--job",
        relevant,
        "--label",
        "apply",
        "--reason",
        "skills_match",
    )
    assert code == 0
    assert decided["result"] == "decided"
    assert decided["revision"] == 1

    code, replayed = run_cli(
        monkeypatch,
        capsys,
        database,
        "decide",
        "--run",
        run_id,
        "--job",
        relevant,
        "--label",
        "apply",
        "--reason",
        "skills_match",
    )
    assert code == 0
    assert replayed["result"] == "unchanged"

    code, summary = run_cli(monkeypatch, capsys, database, "summary", "--run", run_id)
    assert code == 0
    assert summary["decided_jobs"] == 1
    assert summary["labels"]["apply"] == 1


def test_next_redacts_visible_url(monkeypatch: Any, capsys: Any, tmp_path: Path) -> None:
    database = tmp_path / "feedback.db"
    visible_url = "Backend Engineer details: https://jobs.example.test/apply"
    run_id, relevant, _legacy = seed_database(database, relevant_description=visible_url)

    code, payload = run_cli(monkeypatch, capsys, database, "next", "--run", run_id)

    assert code == 0
    assert payload["result"] == "ok"
    assert payload["job_id"] == relevant
    assert visible_url not in payload["rendered"]
    assert "[URL]" in payload["rendered"]


def test_next_maps_display_errors_without_exposing_description(
    monkeypatch: Any, capsys: Any, tmp_path: Path
) -> None:
    database = tmp_path / "feedback.db"
    description = "Backend Engineer confidential details"
    run_id, _relevant, _legacy = seed_database(database, relevant_description=description)

    def fail_render(*_args: Any, **_kwargs: Any) -> str:
        raise DisplayError(DISPLAY_ERROR_HTML_MALFORMED)

    monkeypatch.setattr("role_radar.services.feedback_service.render_candidate", fail_render)
    code, payload = run_cli(monkeypatch, capsys, database, "next", "--run", run_id)

    assert code == 2
    assert payload == {
        "schema_version": "feedback-result-v1",
        "result": "blocked",
        "code": "feedback_display_invalid",
    }
    assert description not in json.dumps(payload)


def test_decide_invalid_reason_is_blocked(monkeypatch: Any, capsys: Any, tmp_path: Path) -> None:
    database = tmp_path / "feedback.db"
    run_id, relevant, _legacy = seed_database(database)
    code, payload = run_cli(
        monkeypatch,
        capsys,
        database,
        "decide",
        "--run",
        run_id,
        "--job",
        relevant,
        "--label",
        "apply",
        "--reason",
        "role_mismatch",
    )
    assert code == 2
    assert payload["code"] == "feedback_decision_invalid"


def test_propose_and_apply(monkeypatch: Any, capsys: Any, tmp_path: Path) -> None:
    database = tmp_path / "feedback.db"
    run_id, _relevant, legacy_jobs = seed_database(database, legacy_jobs=3)
    for legacy_job in legacy_jobs:
        code, _ = run_cli(
            monkeypatch,
            capsys,
            database,
            "decide",
            "--run",
            run_id,
            "--job",
            legacy_job,
            "--label",
            "reject",
            "--reason",
            "skills_mismatch",
        )
        assert code == 0
    policy_path = write_policy(tmp_path, str(uuid4()))
    code, proposal = run_cli(
        monkeypatch,
        capsys,
        database,
        "propose",
        "--run",
        run_id,
        "--policy",
        str(policy_path),
        "--min-decisions",
        "1",
    )
    assert code == 0
    assert proposal["removals"] == ["legacy"]

    output = tmp_path / "successor.toml"
    code, blocked = run_cli(
        monkeypatch,
        capsys,
        database,
        "apply",
        "--run",
        run_id,
        "--policy",
        str(policy_path),
        "--output",
        str(output),
        "--new-policy-version",
        "gate-a-v2",
    )
    assert code == 2
    assert blocked["code"] == "confirmation_required"

    code, applied = run_cli(
        monkeypatch,
        capsys,
        database,
        "apply",
        "--run",
        run_id,
        "--policy",
        str(policy_path),
        "--output",
        str(output),
        "--new-policy-version",
        "gate-a-v2",
        "--confirm",
    )
    assert code == 0
    assert applied["result"] == "applied"
    assert applied["new_policy_version"] == "gate-a-v2"

    code, same = run_cli(
        monkeypatch,
        capsys,
        database,
        "apply",
        "--run",
        run_id,
        "--policy",
        str(policy_path),
        "--output",
        str(policy_path),
        "--new-policy-version",
        "gate-a-v3",
        "--confirm",
    )
    assert code == 2
    assert same["code"] == "refinement_output_matches_input"
