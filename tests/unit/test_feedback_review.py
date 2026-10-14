"""Coverage of the standard interactive current-feedback review session."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from role_radar.cli.main import main
from role_radar.db.base import Base
from role_radar.db.models import CandidateProfile, Job
from role_radar.domain.enums import DiscoveryMode, RunJobStage, RunJobStatus
from role_radar.repositories.discovery import DiscoveryRepository
from role_radar.repositories.feedback import FeedbackRepository
from role_radar.services.feedback_review import ReviewReport, run_review
from role_radar.services.feedback_service import build_surface, submit_feedback

POSTINGS = (
    ("Backend Engineer", "Backend Engineer with Python daily"),
    ("Java Developer", "COBOL maintenance role with on-call rotation"),
    ("Gardener", "Outdoor garden maintenance and landscaping work"),
)


class ScriptIO:
    """Deterministic TerminalIO double driven by a scripted answer list."""

    def __init__(self, lines: list[str]) -> None:
        self._lines = list(lines)
        self.out: list[str] = []

    @property
    def is_tty(self) -> bool:
        return True

    def read_line(self, prompt: str) -> str:
        self.out.append(prompt)
        if not self._lines:
            raise EOFError
        return self._lines.pop(0)

    def write(self, value: str) -> None:
        self.out.append(value)

    def text(self) -> str:
        return "".join(self.out)


def seed_session(session: Session) -> str:
    import role_radar.db.models  # noqa: F401
    from role_radar.repositories.jobs import JobRepository
    from role_radar.repositories.run_jobs import RunJobRepository
    from role_radar.repositories.runs import RunRepository

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
                "canonical_profile_sha256": "0" * 64,
            },
        },
        planner_version="discovery-planner-v2",
        planner_hash="0" * 64,
        policy_version="gate-a-v1",
    )
    for title, description in POSTINGS:
        job = JobRepository(session).create(
            title=title,
            company="Acme",
            description=description,
            description_hash=uuid4().hex,
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
    session.commit()
    for job in session.query(Job):
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
                        "canonical_profile_sha256": "0" * 64,
                    },
                    "input_sha256": "1" * 64,
                    "eligible": True,
                    "reason_codes": ["exact_region_match"],
                    "extraction_id": "fixture-extraction",
                }
            },
        )
    session.commit()
    return run.id


def decide(session: Session, run_id: str, job_id: str, label: str, reason: str) -> None:
    submit_feedback(
        session,
        run_id=run_id,
        job_id=job_id,
        label=label,
        primary_reason=reason,
        secondary_reasons=(),
        note=None,
        expected_revision=0,
    )
    session.commit()


def test_review_decides_skips_and_quits(db_session: Session) -> None:
    run_id = seed_session(db_session)
    io = ScriptIO(["a", "1", "", "", "y", "s", "q"])
    report = run_review(db_session, run_id, io)
    assert isinstance(report, ReviewReport)
    assert (report.decided, report.skipped) == (1, 1)
    assert report.quit_requested is True
    assert report.remaining == 2
    assert FeedbackRepository(db_session).summary(run_id)["decided_jobs"] == 1
    assert "Decision accepted." in io.text()
    assert "Session stopped:" in io.text()


def test_review_resumes_after_interruption(db_session: Session) -> None:
    run_id = seed_session(db_session)
    first = build_surface(db_session, run_id).items[0]
    decide(db_session, run_id, first.job_id, "apply", "role_match")
    io = ScriptIO(["q"])
    report = run_review(db_session, run_id, io)
    assert report.decided == 0
    assert report.quit_requested is True
    assert report.remaining == 2
    assert "2 to label, 1 already decided" in io.text()


def test_review_reprompts_unknown_reason(db_session: Session) -> None:
    run_id = seed_session(db_session)
    io = ScriptIO(["m", "bogus", "2", "", "", "y", "q"])
    report = run_review(db_session, run_id, io)
    assert report.decided == 1
    assert "Unknown reason" in io.text()


def test_review_reprompts_invalid_note_rule(db_session: Session) -> None:
    run_id = seed_session(db_session)
    io = ScriptIO(["a", "1", "", "should not persist", "y", "a", "1", "", "", "y", "q"])
    report = run_review(db_session, run_id, io)
    assert report.decided == 1
    assert "Invalid decision" in io.text()
    summary = FeedbackRepository(db_session).summary(run_id)
    assert summary["decided_jobs"] == 1
    assert summary["labels"]["apply"] == 1


def test_review_unconfirmed_decision_skips(db_session: Session) -> None:
    run_id = seed_session(db_session)
    io = ScriptIO(["r", "1", "", "", "n", "q"])
    report = run_review(db_session, run_id, io)
    assert (report.decided, report.skipped) == (0, 1)
    assert FeedbackRepository(db_session).summary(run_id)["decided_jobs"] == 0


def test_review_relabel_corrects_prior_decision(db_session: Session) -> None:
    run_id = seed_session(db_session)
    first = build_surface(db_session, run_id).items[0]
    decide(db_session, run_id, first.job_id, "apply", "role_match")
    io = ScriptIO(["r", "1", "", "", "y", "q"])
    report = run_review(db_session, run_id, io, relabel=True)
    assert report.decided == 1
    latest = FeedbackRepository(db_session).latest_for_run(run_id)
    assert latest[first.job_id].revision == 2
    assert latest[first.job_id].label == "reject"


def test_review_relabel_identical_content_replays(db_session: Session) -> None:
    run_id = seed_session(db_session)
    first = build_surface(db_session, run_id).items[0]
    decide(db_session, run_id, first.job_id, "apply", "role_match")
    io = ScriptIO(["a", "1", "", "", "y", "q"])
    report = run_review(db_session, run_id, io, relabel=True)
    assert (report.decided, report.replayed) == (0, 1)
    assert FeedbackRepository(db_session).latest_for_run(run_id)[first.job_id].revision == 1


def test_review_conflict_keeps_stored_revision(db_session: Session) -> None:
    run_id = seed_session(db_session)
    first = build_surface(db_session, run_id).items[0]

    def concurrent_decision() -> None:
        submit_feedback(
            db_session,
            run_id=run_id,
            job_id=first.job_id,
            label="reject",
            primary_reason="role_mismatch",
            secondary_reasons=(),
            note=None,
            expected_revision=0,
        )
        db_session.commit()

    class RacingIO(ScriptIO):
        hooked = False

        def read_line(self, prompt: str) -> str:
            if not self.hooked:
                self.hooked = True
                concurrent_decision()
            return super().read_line(prompt)

    io = RacingIO(["a", "1", "", "", "y", "q"])
    report = run_review(db_session, run_id, io)
    assert report.conflicts == 1
    assert report.decided == 0
    assert "concurrently" in io.text()
    latest = FeedbackRepository(db_session).latest_for_run(run_id)
    assert latest[first.job_id].label == "reject"


def test_review_limit_bounds_session(db_session: Session) -> None:
    run_id = seed_session(db_session)
    io = ScriptIO(["a", "1", "", "", "y"])
    report = run_review(db_session, run_id, io, limit=1)
    assert report.decided == 1
    assert report.quit_requested is False
    assert report.remaining == 2


def test_review_eof_stops_and_keeps_decisions(db_session: Session) -> None:
    run_id = seed_session(db_session)
    io = ScriptIO(["a", "1", "", "", "y"])
    report = run_review(db_session, run_id, io)
    assert report.decided == 1
    assert report.quit_requested is True
    assert FeedbackRepository(db_session).summary(run_id)["decided_jobs"] == 1


def test_review_all_decided_reports_completion(db_session: Session) -> None:
    run_id = seed_session(db_session)
    for item in build_surface(db_session, run_id).items:
        decide(db_session, run_id, item.job_id, "reject", "role_mismatch")
    io = ScriptIO([])
    report = run_review(db_session, run_id, io)
    assert (report.decided, report.remaining) == (0, 0)
    assert "already have a decision" in io.text()


def test_review_unknown_run_raises(db_session: Session) -> None:
    with pytest.raises(LookupError):
        run_review(db_session, "missing-run", ScriptIO([]))


def seed_file_database(database: Path) -> str:
    engine = create_engine(f"sqlite:///{database}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    session = factory()
    run_id = seed_session(session)
    session.close()
    engine.dispose()
    return run_id


def test_cli_review_requires_tty(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    database = tmp_path / "feedback.db"
    run_id = seed_file_database(database)
    monkeypatch.setenv("ROLE_RADAR_DATABASE_URL", f"sqlite:///{database}")
    code = main(["feedback", "review", "--run", run_id])
    out = capsys.readouterr().out.strip()
    assert code == 2
    assert json.loads(out)["code"] == "review_requires_tty"


def test_cli_review_interactive_end_to_end(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    import sys

    database = tmp_path / "feedback.db"
    run_id = seed_file_database(database)
    monkeypatch.setenv("ROLE_RADAR_DATABASE_URL", f"sqlite:///{database}")
    answers = iter(["a", "1", "", "", "y", "s", "q"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    code = main(["feedback", "review", "--run", run_id])
    out = capsys.readouterr().out
    assert code == 0
    assert "Decision accepted." in out
    assert "Session stopped:" in out


def test_cli_review_rejects_bad_limit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    import sys

    database = tmp_path / "feedback.db"
    run_id = seed_file_database(database)
    monkeypatch.setenv("ROLE_RADAR_DATABASE_URL", f"sqlite:///{database}")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    code = main(["feedback", "review", "--run", run_id, "--limit", "0"])
    out = capsys.readouterr().out.strip()
    assert code == 2
    assert json.loads(out)["code"] == "review_limit_invalid"
