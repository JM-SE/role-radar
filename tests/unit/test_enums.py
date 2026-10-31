"""Tests de los enums de dominio (D12-D14 + SourceType)."""

from role_radar.domain.enums import (
    JobSearchRunStatus,
    JobStatus,
    RunJobStage,
    RunJobStatus,
    SourceType,
)


def test_job_search_run_status_values() -> None:
    """D12: exactly eleven statuses, including deferred."""
    assert {s.value for s in JobSearchRunStatus} == {
        "pending",
        "collecting",
        "normalizing",
        "extracting",
        "scoring",
        "deep_evaluating",
        "notifying",
        "completed",
        "failed",
        "cancelled",
        "deferred",
    }
    assert len(JobSearchRunStatus) == 11
    assert "deduplicating" not in {s.value for s in JobSearchRunStatus}
    assert "prefiltering" not in {s.value for s in JobSearchRunStatus}


def test_job_status_values() -> None:
    """D13: new | active | expired | archived."""
    assert [s.value for s in JobStatus] == ["new", "active", "expired", "archived"]


def test_run_job_stage_values() -> None:
    """D14: etapas del journal, incluye deduplicated y prefiltered."""
    assert [s.value for s in RunJobStage] == [
        "collected",
        "normalized",
        "deduplicated",
        "prefiltered",
        "extracted",
        "scored",
        "deep_evaluated",
        "notified",
    ]


def test_run_job_status_values() -> None:
    """D14: resultado de etapa."""
    assert [s.value for s in RunJobStatus] == [
        "pending",
        "in_progress",
        "succeeded",
        "failed",
        "skipped",
    ]


def test_source_type_values() -> None:
    """SourceType inicial (extensible)."""
    assert [s.value for s in SourceType] == [
        "greenhouse",
        "lever",
        "ashby",
        "workable",
        "web_search",
        "email",
        "linkedin_public",
        "manual",
        "other",
        "jobicy",
    ]


def test_enums_are_str_enums() -> None:
    """Los enums deben poder usarse como strings (valores en DB)."""
    assert JobSearchRunStatus.PENDING.value == "pending"
    assert str(JobStatus.NEW) == "new"
