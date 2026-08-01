"""Pruebas de las cinco señales D6 y actualización de referencias."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from role_radar.db.models import Job
from role_radar.dedup.service import DedupService
from role_radar.domain.dto import NormalizedJob
from role_radar.domain.enums import SourceType
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.sources import SourceRepository


def _normalized(**changes: Any) -> NormalizedJob:
    values: dict[str, Any] = {
        "source": "greenhouse",
        "external_id": "ext-1",
        "source_url": "https://example.test/source/1",
        "application_url": "https://example.test/app/1",
        "title": "Backend Engineer",
        "company": "Acme",
        "location": "Remote",
        "normalized_location": "remote",
        "description": "Build APIs",
        "description_hash": "a" * 64,
        "collected_at": datetime.now(UTC),
    }
    values.update(changes)
    return NormalizedJob(**values)


def test_dedup_recollect_updates_reference_without_second_job(db_session: Session) -> None:
    source = SourceRepository(db_session).create(
        type=SourceType.GREENHOUSE, name="Acme", configuration={"board_token": "acme"}
    )
    service = DedupService(JobRepository(db_session))
    first = service.resolve(normalized=_normalized(), source_id=source.id)
    db_session.commit()

    second = service.resolve(
        normalized=_normalized(structured_data={"updated_at": "now"}), source_id=source.id
    )
    db_session.commit()
    jobs = db_session.query(Job).all()
    assert first.is_new is True
    assert second.is_new is False
    assert second.matched_by == "source_external_id"
    assert len(jobs) == 1
    assert len(jobs[0].source_references) == 1
    assert jobs[0].source_references[0].raw_payload == {"updated_at": "now"}


def test_dedup_matches_application_url_and_description_hash(db_session: Session) -> None:
    source = SourceRepository(db_session).create(
        type=SourceType.GREENHOUSE, name="Acme 2", configuration={"board_token": "acme-2"}
    )
    jobs = JobRepository(db_session)
    first = DedupService(jobs).resolve(normalized=_normalized(), source_id=source.id)
    db_session.commit()
    by_url = DedupService(jobs).resolve(
        normalized=_normalized(external_id="other", source_url=None), source_id=source.id
    )
    by_hash = DedupService(jobs).resolve(
        normalized=_normalized(
            external_id="third",
            source_url=None,
            application_url=None,
            title="Different title",
            company="Different company",
            normalized_location=None,
        ),
        source_id=source.id,
    )
    assert by_url.job.id == first.job.id
    assert by_url.matched_by == "application_url"
    assert by_hash.job.id == first.job.id
    assert by_hash.matched_by == "description_hash"
