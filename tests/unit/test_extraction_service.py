"""Orquestación y presupuesto de correctivo."""

from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from role_radar.broker.fake import FakeLLMProvider
from role_radar.broker.protocols import ProviderError
from role_radar.domain.enums import ExtractionStatus
from role_radar.repositories.jobs import JobRepository
from role_radar.services.extraction_service import ExtractionService

FIXTURES = Path(__file__).parents[2] / "fixtures"


def _content(name: str) -> str:
    return (FIXTURES / name).read_text()


def _job(db_session: Session) -> str:
    job = JobRepository(db_session).create(
        title="Backend Engineer",
        company="Acme",
        location="Madrid, Spain",
        description="Build and operate the core API platform at Acme.",
    )
    db_session.commit()
    return job.id


@pytest.mark.asyncio
async def test_valid_extraction_persists_evidence_and_is_idempotent(db_session: Session) -> None:
    job_id = _job(db_session)
    provider = FakeLLMProvider(result=_content("extraction_valid.json"))
    service = ExtractionService(db_session, provider=provider)
    extraction = await service.extract_job(job_id=job_id)
    db_session.commit()
    assert extraction.validation_status == ExtractionStatus.VALID
    assert extraction.extraction_json is not None
    assert extraction.extraction_json["required_skills"][0]["evidence"] == "core API platform"
    assert extraction.attempt_count == 1
    again = await service.extract_job(job_id=job_id)
    assert again.id == extraction.id
    assert provider.call_count == 1


@pytest.mark.asyncio
async def test_local_invalid_output_gets_one_corrective(db_session: Session) -> None:
    job_id = _job(db_session)
    provider = FakeLLMProvider(
        responses=[_content("extraction_invalid_evidence.json"), _content("extraction_valid.json")]
    )
    extraction = await ExtractionService(db_session, provider=provider).extract_job(job_id=job_id)
    assert extraction.validation_status == ExtractionStatus.VALID
    assert extraction.attempt_count == 2
    assert provider.call_count == 2


@pytest.mark.asyncio
async def test_provider_auth_failure_does_not_trigger_corrective(db_session: Session) -> None:
    job_id = _job(db_session)
    provider = FakeLLMProvider(error=ProviderError(kind="authentication", code="unauthorized"))
    extraction = await ExtractionService(db_session, provider=provider).extract_job(job_id=job_id)
    assert extraction.validation_status == ExtractionStatus.FAILED
    assert extraction.attempt_count == 1
    assert provider.call_count == 1
