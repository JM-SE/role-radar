"""Criterio de salida F3: Job persistido de F2 -> fake -> valid con evidencia."""

from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from role_radar.broker.fake import FakeLLMProvider
from role_radar.db.seed import load_fixtures
from role_radar.domain.enums import ExtractionStatus
from role_radar.services.extraction_service import ExtractionService


@pytest.mark.asyncio
async def test_f2_seed_extracts_and_persists_valid_payload(db_session: Session) -> None:
    fixtures = Path(__file__).parents[2] / "fixtures"
    seeded = load_fixtures(db_session, fixtures)
    provider = FakeLLMProvider(fixture=fixtures / "extraction_valid.json")
    extraction = await ExtractionService(db_session, provider=provider).extract_job(
        job_id=seeded["job_id"]
    )
    db_session.commit()
    assert extraction.validation_status == ExtractionStatus.VALID
    assert extraction.job_id == seeded["job_id"]
    assert extraction.extraction_json is not None
    assert extraction.extraction_json["required_skills"][0]["evidence"] == "core API platform"
