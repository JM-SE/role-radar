import pytest
from sqlalchemy.orm import Session

from role_radar.domain.enums import SourceType
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.sources import SourceRepository
from role_radar.services.source_service import SourceService, SourceServiceError


def test_create_is_disabled_and_cas_is_required(db_session: Session) -> None:
    service = SourceService(db_session)
    source = service.create(
        source_type=SourceType.GREENHOUSE,
        name="Same display name",
        configuration={"board_token": "acme"},
    )
    other = service.create(
        source_type=SourceType.GREENHOUSE,
        name="Same display name",
        configuration={"board_token": "beta"},
    )
    assert source.enabled is False
    assert source.revision == 1
    assert other.name == source.name
    with pytest.raises(SourceServiceError, match="revision_conflict"):
        service.enable(source.id, expected_revision=9)


def test_identity_is_immutable_after_reference_and_archive_is_not_delete(
    db_session: Session,
) -> None:
    service = SourceService(db_session)
    source = service.create(
        source_type="greenhouse", name="Board", configuration={"board_token": "acme"}
    )
    job = JobRepository(db_session).create(title="Job", company="Acme")
    SourceRepository(db_session).update_health(source.id, last_error_code="collection_failed")
    JobRepository(db_session).add_source_reference(
        job_id=job.id, source_id=source.id, external_id="1"
    )
    with pytest.raises(SourceServiceError, match="identity_immutable"):
        service.update(
            source.id,
            expected_revision=1,
            configuration={"board_token": "new-board"},
        )
    archived = service.archive(source.id, expected_revision=1)
    assert archived.enabled is False
    assert archived.archived_at is not None
    assert SourceRepository(db_session).get(source.id) is not None
