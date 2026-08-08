from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from role_radar.db.base import Base
from role_radar.domain.enums import SourceType
from role_radar.repositories.sources import SourceRepository
from role_radar.services.source_service import SourceService


def test_lever_source_is_file_backed_disabled_and_replay_safe(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'lever.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        source = SourceService(session).create(
            source_type=SourceType.LEVER,
            name="Acme Lever",
            configuration={"site": " Acme ", "region": "global", "company": "Acme"},
        )
        session.commit()
        assert source.enabled is False
        assert source.configuration == {
            "site": "acme",
            "region": "global",
            "company": "Acme",
        }
        assert source.source_key == "lever:global:acme"
        assert SourceRepository(session).get_by_key("lever:global:acme") is not None
    engine.dispose()
