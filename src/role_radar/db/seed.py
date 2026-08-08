"""Carga de fixtures de seed (perfil y oferta canónica).

Usado por tests (criterio de salida F1) y como semilla manual (D3).
La escritura de jobs vía seed/tests es una excepción F1 documentada en
ADR-0002: en producción el único escritor del pipeline será el worker.
"""

import json
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from role_radar.domain.enums import JobStatus, SourceType
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.profiles import ProfileRepository
from role_radar.services.source_service import SourceService


def load_fixtures(session: Session, fixtures_dir: str | Path) -> dict[str, str]:
    """Carga profile_seed.json y job_seed.json; crea Source, Job, ref y perfil.

    Idempotente por sesión nueva (crea siempre instancias frescas).
    Retorna los ids creados: ``{"profile_id", "source_id", "job_id"}``.
    """
    fixtures = Path(fixtures_dir)

    profile_data = json.loads((fixtures / "profile_seed.json").read_text())
    profile = ProfileRepository(session).create_v1(
        name=profile_data["name"],
        profile_json=profile_data["profile_json"],
    )

    job_data = json.loads((fixtures / "job_seed.json").read_text())
    source_data = job_data["source"]
    job_fields: dict[str, Any] = job_data["job"]

    source_service = SourceService(session)
    source = source_service.create(
        source_type=SourceType(source_data["type"]),
        name=source_data["name"],
        configuration={
            "board_token": source_data.get("board_token", "acme"),
            "company": source_data.get("company", job_fields["company"]),
        },
    )

    job_repo = JobRepository(session)
    job = job_repo.create(
        title=job_fields["title"],
        company=job_fields["company"],
        status=JobStatus(job_fields["status"]),
        location=job_fields.get("location"),
        description=job_fields.get("description"),
        application_url=job_fields.get("application_url"),
    )
    job_repo.add_source_reference(
        job_id=job.id,
        source_id=source.id,
        external_id=job_fields.get("external_id"),
        source_url=job_fields.get("source_url"),
        raw_payload=job_fields.get("raw_payload"),
    )

    session.commit()
    return {
        "profile_id": profile.id,
        "source_id": source.id,
        "job_id": job.id,
    }
