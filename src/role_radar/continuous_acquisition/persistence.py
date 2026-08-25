"""Freshness-first savepoint writer for one normalized offer."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from role_radar.continuous_acquisition.contracts import (
    OfferDisposition,
    RejectionCode,
    SourceSnapshot,
)
from role_radar.continuous_acquisition.identity import derive_strong_identities
from role_radar.continuous_acquisition.orm import ContinuousAcquisitionRunJob
from role_radar.continuous_acquisition.policy import freshness_decision
from role_radar.continuous_acquisition.repositories import IdentityRepository
from role_radar.db.models import Job
from role_radar.domain.dto import RawJob
from role_radar.domain.enums import JobStatus


class OfferPersistence:
    """One offer per nested transaction; the caller owns the outer transaction."""

    def __init__(self, session: Session, *, as_of_utc: datetime) -> None:
        self.session = session
        self.as_of_utc = as_of_utc

    def persist(
        self,
        raw: RawJob,
        *,
        source: SourceSnapshot,
        run_id: str,
        operation_id: str,
        assert_fence: Callable[[], None] | None = None,
    ) -> str:
        decision = freshness_decision(raw, as_of_utc=self.as_of_utc)
        if not decision.accepted or decision.provenance is None:
            return decision.code or RejectionCode.INVALID.value
        try:
            identities = derive_strong_identities(
                source_key=source.source_key,
                external_id=raw.external_id,
                posting_url=raw.source_url,
                application_url=raw.application_url,
            )
        except ValueError:
            return "invalid_identity"
        identity_repo = IdentityRepository(self.session)
        owners = {
            job_id
            for identity in identities
            for job_id in identity_repo.jobs_for_identity(
                version=identity.version, kind=identity.kind, value=identity.value
            )
        }
        if len(owners) > 1:
            return RejectionCode.IDENTITY_CONFLICT.value
        with self.session.begin_nested():
            if assert_fence is not None:
                assert_fence()
            job_id = next(iter(owners), None)
            disposition = OfferDisposition.DUPLICATE if job_id else OfferDisposition.CREATED
            if job_id is None:
                job = Job(
                    title=raw.title,
                    company=raw.company,
                    location=raw.location,
                    description=raw.description,
                    application_url=raw.application_url,
                    status=JobStatus.NEW,
                    first_seen_at=self.as_of_utc,
                    last_seen_at=self.as_of_utc,
                    published_at=None
                    if raw.source.casefold() == "greenhouse"
                    else raw.published_at,
                )
                self.session.add(job)
                self.session.flush()
                job_id = job.id
            for identity in identities:
                existing_ids = identity_repo.jobs_for_identity(
                    version=identity.version,
                    kind=identity.kind,
                    value=identity.value,
                )
                if not existing_ids:
                    try:
                        with self.session.begin_nested():
                            identity_repo.add(
                                job_id=job_id,
                                kind=identity.kind,
                                version=identity.version,
                                value=identity.value,
                                digest=hashlib.sha256(identity.value.encode()).hexdigest(),
                            )
                    except IntegrityError:
                        owners = identity_repo.jobs_for_identity(
                            version=identity.version, kind=identity.kind, value=identity.value
                        )
                        if len(owners) != 1 or job_id not in owners:
                            return RejectionCode.IDENTITY_CONFLICT.value
            provenance = hashlib.sha256(
                json.dumps(
                    {"source_key": source.source_key, "external_id": raw.external_id},
                    sort_keys=True,
                ).encode()
            ).hexdigest()
            link = self.session.scalar(
                select(ContinuousAcquisitionRunJob).where(
                    ContinuousAcquisitionRunJob.run_id == run_id,
                    ContinuousAcquisitionRunJob.job_id == job_id,
                )
            )
            if link is None:
                try:
                    with self.session.begin_nested():
                        self.session.add(
                            ContinuousAcquisitionRunJob(
                                run_id=run_id,
                                operation_id=operation_id,
                                job_id=job_id,
                                disposition=disposition.value,
                                provider_recency_at=decision.provenance.provider_recency_at,
                                recency_semantic=decision.provenance.semantic,
                                freshness_policy_version=decision.provenance.policy_version,
                                identity_policy_version=identities[0].version,
                                provenance_hash=provenance,
                            )
                        )
                except IntegrityError:
                    link = self.session.scalar(
                        select(ContinuousAcquisitionRunJob).where(
                            ContinuousAcquisitionRunJob.run_id == run_id,
                            ContinuousAcquisitionRunJob.job_id == job_id,
                        )
                    )
                    if link is None:
                        raise
        return disposition.value
