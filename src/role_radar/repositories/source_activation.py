from __future__ import annotations

from datetime import datetime
from typing import Any
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from role_radar.db.models import JobSearchRun, Source, SourceActivationCampaign, SourceActivationMember

class SourceActivationCampaignRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def active(self) -> SourceActivationCampaign | None:
        return self.session.scalar(select(SourceActivationCampaign).where(SourceActivationCampaign.status == "active").order_by(SourceActivationCampaign.created_at))

    def create(self, *, profile_id: str, batch_size: int, max_failure_streak: int, max_no_signal_streak: int) -> SourceActivationCampaign:
        row = SourceActivationCampaign(profile_id=profile_id, batch_size=batch_size, max_failure_streak=max_failure_streak, max_no_signal_streak=max_no_signal_streak)
        self.session.add(row); self.session.flush(); return row

    def members(self, campaign_id: str) -> list[SourceActivationMember]:
        return list(self.session.scalars(select(SourceActivationMember).where(SourceActivationMember.campaign_id == campaign_id).order_by(SourceActivationMember.ordinal, SourceActivationMember.source_id)))

    def discovered_sources_not_enrolled(self, campaign_id: str) -> list[Source]:
        enrolled = select(SourceActivationMember.source_id).where(
            SourceActivationMember.campaign_id == campaign_id
        )
        return list(
            self.session.scalars(
                select(Source)
                .where(
                    Source.management_origin == "discovery",
                    Source.discovery_verified_at.is_not(None),
                    Source.enabled.is_(True),
                    Source.archived_at.is_(None),
                    Source.id.not_in(enrolled),
                )
                .order_by(Source.created_at, Source.id)
            )
        )

    def next_ordinal(self, campaign_id: str) -> int:
        current = self.session.scalar(
            select(func.max(SourceActivationMember.ordinal)).where(
                SourceActivationMember.campaign_id == campaign_id
            )
        )
        return 0 if current is None else int(current) + 1

    def pending_or_retained(self, campaign_id: str) -> list[SourceActivationMember]:
        return [m for m in self.members(campaign_id) if m.role == "managed" and m.state in {"pending", "retained"}]

    def in_flight(self, campaign_id: str) -> JobSearchRun | None:
        return self.session.scalar(select(JobSearchRun).where(JobSearchRun.activation_campaign_id == campaign_id, JobSearchRun.status.not_in(("completed", "failed", "cancelled"))).order_by(JobSearchRun.created_at.desc()))

    def latest_run(self, campaign_id: str) -> JobSearchRun | None:
        return self.session.scalar(select(JobSearchRun).where(JobSearchRun.activation_campaign_id == campaign_id).order_by(JobSearchRun.created_at.desc()))

    def run_for_slot(self, campaign_id: str, schedule_slot: str) -> JobSearchRun | None:
        return self.session.scalar(
            select(JobSearchRun)
            .where(
                JobSearchRun.activation_campaign_id == campaign_id,
                JobSearchRun.schedule_slot == schedule_slot,
            )
            .order_by(JobSearchRun.created_at.desc())
        )

    def sources(self, ids: list[str]) -> list[Source]:
        if not ids: return []
        return list(self.session.scalars(select(Source).where(Source.id.in_(ids)).order_by(Source.id)))

    def enabled_source_ids(self, ids: list[str]) -> set[str]:
        if not ids:
            return set()
        return set(
            self.session.scalars(
                select(Source.id).where(
                    Source.id.in_(ids),
                    Source.enabled.is_(True),
                    Source.archived_at.is_(None),
                )
            )
        )

    def add_member(self, *, campaign_id: str, source_id: str, role: str, ordinal: int) -> SourceActivationMember:
        row = SourceActivationMember(campaign_id=campaign_id, source_id=source_id, role=role, ordinal=ordinal, state="retained" if role == "baseline" else "pending")
        self.session.add(row); return row
