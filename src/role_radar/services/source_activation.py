from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.db.models import (
    CandidateProfile,
    JobSearchRun,
    Source,
    SourceActivationCampaign,
)
from role_radar.domain.enums import DiscoveryMode, JobSearchRunStatus, NotificationMode, SourceType
from role_radar.repositories.source_activation import SourceActivationCampaignRepository
from role_radar.services.run_service import RunService

_TERMINAL = {JobSearchRunStatus.COMPLETED, JobSearchRunStatus.FAILED, JobSearchRunStatus.CANCELLED}

class SourceActivationError(ValueError):
    pass

class SourceActivationCampaignService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.repo = SourceActivationCampaignRepository(session)

    def create(self, *, profile_id: str, created_since: datetime, source_types: list[str], batch_size: int, max_failure_streak: int, max_no_signal_streak: int, expected_managed: int | None = None) -> dict[str, Any]:
        profile = self.session.get(CandidateProfile, profile_id)
        if profile is None or not profile.is_active: raise SourceActivationError("profile_not_active")
        if self.repo.active() is not None: raise SourceActivationError("active_campaign_exists")
        types = {SourceType(value) for value in source_types}
        cohort = list(self.session.scalars(select(Source).where(Source.created_at >= created_since, Source.type.in_(types), Source.enabled.is_(True), Source.archived_at.is_(None)).order_by(Source.created_at, Source.id)))
        if not cohort: raise SourceActivationError("cohort_empty")
        if expected_managed is not None and len(cohort) != expected_managed: raise SourceActivationError("cohort_count_mismatch")
        enabled = list(self.session.scalars(select(Source).where(Source.enabled.is_(True), Source.archived_at.is_(None)).order_by(Source.created_at, Source.id)))
        cohort_ids = {s.id for s in cohort}
        baseline = [s for s in enabled if s.id not in cohort_ids]
        campaign = self.repo.create(profile_id=profile_id, batch_size=batch_size, max_failure_streak=max_failure_streak, max_no_signal_streak=max_no_signal_streak)
        ordinal = 0
        for source in baseline:
            self.repo.add_member(campaign_id=campaign.id, source_id=source.id, role="baseline", ordinal=ordinal); ordinal += 1
        for source in cohort:
            self.repo.add_member(campaign_id=campaign.id, source_id=source.id, role="managed", ordinal=ordinal); ordinal += 1
        self.session.flush()
        return {"campaign_id": campaign.id, "profile_id": profile_id, "baseline_count": len(baseline), "managed_count": len(cohort), "batch_size": batch_size, "max_failure_streak": max_failure_streak, "max_no_signal_streak": max_no_signal_streak}

    def tick(self, *, schedule_slot: str) -> dict[str, Any]:
        campaign = self.repo.active()
        if campaign is None: return {"result": "idle"}
        busy = self.repo.in_flight(campaign.id)
        if busy is not None: return {"result": "busy", "run_id": busy.id}
        existing = self.repo.run_for_slot(campaign.id, schedule_slot)
        if existing is not None:
            return {"result": "reused", "campaign_id": campaign.id, "run_id": existing.id}
        self._enroll_verified_discovered_sources(campaign.id)
        members = self.repo.members(campaign.id)
        enabled_ids = self.repo.enabled_source_ids([member.source_id for member in members])
        managed = [
            member
            for member in members
            if member.role == "managed"
            and member.source_id in enabled_ids
            and member.state not in {"disabled_failure", "disabled_no_signal"}
        ]
        chosen = sorted(
            managed,
            key=lambda m: (
                _selection_time(m.last_selected_at),
                m.ordinal,
            ),
        )[:campaign.batch_size]
        selected = [
            member
            for member in members
            if member.role == "baseline" and member.source_id in enabled_ids
        ] + chosen
        sources = {s.id: s for s in self.repo.sources([m.source_id for m in selected])}
        if len(sources) != len(selected) or any(s.archived_at is not None for s in sources.values()): raise SourceActivationError("source_unavailable")
        snapshot = [self._snapshot(sources[m.source_id]) for m in selected]
        run = RunService(self.session).create(
            reason="source_activation_campaign",
            profile_id=campaign.profile_id,
            idempotency_key=f"source-campaign:{campaign.id}:{schedule_slot}",
            schedule_slot=schedule_slot,
            discovery_mode=DiscoveryMode.SCHEDULED_DUE,
            notification_mode=NotificationMode.MATCH_ALERTS,
        )
        run.source_snapshot_json = snapshot
        run.activation_campaign_id = campaign.id
        now = datetime.now(UTC)
        for member in chosen:
            member.last_selected_at = now; member.last_run_id = run.id
        self.session.flush()
        return {"result": "created", "campaign_id": campaign.id, "run_id": run.id, "snapshot_count": len(snapshot), "managed_selected": len(chosen), "baseline_selected": len(selected) - len(chosen)}

    def finalize_run(self, run_id: str) -> None:
        run = self.session.get(JobSearchRun, run_id)
        if run is None or run.activation_campaign_id is None or run.campaign_finalized_at is not None: return
        campaign = self.session.get(SourceActivationCampaign, run.activation_campaign_id)
        if campaign is None: return
        members = {m.source_id: m for m in self.repo.members(campaign.id)}
        outcomes = run.source_results_json or {}
        for item in run.source_snapshot_json or []:
            member = members.get(item.get("source_id"))
            if member is None or member.role != "managed": continue
            result = outcomes.get(member.source_id)
            if not isinstance(result, dict): continue
            status = result.get("status")
            if status in {"ok", "partial"}:
                member.failure_streak = 0
                metrics = result.get("metrics") or {}
                signal = int(metrics.get("new_jobs", result.get("new_jobs", 0)) or 0) + int(metrics.get("duplicates", result.get("duplicates", 0)) or 0)
                if signal > 0: member.no_signal_streak = 0; member.state = "retained"
                else:
                    member.no_signal_streak += 1
                    # A healthy empty response is not proof that a board is
                    # invalid. Keep it eligible for future fair revisits.
                    member.state = "retained"
            elif status == "failed":
                member.failure_streak += 1
                # A transient collector failure must not permanently remove a
                # verified board from coverage. Fair rotation bounds retries
                # to one selection per coverage pass.
                member.state = "retained"
        run.campaign_finalized_at = datetime.now(UTC)
        self.session.flush()

    def _enroll_verified_discovered_sources(self, campaign_id: str) -> int:
        """Add every active verified discovery source to the recurring cohort."""
        ordinal = self.repo.next_ordinal(campaign_id)
        sources = self.repo.discovered_sources_not_enrolled(campaign_id)
        for source in sources:
            self.repo.add_member(
                campaign_id=campaign_id,
                source_id=source.id,
                role="managed",
                ordinal=ordinal,
            )
            ordinal += 1
        if sources:
            self.session.flush()
        return len(sources)

    def status(self) -> dict[str, Any]:
        campaign = self.repo.active()
        if campaign is None: return {"result": "idle"}
        members = self.repo.members(campaign.id)
        latest = self.repo.latest_run(campaign.id)
        counts = {state: sum(m.state == state for m in members) for state in ("pending", "retained", "disabled_failure", "disabled_no_signal")}
        return {"campaign_id": campaign.id, "profile_id": campaign.profile_id, "status": campaign.status, "batch_size": campaign.batch_size, "counts": counts, "latest_run_id": latest.id if latest else None, "latest_run_status": latest.status.value if latest else None, "latest_source_results": latest.source_results_json if latest else {}}

    @staticmethod
    def _snapshot(source: Source) -> dict[str, Any]:
        return {"source_id": source.id, "source_type": source.type.value, "name": source.name, "configuration": dict(source.configuration or {}), "source_key": source.source_key, "configuration_version": source.configuration_version}


def _selection_time(value: datetime | None) -> datetime:
    if value is None:
        return datetime.min.replace(tzinfo=UTC)
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
