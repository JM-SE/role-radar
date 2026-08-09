"""SQL-only persistence gateway for minimized discovery journals."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.db.models import DiscoveryCycle, DiscoveryQuery
from role_radar.discovery.contracts import QueryExecution, QueryIdentity
from role_radar.domain.enums import DiscoveryCycleStatus, DiscoveryQueryStatus


class DiscoveryRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_cycle_for_run(self, run_id: str) -> DiscoveryCycle | None:
        return self._session.scalar(select(DiscoveryCycle).where(DiscoveryCycle.run_id == run_id))

    def get_cycle(self, cycle_id: str) -> DiscoveryCycle | None:
        return self._session.get(DiscoveryCycle, cycle_id)

    def create_cycle(
        self,
        *,
        run_id: str,
        profile_snapshot: dict[str, Any],
        planner_version: str,
        planner_hash: str,
        policy_version: str,
        status: DiscoveryCycleStatus = DiscoveryCycleStatus.PLANNED,
        reused_from_cycle_id: str | None = None,
    ) -> DiscoveryCycle:
        cycle = DiscoveryCycle(
            id=str(uuid4()),
            run_id=run_id,
            reused_from_cycle_id=reused_from_cycle_id,
            profile_snapshot_json=profile_snapshot,
            planner_version=planner_version,
            planner_hash=planner_hash,
            policy_version=policy_version,
            status=status,
            stats_json={},
            planned_at=datetime.now(UTC),
        )
        self._session.add(cycle)
        self._session.flush()
        return cycle

    def add_query(
        self,
        *,
        cycle_id: str,
        identity: QueryIdentity,
        status: DiscoveryQueryStatus = DiscoveryQueryStatus.PLANNED,
    ) -> DiscoveryQuery:
        row = DiscoveryQuery(
            cycle_id=cycle_id,
            ordinal=identity.ordinal,
            family=identity.family,
            query_key=identity.query_key,
            provider_intent=identity.provider_intent.value,
            status=status,
        )
        self._session.add(row)
        self._session.flush()
        return row

    def list_queries(self, cycle_id: str) -> list[DiscoveryQuery]:
        return list(
            self._session.scalars(
                select(DiscoveryQuery)
                .where(DiscoveryQuery.cycle_id == cycle_id)
                .order_by(DiscoveryQuery.ordinal)
            )
        )

    def finish_query(self, cycle_id: str, execution: QueryExecution) -> DiscoveryQuery | None:
        row = self._session.scalar(
            select(DiscoveryQuery).where(
                DiscoveryQuery.cycle_id == cycle_id,
                DiscoveryQuery.ordinal == execution.identity.ordinal,
            )
        )
        if row is None:
            return None
        row.status = DiscoveryQueryStatus(execution.status)
        row.candidate_count = execution.candidate_count
        row.known_count = execution.known_count
        row.unknown_count = execution.unknown_count
        row.rejected_count = execution.rejected_count
        row.verified_count = execution.verified_count
        self._session.flush()
        return row

    def finish_cycle(
        self,
        cycle_id: str,
        *,
        status: DiscoveryCycleStatus,
        stats: dict[str, int],
        error_code: str | None = None,
    ) -> DiscoveryCycle:
        cycle = self._session.get(DiscoveryCycle, cycle_id)
        if cycle is None:
            raise LookupError("discovery cycle not found")
        cycle.status = status
        cycle.stats_json = {key: max(0, int(value)) for key, value in stats.items()}
        cycle.error_code = error_code[:64] if error_code else None
        cycle.completed_at = datetime.now(UTC)
        self._session.flush()
        return cycle
