"""Discovery orchestration: synchronous prepare/finalize around DTO-only I/O."""

import inspect
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.acquisition.discovery_policy import LoadedDiscoveryPolicyV1
from role_radar.collectors.outcomes import CollectionSuccess
from role_radar.collectors.policy import CollectionRunBudget
from role_radar.collectors.protocols import CollectorRuntime, JobCollector, SourceSnapshot
from role_radar.collectors.registry import CollectorContext, create_collector
from role_radar.db.models import (
    CandidateProfile,
    DiscoveryCycle,
    DiscoveryQuery,
    JobSearchRun,
    RunJob,
)
from role_radar.discovery.contracts import (
    DiscoveryExecution,
    DiscoveryFinalization,
    DiscoveryPlan,
    KnownOfficialCandidate,
    PlannedQuery,
    QueryExecution,
    QueryIdentity,
    SearchRequest,
    UnknownCandidate,
    VerifiedBatch,
)
from role_radar.discovery.null_provider import NullSearchProvider
from role_radar.discovery.planner_v2 import (
    DiscoveryPlanError,
    plan_profile_discovery,
    validate_discovery_query_plan,
)
from role_radar.discovery.policy import DiscoveryPolicy, DiscoveryPolicyV1
from role_radar.discovery.profile_terms import (
    DiscoveryTermsError,
    FrozenCandidateProfileV1,
    compile_profile_terms,
)
from role_radar.discovery.protocols import SearchProvider
from role_radar.discovery.query_keys import QueryKeyFactory
from role_radar.discovery.url_classifier import classify_url
from role_radar.domain.enums import (
    DiscoveryCycleStatus,
    DiscoveryErrorCode,
    DiscoveryMode,
    DiscoveryQueryStatus,
)
from role_radar.domain.profile import CandidateProfileV1, canonical_profile_sha256
from role_radar.matching.transient_clarification import MAX_ATTEMPTS_PER_RUN
from role_radar.normalization.jobs import normalize_raw_job
from role_radar.repositories.discovery import DiscoveryRepository
from role_radar.services.acquired_job_writer import AcquiredJobWriter
from role_radar.services.discovered_source_service import DiscoveredSourceService
from role_radar.sources.identity import canonical_source_key


class PipelineDiscoveryService:
    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        provider: SearchProvider | None = None,
        collector_factory: Callable[[SourceSnapshot], JobCollector] | None = None,
        query_key_secret: bytes | str | None = None,
        policy: DiscoveryPolicy | None = None,
        discovery_policy_v1: DiscoveryPolicyV1
        | LoadedDiscoveryPolicyV1
        | Mapping[str, object]
        | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._provider = provider or NullSearchProvider()
        self._collector_factory = collector_factory
        self._secret = query_key_secret
        self._policy = policy or DiscoveryPolicy()
        self._discovery_policy_v1 = discovery_policy_v1

    def prepare(self, run_id: str) -> DiscoveryPlan | None:
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            if run is None:
                raise LookupError("run not found")
            mode = DiscoveryMode(getattr(run.discovery_mode, "value", run.discovery_mode))
            if mode is DiscoveryMode.NONE:
                return None
            existing_cycle = DiscoveryRepository(session).get_cycle_for_run(run_id)
            if existing_cycle is not None and existing_cycle.status in {
                DiscoveryCycleStatus.COMPLETED,
                DiscoveryCycleStatus.DEGRADED,
                DiscoveryCycleStatus.REUSED,
            }:
                return self._cycle_reuse_plan(session, run, existing_cycle)
            previous = self._reuse_if_possible(session, run)
            if previous is not None:
                session.commit()
                return previous
            if run.profile_id is None:
                raise LookupError("discovery run has no profile")
            profile_row = session.get(CandidateProfile, run.profile_id)
            if profile_row is None:
                raise LookupError("profile not found")
            profile = CandidateProfileV1.model_validate(profile_row.profile_json)
            try:
                queries, planner_version, policy_version, snapshot = (
                    self._profile_bound_v2_queries(profile_row, profile)
                )
            except DiscoveryPlanError as exc:
                self._record_config_failure(session, run_id, profile, exc.code)
                raise
            identities: tuple[QueryIdentity, ...] = ()
            planner_hash = "query_key_unavailable"
            if self._secret is not None:
                try:
                    factory = QueryKeyFactory(self._secret)
                    identities = factory.identities(queries, planner_version=planner_version)
                    planner_hash = factory.planner_hash(identities, planner_version=planner_version)
                except ValueError:
                    pass
            repo = DiscoveryRepository(session)
            cycle = repo.get_cycle_for_run(run_id)
            if cycle is None:
                cycle = repo.create_cycle(
                    run_id=run_id,
                    profile_snapshot=snapshot,
                    planner_version=planner_version,
                    planner_hash=planner_hash,
                    policy_version=policy_version,
                )
                for identity in identities:
                    repo.add_query(cycle_id=cycle.id, identity=identity)
            else:
                terminal = {
                    DiscoveryQueryStatus.EXECUTED,
                    DiscoveryQueryStatus.EMPTY,
                    DiscoveryQueryStatus.FAILED,
                    DiscoveryQueryStatus.REUSED,
                }
                terminal_ordinals = {
                    row.ordinal for row in repo.list_queries(cycle.id) if row.status in terminal
                }
                identities = tuple(
                    identity for identity in identities if identity.ordinal not in terminal_ordinals
                )
            session.commit()
            return DiscoveryPlan(
                run_id=run_id,
                cycle_id=cycle.id,
                profile_snapshot=MappingProxyType(snapshot),
                queries=queries,
                identities=identities,
                planner_version=planner_version,
                planner_hash=planner_hash,
                policy_version=policy_version,
            )

    def _profile_bound_v2_queries(
        self, profile_row: CandidateProfile, profile: CandidateProfileV1
    ) -> tuple[tuple[PlannedQuery, ...], str, str, dict[str, object]]:
        """Build profile-bound v2 queries; config failures raise a stable code.

        Missing/invalid policy and binding mismatches fail this leg visibly
        (recorded on the FAILED cycle) instead of falling back to the generic
        v1 planner, which ignores mapped target titles.
        """

        configured = self._discovery_policy_v1
        if configured is None:
            raise DiscoveryPlanError(DiscoveryErrorCode.POLICY_MISSING.value)
        if isinstance(configured, LoadedDiscoveryPolicyV1):
            policy = configured.policy
        elif isinstance(configured, DiscoveryPolicyV1):
            policy = configured
        elif isinstance(configured, Mapping):
            try:
                policy = DiscoveryPolicyV1.model_validate(configured)
            except ValueError as exc:
                raise DiscoveryPlanError(DiscoveryErrorCode.POLICY_INVALID.value) from exc
        else:
            raise DiscoveryPlanError(DiscoveryErrorCode.POLICY_INVALID.value)
        binding = policy.profile_binding
        if (
            profile_row.id != binding.profile_id
            or profile_row.version != binding.row_version
            or profile_row.schema_version != binding.schema_version
            or not profile_row.is_active
            or canonical_profile_sha256(profile_row.profile_json)
            != binding.canonical_profile_sha256
        ):
            raise DiscoveryPlanError(DiscoveryErrorCode.PROFILE_BINDING_MISMATCH.value)
        try:
            frozen = FrozenCandidateProfileV1(binding=binding, profile=profile)
            compiled = compile_profile_terms(frozen, policy)
            planned = validate_discovery_query_plan(plan_profile_discovery(compiled, policy))
        except DiscoveryPlanError:
            raise
        except (DiscoveryTermsError, ValueError) as exc:
            raise DiscoveryPlanError(DiscoveryErrorCode.POLICY_INVALID.value) from exc
        queries = tuple(
            PlannedQuery(
                ordinal=item.ordinal,
                family=item.family,
                provider_intent=item.provider_intent,
                canonical_query=item.canonical_query,
            )
            for item in planned.queries
        )
        snapshot = _planner_profile_snapshot(profile)
        snapshot.update(
            {
                "discovery_planner": "v2",
                "profile_binding": binding.as_dict(),
                "policy_version": policy.policy_version,
                "policy_sha256": planned.policy_sha256,
                "plan_sha256": planned.plan_sha256,
                "compiler_version": planned.compiler_version,
                "approved_phrases": list(compiled.approved_phrases),
            }
        )
        return queries, planned.planner_version, policy.policy_version, snapshot

    @staticmethod
    def _record_config_failure(
        session: Session, run_id: str, profile: CandidateProfileV1, code: str
    ) -> None:
        """Persist one FAILED cycle so the config defect is operator-visible."""

        repo = DiscoveryRepository(session)
        if repo.get_cycle_for_run(run_id) is not None:
            return
        snapshot = _planner_profile_snapshot(profile)
        snapshot["discovery_planner"] = "v2"
        cycle = repo.create_cycle(
            run_id=run_id,
            profile_snapshot=snapshot,
            planner_version="discovery-planner-v2",
            planner_hash="query_key_unavailable",
            policy_version="discovery-policy-v1",
            status=DiscoveryCycleStatus.FAILED,
        )
        repo.finish_cycle(cycle.id, status=DiscoveryCycleStatus.FAILED, stats={}, error_code=code)
        session.commit()

    async def execute(self, plan: DiscoveryPlan) -> DiscoveryExecution:
        if plan.reused:
            return DiscoveryExecution(plan, (), (), reused_job_ids=_reused_ids(plan))
        if not plan.identities:
            return DiscoveryExecution(
                plan,
                (),
                (),
                error_code=(
                    DiscoveryErrorCode.QUERY_KEY_UNAVAILABLE.value
                    if plan.planner_hash == "query_key_unavailable"
                    else None
                ),
            )
        by_ordinal = {query.ordinal: query for query in plan.queries}
        query_results: list[QueryExecution] = []
        verified: list[VerifiedBatch] = []
        seen_keys: set[str] = set()
        first_error: str | None = None
        for identity in plan.identities:
            query = by_ordinal[identity.ordinal]
            self._checkpoint_query_started(plan.cycle_id, identity)
            try:
                response = await self._provider.search(
                    SearchRequest(
                        operation_key=f"{plan.cycle_id}:query:{identity.ordinal}",
                        query=query.canonical_query,
                        query_key=identity.query_key,
                        planner_version=plan.planner_version,
                        query_version=plan.policy_version,
                        max_results=min(self._policy.max_results_per_query, 10),
                        provider_intent=identity.provider_intent,
                        cycle_query_count=len(plan.queries),
                    )
                )
            except Exception:
                query_results.append(
                    QueryExecution(identity, DiscoveryQueryStatus.FAILED.value, 0, 0, 0, 0, 0)
                )
                self._checkpoint_query(plan.cycle_id, query_results[-1])
                first_error = first_error or DiscoveryErrorCode.PROVIDER_FAILED.value
                continue
            results = list(response.hits[: self._policy.max_results_per_query])
            known = unknown = rejected = 0
            verified_count = 0
            for result in results:
                classified = classify_url(result.url)
                if isinstance(classified, KnownOfficialCandidate):
                    known += 1
                    source_key = canonical_source_key(
                        classified.source_type, dict(classified.configuration)
                    )
                    if source_key in seen_keys:
                        continue
                    seen_keys.add(source_key)
                    batch = await self._verify(classified)
                    if batch is not None:
                        verified.append(batch)
                        verified_count += 1
                elif isinstance(classified, UnknownCandidate):
                    unknown += 1
                else:
                    rejected += 1
            query_execution = QueryExecution(
                identity,
                (
                    DiscoveryQueryStatus.EMPTY.value
                    if response.status == "empty"
                    else DiscoveryQueryStatus.FAILED.value
                    if response.status != "succeeded"
                    else DiscoveryQueryStatus.EXECUTED.value
                ),
                len(results),
                known,
                unknown,
                rejected,
                verified_count,
            )
            if response.status not in {"succeeded", "empty"}:
                first_error = first_error or DiscoveryErrorCode.PROVIDER_FAILED.value
            query_results.append(query_execution)
            self._checkpoint_query(plan.cycle_id, query_execution)
        return DiscoveryExecution(
            plan, tuple(query_results), tuple(verified), error_code=first_error
        )

    async def _verify(self, candidate: KnownOfficialCandidate) -> VerifiedBatch | None:
        source_key = canonical_source_key(candidate.source_type, dict(candidate.configuration))
        snapshot = SourceSnapshot(
            source_id=f"discovery:{source_key}",
            source_type=candidate.source_type,
            name=f"discovery:{source_key}",
            configuration=MappingProxyType(dict(candidate.configuration)),
            source_key=source_key,
            configuration_version=1,
        )
        collector = (
            self._collector_factory(snapshot)
            if self._collector_factory is not None
            else create_collector(snapshot, CollectorContext())
        )
        runtime = CollectorRuntime(budget=CollectionRunBudget())
        collect: Any = collector.collect
        outcome = (
            await collect(snapshot)
            if len(inspect.signature(collect).parameters) == 1
            else await collect(snapshot, runtime)
        )
        if not isinstance(outcome, CollectionSuccess) or not outcome.jobs:
            return None
        has_valid = any(
            (normalized := normalize_raw_job(raw)).title
            and normalized.description
            and (normalized.application_url or normalized.source_url)
            for raw in outcome.jobs
        )
        if not has_valid:
            return None
        # Preserve the collector's exact tuple; the common writer performs the
        # official prefilter without a second collection or transformation.
        return VerifiedBatch(candidate, snapshot, outcome, outcome.jobs)

    def finalize(self, execution: DiscoveryExecution) -> DiscoveryFinalization:
        if execution.plan.reused:
            return DiscoveryFinalization(
                execution.plan.cycle_id,
                0,
                len(execution.reused_job_ids),
                0,
                bool(execution.reused_job_ids),
                "reused",
            )
        with self._session_factory() as session:
            repo = DiscoveryRepository(session)
            created = verified_sources = verified_jobs = blocked = 0
            for query in execution.queries:
                repo.finish_query(execution.plan.cycle_id, query)
            writer = AcquiredJobWriter(session)
            source_service = DiscoveredSourceService(session)
            clarification_attempts_used = 0
            for batch in execution.verified_batches:
                registration = source_service.register_verified(
                    batch.candidate, new_sources_used=created
                )
                if registration.created:
                    created += 1
                if registration.source_id is None or registration.blocked:
                    blocked += 1
                    continue
                verified_sources += 1
                written = writer.write(
                    run_id=execution.plan.run_id,
                    source_id=registration.source_id,
                    raw_jobs=batch.jobs,
                    acquisition="discovery",
                    cycle_id=execution.plan.cycle_id,
                    max_clarification_attempts=max(
                        0, MAX_ATTEMPTS_PER_RUN - clarification_attempts_used
                    ),
                )
                clarification_attempts_used += written.clarification_attempts
                verified_jobs += written.accepted
            stats = {
                "queries": len(execution.queries),
                "candidates": sum(item.candidate_count for item in execution.queries),
                "known": sum(item.known_count for item in execution.queries),
                "unknown": sum(item.unknown_count for item in execution.queries),
                "rejected": sum(item.rejected_count for item in execution.queries),
                "verified_sources": verified_sources,
                "verified_jobs": verified_jobs,
                "blocked": blocked,
            }
            status = DiscoveryCycleStatus.COMPLETED
            if execution.error_code or blocked or not execution.queries:
                status = DiscoveryCycleStatus.DEGRADED
            repo.finish_cycle(
                execution.plan.cycle_id,
                status=status,
                stats=stats,
                error_code=execution.error_code,
            )
            session.commit()
            return DiscoveryFinalization(
                execution.plan.cycle_id,
                verified_sources,
                verified_jobs,
                blocked,
                bool(verified_jobs),
                status.value,
            )

    def _checkpoint_query_started(self, cycle_id: str, identity: QueryIdentity) -> None:
        """Close the replay window before transmitting a provider request."""
        with self._session_factory() as session:
            row = session.scalar(
                select(DiscoveryQuery).where(
                    DiscoveryQuery.cycle_id == cycle_id,
                    DiscoveryQuery.ordinal == identity.ordinal,
                )
            )
            if row is not None and row.status is DiscoveryQueryStatus.PLANNED:
                row.status = DiscoveryQueryStatus.EXECUTED
                session.commit()

    def _checkpoint_query(self, cycle_id: str, execution: QueryExecution) -> None:
        with self._session_factory() as session:
            DiscoveryRepository(session).finish_query(cycle_id, execution)
            session.commit()

    def _reuse_if_possible(self, session: Session, run: JobSearchRun) -> DiscoveryPlan | None:
        if run.retry_of_run_id is None:
            return None
        parent = session.get(JobSearchRun, run.retry_of_run_id)
        if parent is None:
            return None
        parent_cycle = DiscoveryRepository(session).get_cycle_for_run(parent.id)
        if parent_cycle is None or parent_cycle.status not in {
            DiscoveryCycleStatus.COMPLETED,
            DiscoveryCycleStatus.DEGRADED,
            DiscoveryCycleStatus.REUSED,
        }:
            return None
        cycle = DiscoveryRepository(session).get_cycle_for_run(run.id)
        if cycle is None:
            cycle = DiscoveryRepository(session).create_cycle(
                run_id=run.id,
                profile_snapshot=dict(parent_cycle.profile_snapshot_json),
                planner_version=parent_cycle.planner_version,
                planner_hash=parent_cycle.planner_hash,
                policy_version=parent_cycle.policy_version,
                status=DiscoveryCycleStatus.REUSED,
                reused_from_cycle_id=parent_cycle.id,
            )
        job_ids = tuple(
            session.scalars(
                select(RunJob.job_id).where(
                    RunJob.run_id == parent.id,
                    RunJob.stage == "deduplicated",
                    RunJob.status == "succeeded",
                    RunJob.outcome_json["acquisition"].as_string() == "discovery",
                )
            )
        )
        for job_id in job_ids:
            for stage in ("collected", "normalized", "deduplicated"):
                if (
                    session.scalar(
                        select(RunJob.id).where(
                            RunJob.run_id == run.id, RunJob.job_id == job_id, RunJob.stage == stage
                        )
                    )
                    is None
                ):
                    session.add(
                        RunJob(
                            run_id=run.id,
                            job_id=job_id,
                            stage=stage,
                            status="succeeded",
                            attempt_count=1,
                            outcome_json={"acquisition": "discovery", "cycle_id": cycle.id},
                        )
                    )
        return DiscoveryPlan(
            run.id,
            cycle.id,
            MappingProxyType(dict(cycle.profile_snapshot_json)),
            (),
            (),
            cycle.planner_version,
            cycle.planner_hash,
            cycle.policy_version,
            True,
            tuple(job_ids),
        )

    def _cycle_reuse_plan(
        self, session: Session, run: JobSearchRun, cycle: DiscoveryCycle
    ) -> DiscoveryPlan:
        job_ids = tuple(
            session.scalars(
                select(RunJob.job_id).where(
                    RunJob.run_id == run.id,
                    RunJob.stage == "deduplicated",
                    RunJob.status == "succeeded",
                    RunJob.outcome_json["acquisition"].as_string() == "discovery",
                )
            )
        )
        return DiscoveryPlan(
            run.id,
            cycle.id,
            MappingProxyType(dict(cycle.profile_snapshot_json)),
            (),
            (),
            cycle.planner_version,
            cycle.planner_hash,
            cycle.policy_version,
            True,
            job_ids,
        )


def _planner_profile_snapshot(profile: CandidateProfileV1) -> dict[str, object]:
    return {
        "schema_version": 1,
        "target_roles": list(profile.target_roles),
        "regions": list(profile.regions),
        "core_skills": list(profile.core_skills),
        "secondary_skills": list(profile.secondary_skills),
        "remote_only": profile.remote_only,
        "employment_preferences": list(profile.employment_preferences),
        "languages": dict(profile.languages),
    }


def _reused_ids(plan: DiscoveryPlan) -> tuple[str, ...]:
    # The IDs are intentionally not part of the durable plan.  This function
    # is replaced by the sync copy in prepare; execute only needs the signal.
    return plan.reused_job_ids
