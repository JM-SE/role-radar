"""Discovery composition root for one bounded source-only run."""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from datetime import datetime
from typing import Any, cast

from sqlalchemy.orm import Session

from role_radar.acquisition.configuration import AcquisitionConfig
from role_radar.config import Settings
from role_radar.continuous_acquisition.contracts import DISCOVERY_POLICY_VERSION, DiscoveryRunState
from role_radar.continuous_acquisition.discovery import (
    DiscoveryService,
    SqlAlchemyRegistrationStore,
)
from role_radar.continuous_acquisition.providers import (
    BoundedSearchRuntime,
    OfficialATSVerifier,
    create_bounded_collector_provider,
    create_official_ats_verifier,
)
from role_radar.continuous_acquisition.repositories import (
    DiscoveryRepository,
    FenceLostError,
    LeaseOwnedError,
)
from role_radar.continuous_acquisition.runtime_support import (
    EXIT_CLAIM,
    EXIT_FAILED,
    EXIT_INDETERMINATE,
    RuntimeCompositionError,
    RuntimeResult,
    as_utc,
    build_search_runtime,
    owner_for,
)
from role_radar.continuous_acquisition.scheduling import discovery_slot


async def _run_async(
    session: Session,
    *,
    run_id: str,
    operation_id: str,
    search: BoundedSearchRuntime,
    verifier: OfficialATSVerifier,
) -> tuple[Any, ...]:
    async with AsyncExitStack() as stack:
        if search.brave is not None:
            await stack.enter_async_context(cast(Any, search.brave))
        if search.tavily is not None:
            await stack.enter_async_context(cast(Any, search.tavily))
        store = SqlAlchemyRegistrationStore(session, run_id, operation_id)
        return await DiscoveryService(cast(Any, search), verifier, store).run_async()


def run_discovery_once(
    session: Session,
    *,
    settings: Settings,
    config: AcquisitionConfig,
    now: datetime | None = None,
    owner: str | None = None,
    canary_id: str | None = None,
    search: BoundedSearchRuntime | None = None,
    verifier: OfficialATSVerifier | None = None,
) -> RuntimeResult:
    as_of = as_utc(now)
    slot_key = discovery_slot(as_of, canary_id=canary_id)
    worker = owner_for(settings, owner)
    active_search = search or build_search_runtime(config)
    collector = create_bounded_collector_provider()
    active_verifier = verifier or create_official_ats_verifier(collector)
    repository = DiscoveryRepository(session)
    try:
        run = repository.claim(
            slot_key,
            owner=worker,
            policy_version=DISCOVERY_POLICY_VERSION,
            config_version=config.config_version,
        )
        session.commit()
    except LeaseOwnedError as exc:
        session.rollback()
        raise RuntimeCompositionError("lease_owned", exit_code=EXIT_CLAIM) from exc
    except ValueError as exc:
        session.rollback()
        raise RuntimeCompositionError(
            getattr(exc, "code", "claim_conflict"), exit_code=EXIT_CLAIM
        ) from exc

    if run.state not in {"planned", "running"}:
        return RuntimeResult(
            {
                "schema_version": "continuous-discovery-result-v1",
                "workflow": "discovery",
                "run_id": run.id,
                "slot_key": slot_key,
                "state": run.state,
                "replay": True,
            },
            EXIT_FAILED if run.state == "failed" else EXIT_INDETERMINATE if run.state == "indeterminate" else 0,
        )

    operation = repository.intent(
        run.id,
        operation_key=f"{slot_key}:search",
        provider="brave+tavily",
        operation_type="bounded_search_and_verify",
        reserved_capacity=8,
        owner=worker,
        generation=run.fencing_generation,
    )
    session.commit()
    try:
        results = asyncio.run(
            _run_async(
                session,
                run_id=run.id,
                operation_id=operation.id,
                search=active_search,
                verifier=active_verifier,
            )
        )
        search_status = getattr(active_search, "last_status", "succeeded")
        terminal_state = "failed" if search_status == "failed" and not results else "completed"
        result_code = "search_exhausted" if terminal_state == "failed" else None
        repository.finalize_operation(
            operation.id,
            owner=worker,
            generation=run.fencing_generation,
            intent_state="succeeded" if terminal_state == "completed" else "failed",
            result_state=("succeeded" if results else "empty") if terminal_state == "completed" else "failed",
            attempts=1,
            candidate_count=len(results),
            verified_count=sum(
                1
                for item in results
                if item.disposition
                in {"created", "existing_enabled", "existing_disabled", "existing_archived"}
            ),
            result_code=result_code,
        )
        repository.finalize_run(
            run.id,
            owner=worker,
            generation=run.fencing_generation,
            state=terminal_state,
            candidate_count=len(results),
            reserved_count=0,
            verified_count=len(results),
            registered_count=sum(1 for item in results if item.disposition == "created"),
            terminal_code=result_code,
        )
        session.commit()
    except FenceLostError as exc:
        session.rollback()
        raise RuntimeCompositionError("fence_lost", exit_code=EXIT_CLAIM) from exc
    except Exception as exc:
        session.rollback()
        try:
            repository.finalize_operation(
                operation.id,
                owner=worker,
                generation=run.fencing_generation,
                intent_state="indeterminate",
                result_state="indeterminate",
                result_code="provider_result_unknown",
            )
            repository.finalize_run(
                run.id,
                owner=worker,
                generation=run.fencing_generation,
                state=DiscoveryRunState.INDETERMINATE.value,
                terminal_code="provider_result_unknown",
            )
            session.commit()
        except Exception:
            session.rollback()
        raise RuntimeCompositionError(
            "provider_result_unknown", exit_code=EXIT_INDETERMINATE
        ) from exc

    payload = {
        "schema_version": "continuous-discovery-result-v1",
        "workflow": "discovery",
        "run_id": run.id,
        "slot_key": slot_key,
        "state": terminal_state,
        "registration_count": len(results),
        "created_count": sum(1 for item in results if item.disposition == "created"),
        "dispositions": {
            disposition: sum(1 for item in results if item.disposition == disposition)
            for disposition in sorted({item.disposition for item in results})
        },
    }
    return RuntimeResult(
        payload,
        0 if terminal_state == "completed" else EXIT_FAILED,
    )
