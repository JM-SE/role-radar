"""Shared construction, authorization and sanitized result helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from role_radar.acquisition.configuration import (
    AcquisitionConfig,
    ProductionAcquisitionFilePolicy,
    load_acquisition_config,
)
from role_radar.acquisition.credentials import CredentialResolver
from role_radar.config import Settings
from role_radar.continuous_acquisition.providers import (
    BoundedSearchRuntime,
)
from role_radar.continuous_acquisition.scheduling import daily_canary_slot
from role_radar.db.engine import get_engine
from role_radar.db.session import get_session_factory
from role_radar.discovery.providers.brave import BraveSearchProvider
from role_radar.discovery.providers.tavily import TavilySearchProvider

LIVE_ACKNOWLEDGEMENT = "I_ACKNOWLEDGE_LIVE_PROVIDER_CALLS"
CONTINUOUS_ENABLED_ENV = "ROLE_RADAR_CONTINUOUS_ENABLED"

EXIT_OK = 0
EXIT_PRECONDITION = 10
EXIT_CONFIGURATION = 11
EXIT_CLAIM = 12
EXIT_PARTIAL = 20
EXIT_FAILED = 21
EXIT_INDETERMINATE = 22
EXIT_INTERNAL = 70


class RuntimeCompositionError(ValueError):
    """Stable, path-free runtime error exposed by the CLI."""

    def __init__(self, code: str, *, exit_code: int = EXIT_CONFIGURATION) -> None:
        self.code = code
        self.exit_code = exit_code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class RuntimeResult:
    payload: dict[str, Any]
    exit_code: int


@dataclass(frozen=True, slots=True)
class ProviderSummary:
    brave: str
    tavily: str
    discovery_destinations: tuple[str, ...] = (
        "Brave Search API",
        "Tavily Search API",
        "official Greenhouse API",
        "official Lever API",
    )
    acquisition_destinations: tuple[str, ...] = (
        "official Greenhouse API",
        "official Lever API",
    )

    def as_dict(self, workflow: str) -> dict[str, Any]:
        return {
            "schema_version": "continuous-runtime-summary-v1",
            "workflow": workflow,
            "providers": {"brave": self.brave, "tavily": self.tavily},
            "destinations": list(
                self.discovery_destinations
                if workflow == "discovery"
                else self.acquisition_destinations
            ),
            "jobicy": "omitted",
            "downstream": "disabled",
        }


def provider_summary(config: AcquisitionConfig, workflow: str) -> dict[str, Any]:
    return ProviderSummary(
        brave="enabled" if config.brave_free.enabled else "omitted",
        tavily="enabled" if config.tavily_free.enabled else "omitted",
    ).as_dict(workflow)


def require_mode_authorization(
    *,
    mode: str,
    acknowledgement: str | None,
    canary_id: str | None = None,
    environment: dict[str, str] | None = None,
) -> None:
    if mode not in {"manual-canary", "scheduled"}:
        raise RuntimeCompositionError("mode_required", exit_code=EXIT_PRECONDITION)
    if mode == "manual-canary":
        if acknowledgement != LIVE_ACKNOWLEDGEMENT:
            raise RuntimeCompositionError("live_ack_required", exit_code=EXIT_PRECONDITION)
        if canary_id is None:
            raise RuntimeCompositionError("canary_id_required", exit_code=EXIT_PRECONDITION)
        try:
            daily_canary_slot(datetime.now(UTC), namespace="continuous", canary_id=canary_id)
        except ValueError as exc:
            raise RuntimeCompositionError("canary_id_invalid", exit_code=EXIT_PRECONDITION) from exc
        return
    if acknowledgement is not None:
        raise RuntimeCompositionError("ack_not_allowed_for_scheduled", exit_code=EXIT_PRECONDITION)
    if canary_id is not None:
        raise RuntimeCompositionError("canary_id_not_allowed", exit_code=EXIT_PRECONDITION)
    values = os.environ if environment is None else environment
    if values.get(CONTINUOUS_ENABLED_ENV) != "true":
        raise RuntimeCompositionError("continuous_activation_required", exit_code=EXIT_PRECONDITION)


def load_runtime_config(settings: Settings) -> AcquisitionConfig:
    try:
        return load_acquisition_config(
            settings.acquisition_config_path,
            policy=ProductionAcquisitionFilePolicy(),
        )
    except Exception as exc:
        raise RuntimeCompositionError(
            getattr(exc, "code", "config_invalid"), exit_code=EXIT_CONFIGURATION
        ) from exc


def open_runtime(settings: Settings) -> tuple[Any, Session]:
    try:
        engine = get_engine(settings.database_url)
        return engine, get_session_factory(engine)()
    except Exception as exc:
        raise RuntimeCompositionError("database_unavailable", exit_code=EXIT_CONFIGURATION) from exc


def owner_for(settings: Settings, owner: str | None) -> str:
    value = owner or settings.worker_id or os.environ.get("ROLE_RADAR_WORKER_ID")
    return value or f"continuous-cli-{os.getpid()}-{uuid4().hex[:8]}"


def as_utc(now: datetime | None) -> datetime:
    value = now or datetime.now(UTC)
    if value.tzinfo is None or value.utcoffset() is None:
        raise RuntimeCompositionError("clock_not_timezone_aware")
    return value.astimezone(UTC)


def build_search_runtime(config: AcquisitionConfig) -> BoundedSearchRuntime:
    if config.discovery is None:
        raise RuntimeCompositionError("query_hmac_config_missing")
    if config.brave_paid.enabled:
        raise RuntimeCompositionError("brave_paid_must_be_disabled")
    if not config.brave_free.enabled and not config.tavily_free.enabled:
        raise RuntimeCompositionError("search_provider_not_configured")
    try:
        resolver = CredentialResolver()
        query_secret = resolver.resolve(config.discovery.query_hmac_handle).get_secret_value()
        brave: BraveSearchProvider | None = None
        tavily: TavilySearchProvider | None = None
        if config.brave_free.enabled:
            handle = config.brave_free.credential_handle
            if not handle:
                raise RuntimeCompositionError("brave_credential_missing")
            brave = BraveSearchProvider(resolver.text(handle))
        if config.tavily_free.enabled:
            handle = config.tavily_free.credential_handle
            if not handle:
                raise RuntimeCompositionError("tavily_credential_missing")
            tavily = TavilySearchProvider(resolver.text(handle))
        return BoundedSearchRuntime(brave=brave, tavily=tavily, query_secret=query_secret)
    except RuntimeCompositionError:
        raise
    except Exception as exc:
        raise RuntimeCompositionError(
            getattr(exc, "code", "credentials_unavailable"), exit_code=EXIT_CONFIGURATION
        ) from exc


def state_exit_code(state: str) -> int:
    if state in {"completed", "completed_empty"}:
        return EXIT_OK
    if state in {"completed_partial", "partial"}:
        return EXIT_PARTIAL
    if state == "indeterminate":
        return EXIT_INDETERMINATE
    if state == "failed":
        return EXIT_FAILED
    return EXIT_INTERNAL
