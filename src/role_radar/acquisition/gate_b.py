"""Runtime-only builders for the bounded Gate B smoke."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from role_radar.acquisition.activation import ActivationError, validate_jobicy_activation
from role_radar.acquisition.configuration import AcquisitionConfig
from role_radar.acquisition.credentials import CredentialError, CredentialResolver
from role_radar.acquisition.jobicy_terms_evidence import load_jobicy_terms_evidence
from role_radar.collectors.jobicy import JobicyCollector
from role_radar.discovery.contracts import PlannedQuery, ProviderIntent, SearchRequest
from role_radar.discovery.providers.brave import BraveSearchProvider
from role_radar.discovery.providers.tavily import TavilySearchProvider
from role_radar.discovery.query_keys import QueryKeyFactory
from role_radar.sources.configuration import JobicySourceConfigV1

GATE_B_QUERY = "greenhouse job board software engineer"
GATE_B_PLANNER_VERSION = "gate-b-smoke-v1"
GATE_B_QUERY_VERSION = "gate-b-smoke-v1"


class GateBSmokeConfigurationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class GateBSearchRuntime:
    capability: str
    provider: BraveSearchProvider | TavilySearchProvider
    request: SearchRequest


def validate_jobicy_smoke_config(config: AcquisitionConfig) -> None:
    if config.jobicy is None:
        raise GateBSmokeConfigurationError("jobicy_terms_missing")
    try:
        evidence = load_jobicy_terms_evidence(config.jobicy.terms_sha256)
        validate_jobicy_activation(
            evidence,
            terms_sha256=config.jobicy.terms_sha256,
            reviewed_at=config.jobicy.reviewed_at,
            fair_use_ack=config.jobicy.fair_use_ack,
            preserve_destination_ack=config.jobicy.preserve_destination_ack,
            no_redistribution_ack=config.jobicy.no_redistribution_ack,
            now=datetime.now(UTC),
        )
    except (ActivationError, OSError, ValueError) as exc:
        raise GateBSmokeConfigurationError(
            getattr(exc, "code", "jobicy_terms_invalid")
        ) from exc


def build_jobicy_collector() -> JobicyCollector:
    return JobicyCollector(config=JobicySourceConfigV1(region="latam", remote_only=True))


def build_search_runtime(
    capability: str, config: AcquisitionConfig, resolver: CredentialResolver
) -> GateBSearchRuntime:
    if capability == "brave":
        quota = config.brave_free
        if config.brave_paid.enabled:
            raise GateBSmokeConfigurationError("brave_paid_must_be_disabled")
    elif capability == "tavily":
        quota = config.tavily_free
    else:
        raise GateBSmokeConfigurationError("capability_invalid")

    if not quota.enabled or quota.units_limit < 1 or not quota.credential_handle:
        raise GateBSmokeConfigurationError(f"{capability}_free_not_ready")
    if config.discovery is None:
        raise GateBSmokeConfigurationError("query_hmac_config_missing")

    try:
        api_key = resolver.text(quota.credential_handle)
        query_hmac = resolver.resolve(config.discovery.query_hmac_handle).get_secret_value()
    except CredentialError as exc:
        raise GateBSmokeConfigurationError(
            getattr(exc, "code", f"{capability}_credentials_unavailable")
        ) from exc

    query = PlannedQuery(1, "gate-b", ProviderIntent.EXACT, GATE_B_QUERY)
    query_key = QueryKeyFactory(query_hmac).key(query, planner_version=GATE_B_PLANNER_VERSION)
    request = SearchRequest(
        operation_key=f"gate-b:{capability}:1",
        query=GATE_B_QUERY,
        query_key=query_key,
        planner_version=GATE_B_PLANNER_VERSION,
        query_version=GATE_B_QUERY_VERSION,
        max_results=1,
        provider_intent=ProviderIntent.EXACT,
        cycle_query_count=1,
    )
    provider: BraveSearchProvider | TavilySearchProvider
    if capability == "brave":
        provider = BraveSearchProvider(api_key)
    else:
        provider = TavilySearchProvider(api_key)
    return GateBSearchRuntime(capability, provider, request)
