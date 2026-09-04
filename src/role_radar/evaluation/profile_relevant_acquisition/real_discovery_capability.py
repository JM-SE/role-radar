"""Sealed, independently verified claims for the R2 real Gate C discovery boundary.

This module is deliberately pure. It does not resolve credentials, construct
providers, touch the filesystem, or perform discovery. The only way to obtain
an :class:`ApprovedRealDiscoveryCapability` is through an injected verifier.

The pre-C input schema deliberately carries no board list, board identity,
source configuration, or caller ``SourcePlan``. Boards are discovered inside
the authorized Gate C operation, never supplied by the caller.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Protocol, cast

from role_radar.continuous_acquisition.report_only_v2 import DISCOVERY_DESTINATIONS
from role_radar.discovery.authorization_v2 import (
    MAX_REPORT_ONLY_AUTHORIZATION_TTL_SECONDS,
)
from role_radar.discovery.planner_v2 import (
    DISCOVERY_HOST_REGISTRY,
    MAX_APPROVED_PHRASE_CHARS,
    MAX_BRAVE_REQUESTS_PER_RUN,
    MAX_DISCOVERY_PHRASES,
    MAX_DISCOVERY_QUERIES,
    MAX_DISCOVERY_QUERY_CHARS,
    MAX_DISCOVERY_RESULTS_PER_QUERY,
    MAX_TAVILY_REQUESTS_PER_RUN,
    MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN,
    MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN,
    MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN,
    DiscoveryQueryPlanV2,
)

from .gate_c_authorization import (
    AcceptedGateBBinding,
    GateCAuthorization,
    GateCAuthorizationError,
    authorize_gate_c,
)

REAL_DISCOVERY_DESTINATIONS: Final[tuple[str, ...]] = DISCOVERY_DESTINATIONS
REAL_DISCOVERY_HOSTS: Final[tuple[str, ...]] = tuple(item.host for item in DISCOVERY_HOST_REGISTRY)
REAL_DISCOVERY_BOUNDS: Final[tuple[tuple[str, int], ...]] = (
    ("MAX_DISCOVERY_QUERIES", MAX_DISCOVERY_QUERIES),
    ("MAX_DISCOVERY_PHRASES", MAX_DISCOVERY_PHRASES),
    ("MAX_APPROVED_PHRASE_CHARS", MAX_APPROVED_PHRASE_CHARS),
    ("MAX_DISCOVERY_QUERY_CHARS", MAX_DISCOVERY_QUERY_CHARS),
    ("MAX_DISCOVERY_RESULTS_PER_QUERY", MAX_DISCOVERY_RESULTS_PER_QUERY),
    ("MAX_BRAVE_REQUESTS_PER_RUN", MAX_BRAVE_REQUESTS_PER_RUN),
    ("MAX_TAVILY_REQUESTS_PER_RUN", MAX_TAVILY_REQUESTS_PER_RUN),
    ("MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN", MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN),
    ("MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN", MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN),
    ("MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN", MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN),
)
REAL_DISCOVERY_MAX_TTL_SECONDS: Final[int] = MAX_REPORT_ONLY_AUTHORIZATION_TTL_SECONDS
_TOKEN = object()


class RealDiscoveryCapabilityError(ValueError):
    """Detail-free public failure for malformed or stale discovery claims."""

    def __init__(self, code: str = "real_discovery_capability_rejected") -> None:
        self.code = (
            code if code.startswith("real_discovery_") else "real_discovery_capability_rejected"
        )
        super().__init__(self.code)


def _is_utc_datetime(value: object) -> bool:
    return isinstance(value, datetime) and value.tzinfo is UTC


def _utc(value: object) -> datetime:
    if not _is_utc_datetime(value):
        raise RealDiscoveryCapabilityError()
    return cast(datetime, value)


@dataclass(frozen=True, slots=True, init=False)
class RealDiscoveryVerification:
    """Opaque verifier output; callers cannot manufacture approval claims."""

    operation_id: str
    lineage_id: str
    namespace: str
    root: str
    profile_id: str
    profile_version: str
    profile_sha256: str
    policy_id: str
    policy_version: str
    policy_sha256: str
    query_plan_sha256: str
    destinations: tuple[str, ...]
    bounds: tuple[tuple[str, int], ...]
    window_start: datetime
    window_cutoff: datetime
    expires_at: datetime
    ttl_seconds: int
    brave_units_limit: int
    tavily_units_limit: int
    budget_units: int
    per_board_cap: int
    per_company_cap: int

    def __init__(self, *args: object, _token: object = None, **kwargs: object) -> None:
        if _token is not _TOKEN:
            raise TypeError("real discovery verification is external-only")
        names = tuple(self.__dataclass_fields__)
        if len(args) > len(names) or set(kwargs) - set(names):
            raise TypeError("real discovery verification is malformed")
        values = dict(zip(names, args, strict=False)) | kwargs
        if set(values) != set(names):
            raise TypeError("real discovery verification is incomplete")
        if (
            any(
                type(values[name]) is not str
                for name in (
                    "operation_id",
                    "lineage_id",
                    "namespace",
                    "root",
                    "profile_id",
                    "profile_version",
                    "profile_sha256",
                    "policy_id",
                    "policy_version",
                    "policy_sha256",
                    "query_plan_sha256",
                )
            )
            or type(values["destinations"]) is not tuple
            or type(values["bounds"]) is not tuple
            or any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or type(item[1]) is not int
                for item in values["bounds"]
            )
            or any(
                not _is_utc_datetime(values[name])
                for name in ("window_start", "window_cutoff", "expires_at")
            )
            or type(values["ttl_seconds"]) is not int
            or any(
                type(values[name]) is not int or isinstance(values[name], bool)
                for name in (
                    "ttl_seconds",
                    "brave_units_limit",
                    "tavily_units_limit",
                    "budget_units",
                    "per_board_cap",
                    "per_company_cap",
                )
            )
        ):
            raise TypeError("real discovery verification is malformed")
        for name, value in values.items():
            object.__setattr__(self, name, value)


class RealDiscoveryVerifier(Protocol):
    """Independent boundary. It may verify, but never discover or persist."""

    def verify_real_discovery(
        self,
        authorization: GateCAuthorization,
        accepted_b: AcceptedGateBBinding,
        plan: DiscoveryQueryPlanV2,
        config: object,
    ) -> RealDiscoveryVerification: ...


@dataclass(frozen=True, slots=True, init=False)
class ApprovedRealDiscoveryCapability:
    """Immutable, exact-scope real Gate C discovery capability."""

    claims: RealDiscoveryVerification

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("real discovery capability must be verifier-produced")

    @classmethod
    def _from_verified(
        cls, claims: RealDiscoveryVerification, *, _token: object = None
    ) -> ApprovedRealDiscoveryCapability:
        if _token is not _TOKEN or type(claims) is not RealDiscoveryVerification:
            raise RealDiscoveryCapabilityError()
        instance = object.__new__(cls)
        object.__setattr__(instance, "claims", claims)
        return instance

    def verify_for(
        self,
        authorization: GateCAuthorization,
        accepted_b: AcceptedGateBBinding,
        plan: DiscoveryQueryPlanV2,
        config: object,
        *,
        now: datetime,
    ) -> None:
        claims = self.claims
        try:
            if (
                type(authorization) is not GateCAuthorization
                or type(accepted_b) is not AcceptedGateBBinding
                or type(plan) is not DiscoveryQueryPlanV2
            ):
                raise RealDiscoveryCapabilityError()
            try:
                authorize_gate_c(authorization, accepted_b, plan, now=now)
            except GateCAuthorizationError as exc:
                raise RealDiscoveryCapabilityError() from exc
            current = _utc(now).astimezone(UTC)
            provenance = authorization.provenance
            if (
                claims.operation_id != authorization.operation_id
                or claims.lineage_id != authorization.lineage_id
                or claims.namespace != provenance.namespace
                or claims.root != provenance.approved_root
                or claims.profile_id != provenance.profile_id
                or claims.profile_version != provenance.profile_version
                or claims.profile_sha256 != provenance.profile_sha256
                or claims.policy_id != provenance.policy_id
                or claims.policy_version != provenance.policy_version
                or claims.policy_sha256 != provenance.policy_sha256
                or claims.query_plan_sha256 != provenance.query_plan_sha256
                or claims.query_plan_sha256 != plan.plan_sha256
                or claims.destinations != REAL_DISCOVERY_DESTINATIONS
                or claims.bounds != REAL_DISCOVERY_BOUNDS
                or claims.budget_units != authorization.budget_units
                or claims.per_board_cap != authorization.per_board_cap
                or claims.per_company_cap != authorization.per_company_cap
                or claims.window_start != _parse_utc(provenance.window_start_utc)
                or claims.window_cutoff != _parse_utc(provenance.cutoff_utc)
                or claims.expires_at != _parse_utc(authorization.expires_at_utc)
                or claims.ttl_seconds <= 0
                or claims.ttl_seconds > REAL_DISCOVERY_MAX_TTL_SECONDS
                or current < claims.window_start
                or current >= claims.expires_at
                or current.strftime("%Y-%m") != claims.window_start.strftime("%Y-%m")
            ):
                raise RealDiscoveryCapabilityError()
            _verify_plan_bounds(plan)
            _verify_free_only_config(config, claims)
        except RealDiscoveryCapabilityError:
            raise
        except Exception as exc:
            raise RealDiscoveryCapabilityError() from exc


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value[:-1] + "+00:00") if value.endswith("Z") else None
    if parsed is None or parsed.tzinfo is not UTC:
        raise RealDiscoveryCapabilityError()
    return parsed


def _verify_plan_bounds(plan: DiscoveryQueryPlanV2) -> None:
    expected = dict(REAL_DISCOVERY_BOUNDS)
    actual = {
        "MAX_DISCOVERY_QUERIES": plan.max_discovery_queries,
        "MAX_DISCOVERY_PHRASES": plan.max_discovery_phrases,
        "MAX_APPROVED_PHRASE_CHARS": plan.max_approved_phrase_chars,
        "MAX_DISCOVERY_QUERY_CHARS": plan.max_discovery_query_chars,
        "MAX_DISCOVERY_RESULTS_PER_QUERY": plan.max_discovery_results_per_query,
        "MAX_BRAVE_REQUESTS_PER_RUN": plan.max_brave_requests_per_run,
        "MAX_TAVILY_REQUESTS_PER_RUN": plan.max_tavily_requests_per_run,
        "MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN": plan.max_unique_board_candidates_per_run,
        "MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN": (plan.max_unique_board_verifications_per_run),
        "MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN": (plan.max_verification_wire_attempts_per_run),
    }
    if actual != expected:
        raise RealDiscoveryCapabilityError()
    if tuple(item.host for item in plan.source_registry) != REAL_DISCOVERY_HOSTS:
        raise RealDiscoveryCapabilityError()
    if len(plan.queries) != MAX_DISCOVERY_QUERIES:
        raise RealDiscoveryCapabilityError()


def _quota_field(config: object, field: str) -> object:
    get = getattr(config, field, None)
    if get is None and isinstance(config, dict):
        return config.get(field)
    return get


def _verify_free_only_config(config: object, claims: RealDiscoveryVerification) -> None:
    try:
        from role_radar.continuous_acquisition.report_only_v2 import (
            quota_contexts_from_config as contexts_from_config,
        )

        contexts = contexts_from_config(config, created=claims.window_start)
    except Exception as exc:
        raise RealDiscoveryCapabilityError() from exc
    by_provider = {context.provider: context for context in contexts}
    if set(by_provider) != {"brave", "tavily"}:
        raise RealDiscoveryCapabilityError()
    for provider in ("brave", "tavily"):
        context = by_provider[provider]
        if context.tier != "free" or context.utc_month != claims.window_start.strftime("%Y-%m"):
            raise RealDiscoveryCapabilityError()
    if (
        by_provider["brave"].unit_limit != claims.brave_units_limit
        or by_provider["tavily"].unit_limit != claims.tavily_units_limit
    ):
        raise RealDiscoveryCapabilityError()
    for field in ("brave_paid", "tavily_paid"):
        paid = _quota_field(config, field)
        if paid is None:
            continue
        enabled = (
            paid.enabled
            if hasattr(paid, "enabled")
            else cast(Mapping[str, object], paid).get("enabled")
            if isinstance(paid, Mapping)
            else cast(Any, paid).get("enabled")
        )
        if enabled is True:
            raise RealDiscoveryCapabilityError()


def capability_from_independent_verifier(
    authorization: GateCAuthorization,
    accepted_b: AcceptedGateBBinding,
    plan: DiscoveryQueryPlanV2,
    config: object,
    verifier: RealDiscoveryVerifier,
    *,
    now: datetime,
) -> ApprovedRealDiscoveryCapability:
    if (
        type(authorization) is not GateCAuthorization
        or type(accepted_b) is not AcceptedGateBBinding
        or type(plan) is not DiscoveryQueryPlanV2
    ):
        raise RealDiscoveryCapabilityError()
    if verifier is None or not callable(getattr(verifier, "verify_real_discovery", None)):
        raise RealDiscoveryCapabilityError("real_discovery_verifier_required")
    try:
        claims = verifier.verify_real_discovery(authorization, accepted_b, plan, config)
    except Exception as exc:
        raise RealDiscoveryCapabilityError() from exc
    if type(claims) is not RealDiscoveryVerification:
        raise RealDiscoveryCapabilityError()
    capability = ApprovedRealDiscoveryCapability._from_verified(claims, _token=_TOKEN)
    capability.verify_for(authorization, accepted_b, plan, config, now=now)
    return capability


def make_test_real_discovery_verification(
    authorization: GateCAuthorization,
    accepted_b: AcceptedGateBBinding,
    plan: DiscoveryQueryPlanV2,
    config: object,
) -> RealDiscoveryVerification:
    """Build only verifier output for an offline fake verifier.

    The capability still must be produced through
    :func:`capability_from_independent_verifier`; this helper performs no
    approval and resolves no credential.
    """

    if (
        type(authorization) is not GateCAuthorization
        or type(accepted_b) is not AcceptedGateBBinding
        or type(plan) is not DiscoveryQueryPlanV2
    ):
        raise RealDiscoveryCapabilityError()
    try:
        from role_radar.continuous_acquisition.report_only_v2 import (
            quota_contexts_from_config as contexts_from_config,
        )

        window_start = _parse_utc(authorization.provenance.window_start_utc)
        contexts = contexts_from_config(config, created=window_start)
    except Exception as exc:
        raise RealDiscoveryCapabilityError() from exc
    by_provider = {context.provider: context for context in contexts}
    return RealDiscoveryVerification(
        authorization.operation_id,
        authorization.lineage_id,
        authorization.provenance.namespace,
        authorization.provenance.approved_root,
        authorization.provenance.profile_id,
        authorization.provenance.profile_version,
        authorization.provenance.profile_sha256,
        authorization.provenance.policy_id,
        authorization.provenance.policy_version,
        authorization.provenance.policy_sha256,
        authorization.provenance.query_plan_sha256,
        REAL_DISCOVERY_DESTINATIONS,
        REAL_DISCOVERY_BOUNDS,
        window_start,
        _parse_utc(authorization.provenance.cutoff_utc),
        _parse_utc(authorization.expires_at_utc),
        REAL_DISCOVERY_MAX_TTL_SECONDS,
        by_provider["brave"].unit_limit,
        by_provider["tavily"].unit_limit,
        authorization.budget_units,
        authorization.per_board_cap,
        authorization.per_company_cap,
        _token=_TOKEN,
    )


__all__ = [
    "REAL_DISCOVERY_BOUNDS",
    "REAL_DISCOVERY_DESTINATIONS",
    "REAL_DISCOVERY_HOSTS",
    "REAL_DISCOVERY_MAX_TTL_SECONDS",
    "ApprovedRealDiscoveryCapability",
    "RealDiscoveryCapabilityError",
    "RealDiscoveryVerification",
    "RealDiscoveryVerifier",
    "capability_from_independent_verifier",
    "make_test_real_discovery_verification",
]
