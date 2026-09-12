"""Offline report-only preparation and verification for discovery v2.

This module deliberately stops at immutable, private operation evidence.  It
does not resolve credentials, open a database session, construct a provider, or
send a request.  The existing authorization and artifact contracts remain the
single sources of truth for canonical identities and private publication.
"""

from __future__ import annotations

import base64
import binascii
import os
import secrets
import stat
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, Final, Protocol, cast
from uuid import UUID, uuid4

from role_radar.continuous_acquisition.discovery_artifacts_v2 import (
    MAX_OPERATION_ARTIFACT_BYTES,
    DiscoveryArtifactError,
    ReportOnlyRequestEvidenceV1,
    ReportOnlyTerminalReportV1,
    ReportOnlyVerifiedSourceV1,
    build_start_marker,
    build_terminal_report,
    ensure_private_artifact_root,
    read_private_artifact_bytes,
    read_start_marker,
    read_terminal_report,
    write_private_artifact,
)
from role_radar.continuous_acquisition.discovery_budget_v2 import DiscoveryBudgetError
from role_radar.continuous_acquisition.providers import SearchAuthorizationCapability
from role_radar.discovery.authorization_v2 import (
    MAX_REPORT_ONLY_AUTHORIZATION_TTL_SECONDS,
    DiscoveryOperationV2,
    OperationChallengeV2,
    ProviderQuotaContextV2,
    build_plan_bound_report_only_operation,
    build_report_only_challenge,
    canonical_json_bytes,
    validate_report_only_challenge,
    validate_report_only_operation,
)
from role_radar.discovery.authorization_v2 import (
    ProviderQuotaContextV1 as AuthorizationProviderQuotaContextV1,
)
from role_radar.discovery.authorization_v2 import (
    operation_sha256 as authorization_operation_sha256,
)
from role_radar.discovery.planner_v2 import (
    DISCOVERY_PLAN_SCHEMA_VERSION,
    DISCOVERY_PLANNER_VERSION,
    DiscoveryQueryPlanV2,
    planned_query_v2_to_search_request,
)
from role_radar.discovery.profile_terms import PROFILE_TERMS_COMPILER_VERSION

REPORT_ONLY_OPERATION_SCHEMA_VERSION: Final = "report-only-operation-v1"
REPORT_ONLY_OPERATION_KIND: Final = "continuous_discovery_v2_report_only"
REPORT_ONLY_OPERATION_FILE: Final = "operation-v1.json"
REPORT_ONLY_OPERATIONS_DIRECTORY: Final = "report-only/operations"
DISCOVERY_DESTINATIONS: Final = (
    "brave_search_api",
    "tavily_search_api",
    "greenhouse_official_api",
    "lever_global_official_api",
    "lever_eu_official_api",
)


class ReportOnlyError(ValueError):
    """Stable, sanitized failure from the offline report-only seam."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _utc(value: object, *, field: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ReportOnlyError(f"{field}_invalid")
    return value.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _sha(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ReportOnlyError(f"{field}_invalid")
    return value


def _canonical_uuid(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise ReportOnlyError(f"{field}_invalid")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ReportOnlyError(f"{field}_invalid") from exc
    if str(parsed) != value or value != value.casefold():
        raise ReportOnlyError(f"{field}_invalid")
    return value


def _clock_value(clock: Callable[[], datetime] | datetime | None) -> datetime:
    value = clock() if callable(clock) else clock
    return _utc(datetime.now(UTC) if value is None else value, field="clock")


def _next_month(value: datetime) -> datetime:
    if value.month == 12:
        return datetime(value.year + 1, 1, 1, tzinfo=UTC)
    return datetime(value.year, value.month + 1, 1, tzinfo=UTC)


def _authorization_expiry(created: datetime) -> datetime:
    month_end = _next_month(created) - timedelta(microseconds=1)
    expiry = min(
        created + timedelta(seconds=MAX_REPORT_ONLY_AUTHORIZATION_TTL_SECONDS),
        month_end,
    )
    if expiry <= created:
        raise ReportOnlyError("discovery_v2_authorization_window_invalid")
    return expiry


def _config_value(config: object, name: str) -> object:
    value = getattr(config, name, None)
    if value is None and isinstance(config, Mapping):
        value = config.get(name)
    return value


def _field_value(value: object, name: str, default: object = None) -> object:
    result = getattr(value, name, default)
    if isinstance(value, Mapping):
        result = value.get(name, default)
    return result


@dataclass(frozen=True, slots=True)
class ProviderBindingV1:
    provider: str
    tier: str
    enabled: bool

    def __post_init__(self) -> None:
        if self.provider not in {"brave", "tavily", "greenhouse", "lever"}:
            raise ReportOnlyError("provider_invalid")
        expected_tier = "free" if self.provider in {"brave", "tavily"} else "official"
        if self.tier != expected_tier or type(self.enabled) is not bool:
            raise ReportOnlyError("provider_binding_invalid")

    def as_dict(self) -> dict[str, object]:
        return {"provider": self.provider, "tier": self.tier, "enabled": self.enabled}


ProviderQuotaContextV1 = AuthorizationProviderQuotaContextV1


@dataclass(frozen=True, slots=True)
class ReportOnlyOperationV1:
    """Prepared operation plus the ephemeral challenge used for offline checks."""

    operation: DiscoveryOperationV2
    challenge: OperationChallengeV2
    challenge_nonce: str
    providers: tuple[ProviderBindingV1, ...]
    destinations: tuple[str, ...]
    quota_contexts: tuple[ProviderQuotaContextV1, ...]
    policy_schema_version: int
    plan_identity: Mapping[str, object]
    authorization_max_ttl_seconds: int = MAX_REPORT_ONLY_AUTHORIZATION_TTL_SECONDS

    def __post_init__(self) -> None:
        if (
            not isinstance(self.operation, DiscoveryOperationV2)
            or not self.operation.is_report_only
        ):
            raise ReportOnlyError("operation_invalid")
        if not isinstance(self.challenge, OperationChallengeV2):
            raise ReportOnlyError("challenge_invalid")
        if type(self.challenge_nonce) is not str:
            raise ReportOnlyError("challenge_nonce_invalid")
        try:
            decoded = base64.urlsafe_b64decode(self.challenge_nonce + "===")
        except (ValueError, binascii.Error) as exc:
            raise ReportOnlyError("challenge_nonce_invalid") from exc
        if (
            len(decoded) != 32
            or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != self.challenge_nonce
        ):
            raise ReportOnlyError("challenge_nonce_invalid")
        if self.operation.challenge_nonce != self.challenge_nonce:
            raise ReportOnlyError("challenge_binding_mismatch")
        if type(self.providers) is not tuple or type(self.destinations) is not tuple:
            raise ReportOnlyError("operation_bindings_invalid")
        if any(not isinstance(item, ProviderBindingV1) for item in self.providers):
            raise ReportOnlyError("operation_bindings_invalid")
        expected_providers = (
            ProviderBindingV1("brave", "free", self.providers[0].enabled)
            if len(self.providers) > 0
            else None,
            ProviderBindingV1("tavily", "free", self.providers[1].enabled)
            if len(self.providers) > 1
            else None,
            ProviderBindingV1("greenhouse", "official", True),
            ProviderBindingV1("lever", "official", True),
        )
        if self.providers != expected_providers or self.destinations != DISCOVERY_DESTINATIONS:
            raise ReportOnlyError("operation_bindings_invalid")
        if type(self.quota_contexts) is not tuple:
            raise ReportOnlyError("quota_contexts_invalid")
        if self.operation.quota_contexts != self.quota_contexts:
            raise ReportOnlyError("quota_contexts_mismatch")
        enabled_search_providers = tuple(
            item.provider
            for item in self.providers
            if item.enabled and item.provider in {"brave", "tavily"}
        )
        if tuple(item.provider for item in self.quota_contexts) != enabled_search_providers:
            raise ReportOnlyError("quota_contexts_mismatch")
        if type(self.policy_schema_version) is not int or self.policy_schema_version != 1:
            raise ReportOnlyError("policy_identity_invalid")
        if not isinstance(self.plan_identity, Mapping) or dict(self.plan_identity) != {
            "schema_version": DISCOVERY_PLAN_SCHEMA_VERSION,
            "planner_version": DISCOVERY_PLANNER_VERSION,
            "compiler_version": PROFILE_TERMS_COMPILER_VERSION,
            "plan_sha256": self.plan_sha256,
        }:
            raise ReportOnlyError("plan_identity_invalid")
        if self.operation.authorization_max_ttl_seconds != self.authorization_max_ttl_seconds:
            raise ReportOnlyError("authorization_window_invalid")
        if (
            type(self.authorization_max_ttl_seconds) is not int
            or self.authorization_max_ttl_seconds <= 0
        ):
            raise ReportOnlyError("authorization_window_invalid")
        if self.challenge.operation_id != self.operation_id:
            raise ReportOnlyError("challenge_binding_mismatch")
        if self.challenge.operation_sha256 != authorization_operation_sha256(self.operation):
            raise ReportOnlyError("challenge_binding_mismatch")
        next_month = _next_month(self.created_at_utc)
        if self.authorization_expires_at_utc >= next_month:
            raise ReportOnlyError("authorization_window_invalid")

    @property
    def operation_id(self) -> str:
        return self.operation.operation_id

    @property
    def operation_sha256(self) -> str:
        return sha256(canonical_json_bytes(self._as_dict(include_hash=False))).hexdigest()

    @property
    def challenge_sha256(self) -> str:
        return self.challenge.challenge_sha256

    @property
    def created_at_utc(self) -> datetime:
        return self.operation.created_at

    @property
    def authorization_expires_at_utc(self) -> datetime:
        return self.operation.expires_at

    @property
    def profile_binding(self) -> object:
        return self.operation.profile_binding

    @property
    def policy_version(self) -> str:
        return self.operation.policy_version

    @property
    def policy_sha256(self) -> str:
        return self.operation.policy_sha256

    @property
    def plan_sha256(self) -> str:
        return self.operation.plan_sha256

    @property
    def operation_kind(self) -> str:
        return REPORT_ONLY_OPERATION_KIND

    @property
    def mode(self) -> str:
        return "report_only"

    @property
    def budgets(self) -> dict[str, int]:
        return self.operation.budgets.as_dict()

    def as_dict(self) -> dict[str, object]:
        return self._as_dict(include_hash=True)

    def _as_dict(self, *, include_hash: bool) -> dict[str, object]:
        profile_binding = self.operation.profile_binding
        payload: dict[str, object] = {
            "schema_version": REPORT_ONLY_OPERATION_SCHEMA_VERSION,
            "operation_kind": REPORT_ONLY_OPERATION_KIND,
            "operation_id": self.operation_id,
            "created_at_utc": _iso(self.created_at_utc),
            "challenge_nonce": self.challenge_nonce,
            "profile_binding": profile_binding.as_dict(),
            "policy_identity": {
                "schema_version": self.policy_schema_version,
                "policy_version": self.policy_version,
                "policy_sha256": self.policy_sha256,
            },
            "plan_identity": dict(self.plan_identity),
            "providers": [item.as_dict() for item in self.providers],
            "destinations": list(self.destinations),
            "budgets": self.budgets,
            "quota_contexts": [item.as_dict() for item in self.quota_contexts],
            "authorization_max_ttl_seconds": self.authorization_max_ttl_seconds,
            "authorization_expires_at_utc": _iso(self.authorization_expires_at_utc),
            "challenge_sha256": self.challenge_sha256,
        }
        if include_hash:
            payload["operation_sha256"] = self.operation_sha256
        return payload

    def sanitized_dict(self) -> dict[str, object]:
        return {
            "schema_version": REPORT_ONLY_OPERATION_SCHEMA_VERSION,
            "operation_id": self.operation_id,
            "operation_sha256": self.operation_sha256,
            "challenge_sha256": self.challenge_sha256,
            "profile_id": getattr(self.profile_binding, "profile_id", None),
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "plan_sha256": self.plan_sha256,
            "utc_month": self.created_at_utc.strftime("%Y-%m"),
            "authorization_expires_at_utc": _iso(self.authorization_expires_at_utc),
            "provider_count": sum(1 for item in self.providers if item.enabled),
            "quota_context_count": len(self.quota_contexts),
        }


@dataclass(frozen=True, slots=True)
class ReportOnlyAuthorizationEvidence:
    operation_id: str
    operation_sha256: str
    challenge_sha256: str
    expires_at_utc: datetime

    @property
    def authorization_sha256(self) -> str:
        return sha256(
            canonical_json_bytes(
                {
                    "operation_id": self.operation_id,
                    "operation_sha256": self.operation_sha256,
                    "challenge_sha256": self.challenge_sha256,
                    "expires_at_utc": _iso(self.expires_at_utc),
                }
            )
        ).hexdigest()


def _quota_contexts(config: object, created: datetime) -> tuple[ProviderQuotaContextV1, ...]:
    config_version = _config_value(config, "config_version")
    if type(config_version) is not str or not config_version:
        raise ReportOnlyError("config_invalid")
    result: list[ProviderQuotaContextV1] = []
    for provider, field, maximum in (
        ("brave", "brave_free", 4),
        ("tavily", "tavily_free", 4),
    ):
        quota = _config_value(config, field)
        if quota is None:
            continue
        enabled = _field_value(quota, "enabled", False)
        if type(enabled) is not bool:
            raise ReportOnlyError("config_invalid")
        if not enabled:
            continue
        units_limit = _field_value(quota, "units_limit")
        if type(units_limit) is not int or units_limit < 0:
            raise ReportOnlyError("config_invalid")
        result.append(
            ProviderQuotaContextV1(
                provider=provider,
                tier="free",
                utc_month=created.strftime("%Y-%m"),
                config_version=config_version,
                unit_limit=units_limit,
                micro_usd_limit=0,
                reservation_units_per_call=1,
                reservation_micro_usd_per_call=0,
                operation_max_calls=maximum,
            )
        )
    return tuple(result)


def _provider_bindings(config: object) -> tuple[ProviderBindingV1, ...]:
    values: list[ProviderBindingV1] = []
    for provider, field in (("brave", "brave_free"), ("tavily", "tavily_free")):
        quota = _config_value(config, field)
        enabled_value = _field_value(quota, "enabled", False) if quota is not None else False
        if type(enabled_value) is not bool:
            raise ReportOnlyError("config_invalid")
        enabled = enabled_value
        values.append(ProviderBindingV1(provider, "free", enabled))
    values.extend(
        (
            ProviderBindingV1("greenhouse", "official", True),
            ProviderBindingV1("lever", "official", True),
        )
    )
    return tuple(values)


def _auth_quota_contexts(
    contexts: tuple[ProviderQuotaContextV1, ...],
) -> tuple[ProviderQuotaContextV2, ...]:
    return contexts


def _operation_directory(root: Path, operation_id: str) -> Path:
    if not isinstance(root, Path) or not root.is_absolute() or root == Path(root.anchor):
        raise ReportOnlyError("artifact_root_invalid")
    _canonical_uuid(operation_id, field="operation_id")
    try:
        ensure_private_artifact_root(root)
        directory = root
        for component in (*REPORT_ONLY_OPERATIONS_DIRECTORY.split("/"), operation_id):
            directory = directory / component
            directory.mkdir(mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)
            metadata = directory.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or metadata.st_uid != os.geteuid()
                or directory.is_symlink()
            ):
                raise ReportOnlyError("artifact_root_not_private")
        return directory
    except ReportOnlyError:
        raise
    except OSError as exc:
        raise ReportOnlyError("artifact_root_invalid") from exc


def _write_idempotent(directory: Path, name: str, payload: bytes) -> Path:
    try:
        target = directory / name
        if target.exists():
            current = read_private_artifact_bytes(directory, name)
            if current != payload:
                raise ReportOnlyError("artifact_conflict")
            return target
        return write_private_artifact(directory, name, payload)
    except ReportOnlyError:
        raise
    except DiscoveryArtifactError as exc:
        if exc.code == "artifact_exists":
            try:
                if read_private_artifact_bytes(directory, name) == payload:
                    return directory / name
            except DiscoveryArtifactError:
                pass
            raise ReportOnlyError("artifact_conflict") from exc
        raise ReportOnlyError(exc.code) from exc


def prepare_report_only_operation(
    plan: object,
    config: object,
    *,
    operation_id: str | None = None,
    clock: Callable[[], datetime] | datetime | None = None,
    nonce_source: Callable[[], bytes] | None = None,
    artifact_root: Path | None = None,
) -> ReportOnlyOperationV1:
    """Prepare one immutable report-only operation without any live capability."""

    created = _clock_value(clock)
    raw_id = str(uuid4()) if operation_id is None else operation_id
    operation_id = _canonical_uuid(raw_id, field="operation_id")
    source = secrets.token_bytes if nonce_source is None else nonce_source
    nonce = source()
    if type(nonce) is not bytes or len(nonce) != 32:
        raise ReportOnlyError("challenge_nonce_invalid")
    encoded_nonce = base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("=")
    contexts = _quota_contexts(config, created)
    expires = _authorization_expiry(created)
    try:
        typed_plan = cast(Any, plan)
        plan_identity = {
            "schema_version": typed_plan.schema_version,
            "planner_version": typed_plan.planner_version,
            "compiler_version": typed_plan.compiler_version,
            "plan_sha256": typed_plan.plan_sha256,
        }
        policy_schema_version = typed_plan.policy_schema_version
        operation = build_plan_bound_report_only_operation(
            operation_id=operation_id,
            plan=plan,
            created_at=created,
            ttl_seconds=MAX_REPORT_ONLY_AUTHORIZATION_TTL_SECONDS,
            quota_contexts=_auth_quota_contexts(
                contexts,
            ),
            challenge_nonce=encoded_nonce,
            authorization_max_ttl_seconds=MAX_REPORT_ONLY_AUTHORIZATION_TTL_SECONDS,
            expires_at=expires,
        )
        challenge = build_report_only_challenge(
            operation,
            issued_at=created,
            ttl_seconds=MAX_REPORT_ONLY_AUTHORIZATION_TTL_SECONDS,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ReportOnlyError(getattr(exc, "code", "operation_invalid")) from exc
    prepared = ReportOnlyOperationV1(
        operation=operation,
        challenge=challenge,
        challenge_nonce=encoded_nonce,
        providers=_provider_bindings(config),
        destinations=DISCOVERY_DESTINATIONS,
        quota_contexts=contexts,
        policy_schema_version=policy_schema_version,
        plan_identity=plan_identity,
    )
    if artifact_root is not None:
        directory = _operation_directory(artifact_root, prepared.operation_id)
        payload = canonical_json_bytes(prepared.as_dict())
        _write_idempotent(directory, REPORT_ONLY_OPERATION_FILE, payload)
    return prepared


def verify_report_only_authorization(
    operation: ReportOnlyOperationV1,
    artifact: object | None = None,
    *,
    now: datetime | None = None,
) -> ReportOnlyAuthorizationEvidence:
    """Verify operation/challenge bytes offline; never create a capability."""

    if not isinstance(operation, ReportOnlyOperationV1):
        raise ReportOnlyError("authorization_invalid")
    check_at = _clock_value(now)
    try:
        validate_report_only_operation(
            operation.operation,
            profile_binding=operation.operation.profile_binding,
            policy_version=operation.policy_version,
            policy_sha256=operation.policy_sha256,
            plan_sha256=operation.plan_sha256,
            now=check_at,
        )
        validate_report_only_challenge(operation.operation, operation.challenge, now=check_at)
    except (TypeError, ValueError) as exc:
        raise ReportOnlyError(getattr(exc, "code", "authorization_invalid")) from exc
    if artifact is not None:
        if isinstance(artifact, (bytes, bytearray)):
            try:
                actual = bytes(artifact)
            except (TypeError, ValueError) as exc:
                raise ReportOnlyError("authorization_invalid") from exc
        elif isinstance(artifact, Mapping):
            actual = canonical_json_bytes(dict(artifact))
        else:
            raise ReportOnlyError("authorization_invalid")
        if actual != canonical_json_bytes(operation.as_dict()):
            raise ReportOnlyError("authorization_invalid")
    return ReportOnlyAuthorizationEvidence(
        operation_id=operation.operation_id,
        operation_sha256=operation.operation_sha256,
        challenge_sha256=operation.challenge_sha256,
        expires_at_utc=operation.authorization_expires_at_utc,
    )


def revalidate_report_only_quota_context(
    operation: ReportOnlyOperationV1,
    authorization: ReportOnlyAuthorizationEvidence,
    config: object,
    now: datetime,
    quota_evidence: tuple[ProviderQuotaContextV1, ...] | None = None,
) -> tuple[ProviderQuotaContextV1, ...]:
    """Recheck immutable month/config facts before a future request seam."""

    if not isinstance(operation, ReportOnlyOperationV1):
        raise ReportOnlyError("authorization_invalid")
    if not isinstance(authorization, ReportOnlyAuthorizationEvidence):
        raise ReportOnlyError("authorization_invalid")
    if (
        authorization.operation_id != operation.operation_id
        or authorization.operation_sha256 != operation.operation_sha256
        or authorization.challenge_sha256 != operation.challenge_sha256
        or authorization.expires_at_utc != operation.authorization_expires_at_utc
    ):
        raise ReportOnlyError("authorization_invalid")
    current = _utc(now, field="now")
    if current.strftime("%Y-%m") != operation.created_at_utc.strftime("%Y-%m"):
        raise ReportOnlyError("discovery_quota_month_stale")
    if current >= operation.authorization_expires_at_utc:
        raise ReportOnlyError("discovery_v2_authorization_expired")
    expected = _quota_contexts(config, operation.created_at_utc)
    if expected != operation.quota_contexts:
        raise ReportOnlyError("discovery_quota_context_stale")
    if quota_evidence is not None and quota_evidence != expected:
        raise ReportOnlyError("discovery_quota_evidence_invalid")
    return expected


def quota_contexts_from_config(
    config: object, *, created: datetime | None = None
) -> tuple[ProviderQuotaContextV1, ...]:
    """Expose the pure config-to-context binding for the runtime seam."""

    return _quota_contexts(config, _clock_value(created))


class ReportOnlySearchRuntime(Protocol):
    """Small structural contract consumed by the report-only state machine."""

    plan: object
    last_responses: tuple[tuple[int, object], ...]

    async def search(self) -> tuple[object, ...]: ...


ReportOnlyVerifier = Callable[[object], Awaitable[ReportOnlyVerifiedSourceV1 | None]]


def _report_only_directory(root: Path, operation_id: str) -> Path:
    return _operation_directory(root, operation_id)


def _report_request_evidence(
    operation: ReportOnlyOperationV1, runtime: ReportOnlySearchRuntime
) -> tuple[ReportOnlyRequestEvidenceV1, ...]:
    plan = cast(DiscoveryQueryPlanV2, runtime.plan)
    responses = runtime.last_responses
    result: list[ReportOnlyRequestEvidenceV1] = []
    for request_ordinal, (query_ordinal, response) in enumerate(responses, start=1):
        query = next(
            (item for item in getattr(plan, "queries", ()) if item.ordinal == query_ordinal),
            None,
        )
        if query is None:
            raise ReportOnlyError("discovery_quota_evidence_invalid")
        request = planned_query_v2_to_search_request(query, plan, operation.operation_id)
        provider = str(getattr(response, "provider", ""))
        if provider not in {"brave", "tavily"}:
            raise ReportOnlyError("discovery_quota_evidence_invalid")
        durable_key = f"{request.operation_key}:{provider}"
        identity = canonical_json_bytes(
            {
                "operation_sha256": operation.operation_sha256,
                "plan_sha256": operation.plan_sha256,
                "provider": provider,
                "destination": f"search:{provider}",
                "query_ordinal": query_ordinal,
                "query_sha256": sha256(request.query.encode("utf-8")).hexdigest(),
                "max_results": request.max_results,
            }
        )
        status = str(getattr(response, "status", "malformed"))
        transmission = "indeterminate" if status == "indeterminate" else "sent"
        result.append(
            ReportOnlyRequestEvidenceV1(
                request_ordinal=request_ordinal,
                kind="search",
                provider=provider,
                destination=f"search:{provider}",
                query_ordinal=query_ordinal,
                operation_key_sha256=sha256(durable_key.encode("utf-8")).hexdigest(),
                request_identity_sha256=sha256(identity).hexdigest(),
                transmission=transmission,
                outcome=status,
                result_count=int(getattr(response, "result_count", 0)),
                known_count=int(getattr(response, "known_count", 0)),
                unknown_count=max(
                    0,
                    int(getattr(response, "result_count", 0))
                    - int(getattr(response, "known_count", 0)),
                ),
                rejected_count=0,
                duration_ms=int(getattr(response, "duration_ms", 0)),
                error_code=getattr(response, "error_code", None),
                identity_query_sha256=sha256(request.query.encode("utf-8")).hexdigest(),
                identity_max_results=request.max_results,
            )
        )
    return tuple(result)


async def execute_report_only(
    operation: ReportOnlyOperationV1,
    authorization: ReportOnlyAuthorizationEvidence,
    config: object,
    *,
    search_runtime: ReportOnlySearchRuntime,
    artifact_root: Path,
    official_verifier: ReportOnlyVerifier | None = None,
    clock: Callable[[], datetime] | datetime | None = None,
) -> ReportOnlyTerminalReportV1:
    """Execute the injected report-only state machine without registration.

    Production capability creation remains blocked in Gate A.  This seam exists
    for explicit fake-capability tests and future manually authorized gates;
    it owns marker-before-transport, terminal publication, and replay rules.
    """

    now = _clock_value(clock)
    directory = _report_only_directory(artifact_root, operation.operation_id)
    try:
        operation_bytes = read_private_artifact_bytes(
            directory,
            REPORT_ONLY_OPERATION_FILE,
            max_bytes=MAX_OPERATION_ARTIFACT_BYTES,
        )
    except DiscoveryArtifactError as exc:
        raise ReportOnlyError("discovery_quota_evidence_invalid") from exc
    if operation_bytes != canonical_json_bytes(operation.as_dict()):
        raise ReportOnlyError("discovery_quota_evidence_invalid")
    try:
        report = read_terminal_report(directory)
    except DiscoveryArtifactError as exc:
        if exc.code == "artifact_missing":
            report = None
        else:
            raise ReportOnlyError("discovery_report_indeterminate") from exc
    if report is not None:
        try:
            marker = read_start_marker(directory)
        except DiscoveryArtifactError as exc:
            raise ReportOnlyError("discovery_report_indeterminate") from exc
        expected_binding = cast(Any, operation.profile_binding).as_dict()
        if (
            report.operation_id != operation.operation_id
            or report.operation_sha256 != operation.operation_sha256
            or report.challenge_sha256 != operation.challenge_sha256
            or report.start_marker_sha256 != marker.start_marker_sha256
            or report.authorization_sha256 != authorization.authorization_sha256
            or report.policy_sha256 != operation.policy_sha256
            or report.plan_sha256 != operation.plan_sha256
            or report.quota_contexts != operation.quota_contexts
            or report.authorization_max_ttl_seconds != operation.authorization_max_ttl_seconds
            or report.authorization_expires_at_utc != operation.authorization_expires_at_utc
            or canonical_json_bytes(report.profile_binding)
            != canonical_json_bytes(expected_binding)
            or marker.operation_id != operation.operation_id
            or marker.operation_sha256 != operation.operation_sha256
            or marker.challenge_sha256 != operation.challenge_sha256
            or marker.authorization_sha256 != authorization.authorization_sha256
            or canonical_json_bytes(marker.profile_binding)
            != canonical_json_bytes(expected_binding)
            or marker.policy_sha256 != operation.policy_sha256
            or marker.plan_sha256 != operation.plan_sha256
            or marker.quota_contexts != operation.quota_contexts
            or marker.authorization_max_ttl_seconds != operation.authorization_max_ttl_seconds
            or marker.authorization_expires_at_utc != operation.authorization_expires_at_utc
        ):
            raise ReportOnlyError("discovery_quota_evidence_invalid")
        return report
    try:
        read_start_marker(directory)
    except DiscoveryArtifactError as exc:
        if exc.code != "artifact_missing":
            raise ReportOnlyError("discovery_report_indeterminate") from exc
    else:
        raise ReportOnlyError("discovery_report_indeterminate")

    verify_report_only_authorization(operation, now=now)
    revalidate_report_only_quota_context(operation, authorization, config, now)
    capability = getattr(search_runtime, "authorization", None)
    if not isinstance(capability, SearchAuthorizationCapability):
        raise ReportOnlyError("discovery_v2_authorization_required")
    if (
        capability.operation_id != authorization.operation_id
        or capability.operation_sha256 != authorization.operation_sha256
        or capability.plan_sha256 != operation.plan_sha256
        or (
            capability.authorization_sha256 is not None
            and capability.authorization_sha256 != authorization.authorization_sha256
        )
    ):
        raise ReportOnlyError("discovery_v2_authorization_invalid")

    quota_adapter = getattr(search_runtime, "quota_adapter", None)
    revalidate = getattr(quota_adapter, "revalidate_context_v2", None)
    contexts = getattr(search_runtime, "quota_contexts", ())
    if not callable(revalidate):
        raise ReportOnlyError("discovery_v2_quota_adapter_required")
    preflight_replay = getattr(quota_adapter, "preflight_replay_v2", None)
    if callable(preflight_replay):
        try:
            preflight_replay(
                operation_id=operation.operation_id,
                plan_sha256=operation.plan_sha256,
            )
        except Exception as exc:
            raise ReportOnlyError(getattr(exc, "code", str(exc))) from exc
    try:
        for context in contexts:
            revalidate(
                operation_id=operation.operation_id,
                plan_sha256=operation.plan_sha256,
                context=context,
            )
    except Exception as exc:
        raise ReportOnlyError(getattr(exc, "code", str(exc))) from exc

    marker = build_start_marker(
        operation_id=operation.operation_id,
        operation_sha256=operation.operation_sha256,
        challenge_sha256=operation.challenge_sha256,
        authorization_sha256=authorization.authorization_sha256,
        profile_binding=operation.profile_binding,
        policy_sha256=operation.policy_sha256,
        plan_sha256=operation.plan_sha256,
        quota_contexts=operation.quota_contexts,
        authorization_max_ttl_seconds=operation.authorization_max_ttl_seconds,
        authorization_expires_at_utc=operation.authorization_expires_at_utc,
        started_at_utc=now,
    )
    try:
        write_private_artifact(directory, "started-v1.json", marker.as_dict())
    except DiscoveryArtifactError as exc:
        raise ReportOnlyError(exc.code) from exc

    terminal_code: str | None = None
    truncation = {
        "unique_board_candidates": False,
        "board_verifications": False,
        "verification_wire_attempts": False,
    }
    try:
        candidates = await search_runtime.search()
        requests = _report_request_evidence(operation, search_runtime)
        if bool(getattr(search_runtime, "candidate_truncated", False)):
            truncation["unique_board_candidates"] = True
            terminal_code = "unique_board_candidates_exhausted"
        verified_sources: tuple[ReportOnlyVerifiedSourceV1, ...] = ()
        official_requests: list[ReportOnlyRequestEvidenceV1] = []
        official_failures = 0
        official_precondition_codes = {
            "discovery_v2_authorization_window_invalid": "authorization_window_invalid",
            "discovery_v2_authorization_expired": "authorization_expired",
            "discovery_quota_month_stale": "quota_month_stale",
            "discovery_quota_context_stale": "quota_context_stale",
            "discovery_quota_evidence_invalid": "quota_evidence_invalid",
        }
        selected_candidates = tuple(candidates)[:8]
        if official_verifier is not None:
            if len(candidates) > 8:
                truncation["board_verifications"] = True
                terminal_code = terminal_code or "board_verifications_exhausted"
            budget = getattr(search_runtime, "execution_budget", None)
            transport_check = getattr(official_verifier, "before_transport_check", None)
            for candidate in selected_candidates:
                try:
                    revalidate_report_only_quota_context(
                        operation,
                        authorization,
                        config,
                        _clock_value(clock),
                    )
                    if callable(transport_check):
                        transport_check()
                except ReportOnlyError as exc:
                    terminal_code = official_precondition_codes.get(exc.code)
                    if terminal_code is None:
                        raise
                    break
                try:
                    if budget is not None:
                        budget.reserve_verification()
                        budget.reserve_wire_attempt()
                except DiscoveryBudgetError as exc:
                    if exc.code == "discovery_verification_cap_exhausted":
                        truncation["board_verifications"] = True
                        terminal_code = "board_verifications_exhausted"
                    else:
                        truncation["verification_wire_attempts"] = True
                        terminal_code = "verification_wire_attempts_exhausted"
                    break
                candidate_ordinal = int(getattr(candidate, "ordinal", len(official_requests) + 1))
                source_type = str(getattr(candidate, "source_type", ""))
                provider = source_type if source_type in {"greenhouse", "lever"} else "greenhouse"
                wire_key = (
                    f"cdv2:{operation.operation_id}:{operation.plan_sha256}:"
                    f"b{candidate_ordinal:02d}:w001:{provider}"
                )
                configuration = dict(getattr(candidate, "configuration", {}))
                configuration_sha256 = sha256(canonical_json_bytes(configuration)).hexdigest()
                destination = (
                    "greenhouse_official_api"
                    if source_type == "greenhouse"
                    else "lever_eu_official_api"
                    if configuration.get("region") == "eu"
                    else "lever_global_official_api"
                )
                request_identity_sha256 = sha256(
                    canonical_json_bytes(
                        {
                            "operation_sha256": operation.operation_sha256,
                            "source_type": source_type,
                            "source_key": str(getattr(candidate, "source_key", "")),
                            "configuration_sha256": configuration_sha256,
                            "destination": destination,
                            "board_candidate_ordinal": candidate_ordinal,
                            "wire_attempt_ordinal": 1,
                            "collector_request_ordinal": 1,
                        }
                    )
                ).hexdigest()
                try:
                    verified = await official_verifier(candidate)
                except Exception:
                    official_requests.append(
                        ReportOnlyRequestEvidenceV1(
                            request_ordinal=len(requests) + len(official_requests) + 1,
                            kind="official_verification",
                            provider=provider,
                            destination=destination,
                            board_candidate_ordinal=candidate_ordinal,
                            operation_key_sha256=sha256(wire_key.encode("utf-8")).hexdigest(),
                            request_identity_sha256=request_identity_sha256,
                            transmission="indeterminate",
                            outcome="indeterminate",
                            error_code="transmission_indeterminate",
                            collector_request_ordinal=1,
                            wire_attempt_ordinal=1,
                            identity_source_key=str(getattr(candidate, "source_key", "")),
                            identity_configuration_sha256=configuration_sha256,
                        )
                    )
                    terminal_code = "transmission_indeterminate"
                    break
                if verified is not None:
                    if (
                        verified.source_type != source_type
                        or verified.source_key != getattr(candidate, "source_key", None)
                        or dict(verified.configuration) != configuration
                        or verified.configuration_sha256 != configuration_sha256
                        or verified.board_candidate_ordinal != candidate_ordinal
                        or verified.postings_count < 0
                    ):
                        raise ReportOnlyError("discovery_quota_evidence_invalid")
                    verified = replace(
                        verified,
                        request_identity_sha256=request_identity_sha256,
                    )
                    verified_sources = (*verified_sources, verified)
                else:
                    official_failures += 1
                official_requests.append(
                    ReportOnlyRequestEvidenceV1(
                        request_ordinal=len(requests) + len(official_requests) + 1,
                        kind="official_verification",
                        provider=provider,
                        destination=destination,
                        board_candidate_ordinal=candidate_ordinal,
                        operation_key_sha256=sha256(wire_key.encode("utf-8")).hexdigest(),
                        request_identity_sha256=request_identity_sha256,
                        transmission="sent",
                        outcome="succeeded" if verified is not None else "failed",
                        postings_count=verified.postings_count if verified is not None else 0,
                        error_code=None if verified is not None else "provider_failed",
                        collector_request_ordinal=1,
                        wire_attempt_ordinal=1,
                        identity_source_key=str(getattr(candidate, "source_key", "")),
                        identity_configuration_sha256=configuration_sha256,
                    )
                )
        requests = (*requests, *official_requests)
        if sum(truncation.values()) > 1:
            terminal_code = "multiple_budgets_exhausted"
        response_statuses = tuple(str(getattr(item, "outcome", "failed")) for item in requests)
        has_usable_search = any(
            status in {"succeeded", "empty"}
            for item in requests
            if item.kind == "search"
            for status in (item.outcome,)
        )
        if terminal_code in set(official_precondition_codes.values()):
            state = "failed"
        elif any(truncation.values()):
            state = "completed_partial"
        elif (
            official_verifier is not None
            and selected_candidates
            and official_failures == len(selected_candidates)
        ):
            state = "failed"
            terminal_code = "official_verification_failed"
        elif verified_sources:
            state = "completed"
        elif has_usable_search:
            state = "completed_empty"
        else:
            state = "failed"
        if any(status == "indeterminate" for status in response_statuses):
            state = "indeterminate"
            terminal_code = "transmission_indeterminate"
    except Exception as exc:
        if isinstance(exc, ReportOnlyError):
            raise
        candidates = ()
        verified_sources = ()
        try:
            requests = _report_request_evidence(operation, search_runtime)
        except Exception:
            requests = ()
        error_code = str(exc)
        terminal_codes = {
            "discovery_v2_authorization_window_invalid": "authorization_window_invalid",
            "discovery_v2_authorization_expired": "authorization_expired",
            "discovery_quota_month_stale": "quota_month_stale",
            "discovery_quota_context_stale": "quota_context_stale",
            "discovery_quota_evidence_invalid": "quota_evidence_invalid",
            "discovery_budget_exhausted": "provider_quota_exhausted",
            "transmission_indeterminate": "transmission_indeterminate",
        }
        terminal_code = terminal_codes.get(error_code, "provider_search_failed")
        state = (
            "indeterminate"
            if terminal_code
            in {
                "transmission_indeterminate",
                "quota_evidence_invalid",
            }
            else "failed"
        )

    completed = _clock_value(clock)
    if completed <= marker.started_at_utc:
        completed = marker.started_at_utc + timedelta(microseconds=1)
    candidate_count = len(candidates)
    counts = {
        "search_requests_attempted": sum(1 for item in requests if item.kind == "search"),
        "search_requests_completed": sum(
            1 for item in requests if item.outcome in {"succeeded", "empty", "failed", "malformed"}
        ),
        "classified_hits": sum(item.known_count for item in requests),
        "unique_board_candidates_seen": max(
            candidate_count,
            int(getattr(search_runtime, "unique_board_candidates_seen", candidate_count)),
        ),
        "unique_board_candidates_retained": min(candidate_count, 10),
        "board_verifications_attempted": sum(
            1 for item in requests if item.kind == "official_verification"
        ),
        "boards_verified": len(verified_sources),
        "verification_wire_attempts_consumed": sum(
            1 for item in requests if item.kind == "official_verification"
        ),
    }
    report = build_terminal_report(
        operation_id=operation.operation_id,
        operation_sha256=operation.operation_sha256,
        challenge_sha256=operation.challenge_sha256,
        start_marker_sha256=marker.start_marker_sha256,
        authorization_sha256=authorization.authorization_sha256,
        profile_binding=operation.profile_binding,
        policy_sha256=operation.policy_sha256,
        plan_sha256=operation.plan_sha256,
        quota_contexts=operation.quota_contexts,
        authorization_max_ttl_seconds=operation.authorization_max_ttl_seconds,
        authorization_expires_at_utc=operation.authorization_expires_at_utc,
        state=state,
        started_at_utc=marker.started_at_utc,
        completed_at_utc=completed,
        counts=counts,
        truncation=truncation,
        requests=requests,
        verified_sources=verified_sources,
        terminal_code=terminal_code,
    )
    try:
        write_private_artifact(directory, "terminal-report-v1.json", report.as_dict())
    except DiscoveryArtifactError as exc:
        raise ReportOnlyError(exc.code) from exc
    return report


__all__ = [
    "DISCOVERY_DESTINATIONS",
    "MAX_REPORT_ONLY_AUTHORIZATION_TTL_SECONDS",
    "REPORT_ONLY_OPERATIONS_DIRECTORY",
    "REPORT_ONLY_OPERATION_FILE",
    "REPORT_ONLY_OPERATION_KIND",
    "REPORT_ONLY_OPERATION_SCHEMA_VERSION",
    "ProviderBindingV1",
    "ProviderQuotaContextV1",
    "ReportOnlyAuthorizationEvidence",
    "ReportOnlyError",
    "ReportOnlyOperationV1",
    "ReportOnlyVerifier",
    "execute_report_only",
    "prepare_operation",
    "prepare_report_only_operation",
    "quota_contexts_from_config",
    "revalidate_report_only_quota_context",
    "verify_authorization",
    "verify_report_only_authorization",
]


prepare_operation = prepare_report_only_operation
verify_authorization = verify_report_only_authorization
