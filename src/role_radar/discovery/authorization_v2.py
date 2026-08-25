"""Pure F10.1D authorization contracts.

This module deliberately stops at authorization.  It contains no adapter,
provider, credential, or transport seam.  A report operation is a signed
description of what *would* be allowed; it is not an instruction to perform
I/O.  Registration is represented as a separate operation kind so that Gate
A can reject it before a capability can be selected.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType
from typing import Final
from uuid import UUID

from role_radar.discovery.policy import (
    DiscoveryPolicyV1,
    ProfileBindingV1,
)
from role_radar.discovery.policy import canonical_policy_bytes as policy_canonical_bytes
from role_radar.discovery.policy import canonical_policy_payload as policy_canonical_payload
from role_radar.domain.profile import CandidateProfileV1
from role_radar.domain.profile import canonical_profile_bytes as profile_canonical_bytes
from role_radar.domain.profile import canonical_profile_payload as profile_canonical_payload

# Duck-typed conversion helpers intentionally accept injected test DTOs.
# Their attribute access is bounded and never crosses an I/O boundary.
# ruff: noqa: B009


AUTHORIZATION_SCHEMA_VERSION: Final = "f10.1d-authorization-v2"
AUTHORIZATION_PROTOCOL_VERSION: Final = "f10.1d-report-only-v2"
REPORT_ONLY_CONFIRMATION: Final = "I ACKNOWLEDGE F10.1D REPORT ONLY"
REPORT_ONLY_CHALLENGE_DOMAIN: Final = "f10.1d:report-only-challenge-v2"

MIN_TTL_SECONDS: Final = 1
MAX_OPERATION_TTL_SECONDS: Final = 86_400
MAX_CHALLENGE_TTL_SECONDS: Final = 86_400
MAX_ARTIFACT_TTL_SECONDS: Final = 86_400
MAX_REPORT_ONLY_AUTHORIZATION_TTL_SECONDS: Final = 86_400

# These are intentionally the same ten code-owned limits frozen into the v2
# discovery plan.  A caller cannot replace one with a larger value or append
# an eleventh budget without changing this contract.
MAX_DISCOVERY_QUERIES: Final = 4
MAX_DISCOVERY_PHRASES: Final = 8
MAX_APPROVED_PHRASE_CHARS: Final = 128
MAX_DISCOVERY_QUERY_CHARS: Final = 2048
MAX_DISCOVERY_RESULTS_PER_QUERY: Final = 10
MAX_BRAVE_REQUESTS_PER_RUN: Final = 4
MAX_TAVILY_REQUESTS_PER_RUN: Final = 4
MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN: Final = 10
MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN: Final = 8
MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN: Final = 100

EXACT_BUDGET_NAMES: Final = (
    "MAX_DISCOVERY_QUERIES",
    "MAX_DISCOVERY_PHRASES",
    "MAX_APPROVED_PHRASE_CHARS",
    "MAX_DISCOVERY_QUERY_CHARS",
    "MAX_DISCOVERY_RESULTS_PER_QUERY",
    "MAX_BRAVE_REQUESTS_PER_RUN",
    "MAX_TAVILY_REQUESTS_PER_RUN",
    "MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN",
    "MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN",
    "MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN",
)
DISCOVERY_BUDGET_NAMES: Final = EXACT_BUDGET_NAMES
EXACT_TEN_BUDGETS: Final = EXACT_BUDGET_NAMES

_BUDGET_VALUES: Final = dict(
    zip(
        EXACT_BUDGET_NAMES,
        (
            MAX_DISCOVERY_QUERIES,
            MAX_DISCOVERY_PHRASES,
            MAX_APPROVED_PHRASE_CHARS,
            MAX_DISCOVERY_QUERY_CHARS,
            MAX_DISCOVERY_RESULTS_PER_QUERY,
            MAX_BRAVE_REQUESTS_PER_RUN,
            MAX_TAVILY_REQUESTS_PER_RUN,
            MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN,
            MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN,
            MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN,
        ),
        strict=True,
    )
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9_.-]{0,126}[a-z0-9])?\Z", re.ASCII)


class AuthorizationError(ValueError):
    """Stable, sanitized failure from a pure authorization seam."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class OperationKind(StrEnum):
    """The two meanings are intentionally not interchangeable."""

    REPORT = "report"
    REPORT_ONLY = "continuous_discovery_v2_report_only"
    REGISTER = "register"


DiscoveryOperationKind = OperationKind
ReportOperationKind = OperationKind


def _sha256(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise AuthorizationError(f"{field}_invalid")
    return value


def _identifier(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise AuthorizationError(f"{field}_invalid")
    return value


def _utc(value: object, *, field: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise AuthorizationError(f"{field}_invalid")
    return value.astimezone(UTC)


def _ttl(value: object, *, field: str, maximum: int) -> int:
    if type(value) is not int or not MIN_TTL_SECONDS <= value <= maximum:
        raise AuthorizationError(f"{field}_invalid")
    return value


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise AuthorizationError("json_key_invalid")
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise AuthorizationError("json_value_invalid")


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def canonical_json_bytes(value: object) -> bytes:
    """Serialize JSON with one deterministic, non-floating-point contract."""

    try:
        return json.dumps(
            _thaw(_freeze(value)),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise AuthorizationError("canonical_json_invalid") from exc


def canonical_sha256(value: object) -> str:
    return sha256(canonical_json_bytes(value)).hexdigest()


def _canonical_uuid(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise AuthorizationError(f"{field}_invalid")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise AuthorizationError(f"{field}_invalid") from exc
    if str(parsed) != value or value != value.casefold():
        raise AuthorizationError(f"{field}_invalid")
    return value


def _challenge_nonce(value: object, *, field: str = "challenge_nonce") -> str:
    if not isinstance(value, str) or not value:
        raise AuthorizationError(f"{field}_invalid")
    try:
        decoded = base64.urlsafe_b64decode(value + "===")
    except (ValueError, binascii.Error) as exc:
        raise AuthorizationError(f"{field}_invalid") from exc
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise AuthorizationError(f"{field}_invalid")
    return value


ProfileBindingV2 = ProfileBindingV1
AuthorizationProfileV2 = ProfileBindingV1


def profile_binding_v2(value: object) -> ProfileBindingV2:
    """Convert the existing v1 selected-row binding without importing runtime code."""

    if isinstance(value, ProfileBindingV2):
        return value
    if not isinstance(value, Mapping):
        values = {
            "profile_id": getattr(value, "profile_id", None),
            "profile_version": getattr(
                value, "profile_version", getattr(value, "row_version", None)
            ),
            "profile_schema_version": getattr(
                value, "profile_schema_version", getattr(value, "schema_version", None)
            ),
            "profile_sha256": getattr(
                value, "profile_sha256", getattr(value, "canonical_profile_sha256", None)
            ),
        }
    else:
        accepted = {
            "profile_id",
            "profile_version",
            "profile_schema_version",
            "profile_sha256",
            "row_version",
            "schema_version",
            "canonical_profile_sha256",
        }
        if any(key not in accepted for key in value):
            raise AuthorizationError("profile_binding_invalid")
        values = {
            "profile_id": value.get("profile_id"),
            "profile_version": value.get("profile_version", value.get("row_version")),
            "profile_schema_version": value.get(
                "profile_schema_version", value.get("schema_version")
            ),
            "profile_sha256": value.get("profile_sha256", value.get("canonical_profile_sha256")),
        }
    return ProfileBindingV2.model_validate(
        {
            "profile_id": values["profile_id"],
            "row_version": values["profile_version"],
            "schema_version": values["profile_schema_version"],
            "canonical_profile_sha256": values["profile_sha256"],
        }
    )


@dataclass(frozen=True, slots=True)
class PolicyBindingV2:
    policy_version: str
    policy_sha256: str
    profile_binding: ProfileBindingV2

    def __post_init__(self) -> None:
        _identifier(self.policy_version, field="policy_version")
        _sha256(self.policy_sha256, field="policy_sha256")
        binding = profile_binding_v2(self.profile_binding)
        object.__setattr__(self, "profile_binding", binding)

    def as_dict(self) -> dict[str, object]:
        return {
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "profile_binding": self.profile_binding.as_dict(),
        }


@dataclass(frozen=True, slots=True)
class PlanBindingV2:
    plan_schema_version: str
    planner_version: str
    plan_sha256: str
    policy_binding: PolicyBindingV2

    def __post_init__(self) -> None:
        _identifier(self.plan_schema_version, field="plan_schema_version")
        _identifier(self.planner_version, field="planner_version")
        _sha256(self.plan_sha256, field="plan_sha256")
        if not isinstance(self.policy_binding, PolicyBindingV2):
            raise AuthorizationError("policy_binding_invalid")

    @property
    def profile_binding(self) -> ProfileBindingV2:
        return self.policy_binding.profile_binding

    @property
    def policy_version(self) -> str:
        return self.policy_binding.policy_version

    @property
    def policy_sha256(self) -> str:
        return self.policy_binding.policy_sha256

    def as_dict(self) -> dict[str, object]:
        return {
            "plan_schema_version": self.plan_schema_version,
            "planner_version": self.planner_version,
            "plan_sha256": self.plan_sha256,
            "policy_binding": self.policy_binding.as_dict(),
        }


@dataclass(frozen=True, slots=True)
class DiscoveryBudgetsV2:
    """The exact ten immutable discovery budgets."""

    max_discovery_queries: int = MAX_DISCOVERY_QUERIES
    max_discovery_phrases: int = MAX_DISCOVERY_PHRASES
    max_approved_phrase_chars: int = MAX_APPROVED_PHRASE_CHARS
    max_discovery_query_chars: int = MAX_DISCOVERY_QUERY_CHARS
    max_discovery_results_per_query: int = MAX_DISCOVERY_RESULTS_PER_QUERY
    max_brave_requests_per_run: int = MAX_BRAVE_REQUESTS_PER_RUN
    max_tavily_requests_per_run: int = MAX_TAVILY_REQUESTS_PER_RUN
    max_unique_board_candidates_per_run: int = MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN
    max_unique_board_verifications_per_run: int = MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN
    max_verification_wire_attempts_per_run: int = MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN

    def __post_init__(self) -> None:
        actual = self.as_dict()
        if set(actual) != set(EXACT_BUDGET_NAMES) or actual != _BUDGET_VALUES:
            raise AuthorizationError("budgets_invalid")
        if any(type(value) is not int or value < 0 for value in actual.values()):
            raise AuthorizationError("budgets_invalid")

    def as_dict(self) -> dict[str, int]:
        return {name: getattr(self, name.casefold()) for name in EXACT_BUDGET_NAMES}

    @property
    def values(self) -> dict[str, int]:
        return self.as_dict()

    @property
    def limits(self) -> dict[str, int]:
        """The uppercase spelling used by ``DiscoveryQueryPlanV2``."""

        return self.as_dict()


ExactTenBudgetsV2 = DiscoveryBudgetsV2
BudgetV2 = DiscoveryBudgetsV2
DEFAULT_DISCOVERY_BUDGETS = DiscoveryBudgetsV2()
DEFAULT_BUDGETS = DEFAULT_DISCOVERY_BUDGETS


def validate_exact_budgets(value: object) -> DiscoveryBudgetsV2:
    if isinstance(value, DiscoveryBudgetsV2):
        return value
    if not isinstance(value, Mapping) or set(value) != set(EXACT_BUDGET_NAMES):
        raise AuthorizationError("budgets_invalid")
    try:
        return DiscoveryBudgetsV2(**{name.casefold(): item for name, item in value.items()})
    except (TypeError, ValueError) as exc:
        raise AuthorizationError("budgets_invalid") from exc


@dataclass(frozen=True, slots=True)
class ProviderQuotaContextV1:
    """Exact non-secret quota facts bound to one enabled free tier."""

    provider: str
    tier: str
    utc_month: str
    config_version: str
    unit_limit: int
    micro_usd_limit: int
    reservation_units_per_call: int
    reservation_micro_usd_per_call: int
    operation_max_calls: int

    def __post_init__(self) -> None:
        if self.provider not in {"brave", "tavily"} or self.tier != "free":
            raise AuthorizationError("quota_context_invalid")
        if re.fullmatch(r"[0-9]{4}-(?:0[1-9]|1[0-2])", self.utc_month) is None:
            raise AuthorizationError("quota_context_invalid")
        if type(self.config_version) is not str or not self.config_version:
            raise AuthorizationError("quota_context_invalid")
        values = (
            self.unit_limit,
            self.micro_usd_limit,
            self.reservation_units_per_call,
            self.reservation_micro_usd_per_call,
            self.operation_max_calls,
        )
        if any(type(value) is not int or value < 0 for value in values):
            raise AuthorizationError("quota_context_invalid")
        if self.reservation_units_per_call <= 0 or self.operation_max_calls <= 0:
            raise AuthorizationError("quota_context_invalid")

    def as_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "tier": self.tier,
            "utc_month": self.utc_month,
            "config_version": self.config_version,
            "unit_limit": self.unit_limit,
            "micro_usd_limit": self.micro_usd_limit,
            "reservation_units_per_call": self.reservation_units_per_call,
            "reservation_micro_usd_per_call": self.reservation_micro_usd_per_call,
            "operation_max_calls": self.operation_max_calls,
        }


ProviderQuotaContextV2 = ProviderQuotaContextV1
ProviderQuotaV2 = ProviderQuotaContextV1


def _iso(value: datetime | None) -> str | None:
    return (
        value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
        if value
        else None
    )


@dataclass(frozen=True, slots=True)
class AuthorizationPolicyV2:
    profile_binding: ProfileBindingV2
    policy_version: str
    policy_sha256: str
    budgets: DiscoveryBudgetsV2 = DEFAULT_DISCOVERY_BUDGETS
    quota_contexts: tuple[ProviderQuotaContextV2, ...] = ()
    operation_ttl_seconds: int = MAX_OPERATION_TTL_SECONDS
    challenge_ttl_seconds: int = MAX_CHALLENGE_TTL_SECONDS
    artifact_ttl_seconds: int = MAX_ARTIFACT_TTL_SECONDS

    def __post_init__(self) -> None:
        binding = profile_binding_v2(self.profile_binding)
        object.__setattr__(self, "profile_binding", binding)
        _identifier(self.policy_version, field="policy_version")
        _sha256(self.policy_sha256, field="policy_sha256")
        budgets = validate_exact_budgets(self.budgets)
        object.__setattr__(self, "budgets", budgets)
        if type(self.quota_contexts) is not tuple or any(
            not isinstance(item, ProviderQuotaContextV2) for item in self.quota_contexts
        ):
            raise AuthorizationError("quota_contexts_invalid")
        identities = {(item.provider, item.tier) for item in self.quota_contexts}
        if len(identities) != len(self.quota_contexts):
            raise AuthorizationError("quota_contexts_duplicate")
        _ttl(
            self.operation_ttl_seconds,
            field="operation_ttl_seconds",
            maximum=MAX_OPERATION_TTL_SECONDS,
        )
        _ttl(
            self.challenge_ttl_seconds,
            field="challenge_ttl_seconds",
            maximum=MAX_CHALLENGE_TTL_SECONDS,
        )
        _ttl(
            self.artifact_ttl_seconds,
            field="artifact_ttl_seconds",
            maximum=MAX_ARTIFACT_TTL_SECONDS,
        )

    @property
    def policy_binding(self) -> PolicyBindingV2:
        return PolicyBindingV2(self.policy_version, self.policy_sha256, self.profile_binding)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": AUTHORIZATION_SCHEMA_VERSION,
            "profile_binding": self.profile_binding.as_dict(),
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "budgets": self.budgets.as_dict(),
            "quota_contexts": [item.as_dict() for item in self.quota_contexts],
            "operation_ttl_seconds": self.operation_ttl_seconds,
            "challenge_ttl_seconds": self.challenge_ttl_seconds,
            "artifact_ttl_seconds": self.artifact_ttl_seconds,
        }


DiscoveryAuthorizationPolicyV2 = AuthorizationPolicyV2


def _binding_from_plan(plan: object) -> PlanBindingV2:
    try:
        policy_binding = PolicyBindingV2(
            policy_version=str(getattr(plan, "policy_version")),
            policy_sha256=str(getattr(plan, "policy_sha256")),
            profile_binding=profile_binding_v2(getattr(plan, "profile_binding")),
        )
        return PlanBindingV2(
            plan_schema_version=str(getattr(plan, "schema_version")),
            planner_version=str(getattr(plan, "planner_version")),
            plan_sha256=str(getattr(plan, "plan_sha256")),
            policy_binding=policy_binding,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise AuthorizationError("plan_binding_invalid") from exc


def plan_binding_v2(plan: object) -> PlanBindingV2:
    """Return a plan identity without retaining the executable plan object."""

    binding = _binding_from_plan(plan)
    plan_limits = getattr(plan, "limits", None)
    if callable(plan_limits):
        plan_limits = plan_limits()
    if not isinstance(plan_limits, Mapping):
        raise AuthorizationError("plan_budgets_invalid")
    expected = {name.upper(): value for name, value in _BUDGET_VALUES.items()}
    if dict(plan_limits) != expected:
        raise AuthorizationError("plan_budgets_invalid")
    return binding


def budgets_from_plan(plan: object) -> DiscoveryBudgetsV2:
    """Extract and validate the ten frozen limits from a v2 plan."""

    plan_binding_v2(plan)
    limits = getattr(plan, "limits")
    if callable(limits):
        limits = limits()
    if not isinstance(limits, Mapping):
        raise AuthorizationError("plan_budgets_invalid")
    expected = {name.upper(): value for name, value in _BUDGET_VALUES.items()}
    if dict(limits) != expected:
        raise AuthorizationError("plan_budgets_invalid")
    return DEFAULT_DISCOVERY_BUDGETS


@dataclass(frozen=True, slots=True)
class DiscoveryOperationV2:
    """Plan-bound operation intent.  It has no executable capability."""

    operation_id: str
    kind: OperationKind
    created_at: datetime
    expires_at: datetime
    profile_binding: ProfileBindingV2
    policy_version: str
    policy_sha256: str
    plan_sha256: str
    budgets: DiscoveryBudgetsV2 = DEFAULT_DISCOVERY_BUDGETS
    quota_contexts: tuple[ProviderQuotaContextV2, ...] = ()
    challenge_nonce: str = ""
    authorization_max_ttl_seconds: int = MAX_REPORT_ONLY_AUTHORIZATION_TTL_SECONDS

    def __post_init__(self) -> None:
        operation_id = _canonical_uuid(self.operation_id, field="operation_id")
        created = _utc(self.created_at, field="created_at")
        expires = _utc(self.expires_at, field="expires_at")
        if expires <= created:
            raise AuthorizationError("expiry_invalid")
        if expires - created > timedelta(seconds=MAX_OPERATION_TTL_SECONDS):
            raise AuthorizationError("expiry_invalid")
        binding = profile_binding_v2(self.profile_binding)
        if not isinstance(self.kind, OperationKind):
            try:
                object.__setattr__(self, "kind", OperationKind(self.kind))
            except (TypeError, ValueError) as exc:
                raise AuthorizationError("operation_kind_invalid") from exc
        _identifier(self.policy_version, field="policy_version")
        _sha256(self.policy_sha256, field="policy_sha256")
        _sha256(self.plan_sha256, field="plan_sha256")
        object.__setattr__(self, "operation_id", operation_id)
        object.__setattr__(self, "created_at", created)
        object.__setattr__(self, "expires_at", expires)
        object.__setattr__(self, "profile_binding", binding)
        object.__setattr__(self, "budgets", validate_exact_budgets(self.budgets))
        if type(self.quota_contexts) is not tuple or any(
            not isinstance(item, ProviderQuotaContextV2) for item in self.quota_contexts
        ):
            raise AuthorizationError("quota_contexts_invalid")
        if self.challenge_nonce:
            object.__setattr__(self, "challenge_nonce", _challenge_nonce(self.challenge_nonce))
        if self.authorization_max_ttl_seconds != MAX_REPORT_ONLY_AUTHORIZATION_TTL_SECONDS:
            raise AuthorizationError("authorization_window_invalid")

    @property
    def is_report_only(self) -> bool:
        return self.kind is OperationKind.REPORT_ONLY

    @property
    def operation_kind(self) -> OperationKind:
        return self.kind

    @property
    def mode(self) -> str:
        return "report_only" if self.is_report_only else "register"

    def expired(self, now: datetime) -> bool:
        return _utc(now, field="now") >= self.expires_at

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": AUTHORIZATION_SCHEMA_VERSION,
            "protocol_version": AUTHORIZATION_PROTOCOL_VERSION,
            "operation_id": self.operation_id,
            "kind": self.kind.value,
            "created_at": _iso(self.created_at),
            "expires_at": _iso(self.expires_at),
            "profile_binding": self.profile_binding.as_dict(),
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "plan_sha256": self.plan_sha256,
            "budgets": self.budgets.as_dict(),
            "quota_contexts": [item.as_dict() for item in self.quota_contexts],
            "challenge_nonce": self.challenge_nonce,
            "authorization_max_ttl_seconds": self.authorization_max_ttl_seconds,
        }


ReportOnlyOperationV2 = DiscoveryOperationV2
AuthorizationContextV2 = DiscoveryOperationV2
ReportOnlyAuthorizationV2 = DiscoveryOperationV2


def canonical_operation_payload(operation: DiscoveryOperationV2) -> dict[str, object]:
    if not isinstance(operation, DiscoveryOperationV2):
        raise TypeError("canonical_operation_payload requires DiscoveryOperationV2")
    return operation.as_dict()


def canonical_operation_bytes(operation: DiscoveryOperationV2) -> bytes:
    return canonical_json_bytes(canonical_operation_payload(operation))


def operation_sha256(operation: DiscoveryOperationV2) -> str:
    return sha256(canonical_operation_bytes(operation)).hexdigest()


canonical_authorization_payload = canonical_operation_payload
canonical_authorization_bytes = canonical_operation_bytes
canonical_authorization_sha256 = operation_sha256


def build_report_only_operation(
    *,
    operation_id: str,
    profile_binding: ProfileBindingV2 | object,
    policy_version: str,
    policy_sha256: str,
    plan_sha256: str,
    created_at: datetime,
    ttl_seconds: int = MAX_OPERATION_TTL_SECONDS,
    budgets: DiscoveryBudgetsV2 = DEFAULT_DISCOVERY_BUDGETS,
    quota_contexts: tuple[ProviderQuotaContextV2, ...] = (),
    challenge_nonce: str = "",
    authorization_max_ttl_seconds: int = MAX_REPORT_ONLY_AUTHORIZATION_TTL_SECONDS,
    expires_at: datetime | None = None,
) -> DiscoveryOperationV2:
    ttl = _ttl(ttl_seconds, field="ttl_seconds", maximum=MAX_OPERATION_TTL_SECONDS)
    created = _utc(created_at, field="created_at")
    return DiscoveryOperationV2(
        operation_id=operation_id,
        kind=OperationKind.REPORT_ONLY,
        created_at=created,
        expires_at=created + timedelta(seconds=ttl) if expires_at is None else expires_at,
        profile_binding=profile_binding_v2(profile_binding),
        policy_version=policy_version,
        policy_sha256=policy_sha256,
        plan_sha256=plan_sha256,
        budgets=budgets,
        quota_contexts=quota_contexts,
        challenge_nonce=challenge_nonce,
        authorization_max_ttl_seconds=authorization_max_ttl_seconds,
    )


create_report_only_operation = build_report_only_operation


def build_plan_bound_report_only_operation(
    *,
    operation_id: str,
    plan: object,
    created_at: datetime,
    ttl_seconds: int = MAX_OPERATION_TTL_SECONDS,
    quota_contexts: tuple[ProviderQuotaContextV2, ...] = (),
    challenge_nonce: str = "",
    authorization_max_ttl_seconds: int = MAX_REPORT_ONLY_AUTHORIZATION_TTL_SECONDS,
    expires_at: datetime | None = None,
) -> DiscoveryOperationV2:
    binding = plan_binding_v2(plan)
    return build_report_only_operation(
        operation_id=operation_id,
        profile_binding=binding.profile_binding,
        policy_version=binding.policy_version,
        policy_sha256=binding.policy_sha256,
        plan_sha256=binding.plan_sha256,
        created_at=created_at,
        ttl_seconds=ttl_seconds,
        budgets=budgets_from_plan(plan),
        quota_contexts=quota_contexts,
        challenge_nonce=challenge_nonce,
        authorization_max_ttl_seconds=authorization_max_ttl_seconds,
        expires_at=expires_at,
    )


authorize_report_only = build_plan_bound_report_only_operation


def build_register_operation(**_kwargs: object) -> DiscoveryOperationV2:
    """Explicitly fail instead of accidentally turning Gate A into Gate B."""

    raise AuthorizationError("gate_a_blocked")


def validate_report_only_operation(
    operation: DiscoveryOperationV2,
    *,
    profile_binding: ProfileBindingV2 | object,
    policy_version: str,
    policy_sha256: str,
    plan_sha256: str,
    now: datetime,
    budgets: DiscoveryBudgetsV2 = DEFAULT_DISCOVERY_BUDGETS,
) -> DiscoveryOperationV2:
    if not isinstance(operation, DiscoveryOperationV2):
        raise TypeError("validate_report_only_operation requires DiscoveryOperationV2")
    if operation.kind is OperationKind.REGISTER:
        raise AuthorizationError("gate_a_blocked")
    if operation.kind is not OperationKind.REPORT_ONLY:
        raise AuthorizationError("operation_kind_invalid")
    if operation.expired(now):
        raise AuthorizationError("operation_expired")
    if operation.profile_binding != profile_binding_v2(profile_binding):
        raise AuthorizationError("profile_binding_mismatch")
    if operation.policy_version != policy_version or operation.policy_sha256 != policy_sha256:
        raise AuthorizationError("policy_binding_mismatch")
    if operation.plan_sha256 != plan_sha256:
        raise AuthorizationError("plan_binding_mismatch")
    if operation.budgets != validate_exact_budgets(budgets):
        raise AuthorizationError("budgets_mismatch")
    return operation


@dataclass(frozen=True, slots=True)
class OperationChallengeV2:
    operation_id: str
    operation_sha256: str
    challenge_sha256: str
    issued_at: datetime
    expires_at: datetime
    acknowledgement: str

    def __post_init__(self) -> None:
        _canonical_uuid(self.operation_id, field="operation_id")
        _sha256(self.operation_sha256, field="operation_sha256")
        _sha256(self.challenge_sha256, field="challenge_sha256")
        issued = _utc(self.issued_at, field="issued_at")
        expires = _utc(self.expires_at, field="expires_at")
        if expires <= issued:
            raise AuthorizationError("challenge_expiry_invalid")
        if type(self.acknowledgement) is not str or not self.acknowledgement.isascii():
            raise AuthorizationError("acknowledgement_invalid")
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)

    def expired(self, now: datetime) -> bool:
        return _utc(now, field="now") >= self.expires_at

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": AUTHORIZATION_SCHEMA_VERSION,
            "operation_id": self.operation_id,
            "operation_sha256": self.operation_sha256,
            "challenge_sha256": self.challenge_sha256,
            "issued_at": _iso(self.issued_at),
            "expires_at": _iso(self.expires_at),
            "acknowledgement": self.acknowledgement,
        }


ReportOnlyChallengeV2 = OperationChallengeV2
ChallengeV2 = OperationChallengeV2


def _challenge_preimage(operation: DiscoveryOperationV2) -> dict[str, object]:
    return {
        "domain": REPORT_ONLY_CHALLENGE_DOMAIN,
        "operation": operation.as_dict(),
        "operation_sha256": operation_sha256(operation),
    }


def challenge_sha256(operation: DiscoveryOperationV2) -> str:
    if not isinstance(operation, DiscoveryOperationV2):
        raise TypeError("challenge_sha256 requires DiscoveryOperationV2")
    return sha256(canonical_challenge_bytes(operation)).hexdigest()


def canonical_challenge_bytes(operation: DiscoveryOperationV2) -> bytes:
    if not isinstance(operation, DiscoveryOperationV2):
        raise TypeError("canonical_challenge_bytes requires DiscoveryOperationV2")
    return (
        REPORT_ONLY_CHALLENGE_DOMAIN.encode("ascii")
        + b"\0"
        + canonical_json_bytes(_challenge_preimage(operation))
    )


def challenge_acknowledgement(operation: DiscoveryOperationV2, digest: str) -> str:
    _sha256(digest, field="challenge_sha256")
    return (
        f"{REPORT_ONLY_CONFIRMATION} operation_id={operation.operation_id} "
        f"profile_sha256={operation.profile_binding.profile_sha256} "
        f"policy_sha256={operation.policy_sha256} plan_sha256={operation.plan_sha256} "
        f"challenge_sha256={digest}"
    )


report_only_acknowledgement = challenge_acknowledgement


def build_report_only_challenge(
    operation: DiscoveryOperationV2,
    *,
    issued_at: datetime | None = None,
    ttl_seconds: int = MAX_CHALLENGE_TTL_SECONDS,
) -> OperationChallengeV2:
    if not isinstance(operation, DiscoveryOperationV2):
        raise TypeError("build_report_only_challenge requires DiscoveryOperationV2")
    if not operation.is_report_only:
        raise AuthorizationError("gate_a_blocked")
    issued = _utc(operation.created_at if issued_at is None else issued_at, field="issued_at")
    ttl = _ttl(ttl_seconds, field="ttl_seconds", maximum=MAX_CHALLENGE_TTL_SECONDS)
    expiry = min(issued + timedelta(seconds=ttl), operation.expires_at)
    if expiry <= issued:
        raise AuthorizationError("challenge_expiry_invalid")
    operation_digest = operation_sha256(operation)
    digest = challenge_sha256(operation)
    return OperationChallengeV2(
        operation_id=operation.operation_id,
        operation_sha256=operation_digest,
        challenge_sha256=digest,
        issued_at=issued,
        expires_at=expiry,
        acknowledgement=challenge_acknowledgement(operation, digest),
    )


make_report_only_challenge = build_report_only_challenge
build_report_challenge = build_report_only_challenge
build_challenge = build_report_only_challenge


def validate_report_only_challenge(
    operation: DiscoveryOperationV2,
    challenge: OperationChallengeV2,
    *,
    now: datetime,
    acknowledgement: str | None = None,
) -> OperationChallengeV2:
    if not operation.is_report_only:
        raise AuthorizationError("gate_a_blocked")
    if challenge.operation_id != operation.operation_id:
        raise AuthorizationError("challenge_operation_mismatch")
    if challenge.operation_sha256 != operation_sha256(operation):
        raise AuthorizationError("challenge_operation_mismatch")
    if challenge.challenge_sha256 != challenge_sha256(operation):
        raise AuthorizationError("challenge_mismatch")
    if challenge.expired(now):
        raise AuthorizationError("challenge_expired")
    expected = challenge_acknowledgement(operation, challenge.challenge_sha256)
    if challenge.acknowledgement != expected:
        raise AuthorizationError("challenge_mismatch")
    if acknowledgement is not None and acknowledgement != expected:
        raise AuthorizationError("acknowledgement_mismatch")
    return challenge


def validate_authorization(
    operation: DiscoveryOperationV2,
    challenge: OperationChallengeV2,
    *,
    profile_binding: ProfileBindingV2 | object,
    policy_version: str,
    policy_sha256: str,
    plan_sha256: str,
    now: datetime,
    acknowledgement: str | None = None,
) -> DiscoveryOperationV2:
    validate_report_only_operation(
        operation,
        profile_binding=profile_binding,
        policy_version=policy_version,
        policy_sha256=policy_sha256,
        plan_sha256=plan_sha256,
        now=now,
    )
    validate_report_only_challenge(operation, challenge, now=now, acknowledgement=acknowledgement)
    return operation


validate_operation = validate_report_only_operation
validate_challenge = validate_report_only_challenge
validate_operation_challenge = validate_report_only_challenge


def _document_payload(value: object, *, field: str) -> dict[str, object]:
    if isinstance(value, Mapping):
        payload = value
    elif hasattr(value, "model_dump"):
        payload = getattr(value, "model_dump")(mode="python")
    elif hasattr(value, "as_dict"):
        payload = getattr(value, "as_dict")()
    else:
        raise TypeError(f"canonical_{field}_payload requires a mapping or DTO")
    if not isinstance(payload, Mapping):
        raise AuthorizationError(f"{field}_payload_invalid")
    converted = _thaw(_freeze(payload))
    if not isinstance(converted, dict):
        raise AuthorizationError(f"{field}_payload_invalid")
    return converted


def canonical_profile_payload(value: object) -> dict[str, object]:
    if isinstance(value, CandidateProfileV1):
        return profile_canonical_payload(value.model_dump(mode="json"))
    if isinstance(value, Mapping) and "title" in value:
        return profile_canonical_payload(dict(value))
    if isinstance(value, ProfileBindingV2) or (
        isinstance(value, Mapping) and "profile_version" in value
    ):
        return profile_binding_v2(value).as_dict()
    return _document_payload(value, field="profile")


def canonical_profile_bytes(value: object) -> bytes:
    if isinstance(value, CandidateProfileV1):
        return profile_canonical_bytes(value.model_dump(mode="json"))
    if isinstance(value, Mapping) and "title" in value:
        return profile_canonical_bytes(dict(value))
    return canonical_json_bytes(canonical_profile_payload(value))


def canonical_profile_sha256(value: object) -> str:
    return sha256(canonical_profile_bytes(value)).hexdigest()


def canonical_policy_payload(value: object) -> dict[str, object]:
    if isinstance(value, DiscoveryPolicyV1):
        return policy_canonical_payload(value)
    return _document_payload(value, field="policy")


def canonical_policy_bytes(value: object) -> bytes:
    if isinstance(value, DiscoveryPolicyV1):
        return policy_canonical_bytes(value)
    return canonical_json_bytes(canonical_policy_payload(value))


def canonical_policy_sha256(value: object) -> str:
    return sha256(canonical_policy_bytes(value)).hexdigest()


def canonical_plan_payload(value: object) -> dict[str, object]:
    """Canonicalize a v2 plan without retaining or trusting its plan hash."""

    try:
        source_registry = getattr(value, "source_registry")
        queries = getattr(value, "queries")
        limits = getattr(value, "limits")
        if callable(limits):
            limits = limits()
        raw_binding = getattr(value, "profile_binding")
        if hasattr(raw_binding, "row_version"):
            plan_profile_binding: object = {
                "profile_id": getattr(raw_binding, "profile_id"),
                "row_version": getattr(raw_binding, "row_version"),
                "schema_version": getattr(raw_binding, "schema_version"),
                "canonical_profile_sha256": getattr(raw_binding, "canonical_profile_sha256"),
            }
        else:
            plan_profile_binding = profile_binding_v2(raw_binding).as_dict()
        payload: dict[str, object] = {
            "schema_version": getattr(value, "schema_version"),
            "planner_version": getattr(value, "planner_version"),
            "compiler_version": getattr(value, "compiler_version"),
            "profile_binding": plan_profile_binding,
            "policy_schema_version": getattr(value, "policy_schema_version"),
            "policy_version": getattr(value, "policy_version"),
            "policy_sha256": getattr(value, "policy_sha256"),
            "source_registry": [
                {
                    "ordinal": getattr(item, "ordinal"),
                    "family": getattr(item, "family"),
                    "host": getattr(item, "host"),
                }
                for item in source_registry
            ],
            "limits": dict(limits),
            "queries": [
                {
                    "ordinal": getattr(item, "ordinal"),
                    "family": getattr(item, "family"),
                    "host": getattr(item, "host"),
                    "provider_intent": getattr(
                        getattr(item, "provider_intent"), "value", getattr(item, "provider_intent")
                    ),
                    "canonical_query": getattr(item, "canonical_query"),
                }
                for item in queries
            ],
        }
    except (AttributeError, TypeError, ValueError) as exc:
        raise AuthorizationError("plan_payload_invalid") from exc
    return payload


def canonical_plan_bytes(value: object) -> bytes:
    return canonical_json_bytes(canonical_plan_payload(value))


def canonical_plan_sha256(value: object) -> str:
    return sha256(canonical_plan_bytes(value)).hexdigest()


def validate_profile_binding(value: object) -> ProfileBindingV2:
    return profile_binding_v2(value)


def validate_policy_binding(
    policy: object, *, profile_binding: ProfileBindingV2 | object
) -> PolicyBindingV2:
    binding = PolicyBindingV2(
        policy_version=str(getattr(policy, "policy_version")),
        policy_sha256=str(getattr(policy, "sha256", getattr(policy, "policy_sha256", ""))),
        profile_binding=profile_binding_v2(profile_binding),
    )
    if canonical_policy_sha256(policy) != binding.policy_sha256:
        raise AuthorizationError("policy_hash_mismatch")
    return binding


def validate_plan_binding(
    plan: object,
    *,
    profile_binding: ProfileBindingV2 | object,
    policy_version: str,
    policy_sha256: str,
) -> PlanBindingV2:
    binding = plan_binding_v2(plan)
    if (
        binding.profile_binding != profile_binding_v2(profile_binding)
        or binding.policy_version != policy_version
        or binding.policy_sha256 != policy_sha256
        or binding.plan_sha256 != canonical_plan_sha256(plan)
    ):
        raise AuthorizationError("plan_binding_mismatch")
    return binding


__all__ = [  # noqa: RUF022
    "AUTHORIZATION_PROTOCOL_VERSION",
    "AUTHORIZATION_SCHEMA_VERSION",
    "AuthorizationError",
    "AuthorizationContextV2",
    "AuthorizationPolicyV2",
    "AuthorizationProfileV2",
    "BudgetV2",
    "ChallengeV2",
    "DEFAULT_BUDGETS",
    "DEFAULT_DISCOVERY_BUDGETS",
    "DISCOVERY_BUDGET_NAMES",
    "DiscoveryAuthorizationPolicyV2",
    "DiscoveryBudgetsV2",
    "DiscoveryOperationKind",
    "DiscoveryOperationV2",
    "EXACT_BUDGET_NAMES",
    "EXACT_TEN_BUDGETS",
    "ExactTenBudgetsV2",
    "MAX_APPROVED_PHRASE_CHARS",
    "MAX_ARTIFACT_TTL_SECONDS",
    "MAX_BRAVE_REQUESTS_PER_RUN",
    "MAX_CHALLENGE_TTL_SECONDS",
    "MAX_DISCOVERY_PHRASES",
    "MAX_DISCOVERY_QUERIES",
    "MAX_DISCOVERY_QUERY_CHARS",
    "MAX_DISCOVERY_RESULTS_PER_QUERY",
    "MAX_OPERATION_TTL_SECONDS",
    "MAX_REPORT_ONLY_AUTHORIZATION_TTL_SECONDS",
    "MAX_TAVILY_REQUESTS_PER_RUN",
    "MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN",
    "MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN",
    "MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN",
    "OperationChallengeV2",
    "OperationKind",
    "PlanBindingV2",
    "PolicyBindingV2",
    "ProfileBindingV2",
    "ProviderQuotaContextV2",
    "ProviderQuotaContextV1",
    "ProviderQuotaV2",
    "REPORT_ONLY_CHALLENGE_DOMAIN",
    "REPORT_ONLY_CONFIRMATION",
    "ReportOnlyChallengeV2",
    "ReportOnlyAuthorizationV2",
    "ReportOnlyOperationV2",
    "ReportOperationKind",
    "build_register_operation",
    "build_challenge",
    "build_plan_bound_report_only_operation",
    "build_report_challenge",
    "build_report_only_challenge",
    "build_report_only_operation",
    "canonical_authorization_bytes",
    "canonical_authorization_payload",
    "canonical_authorization_sha256",
    "canonical_json_bytes",
    "canonical_operation_bytes",
    "canonical_operation_payload",
    "canonical_plan_bytes",
    "canonical_plan_payload",
    "canonical_plan_sha256",
    "canonical_policy_bytes",
    "canonical_policy_payload",
    "canonical_policy_sha256",
    "canonical_profile_bytes",
    "canonical_profile_payload",
    "canonical_profile_sha256",
    "canonical_sha256",
    "challenge_acknowledgement",
    "canonical_challenge_bytes",
    "challenge_sha256",
    "create_report_only_operation",
    "make_report_only_challenge",
    "operation_sha256",
    "report_only_acknowledgement",
    "authorize_report_only",
    "budgets_from_plan",
    "plan_binding_v2",
    "profile_binding_v2",
    "validate_authorization",
    "validate_challenge",
    "validate_exact_budgets",
    "validate_operation",
    "validate_operation_challenge",
    "validate_plan_binding",
    "validate_policy_binding",
    "validate_profile_binding",
    "validate_report_only_challenge",
    "validate_report_only_operation",
]
