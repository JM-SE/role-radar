"""Pure readiness projection; this module performs no I/O."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from role_radar.acquisition.configuration import AcquisitionConfig

COMMON_CODES = {
    "capability_disabled",
    "capability_configured",
    "capability_ready",
    "credential_directory_unavailable",
}


@dataclass(frozen=True, slots=True)
class CapabilityMetadata:
    """Sanitized observations supplied by the caller (never raw filesystem data)."""

    available_credentials: frozenset[str] = frozenset()
    config_code: str | None = None
    terms_code: str | None = None
    oauth_code: str | None = None
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CapabilityReadiness:
    capability: str
    state: str
    codes: tuple[str, ...]
    required_credentials: int
    available_credentials: int


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    schema_version: str
    policy: str
    runtime: bool
    state: str
    codes: tuple[str, ...]
    capabilities: tuple[CapabilityReadiness, ...]
    required_credentials: int
    available_credentials: int

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "policy": self.policy,
            "runtime": self.runtime,
            "state": self.state,
            "codes": list(self.codes),
            "required_credentials": self.required_credentials,
            "available_credentials": self.available_credentials,
            "capabilities": [
                {
                    "capability": item.capability,
                    "state": item.state,
                    "codes": list(item.codes),
                    "required_credentials": item.required_credentials,
                    "available_credentials": item.available_credentials,
                }
                for item in self.capabilities
            ],
        }


def calculate_readiness(
    config: AcquisitionConfig,
    *,
    metadata: dict[str, CapabilityMetadata] | None = None,
    now: datetime | None = None,
    policy: str = "production",
    runtime: bool = False,
) -> ReadinessReport:
    del now  # Time-sensitive observations are computed by the I/O boundary.
    observations = metadata or {}
    result: list[CapabilityReadiness] = []
    query_enabled = (
        config.brave_free.enabled or config.tavily_free.enabled or config.brave_paid.enabled
    )
    if query_enabled:
        query_required = 1 if config.discovery is not None else 0
        result.append(
            _capability(
                "query_hmac", True, query_required, observations.get("query_hmac"),
                config.discovery is not None,
            )
        )
    else:
        result.append(_capability("query_hmac", False, 0, observations.get("query_hmac"), False))
    result.append(
        _capability(
            "brave",
            config.brave_free.enabled or config.brave_paid.enabled,
            _provider_required(config.brave_free, config.brave_paid),
            observations.get("brave"),
            True,
        )
    )
    result.append(
        _capability(
            "tavily", config.tavily_free.enabled,
            1 if config.tavily_free.enabled else 0, observations.get("tavily"), True,
        )
    )
    result.append(
        _capability("jobicy", config.jobicy is not None, 0, observations.get("jobicy"), True)
    )
    for alias, descriptor in sorted(config.mailboxes.items()):
        handles = {
            descriptor.username_handle,
            descriptor.message_hmac_handle,
            descriptor.content_hmac_handle,
        }
        auth_handle = (
            descriptor.oauth2_handle
            if descriptor.auth_mode == "xoauth2"
            else descriptor.app_password_handle
        )
        expiry = descriptor.oauth2_expiry_handle if descriptor.auth_mode == "xoauth2" else None
        handles.update(item for item in (auth_handle, expiry) if item is not None)
        observation = observations.get(f"mailbox:{alias}")
        if descriptor.auth_mode == "app_password" and not descriptor.dedicated_account_ack:
            available_credentials = (
                observation.available_credentials if observation else frozenset()
            )
            observation = CapabilityMetadata(
                available_credentials=available_credentials,
                config_code=(observation.config_code if observation else None),
                terms_code=(observation.terms_code if observation else None),
                oauth_code=(observation.oauth_code if observation else None),
                warnings=(observation.warnings if observation else ())
                + ("dedicated_account_recommended",),
            )
        result.append(
            _capability(
                f"mailbox:{alias}", True, len(handles),
                observation, True,
            )
        )
    global_codes = _ordered_unique(
        code
        for item in result
        for code in item.codes
        if code not in {"capability_disabled", "capability_configured", "capability_ready"}
    )
    states = {item.state for item in result}
    state = (
        "disabled" if states == {"disabled"}
        else "blocked" if "blocked" in states
        else "ready" if states <= {"ready", "disabled"}
        else "configured"
    )
    return ReadinessReport(
        "acquisition-readiness-v1",
        policy,
        runtime,
        state,
        tuple(global_codes),
        tuple(result),
        sum(item.required_credentials for item in result),
        sum(item.available_credentials for item in result),
    )


def _provider_required(free: object, paid: object) -> int:
    return int(getattr(free, "enabled", False)) + int(getattr(paid, "enabled", False))


def _capability(
    name: str,
    enabled: bool,
    required: int,
    observation: CapabilityMetadata | None,
    configured: bool,
) -> CapabilityReadiness:
    if not enabled:
        return CapabilityReadiness(name, "disabled", ("capability_disabled",), 0, 0)
    item = observation or CapabilityMetadata()
    available = min(required, len(item.available_credentials))
    state = "configured"
    codes = list(item.warnings)
    if item.config_code:
        codes.append(item.config_code)
    if item.terms_code:
        codes.append(item.terms_code)
    if item.oauth_code:
        codes.append(item.oauth_code)
    if not configured:
        codes.append("config_unavailable")
    if available < required:
        codes.append("credential_missing")
        state = "blocked"
    elif any(
        code.startswith(("config_", "credential_", "terms_", "oauth_", "app_password_"))
        for code in codes
    ):
        state = "blocked"
    elif available == required:
        # Warnings such as the dedicated-account recommendation do not block
        # an explicitly acknowledged app-password rollout.
        codes.append("capability_ready")
        state = "ready"
    else:
        codes.append("capability_configured")
        state = "configured"
    return CapabilityReadiness(name, state, _ordered_unique(codes), required, available)


def _ordered_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


build_readiness_report = calculate_readiness
