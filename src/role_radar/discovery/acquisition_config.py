"""Strict non-secret acquisition TOML configuration."""

from __future__ import annotations

import os
import stat
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from role_radar.free_sources.terms import JobicyTermsAcceptance

DEFAULT_ACQUISITION_CONFIG = Path("/etc/role-radar/acquisition.toml")
BRAVE_PAID_LOCAL_CAP_MICRO_USD = 5_000_000


class AcquisitionConfigError(ValueError):
    pass


class FreeQuota(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    enabled: bool = False
    units_limit: int = Field(default=0, ge=0)
    version: str = Field(default="", max_length=64)

    @model_validator(mode="after")
    def require_version_when_enabled(self) -> FreeQuota:
        if self.enabled and self.units_limit > 0 and not self.version:
            raise ValueError("enabled free quota requires a version")
        return self


class BravePaidConfig(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    enabled: bool = False
    quote_version: str = ""
    reviewed_at: datetime | None = None
    unit_price_micro_usd: int | None = Field(default=None, ge=0)
    provider_ceiling_micro_usd: int | None = Field(default=None, ge=0)
    provider_ceiling_evidence: bool = False
    payment_control_evidence: bool = False

    @model_validator(mode="after")
    def validate_paid_gates(self) -> BravePaidConfig:
        if not self.enabled:
            return self
        if not self.quote_version or self.unit_price_micro_usd is None:
            raise ValueError("Brave paid requires a price quote and integer unit price")
        if self.provider_ceiling_micro_usd is None:
            raise ValueError("Brave paid requires a provider-side ceiling")
        if not self.provider_ceiling_evidence or not self.payment_control_evidence:
            raise ValueError("Brave paid requires provider-side evidence")
        if self.reviewed_at is None:
            raise ValueError("Brave paid requires a review timestamp")
        reviewed = self.reviewed_at
        if reviewed.tzinfo is None or reviewed.utcoffset() != timedelta(0):
            raise ValueError("paid review timestamp must be UTC")
        return self


class JobicyTermsConfig(BaseModel):
    """Non-secret operator acceptance; origins and request policy stay in code."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    terms_url: str = Field(min_length=1, max_length=2048)
    reviewed_at: datetime
    policy_version: str = Field(min_length=1, max_length=64)
    fair_use_ack: bool = False
    preserve_destination_ack: bool = False
    no_redistribution_ack: bool = False

    @model_validator(mode="after")
    def validate_terms(self) -> JobicyTermsConfig:
        if not self.terms_url.startswith("https://"):
            raise ValueError("Jobicy terms URL must use HTTPS")
        if self.reviewed_at.tzinfo is None or self.reviewed_at.utcoffset() != timedelta(0):
            raise ValueError("Jobicy terms review timestamp must be UTC")
        return self

    def acceptance(self) -> JobicyTermsAcceptance:
        return JobicyTermsAcceptance(
            terms_url=self.terms_url,
            reviewed_at=self.reviewed_at,
            policy_version=self.policy_version,
            fair_use_ack=self.fair_use_ack,
            preserve_destination_ack=self.preserve_destination_ack,
            no_redistribution_ack=self.no_redistribution_ack,
        )


class AcquisitionConfig(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    config_version: str = Field(min_length=1, max_length=64)
    brave_free: FreeQuota = FreeQuota()
    tavily_free: FreeQuota = FreeQuota()
    brave_paid: BravePaidConfig = BravePaidConfig()
    jobicy: JobicyTermsConfig | None = None

    @property
    def effective_brave_paid_cap(self) -> int:
        if not self.brave_paid.enabled:
            return 0
        ceiling = self.brave_paid.provider_ceiling_micro_usd
        if ceiling is None:
            return 0
        return min(BRAVE_PAID_LOCAL_CAP_MICRO_USD, ceiling)

    @property
    def semantic_query_limit(self) -> int:
        return 0

    def paid_is_current(self, now: datetime) -> bool:
        reviewed = self.brave_paid.reviewed_at
        if reviewed is None or reviewed.tzinfo is None:
            return False
        return now.astimezone(UTC) - reviewed.astimezone(UTC) <= timedelta(days=30)


def load_acquisition_config(
    path: str | os.PathLike[str] = DEFAULT_ACQUISITION_CONFIG,
) -> AcquisitionConfig:
    """Load only non-secret config from a secure, explicit TOML path."""
    candidate = Path(path)
    _check_secure_file(candidate)
    try:
        with candidate.open("rb") as handle:
            raw: dict[str, Any] = tomllib.load(handle)
        config = AcquisitionConfig.model_validate(raw)
    except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
        if isinstance(exc, AcquisitionConfigError):
            raise
        raise AcquisitionConfigError("acquisition configuration is invalid") from exc
    if config.brave_paid.reviewed_at is not None:
        reviewed = config.brave_paid.reviewed_at
        if reviewed.tzinfo is None or reviewed.utcoffset() is None:
            raise AcquisitionConfigError("paid review timestamp must be UTC-aware")
    return config


def _check_secure_file(path: Path) -> None:
    try:
        if path.is_symlink() or not path.is_file():
            raise AcquisitionConfigError("acquisition config path is not a regular file")
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode != 0o600:
            raise AcquisitionConfigError("acquisition config must have mode 0600")
        if path.stat().st_uid not in {0, os.geteuid()}:
            raise AcquisitionConfigError("acquisition config owner is invalid")
    except OSError as exc:
        raise AcquisitionConfigError("acquisition config is unavailable") from exc
