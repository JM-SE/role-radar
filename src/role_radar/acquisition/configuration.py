"""The single strict acquisition configuration contract and safe TOML loader."""

from __future__ import annotations

import grp
import os
import stat
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from role_radar.free_sources.terms import JobicyTermsAcceptance
from role_radar.mailbox.configuration import ExternalMailboxConfig

DEFAULT_ACQUISITION_CONFIG = Path("/etc/role-radar/acquisition.toml")
BRAVE_PAID_LOCAL_CAP_MICRO_USD = 5_000_000
MAX_CONFIG_BYTES = 64 * 1024


class AcquisitionConfigError(ValueError):
    """Public, path-free configuration error."""

    def __init__(self, code: str = "config_unavailable") -> None:
        self.code = code
        super().__init__(code)


class QueryHmacConfig(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    query_hmac_handle: str = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
    )


class FreeQuota(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    enabled: bool = False
    units_limit: int = Field(default=0, ge=0)
    version: str = Field(default="", max_length=64)
    credential_handle: str | None = Field(
        default=None,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$",
    )

    @model_validator(mode="after")
    def require_version_and_handle_when_enabled(self) -> FreeQuota:
        if self.enabled and self.units_limit > 0 and not self.version:
            raise ValueError("enabled free quota requires a version")
        if self.enabled and not self.credential_handle:
            raise ValueError("enabled free quota requires a credential handle")
        if not self.enabled and self.credential_handle is not None:
            # A disabled capability must not even be mentioned as a requirement.
            raise ValueError("disabled free quota must not declare credentials")
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
        if self.reviewed_at is None or self.reviewed_at.utcoffset() != timedelta(0):
            raise ValueError("paid review timestamp must be UTC")
        return self


class JobicyTermsConfig(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    terms_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewed_at: datetime
    policy_version: str = Field(min_length=1, max_length=64)
    fair_use_ack: bool = False
    preserve_destination_ack: bool = False
    no_redistribution_ack: bool = False

    @model_validator(mode="after")
    def validate_terms(self) -> JobicyTermsConfig:
        if self.policy_version != "jobicy-terms-v1":
            raise ValueError("unsupported Jobicy terms policy")
        if self.reviewed_at.tzinfo is None or self.reviewed_at.utcoffset() != timedelta(0):
            raise ValueError("Jobicy terms review timestamp must be UTC")
        return self

    def acceptance(self) -> JobicyTermsAcceptance:
        # URL is code-owned and intentionally not part of the TOML contract.
        return JobicyTermsAcceptance(
            terms_url="https://jobicy.com/terms-and-conditions",
            reviewed_at=self.reviewed_at,
            policy_version=self.policy_version,
            fair_use_ack=self.fair_use_ack,
            preserve_destination_ack=self.preserve_destination_ack,
            no_redistribution_ack=self.no_redistribution_ack,
            terms_sha256=self.terms_sha256,
        )


class AcquisitionConfig(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    config_version: str = Field(min_length=1, max_length=64)
    discovery: QueryHmacConfig | None = None
    brave_free: FreeQuota = FreeQuota()
    tavily_free: FreeQuota = FreeQuota()
    brave_paid: BravePaidConfig = BravePaidConfig()
    jobicy: JobicyTermsConfig | None = None
    mailboxes: dict[str, ExternalMailboxConfig] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_aliases(self) -> AcquisitionConfig:
        if set(self.mailboxes) != {item.connection_alias for item in self.mailboxes.values()}:
            raise ValueError("mailbox aliases must be unique and match descriptors")
        return self

    @property
    def effective_brave_paid_cap(self) -> int:
        if not self.brave_paid.enabled or self.brave_paid.provider_ceiling_micro_usd is None:
            return 0
        return min(BRAVE_PAID_LOCAL_CAP_MICRO_USD, self.brave_paid.provider_ceiling_micro_usd)

    @property
    def semantic_query_limit(self) -> int:
        return 0

    def paid_is_current(self, now: datetime) -> bool:
        reviewed = self.brave_paid.reviewed_at
        return bool(
            reviewed is not None
            and reviewed.tzinfo is not None
            and now.astimezone(UTC) - reviewed.astimezone(UTC) <= timedelta(days=30)
        )


class AcquisitionFilePolicy(Protocol):
    def validate(self, descriptor: int, *, path: Path) -> None: ...


@dataclass(frozen=True, slots=True)
class ProductionAcquisitionFilePolicy:
    path: Path = DEFAULT_ACQUISITION_CONFIG
    name: str = "production"
    max_bytes: int = MAX_CONFIG_BYTES
    mode: int = 0o640
    owner_uid: int = 0
    group_name: str = "role-radar"

    def validate(self, descriptor: int, *, path: Path) -> None:
        _validate_descriptor(
            descriptor,
            path=path,
            policy_name=self.name,
            max_bytes=self.max_bytes,
            mode=self.mode,
            owner_uid=self.owner_uid,
            group_gid=_group_gid(self.group_name),
        )


@dataclass(frozen=True, slots=True)
class DevelopmentAcquisitionFilePolicy:
    path: Path | None = None
    name: str = "development"
    max_bytes: int = MAX_CONFIG_BYTES
    mode: int = 0o600
    owner_uid: int | None = None

    def validate(self, descriptor: int, *, path: Path) -> None:
        del path
        _validate_descriptor(
            descriptor,
            path=Path("<config>"),
            policy_name=self.name,
            max_bytes=self.max_bytes,
            mode=self.mode,
            owner_uid=os.geteuid() if self.owner_uid is None else self.owner_uid,
            group_gid=None,
        )


class TestAcquisitionFilePolicy(DevelopmentAcquisitionFilePolicy):
    """Explicit policy name useful to callers that want a test report."""

    name: str = "test"


def load_acquisition_config(
    path: str | os.PathLike[str] = DEFAULT_ACQUISITION_CONFIG,
    *,
    policy: AcquisitionFilePolicy | None = None,
) -> AcquisitionConfig:
    selected = policy or ProductionAcquisitionFilePolicy()
    candidate = Path(path)
    if isinstance(selected, ProductionAcquisitionFilePolicy) and candidate != selected.path:
        raise AcquisitionConfigError("config_path_invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(candidate, flags)
        selected.validate(descriptor, path=candidate)
        before = os.fstat(descriptor)
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as handle:
            payload = handle.read(MAX_CONFIG_BYTES + 1)
        if len(payload) > MAX_CONFIG_BYTES:
            raise AcquisitionConfigError("config_too_large")
        after = os.fstat(descriptor)
        if (
            after.st_size != before.st_size
            or after.st_ino != before.st_ino
            or after.st_dev != before.st_dev
        ):
            raise AcquisitionConfigError("config_changed")
        raw = tomllib.loads(payload.decode("utf-8"))
        return AcquisitionConfig.model_validate(raw)
    except AcquisitionConfigError:
        raise
    except (OSError, tomllib.TOMLDecodeError, ValueError, TypeError) as exc:
        raise AcquisitionConfigError("config_invalid") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _group_gid(name: str) -> int:
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError as exc:
        raise AcquisitionConfigError("config_group_unavailable") from exc


def _validate_descriptor(
    descriptor: int,
    *,
    path: Path,
    policy_name: str,
    max_bytes: int,
    mode: int,
    owner_uid: int,
    group_gid: int | None,
) -> None:
    try:
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise AcquisitionConfigError("config_unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise AcquisitionConfigError("config_not_regular")
    if metadata.st_uid != owner_uid:
        raise AcquisitionConfigError("config_owner_invalid")
    if group_gid is not None and metadata.st_gid != group_gid:
        raise AcquisitionConfigError("config_group_invalid")
    if stat.S_IMODE(metadata.st_mode) != mode:
        raise AcquisitionConfigError("config_mode_invalid")
    if metadata.st_size > max_bytes:
        raise AcquisitionConfigError("config_too_large")
    del path, policy_name


# Compatibility name used by old imports; the implementation above is the only loader.
DEFAULT_POLICY = ProductionAcquisitionFilePolicy()
