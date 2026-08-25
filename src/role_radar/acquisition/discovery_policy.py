"""Secure fixed-path loader for the profile-driven discovery policy.

The policy model is pure and lives in ``role_radar.discovery.policy``.  This
module owns only bounded file access and the injected temporary-root seam used
by Gate A tests.
"""

from __future__ import annotations

import grp
import os
import stat
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from role_radar.discovery.policy import DiscoveryPolicyV1, canonical_policy_sha256

DEFAULT_DISCOVERY_POLICY_PATH: Final = Path("/etc/role-radar/discovery-policy.toml")
MAX_DISCOVERY_POLICY_BYTES: Final = 262_144


class DiscoveryPolicyFileError(ValueError):
    """Stable, path-free policy file error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class DiscoveryPolicyFilePolicy:
    """Metadata policy for production or injected test files."""

    owner_uid: int | None = None
    group_gid: int | None = None
    mode: int = 0o640
    require_owner: bool = True

    def validate(self, descriptor: int) -> None:
        try:
            metadata = os.fstat(descriptor)
        except OSError as exc:
            raise DiscoveryPolicyFileError("discovery_policy_unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise DiscoveryPolicyFileError("discovery_policy_not_regular")
        if stat.S_IMODE(metadata.st_mode) != self.mode:
            raise DiscoveryPolicyFileError("discovery_policy_mode_invalid")
        if metadata.st_nlink != 1:
            raise DiscoveryPolicyFileError("discovery_policy_link_invalid")
        if self.require_owner and self.owner_uid is not None and metadata.st_uid != self.owner_uid:
            raise DiscoveryPolicyFileError("discovery_policy_owner_invalid")
        if self.require_owner and self.group_gid is not None and metadata.st_gid != self.group_gid:
            raise DiscoveryPolicyFileError("discovery_policy_group_invalid")


@dataclass(frozen=True, slots=True)
class LoadedDiscoveryPolicyV1:
    policy: DiscoveryPolicyV1
    raw_bytes: bytes
    policy_sha256: str
    source_path: Path | None = None

    def __post_init__(self) -> None:
        if canonical_policy_sha256(self.policy) != self.policy_sha256:
            raise DiscoveryPolicyFileError("discovery_policy_hash_mismatch")


def _validate_parent_chain(parent: Path, file_policy: DiscoveryPolicyFilePolicy | None) -> None:
    """Reject symlinked/untrusted path components before opening the file."""

    current = parent
    while True:
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise DiscoveryPolicyFileError("discovery_policy_unavailable") from exc
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise DiscoveryPolicyFileError("discovery_policy_parent_invalid")
        mode = stat.S_IMODE(metadata.st_mode)
        if (mode & (stat.S_IWGRP | stat.S_IWOTH)) and not mode & stat.S_ISVTX:
            raise DiscoveryPolicyFileError("discovery_policy_parent_invalid")
        if (
            file_policy is not None
            and file_policy.owner_uid is not None
            and metadata.st_uid != file_policy.owner_uid
            and current not in {Path("/tmp"), Path("/")}
        ):
            raise DiscoveryPolicyFileError("discovery_policy_parent_invalid")
        if current == Path(current.anchor):
            return
        current = current.parent


def _read_bounded(path: Path, file_policy: DiscoveryPolicyFilePolicy | None) -> bytes:
    if not path.is_absolute() or path == Path(path.anchor):
        raise DiscoveryPolicyFileError("discovery_policy_path_invalid")
    if (
        file_policy is not None
        and file_policy.owner_uid == 0
        and path != DEFAULT_DISCOVERY_POLICY_PATH
    ):
        raise DiscoveryPolicyFileError("discovery_policy_path_invalid")
    _validate_parent_chain(path.parent, file_policy)
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        if file_policy is not None:
            file_policy.validate(descriptor)
        before = os.fstat(descriptor)
        payload = os.read(descriptor, MAX_DISCOVERY_POLICY_BYTES + 1)
        after = os.fstat(descriptor)
        if len(payload) > MAX_DISCOVERY_POLICY_BYTES:
            raise DiscoveryPolicyFileError("discovery_policy_too_large")
        if (
            before.st_size != after.st_size
            or before.st_ino != after.st_ino
            or before.st_dev != after.st_dev
        ):
            raise DiscoveryPolicyFileError("discovery_policy_changed")
        return payload
    except DiscoveryPolicyFileError:
        raise
    except OSError as exc:
        raise DiscoveryPolicyFileError("discovery_policy_unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load_discovery_policy(
    path: str | os.PathLike[str] | None = None,
    *,
    policy: DiscoveryPolicyV1 | Mapping[str, object] | None = None,
    policy_bytes: bytes | None = None,
    file_policy: DiscoveryPolicyFilePolicy | None = None,
) -> LoadedDiscoveryPolicyV1:
    """Load and hash one strict policy without exposing file details."""

    if policy is not None:
        if file_policy is not None and file_policy.owner_uid == 0:
            raise DiscoveryPolicyFileError("discovery_policy_path_invalid")
        try:
            parsed = (
                policy
                if isinstance(policy, DiscoveryPolicyV1)
                else DiscoveryPolicyV1.model_validate(policy)
            )
            canonical = canonical_policy_bytes(parsed)
            if policy_bytes is not None and policy_bytes != canonical:
                raise DiscoveryPolicyFileError("discovery_policy_hash_mismatch")
            raw = canonical
            return LoadedDiscoveryPolicyV1(parsed, raw, canonical_policy_sha256(parsed), None)
        except DiscoveryPolicyFileError:
            raise
        except (TypeError, ValueError) as exc:
            raise DiscoveryPolicyFileError("discovery_policy_invalid") from exc

    selected = DEFAULT_DISCOVERY_POLICY_PATH if path is None else Path(path)
    raw = _read_bounded(selected, file_policy)
    try:
        parsed_payload = tomllib.loads(raw.decode("utf-8", errors="strict"))
        parsed = DiscoveryPolicyV1.model_validate(parsed_payload)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, TypeError, ValueError) as exc:
        raise DiscoveryPolicyFileError("discovery_policy_invalid") from exc
    return LoadedDiscoveryPolicyV1(parsed, raw, canonical_policy_sha256(parsed), selected)


def production_discovery_policy_file_policy() -> DiscoveryPolicyFilePolicy:
    """Return the root-owned production metadata contract without reading it."""

    try:
        group_gid = grp.getgrnam("role-radar").gr_gid
    except KeyError:
        group_gid = -1
    return DiscoveryPolicyFilePolicy(
        owner_uid=0,
        group_gid=group_gid,
        mode=0o640,
        require_owner=True,
    )


def test_discovery_policy_file_policy() -> DiscoveryPolicyFilePolicy:
    """Return the current-user, private temporary-file policy for tests."""

    return DiscoveryPolicyFilePolicy(owner_uid=os.geteuid(), mode=0o600, require_owner=True)


def canonical_policy_bytes(policy: DiscoveryPolicyV1) -> bytes:
    from role_radar.discovery.policy import canonical_policy_bytes as serialize

    return serialize(policy)


__all__ = [
    "DEFAULT_DISCOVERY_POLICY_PATH",
    "MAX_DISCOVERY_POLICY_BYTES",
    "DiscoveryPolicyFileError",
    "DiscoveryPolicyFilePolicy",
    "LoadedDiscoveryPolicyV1",
    "canonical_policy_bytes",
    "load_discovery_policy",
    "production_discovery_policy_file_policy",
    "test_discovery_policy_file_policy",
]
