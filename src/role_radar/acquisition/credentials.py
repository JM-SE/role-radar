"""Capability-scoped, descriptor-relative credential access."""

from __future__ import annotations

import errno
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from role_radar.mailbox.contracts import CredentialMaterial, MailboxDescriptor

HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
MAX_CREDENTIAL_BYTES = 4096
_STRICT_CREDENTIAL_MODES = frozenset({0o400, 0o600})
_SYSTEMD_CREDENTIAL_MODE = 0o440


class CredentialError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class CredentialHandle:
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or HANDLE_RE.fullmatch(self.value) is None:
            raise CredentialError("credential_handle_invalid")

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return "CredentialHandle(<redacted>)"


@dataclass(frozen=True, slots=True)
class SecretMaterial:
    """Worker-only value whose representation and string conversion are redacted."""

    _value: bytes

    def get_secret_value(self) -> bytes:
        return self._value

    def __repr__(self) -> str:
        return "SecretMaterial(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


class CredentialResolver:
    """Resolve only basenames below ``CREDENTIALS_DIRECTORY``.

    The directory and each credential are opened with ``O_NOFOLLOW`` and all
    checks are made against the same descriptor used for reading.
    """

    def __init__(
        self,
        directory: str | os.PathLike[str] | None = None,
        *,
        require_env: bool = True,
    ):
        configured = directory if directory is not None else os.environ.get("CREDENTIALS_DIRECTORY")
        if require_env and not configured:
            raise CredentialError("credential_directory_unavailable")
        self._directory = Path(configured) if configured else None
        self._require_env = require_env

    def resolve(self, handle: str | CredentialHandle, *, text: bool = False) -> SecretMaterial:
        candidate = handle if isinstance(handle, CredentialHandle) else CredentialHandle(handle)
        if self._directory is None:
            raise CredentialError("credential_directory_unavailable")
        root_fd = -1
        child_fd = -1
        try:
            root_fd = os.open(
                self._directory,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            )
            child_fd = os.open(
                candidate.value,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
            before = os.fstat(child_fd)
            if stat.S_ISLNK(before.st_mode):
                raise CredentialError("credential_symlink")
            if not stat.S_ISREG(before.st_mode):
                raise CredentialError("credential_not_regular")
            if before.st_uid not in {0, os.geteuid()}:
                raise CredentialError("credential_owner_invalid")
            if not _credential_mode_allowed(before):
                raise CredentialError("credential_mode_invalid")
            if before.st_size > MAX_CREDENTIAL_BYTES:
                raise CredentialError("credential_too_large")
            value = b""
            while len(value) <= MAX_CREDENTIAL_BYTES:
                chunk = os.read(child_fd, MAX_CREDENTIAL_BYTES + 1 - len(value))
                if not chunk:
                    break
                value += chunk
            after = os.fstat(child_fd)
            if (
                before.st_ino != after.st_ino
                or before.st_dev != after.st_dev
                or before.st_size != after.st_size
            ):
                raise CredentialError("credential_changed")
            if len(value) > MAX_CREDENTIAL_BYTES:
                raise CredentialError("credential_too_large")
            value = value.rstrip(b"\r\n")
            if not value:
                raise CredentialError("credential_empty")
            if b"\x00" in value:
                raise CredentialError("credential_invalid_encoding")
            if text:
                try:
                    value.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise CredentialError("credential_invalid_encoding") from exc
            return SecretMaterial(value)
        except CredentialError:
            raise
        except FileNotFoundError as exc:
            raise CredentialError("credential_missing") from exc
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise CredentialError("credential_symlink") from exc
            raise CredentialError("credential_directory_unavailable") from exc
        finally:
            if child_fd >= 0:
                os.close(child_fd)
            if root_fd >= 0:
                os.close(root_fd)

    def text(self, handle: str | CredentialHandle) -> str:
        return self.resolve(handle, text=True).get_secret_value().decode("utf-8")


def _credential_mode_allowed(metadata: os.stat_result) -> bool:
    """Accept private files and systemd's root-owned credential projection.

    ``LoadCredential`` may expose a root-owned credential as ``0440``. That
    mode is accepted only for the exact ``root:root`` ownership; a
    group-readable file owned by an untrusted account remains rejected.
    """

    mode = stat.S_IMODE(metadata.st_mode)
    if mode in _STRICT_CREDENTIAL_MODES:
        return True
    return (
        mode == _SYSTEMD_CREDENTIAL_MODE
        and metadata.st_uid == 0
        and metadata.st_gid == 0
    )


def resolve_mailbox_credentials(
    descriptor: MailboxDescriptor,
    resolver: CredentialResolver,
    *,
    expiry_metadata: bytes | str | None = None,
    now: datetime | None = None,
) -> CredentialMaterial:
    """Resolve one mailbox only; no descriptor can borrow another alias's keys."""
    username = resolver.text(descriptor.username_handle)
    oauth = None
    password = None
    expires_at = None
    if descriptor.auth_mode == "xoauth2":
        if descriptor.oauth2_handle is None or descriptor.oauth2_expiry_handle is None:
            raise CredentialError("oauth_expiry_missing")
        from role_radar.acquisition.activation import parse_xoauth_expiry

        expiry = expiry_metadata
        if expiry is None:
            expiry = resolver.resolve(descriptor.oauth2_expiry_handle, text=True).get_secret_value()
        expires_at = parse_xoauth_expiry(expiry, now=now or datetime.now(UTC))
        oauth = resolver.text(descriptor.oauth2_handle)
    else:
        if descriptor.app_password_handle is None:
            raise CredentialError("credential_missing")
        password = resolver.text(descriptor.app_password_handle)
    return CredentialMaterial(
        username=username,
        oauth2_token=oauth,
        app_password=password,
        oauth2_expires_at=expires_at,
    )


def credential_ids(directory: str | os.PathLike[str] | None = None) -> frozenset[str]:
    """Return only mounted basenames; used for sanitized runtime counters."""

    root = Path(directory or os.environ.get("CREDENTIALS_DIRECTORY", ""))
    try:
        return frozenset(
            item.name
            for item in root.iterdir()
            if item.name
            and HANDLE_RE.fullmatch(item.name)
            and not item.is_symlink()
        )
    except OSError:
        return frozenset()


FileCredentialResolver = CredentialResolver
