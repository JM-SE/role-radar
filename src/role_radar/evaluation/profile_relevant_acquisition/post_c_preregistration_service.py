"""The sole effectful boundary for offline post-C preregistration."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from role_radar.evaluation.filesystem import atomic_write, ensure_private_root
from role_radar.evaluation.profile_relevant_acquisition.post_c_effect_contracts import (
    PostCPreregistrationError,
    PostCPreregistrationSeal,
    PrivateSealWriter,
)
from role_radar.evaluation.profile_relevant_acquisition.post_c_recovery_authorization import (
    PostCAuthorization,
    PostCRecoveryAuthorizationError,
)
from role_radar.evaluation.profile_relevant_acquisition.post_c_recovery_filesystem import (
    RecoveryFilesystemError,
    pinned_root,
    read_bytes,
    read_optional_bytes,
    write_no_replace,
)
from role_radar.evaluation.profile_relevant_acquisition.post_c_recovery_loader import (
    RecoveredPostCData,
    load_recovered_post_c,
)

if TYPE_CHECKING:
    from role_radar.evaluation.profile_relevant_acquisition import (
        post_c_preregistration_contracts as _ordinary_contracts,
    )


@dataclass(frozen=True, slots=True)
class PostCPreregistrationPublicResult:
    operation_id: str
    preregistration_sha256: str
    source_plan_sha256: str
    report_sha256: str
    status: str
    result: str
    code: str

    def as_dict(self) -> dict[str, str]:
        return {
            name: getattr(self, name)
            for name in (
                "operation_id",
                "preregistration_sha256",
                "source_plan_sha256",
                "report_sha256",
                "status",
                "result",
                "code",
            )
        }


class FilesystemPrivateSealWriter:
    """Explicit-root writer; it writes only preregistration evidence."""

    def __init__(self, approved_root: str) -> None:
        self.approved_root = approved_root
        self._root = Path(approved_root)

    def write(self, seal: PostCPreregistrationSeal) -> None:
        ensure_private_root(self._root)
        atomic_write(self._root / "post-c" / f"{seal.operation_id}.json", seal.canonical_bytes)

    def read(self, operation_id: str) -> bytes | None:
        path = self._root / "post-c" / f"{operation_id}.json"
        try:
            path.lstat()
        except FileNotFoundError:
            return None
        try:
            with pinned_root(self._root) as root_fd:
                return read_bytes(root_fd, self._root, path, maximum=64 * 1024)
        except RecoveryFilesystemError as exc:
            raise PostCPreregistrationError("post_c_conflicting_repeat") from exc
        except OSError as exc:
            raise PostCPreregistrationError("post_c_conflicting_repeat") from exc


class RecoveredFilesystemPrivateSealWriter:
    """Strict writer used only after the recovered output root is approved."""

    def __init__(self, approved_root: str) -> None:
        self.approved_root = approved_root
        self._root = Path(approved_root)
        try:
            with pinned_root(self._root) as root_fd:
                metadata = os.fstat(root_fd)
                self._root_identity = (metadata.st_dev, metadata.st_ino)
        except RecoveryFilesystemError as exc:
            raise PostCPreregistrationError(exc.code) from exc

    def write(self, seal: PostCPreregistrationSeal) -> None:
        try:
            write_no_replace(
                self._root,
                ("post-c", f"{seal.operation_id}.json"),
                seal.canonical_bytes,
                expected_identity=self._root_identity,
                expected_leaf=f"{seal.operation_id}.json",
            )
        except RecoveryFilesystemError as exc:
            raise PostCPreregistrationError(exc.code) from exc

    def read(self, operation_id: str) -> bytes | None:
        path = self._root / "post-c" / f"{operation_id}.json"
        try:
            with pinned_root(self._root) as root_fd:
                return read_optional_bytes(
                    root_fd,
                    self._root,
                    path,
                    maximum=64 * 1024,
                    expected_identity=self._root_identity,
                )
        except RecoveryFilesystemError as exc:
            raise PostCPreregistrationError("post_c_conflicting_repeat") from exc
        except OSError as exc:
            raise PostCPreregistrationError("post_c_conflicting_repeat") from exc


def preregister_post_c(
    *, request: _ordinary_contracts.PostCPreregistrationRequest, writer: PrivateSealWriter
) -> PostCPreregistrationPublicResult:
    """Validate everything, then perform exactly one idempotent private write."""
    from role_radar.evaluation.profile_relevant_acquisition import (
        post_c_preregistration_contracts as _ordinary_contracts,
    )

    if not callable(getattr(writer, "write", None)) or not callable(getattr(writer, "read", None)):
        raise PostCPreregistrationError("post_c_writer_invalid")
    if getattr(writer, "approved_root", None) != request.source_plan.root:
        raise PostCPreregistrationError("post_c_root_mismatch")
    seal = _ordinary_contracts.build_seal(request)
    existing = writer.read(request.operation_id)
    if existing is not None and existing != seal.canonical_bytes:
        raise PostCPreregistrationError("post_c_conflicting_repeat")
    if existing is None:
        writer.write(seal)
        existing = writer.read(request.operation_id)
    if existing != seal.canonical_bytes:
        raise PostCPreregistrationError("post_c_readback_mismatch")
    return PostCPreregistrationPublicResult(
        request.operation_id,
        seal.preregistration_sha256,
        request.source_plan.source_plan_sha256,
        request.gate_c_result.public.report_sha256 or "",
        "sealed",
        "completed",
        "post_c_preregistration_sealed",
    )


def _validate_recovered_output_root(authorization: PostCAuthorization) -> None:
    try:
        with pinned_root(Path(authorization.output_root)) as root_fd:
            children = tuple(os.listdir(root_fd))
            if not children:
                return
            if set(children) != {"post-c"}:
                raise PostCPreregistrationError("post_c_recovery_output_root_not_empty")
            post_c_fd = os.open(
                "post-c",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
            try:
                post_c_metadata = os.fstat(post_c_fd)
                if not stat.S_ISDIR(post_c_metadata.st_mode) or (
                    post_c_metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(post_c_metadata.st_mode) != 0o700
                ):
                    raise PostCPreregistrationError("post_c_recovery_output_root_invalid")
                expected_name = f"{authorization.operation_id}.json"
                if tuple(os.listdir(post_c_fd)) != (expected_name,):
                    raise PostCPreregistrationError("post_c_recovery_output_root_not_empty")
            finally:
                os.close(post_c_fd)
    except PostCPreregistrationError:
        raise
    except RecoveryFilesystemError as exc:
        raise PostCPreregistrationError("post_c_recovery_output_root_invalid") from exc
    except OSError as exc:
        raise PostCPreregistrationError("post_c_recovery_output_root_invalid") from exc


def _recovered_seal(data: RecoveredPostCData) -> PostCPreregistrationSeal:
    authorization = data.authorization
    payload = {
        "schema_version": "f10.1f-post-c-recovered-v1",
        "action": authorization.action,
        "approval_reference": authorization.approval_reference,
        "authorization_sha256": authorization.authorization_sha256,
        "operation_id": authorization.operation_id,
        "operation_sha256": authorization.operation_sha256,
        "profile_id": authorization.profile_id,
        "profile_version": authorization.profile_version,
        "profile_sha256": authorization.profile_sha256,
        "policy_sha256": authorization.policy_sha256,
        "plan_sha256": authorization.plan_sha256,
        "report_sha256": authorization.report_sha256,
        "source_plan_sha256": data.source_plan.source_plan_sha256,
        "evidence_sha256": data.evidence_sha256,
        "verified_source_count": len(data.terminal.verified_sources),
        "state": data.terminal.state,
        "terminal_code": data.terminal.terminal_code,
        "window_start_utc": authorization.window_start_utc,
        "expires_at_utc": authorization.expires_at_utc,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    return PostCPreregistrationSeal(
        authorization.operation_id, raw, hashlib.sha256(raw).hexdigest()
    )


def preregister_recovered_post_c(
    *,
    authorization: PostCAuthorization,
    writer: PrivateSealWriter,
    clock: Callable[[], datetime] | None = None,
) -> PostCPreregistrationPublicResult:
    """Load, validate, and seal one independently authorized partial result."""
    if not isinstance(authorization, PostCAuthorization):
        raise PostCPreregistrationError("post_c_recovery_authorization_invalid")
    if not callable(getattr(writer, "write", None)) or not callable(getattr(writer, "read", None)):
        raise PostCPreregistrationError("post_c_writer_invalid")
    clock = clock or (lambda: datetime.now(UTC))
    try:
        authorization.validate_current(clock())
        _validate_recovered_output_root(authorization)
        data = load_recovered_post_c(authorization, clock=clock)
    except PostCPreregistrationError:
        raise
    except Exception as exc:
        code = getattr(exc, "code", "post_c_recovery_load_failed")
        raise PostCPreregistrationError(code) from exc
    if not isinstance(data, RecoveredPostCData):
        raise PostCPreregistrationError("post_c_recovery_data_invalid")
    try:
        authorization.validate_current(clock())
        _validate_recovered_output_root(authorization)
    except PostCRecoveryAuthorizationError as exc:
        raise PostCPreregistrationError(exc.code) from exc
    seal = _recovered_seal(data)
    if getattr(writer, "approved_root", None) != authorization.output_root:
        raise PostCPreregistrationError("post_c_root_mismatch")
    authorization.validate_current(clock())
    _validate_recovered_output_root(authorization)
    existing = writer.read(seal.operation_id)
    if existing is not None and existing != seal.canonical_bytes:
        raise PostCPreregistrationError("post_c_conflicting_repeat")
    if existing is None:
        authorization.validate_current(clock())
        _validate_recovered_output_root(authorization)
        writer.write(seal)
        authorization.validate_current(clock())
        existing = writer.read(seal.operation_id)
    if existing != seal.canonical_bytes:
        raise PostCPreregistrationError("post_c_readback_mismatch")
    return PostCPreregistrationPublicResult(
        authorization.operation_id,
        seal.preregistration_sha256,
        data.source_plan.source_plan_sha256,
        authorization.report_sha256,
        "sealed",
        "completed_partial",
        "post_c_recovered_preregistration_sealed",
    )


__all__ = [
    "FilesystemPrivateSealWriter",
    "PostCPreregistrationPublicResult",
    "RecoveredFilesystemPrivateSealWriter",
    "preregister_post_c",
    "preregister_recovered_post_c",
]
