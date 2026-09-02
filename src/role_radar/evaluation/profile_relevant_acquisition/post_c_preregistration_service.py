"""The sole effectful boundary for offline post-C preregistration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from role_radar.evaluation.filesystem import atomic_write, ensure_private_root
from role_radar.evaluation.profile_relevant_acquisition.post_c_preregistration_contracts import (
    PostCPreregistrationError,
    PostCPreregistrationRequest,
    PostCPreregistrationSeal,
    PrivateSealWriter,
    build_seal,
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
            return path.read_bytes()
        except FileNotFoundError:
            return None


def preregister_post_c(
    *, request: PostCPreregistrationRequest, writer: PrivateSealWriter
) -> PostCPreregistrationPublicResult:
    """Validate everything, then perform exactly one idempotent private write."""
    if not callable(getattr(writer, "write", None)) or not callable(getattr(writer, "read", None)):
        raise PostCPreregistrationError("post_c_writer_invalid")
    if getattr(writer, "approved_root", None) != request.source_plan.root:
        raise PostCPreregistrationError("post_c_root_mismatch")
    seal = build_seal(request)
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


__all__ = ["FilesystemPrivateSealWriter", "PostCPreregistrationPublicResult", "preregister_post_c"]
