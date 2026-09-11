"""Independent packet verification for the R2 real discovery boundary.

This module implements the production ``RealDiscoveryVerifier``. It receives
the same in-memory objects as any verifier, but trusts none of them: every
binding is re-derived from the persisted packet file and compared field by
field before any claims are minted.

Read-only by construction. It reads the packet file, walks repository history
roots, and runs one local ``git rev-parse HEAD``. It never resolves
credentials, constructs providers, opens network sockets, writes to the
application database, or invokes any later gate. Verdict output carries
digests and check names only, never seed values.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from role_radar.continuous_acquisition.report_only_v2 import quota_contexts_from_config
from role_radar.discovery.planner_v2 import MAX_DISCOVERY_QUERIES, DiscoveryQueryPlanV2

from .gate_b_preflight import (
    MAX_PACKET_BYTES,
    GateBPacket,
    GateBPreflightError,
)
from .gate_b_preflight import (
    SCHEMA_VERSION as GATE_B_SCHEMA_VERSION,
)
from .gate_c_authorization import (
    AcceptedGateBBinding,
    GateCAuthorization,
    GateCAuthorizationError,
    gate_b_packet_sha256,
    parse_gate_c_authorization,
)
from .real_discovery_capability import (
    REAL_DISCOVERY_BOUNDS,
    REAL_DISCOVERY_HOSTS,
    REAL_DISCOVERY_MAX_TTL_SECONDS,
    RealDiscoveryVerification,
    make_test_real_discovery_verification,
)

VERDICT_SCHEMA_VERSION: Final[str] = "r2-discovery-verdict-v1"

_SEED_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{40,64}$")
_B_PACKET_FIELDS: Final[frozenset[str]] = frozenset(GateBPacket.__dataclass_fields__)
_SKIP_DIRS: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".venv",
        "__pycache__",
        "node_modules",
        ".hg",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
    }
)
_CHUNK_SIZE: Final[int] = 65536
_CHECK_NAMES: Final[tuple[str, ...]] = (
    "packet_load",
    "packet_sections",
    "authorization",
    "binding",
    "seeds",
    "history",
    "window",
    "plan",
    "quota",
    "commit",
    "approval",
)


class RealDiscoveryVerifierError(ValueError):
    """Stable, sanitized failure for independent packet verification."""

    def __init__(self, code: str = "verdict_rejected") -> None:
        self.code = code if code.startswith("verdict_") else "verdict_rejected"
        super().__init__(self.code)


def _default_git_head(repo: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RealDiscoveryVerifierError("verdict_commit_unavailable") from exc
    head = completed.stdout.strip()
    if completed.returncode != 0 or _COMMIT_RE.fullmatch(head) is None:
        raise RealDiscoveryVerifierError("verdict_commit_unavailable")
    return head


def _parse_z(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RealDiscoveryVerifierError("verdict_window_invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RealDiscoveryVerifierError("verdict_window_invalid") from exc
    if parsed.tzinfo is not UTC:
        raise RealDiscoveryVerifierError("verdict_window_invalid")
    return parsed


@dataclass(frozen=True, slots=True)
class IndependentPacketVerifier:
    """File-anchored production verifier for one real discovery packet."""

    packet_path: Path
    repo_path: Path
    expected_approval_reference: str
    history_roots: tuple[Path, ...] | None = None
    verdict_path: Path | None = None
    verifier_id: str = "independent-packet-verifier-v1"
    git_head: Callable[[], str] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.packet_path, Path) or not isinstance(self.repo_path, Path):
            raise RealDiscoveryVerifierError("verdict_type_invalid")
        if (
            type(self.expected_approval_reference) is not str
            or not self.expected_approval_reference
        ):
            raise RealDiscoveryVerifierError("verdict_type_invalid")
        if type(self.verifier_id) is not str or not self.verifier_id:
            raise RealDiscoveryVerifierError("verdict_type_invalid")
        if self.history_roots is None:
            object.__setattr__(self, "history_roots", (self.repo_path,))
        elif (
            type(self.history_roots) is not tuple
            or not self.history_roots
            or any(not isinstance(item, Path) for item in self.history_roots)
        ):
            raise RealDiscoveryVerifierError("verdict_type_invalid")
        if self.verdict_path is not None and not isinstance(self.verdict_path, Path):
            raise RealDiscoveryVerifierError("verdict_type_invalid")
        if self.git_head is not None and not callable(self.git_head):
            raise RealDiscoveryVerifierError("verdict_type_invalid")

    def verify_real_discovery(
        self,
        authorization: GateCAuthorization,
        accepted_b: AcceptedGateBBinding,
        plan: DiscoveryQueryPlanV2,
        config: object,
    ) -> RealDiscoveryVerification:
        """Re-derive every binding from the packet file, then mint claims."""
        if (
            type(authorization) is not GateCAuthorization
            or type(accepted_b) is not AcceptedGateBBinding
            or type(plan) is not DiscoveryQueryPlanV2
            or config is None
        ):
            raise RealDiscoveryVerifierError("verdict_type_invalid")
        doc = self._load_packet()
        packet = self._rebuild_packet(doc)
        auth = self._parse_authorization(doc)
        self._check_approval(doc)
        self._check_binding(doc, packet, auth, authorization, accepted_b)
        seeds = self._check_seeds(packet)
        self._check_history(seeds)
        window_start = self._check_window(auth)
        self._check_plan(doc, auth, plan)
        self._check_quota(config, window_start)
        self._check_commit(doc, auth)
        try:
            claims = make_test_real_discovery_verification(authorization, accepted_b, plan, config)
        except Exception as exc:
            raise RealDiscoveryVerifierError("verdict_claims_invalid") from exc
        self._write_verdict(packet, plan, auth)
        return claims

    def _load_packet(self) -> Mapping[str, Any]:
        try:
            raw = self.packet_path.read_bytes()
        except OSError as exc:
            raise RealDiscoveryVerifierError("verdict_packet_unreadable") from exc
        if not 0 < len(raw) <= MAX_PACKET_BYTES:
            raise RealDiscoveryVerifierError("verdict_packet_unreadable")
        try:
            parsed: Any = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise RealDiscoveryVerifierError("verdict_packet_unreadable") from exc
        if not isinstance(parsed, dict):
            raise RealDiscoveryVerifierError("verdict_packet_fields_invalid")
        return parsed

    def _rebuild_packet(self, doc: Mapping[str, Any]) -> GateBPacket:
        section = doc.get("gate_b_packet")
        if not isinstance(section, Mapping):
            raise RealDiscoveryVerifierError("verdict_packet_fields_invalid")
        values = dict(section)
        marker = values.pop("schema_version", None)
        if marker is not None and marker != GATE_B_SCHEMA_VERSION:
            raise RealDiscoveryVerifierError("verdict_packet_fields_invalid")
        if set(values) != _B_PACKET_FIELDS:
            raise RealDiscoveryVerifierError("verdict_packet_fields_invalid")
        try:
            return GateBPacket(**values)
        except (TypeError, GateBPreflightError) as exc:
            raise RealDiscoveryVerifierError("verdict_packet_fields_invalid") from exc

    def _parse_authorization(self, doc: Mapping[str, Any]) -> GateCAuthorization:
        section = doc.get("authorization")
        if not isinstance(section, Mapping):
            raise RealDiscoveryVerifierError("verdict_packet_fields_invalid")
        try:
            return parse_gate_c_authorization(section)
        except GateCAuthorizationError as exc:
            raise RealDiscoveryVerifierError("verdict_authorization_invalid") from exc

    def _check_approval(self, doc: Mapping[str, Any]) -> None:
        if doc.get("approval_reference_NOT_GRANTED") != self.expected_approval_reference:
            raise RealDiscoveryVerifierError("verdict_approval_unbound")

    def _check_binding(
        self,
        doc: Mapping[str, Any],
        packet: GateBPacket,
        auth: GateCAuthorization,
        authorization: GateCAuthorization,
        accepted_b: AcceptedGateBBinding,
    ) -> None:
        declared = doc.get("gate_b_packet_sha256")
        if not isinstance(declared, str):
            raise RealDiscoveryVerifierError("verdict_packet_fields_invalid")
        computed = gate_b_packet_sha256(packet)
        if computed != declared or accepted_b.packet_sha256 != declared:
            raise RealDiscoveryVerifierError("verdict_binding_mismatch")
        if accepted_b.packet != packet:
            raise RealDiscoveryVerifierError("verdict_binding_mismatch")
        if (
            accepted_b.report.result != "ready"
            or accepted_b.report.code != "gate_b_packet_ready"
            or accepted_b.report.packet_sha256 != declared
        ):
            raise RealDiscoveryVerifierError("verdict_binding_mismatch")
        report = doc.get("gate_b_report")
        if (
            not isinstance(report, Mapping)
            or report.get("result") != "ready"
            or report.get("code") != "gate_b_packet_ready"
            or report.get("packet_sha256") != declared
        ):
            raise RealDiscoveryVerifierError("verdict_binding_mismatch")
        if authorization != auth:
            raise RealDiscoveryVerifierError("verdict_binding_mismatch")
        if auth.provenance.gate_b_packet_sha256 != declared:
            raise RealDiscoveryVerifierError("verdict_binding_mismatch")

    def _check_seeds(self, packet: GateBPacket) -> tuple[str, str]:
        selection = packet.selection_seed
        partition = packet.partition_seed
        if (
            _SEED_RE.fullmatch(selection) is None
            or _SEED_RE.fullmatch(partition) is None
            or selection == partition
        ):
            raise RealDiscoveryVerifierError("verdict_seed_invalid")
        return selection, partition

    def _check_history(self, seeds: tuple[str, str]) -> None:
        roots = self.history_roots
        assert roots is not None
        needles = (seeds[0].encode("ascii"), seeds[1].encode("ascii"))
        skip = {self.packet_path.resolve()}
        if self.verdict_path is not None:
            skip.add(self.verdict_path.resolve())
        for root in roots:
            if not root.is_dir():
                raise RealDiscoveryVerifierError("verdict_history_unreadable")
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                here = Path(dirpath)
                dirnames[:] = [
                    name
                    for name in dirnames
                    if name not in _SKIP_DIRS and not (here / name).is_symlink()
                ]
                for name in filenames:
                    candidate = here / name
                    if candidate.is_symlink() or not candidate.is_file():
                        continue
                    try:
                        resolved = candidate.resolve()
                    except OSError as exc:
                        raise RealDiscoveryVerifierError("verdict_history_unreadable") from exc
                    if resolved in skip:
                        continue
                    self._scan_file(candidate, needles)

    @staticmethod
    def _scan_file(path: Path, needles: tuple[bytes, bytes]) -> None:
        try:
            with path.open("rb") as handle:
                overlap = b""
                while True:
                    try:
                        chunk = handle.read(_CHUNK_SIZE)
                    except OSError as exc:
                        raise RealDiscoveryVerifierError("verdict_history_unreadable") from exc
                    if not chunk:
                        return
                    window = overlap + chunk
                    for needle in needles:
                        if needle in window:
                            raise RealDiscoveryVerifierError("verdict_seed_reused")
                    overlap = window[-63:]
        except OSError as exc:
            raise RealDiscoveryVerifierError("verdict_history_unreadable") from exc

    def _check_window(self, auth: GateCAuthorization) -> datetime:
        provenance = auth.provenance
        start = _parse_z(provenance.window_start_utc)
        end = _parse_z(provenance.window_end_utc)
        cutoff = _parse_z(provenance.cutoff_utc)
        expires = _parse_z(auth.expires_at_utc)
        if not start < cutoff <= end:
            raise RealDiscoveryVerifierError("verdict_window_invalid")
        total = (expires - start).total_seconds()
        if total != int(total) or not 0 < total <= REAL_DISCOVERY_MAX_TTL_SECONDS:
            raise RealDiscoveryVerifierError("verdict_window_invalid")
        return start

    def _check_plan(
        self, doc: Mapping[str, Any], auth: GateCAuthorization, plan: DiscoveryQueryPlanV2
    ) -> None:
        declared = doc.get("plan_sha256")
        if (
            not isinstance(declared, str)
            or declared != plan.plan_sha256
            or declared != auth.provenance.query_plan_sha256
        ):
            raise RealDiscoveryVerifierError("verdict_plan_mismatch")
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
            raise RealDiscoveryVerifierError("verdict_plan_mismatch")
        if tuple(item.host for item in plan.source_registry) != REAL_DISCOVERY_HOSTS:
            raise RealDiscoveryVerifierError("verdict_plan_mismatch")
        if len(plan.queries) != MAX_DISCOVERY_QUERIES:
            raise RealDiscoveryVerifierError("verdict_plan_mismatch")

    def _check_quota(self, config: object, window_start: datetime) -> None:
        try:
            contexts = quota_contexts_from_config(config, created=window_start)
        except Exception as exc:
            raise RealDiscoveryVerifierError("verdict_quota_invalid") from exc
        by_provider = {context.provider: context for context in contexts}
        if set(by_provider) != {"brave", "tavily"}:
            raise RealDiscoveryVerifierError("verdict_quota_invalid")
        month = window_start.strftime("%Y-%m")
        for provider in ("brave", "tavily"):
            context = by_provider[provider]
            if context.tier != "free" or context.utc_month != month:
                raise RealDiscoveryVerifierError("verdict_quota_invalid")
        for field in ("brave_paid", "tavily_paid"):
            paid = getattr(config, field, None)
            if paid is not None and getattr(paid, "enabled", None) is True:
                raise RealDiscoveryVerifierError("verdict_quota_invalid")

    def _check_commit(self, doc: Mapping[str, Any], auth: GateCAuthorization) -> None:
        if self.git_head is not None:
            try:
                head = self.git_head()
            except Exception as exc:
                raise RealDiscoveryVerifierError("verdict_commit_unavailable") from exc
            if not isinstance(head, str) or _COMMIT_RE.fullmatch(head) is None:
                raise RealDiscoveryVerifierError("verdict_commit_unavailable")
        else:
            head = _default_git_head(self.repo_path)
        try:
            derived = hashlib.sha256(head.encode("ascii")).hexdigest()
        except (UnicodeEncodeError, ValueError) as exc:
            raise RealDiscoveryVerifierError("verdict_commit_unavailable") from exc
        if derived != auth.provenance.candidate_commit_sha256:
            raise RealDiscoveryVerifierError("verdict_commit_mismatch")
        recorded = doc.get("derived_code_commit_sha256")
        if recorded is not None and recorded != derived:
            raise RealDiscoveryVerifierError("verdict_commit_mismatch")

    def _write_verdict(
        self, packet: GateBPacket, plan: DiscoveryQueryPlanV2, auth: GateCAuthorization
    ) -> None:
        if self.verdict_path is None:
            return
        parent = self.verdict_path.parent
        try:
            parent_metadata = parent.lstat()
        except OSError as exc:
            raise RealDiscoveryVerifierError("verdict_output_invalid") from exc
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
            or parent_metadata.st_uid != os.geteuid()
            or parent.is_symlink()
            or self.verdict_path.is_symlink()
            or self.verdict_path.exists()
        ):
            raise RealDiscoveryVerifierError("verdict_output_invalid")
        body = {
            "approval_reference": self.expected_approval_reference,
            "candidate_commit_sha256": auth.provenance.candidate_commit_sha256,
            "checks": list(_CHECK_NAMES),
            "gate_b_packet_sha256": gate_b_packet_sha256(packet),
            "packet_path": str(self.packet_path),
            "query_plan_sha256": plan.plan_sha256,
            "schema_version": VERDICT_SCHEMA_VERSION,
            "verified_at_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "verifier_id": self.verifier_id,
        }
        payload = json.dumps(body, sort_keys=True, indent=2).encode("utf-8") + b"\n"
        temporary_name: str | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(prefix=".verdict-", dir=parent)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary_name, self.verdict_path, follow_symlinks=False)
            directory_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except (FileExistsError, OSError) as exc:
            raise RealDiscoveryVerifierError("verdict_output_invalid") from exc
        finally:
            if temporary_name is not None:
                with suppress(FileNotFoundError):
                    Path(temporary_name).unlink()


__all__ = [
    "VERDICT_SCHEMA_VERSION",
    "IndependentPacketVerifier",
    "RealDiscoveryVerifierError",
]
