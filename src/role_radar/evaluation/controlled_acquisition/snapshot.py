"""Canonical private snapshot materialization and tamper verification."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from role_radar.evaluation.controlled_acquisition.contracts import (
    DatasetItem,
    SelectedCandidate,
)
from role_radar.evaluation.controlled_acquisition.manifest import sanitized_manifest
from role_radar.evaluation.controlled_acquisition.protocols import SNAPSHOT_VERSION
from role_radar.evaluation.controlled_acquisition.selection import blind_order

_DATASET_ID = re.compile(r"^[0-9a-f]{64}$")


def _json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=lambda item: item.isoformat().replace("+00:00", "Z"),
    ).encode("utf-8")


def canonical_line(value: Any) -> bytes:
    return _json(value) + b"\n"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def opaque_label_id(dataset_seed: str, cluster_id: str) -> str:
    return hashlib.sha256(
        f"{SNAPSHOT_VERSION}:label-id:{dataset_seed}:{cluster_id}".encode()
    ).hexdigest()[:24]


def materialize_records(
    items: tuple[DatasetItem, ...], *, dataset_seed: str
) -> tuple[tuple[bytes, ...], tuple[bytes, ...], tuple[bytes, ...]]:
    """Create the three ordered line streams without leaking selection metadata."""
    dataset_lines: list[bytes] = []
    provenance_lines: list[bytes] = []
    label_records: dict[str, dict[str, Any]] = {}
    for item in items:
        dataset_lines.append(canonical_line(item.__dict__ if hasattr(item, "__dict__") else {
            "ordinal": item.ordinal,
            "opaque_id": item.opaque_id,
            "title": item.title,
            "company": item.company,
            "location": item.location,
            "description": item.description,
            "source_url": item.source_url,
            "application_url": item.application_url,
            "provider_recency_at": item.provider_recency_at,
            "recency_semantic": item.recency_semantic,
            "selection_family": item.selection_family,
            "selection_reason": item.selection_reason,
        }))
        provenance_lines.append(
            canonical_line(
                {
                    "ordinal": item.ordinal,
                    "opaque_id": item.opaque_id,
                    "selection_family": item.selection_family,
                    "selection_reason": item.selection_reason,
                }
            )
        )
        label_records[item.opaque_id] = label_view_item(item)
    ordered_ids = blind_order(dataset_seed, label_records)
    label_lines = tuple(canonical_line(label_records[opaque_id]) for opaque_id in ordered_ids)
    return tuple(dataset_lines), tuple(provenance_lines), label_lines


def materialize_selection(
    selected: tuple[SelectedCandidate, ...], *, dataset_seed: str
) -> tuple[tuple[bytes, ...], tuple[bytes, ...], tuple[bytes, ...]]:
    """Materialize full private records and all corresponding provenances."""
    items: list[DatasetItem] = []
    provenances: list[dict[str, Any]] = []
    for ordinal, selected_item in enumerate(selected, start=1):
        cluster = selected_item.cluster
        primary = cluster.primary
        opaque_id = opaque_label_id(dataset_seed, cluster.cluster_id)
        items.append(
            DatasetItem(
                ordinal=ordinal,
                opaque_id=opaque_id,
                title=primary.title,
                company=primary.company,
                location=primary.location,
                description=primary.description,
                source_url=primary.source_url,
                application_url=primary.application_url,
                provider_recency_at=primary.provider_recency_at,
                recency_semantic=primary.recency_semantic,
                selection_family=selected_item.selection_family,
                selection_reason=selected_item.selection_reason,
            )
        )
        provenances.append(
            {
                "ordinal": ordinal,
                "opaque_id": opaque_id,
                "provenances": [
                    {
                        "source_family": observation.source_family,
                        "source_id": observation.source_id,
                        "source_key": observation.source_key,
                        "source_revision": observation.source_revision,
                        "configuration_version": observation.configuration_version,
                        "external_id": observation.external_id,
                        "source_url": observation.source_url,
                        "application_url": observation.application_url,
                        "collected_at": observation.collected_at,
                    }
                    for observation in cluster.observations
                ],
            }
        )
    dataset_lines, _, label_lines = materialize_records(
        tuple(items), dataset_seed=dataset_seed
    )
    provenance_lines = tuple(canonical_line(item) for item in provenances)
    return dataset_lines, provenance_lines, label_lines


def semantic_dataset_sha256(
    *,
    header: Mapping[str, Any],
    dataset_lines: Iterable[bytes],
    provenance_lines: Iterable[bytes],
    label_lines: Iterable[bytes],
) -> str:
    payload = bytearray()
    payload.extend(_json({"snapshot_version": SNAPSHOT_VERSION, "header": dict(header)}))
    for group in (dataset_lines, provenance_lines, label_lines):
        for line in group:
            payload.extend(hashlib.sha256(line).digest())
    return sha256_bytes(bytes(payload))


def _safe_directory(path: Path) -> None:
    current = Path(path.anchor) if path.anchor else Path()
    for part in path.parts[1:] if path.anchor else path.parts:
        current /= part
        if current.is_symlink():
            raise ValueError("snapshot_symlink_rejected")
        if not current.exists():
            current.mkdir(mode=0o700)
    if path.is_symlink():
        raise ValueError("snapshot_symlink_rejected")
    os.chmod(path, 0o700)
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ValueError("snapshot_directory_mode")


class SnapshotStore:
    """Fixed-root store; ``root`` is injectable only for offline tests."""

    FILES = (
        "dataset.jsonl",
        "provenance.jsonl",
        "label-view.jsonl",
        "internal-manifest.json",
        "checksums.sha256",
    )

    def __init__(self, root: Path) -> None:
        self.root = root
        _safe_directory(root)

    @contextmanager
    def _publish_lock(self) -> Any:
        lock_path = self.root / ".publish.lock"
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def publish(
        self,
        *,
        dataset_id: str,
        dataset_lines: tuple[bytes, ...],
        provenance_lines: tuple[bytes, ...],
        label_lines: tuple[bytes, ...],
        internal: Mapping[str, Any],
    ) -> Path:
        if not _DATASET_ID.fullmatch(dataset_id):
            raise ValueError("snapshot_dataset_id_invalid")
        if len(dataset_lines) != 50 or len(provenance_lines) != 50 or len(label_lines) != 50:
            raise ValueError("snapshot_requires_exactly_50_records")
        content = {
            "dataset.jsonl": b"".join(dataset_lines),
            "provenance.jsonl": b"".join(provenance_lines),
            "label-view.jsonl": b"".join(label_lines),
            "internal-manifest.json": _json(dict(internal)) + b"\n",
        }
        checksums = {name: sha256_bytes(payload) for name, payload in content.items()}
        content["checksums.sha256"] = "".join(
            f"{checksums[name]}  {name}\n" for name in checksums
        ).encode("ascii")
        with self._publish_lock():
            target = self.root / dataset_id
            if target.exists() or target.is_symlink():
                existing = self.verify(dataset_id)
                if existing:
                    if all(
                        (target / name).read_bytes() == payload
                        for name, payload in content.items()
                    ):
                        return target
                    raise FileExistsError("snapshot_id_conflict")
                raise FileExistsError("snapshot_id_conflict")
            staging = Path(tempfile.mkdtemp(prefix=f".{dataset_id}.", dir=self.root))
            os.chmod(staging, 0o700)
            try:
                for name, payload in content.items():
                    if name == "checksums.sha256":
                        continue
                    file_path = staging / name
                    file_path.write_bytes(payload)
                    os.chmod(file_path, 0o600)
                (staging / "checksums.sha256").write_text(
                    content["checksums.sha256"].decode("ascii"), encoding="ascii"
                )
                os.chmod(staging / "checksums.sha256", 0o600)
                for name in self.FILES:
                    with (staging / name).open("rb") as stream:
                        os.fsync(stream.fileno())
                directory_fd = os.open(staging, os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
                os.rename(staging, target)
                directory_fd = os.open(self.root, os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
                return target
            finally:
                if staging.exists():
                    for child in staging.iterdir():
                        child.unlink()
                    staging.rmdir()

    def verify(self, dataset_id: str) -> bool:
        if not _DATASET_ID.fullmatch(dataset_id):
            return False
        target = self.root / dataset_id
        if not target.is_dir() or target.is_symlink():
            return False
        children = tuple(target.iterdir())
        if any(item.is_symlink() for item in children):
            return False
        if set(item.name for item in children) != set(self.FILES):
            return False
        if any(stat.S_IMODE(item.stat().st_mode) != 0o600 for item in children):
            return False
        if stat.S_IMODE(target.stat().st_mode) != 0o700:
            return False
        for name in ("dataset.jsonl", "provenance.jsonl", "label-view.jsonl"):
            with (target / name).open("rb") as stream:
                if sum(1 for _ in stream) != 50:
                    return False
        checksums = (target / "checksums.sha256").read_text(encoding="ascii").splitlines()
        for entry in checksums:
            digest, _, name = entry.partition("  ")
            if name not in self.FILES or name == "checksums.sha256":
                return False
            if sha256_bytes((target / name).read_bytes()) != digest:
                return False
        return len(checksums) == 4


def label_view_item(item: DatasetItem) -> dict[str, Any]:
    return {
        "opaque_id": item.opaque_id,
        "title": item.title,
        "company": item.company,
        "location": item.location,
        "description": item.description,
    }


def external_projection(internal: Mapping[str, Any]) -> dict[str, Any]:
    return sanitized_manifest(internal)
