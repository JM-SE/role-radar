"""Private namespace/root store for F10.1F artifacts.

Uses the single domain-neutral filesystem primitive owner; no historical root,
no copy of historical store code.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

from role_radar.evaluation.fresh_acquisition.filesystem import (
    FilesystemError,
    atomic_write,
    bounded_read,
    ensure_private_root,
    fenced_lock,
    resolve_nofollow,
    sha256_bytes,
    write_no_replace,
)
from role_radar.evaluation.fresh_acquisition.provenance import LIVE_NAMESPACE, LIVE_ROOT

DATASET_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
MANIFEST_NAME: Final[str] = "manifest.json"
POOL_NAME: Final[str] = "sealed_pool.jsonl"
CAPABILITY_SEAL_NAME: Final[str] = "capability_seal.json"


class StoreError(ValueError):
    def __init__(self, code: str) -> None:
        self.code: str = code
        super().__init__(code)


def _require_namespace(namespace: str) -> None:
    if namespace != LIVE_NAMESPACE:
        raise StoreError("store_namespace_mismatch")


def _require_root(root: Path) -> None:
    if not root.is_absolute():
        raise StoreError("store_root_must_be_absolute")
    text = str(root)
    if text.startswith("/opt/role-radar/data/evaluation/snapshot"):
        raise StoreError("store_historical_root_rejected")
    legacy_f101 = "/opt/role-radar/data/evaluation/f10.1/"
    if text.startswith(legacy_f101) and text != LIVE_ROOT and not text.startswith(LIVE_ROOT):
        raise StoreError("store_historical_root_rejected")
    # For live deployments, root must equal LIVE_ROOT; for offline tests any non-historical
    # absolute path is allowed (injectable). Enforce live equality only if under /opt.
    if text.startswith("/opt/") and text != LIVE_ROOT:
        raise StoreError("store_root_mismatch")


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (ValueError, TypeError) as exc:
        raise StoreError("store_canonical_invalid") from exc


class FreshAcquisitionStore:
    """Sole F10.1F domain store — composes filesystem primitive."""

    def __init__(self, root: Path, namespace: str = LIVE_NAMESPACE) -> None:
        _require_namespace(namespace)
        _require_root(root)
        try:
            ensure_private_root(root)
        except FilesystemError as exc:
            raise StoreError(exc.code) from exc
        self.root: Path = root
        self.namespace: str = namespace

    def _dataset_dir(self, dataset_id: str) -> Path:
        if DATASET_ID_RE.fullmatch(dataset_id) is None:
            raise StoreError("store_dataset_id_invalid")
        try:
            return resolve_nofollow(self.root, dataset_id)
        except FilesystemError as exc:
            raise StoreError(exc.code) from exc

    def publish_sealed_pool(
        self,
        *,
        dataset_id: str,
        pool_lines: tuple[bytes, ...],
        manifest: Mapping[str, Any],
    ) -> Path:
        """Publish sealed pool + manifest atomically under fence, no-replace."""

        _require_namespace(self.namespace)
        _require_root(self.root)
        if not pool_lines:
            raise StoreError("store_pool_empty")
        dataset_dir = self._dataset_dir(dataset_id)
        manifest_bytes = _canonical(dict(manifest))
        pool_bytes = b"".join(pool_lines)
        checksum_payload = _canonical(
            {
                "dataset_id": dataset_id,
                "manifest_sha256": sha256_bytes(manifest_bytes),
                "pool_sha256": sha256_bytes(pool_bytes),
            }
        )
        try:
            with fenced_lock(self.root):
                if dataset_dir.exists():
                    # idempotent if identical, else conflict
                    try:
                        existing_manifest = bounded_read(dataset_dir / MANIFEST_NAME)
                        existing_pool = bounded_read(dataset_dir / POOL_NAME)
                    except FilesystemError as exc:
                        raise StoreError(exc.code) from exc
                    if existing_manifest == manifest_bytes and existing_pool == pool_bytes:
                        return dataset_dir
                    raise StoreError("store_id_conflict")
                # create dataset dir
                try:
                    dataset_dir.mkdir(mode=0o700)
                except OSError as exc:
                    raise StoreError("store_mkdir_failed") from exc
                # write files no-replace
                try:
                    write_no_replace(dataset_dir / MANIFEST_NAME, manifest_bytes)
                    write_no_replace(dataset_dir / POOL_NAME, pool_bytes)
                    atomic_write(dataset_dir / "checksums.sha256", checksum_payload)
                except FilesystemError as exc:
                    raise StoreError(exc.code) from exc
                # ensure modes
                for name in (MANIFEST_NAME, POOL_NAME, "checksums.sha256"):
                    p = dataset_dir / name
                    try:
                        p.chmod(0o600)
                    except OSError as exc:
                        raise StoreError("store_chmod_failed") from exc
                try:
                    dataset_dir.chmod(0o700)
                except OSError as exc:
                    raise StoreError("store_chmod_failed") from exc
                return dataset_dir
        except FilesystemError as exc:
            raise StoreError(exc.code) from exc

    def publish_capability_seal(
        self,
        *,
        dataset_id: str,
        seal: Mapping[str, Any],
    ) -> Path:
        dataset_dir = self._dataset_dir(dataset_id)
        if not dataset_dir.is_dir():
            raise StoreError("store_dataset_not_found")
        seal_bytes = _canonical(dict(seal))
        target = dataset_dir / CAPABILITY_SEAL_NAME
        try:
            with fenced_lock(self.root):
                if target.exists():
                    existing = bounded_read(target)
                    if existing == seal_bytes:
                        return target
                    raise StoreError("store_capability_conflict")
                try:
                    write_no_replace(target, seal_bytes)
                except FilesystemError as exc:
                    raise StoreError(exc.code) from exc
                try:
                    target.chmod(0o600)
                except OSError as exc:
                    raise StoreError("store_chmod_failed") from exc
                return target
        except FilesystemError as exc:
            raise StoreError(exc.code) from exc

    def verify(self, dataset_id: str) -> bool:
        dataset_dir = self._dataset_dir(dataset_id)
        try:
            if not dataset_dir.is_dir() or dataset_dir.is_symlink():
                return False
            for name in (MANIFEST_NAME, POOL_NAME, "checksums.sha256"):
                p = dataset_dir / name
                if not p.is_file() or p.is_symlink():
                    return False
                if p.stat().st_mode & 0o777 != 0o600:
                    return False
            if dataset_dir.stat().st_mode & 0o777 != 0o700:
                return False
            manifest = bounded_read(dataset_dir / MANIFEST_NAME)
            pool = bounded_read(dataset_dir / POOL_NAME)
            checksums = bounded_read(dataset_dir / "checksums.sha256")
            expected = _canonical(
                {
                    "dataset_id": dataset_id,
                    "manifest_sha256": sha256_bytes(manifest),
                    "pool_sha256": sha256_bytes(pool),
                }
            )
            if checksums != expected:
                return False
            # also verify capability seal if present is well-formed json
            cap = dataset_dir / CAPABILITY_SEAL_NAME
            if cap.exists():
                if cap.is_symlink() or not cap.is_file():
                    return False
                raw = bounded_read(cap)
                try:
                    json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeError):
                    return False
            return True
        except (OSError, FilesystemError, ValueError):
            return False

    def read_manifest(self, dataset_id: str) -> dict[str, Any]:
        dataset_dir = self._dataset_dir(dataset_id)
        data = bounded_read(dataset_dir / MANIFEST_NAME)
        try:
            val = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeError) as exc:
            raise StoreError("store_manifest_invalid") from exc
        if not isinstance(val, dict):
            raise StoreError("store_manifest_invalid")
        return val

    def capability_sealed(self, dataset_id: str) -> bool:
        dataset_dir = self._dataset_dir(dataset_id)
        cap = dataset_dir / CAPABILITY_SEAL_NAME
        return cap.is_file() and not cap.is_symlink() and self.verify(dataset_id)


__all__ = ["FreshAcquisitionStore", "StoreError"]
