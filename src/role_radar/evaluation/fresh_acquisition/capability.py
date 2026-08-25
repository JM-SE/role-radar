"""Capability seal for F10.1F — sole capability sealing/verification adapter.

Seals the private, pilot, and sealed-holdout capability destinations under the
new private root through the one domain-neutral filesystem primitive owner
(no-replace, fsync, no-follow, fence). Performs no payload or domain selection:
it binds only dataset identity, namespace/root, capability kind, and the
already-computed payload-group checksum supplied by the freeze transaction.

Post-publication capability verification re-reads the sealed descriptors with
bounded no-follow reads, rebuilds the canonical bytes, recomputes the domain
hash, and fails closed on any drift, unknown field, or noncanonical form.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from role_radar.evaluation.fresh_acquisition.filesystem import (
    FilesystemError,
    bounded_read,
    fenced_lock,
    resolve_nofollow,
    write_no_replace,
)

CAPABILITY_SCHEMA_VERSION: Final[str] = "f10.1f-capability-seal-v1"
DOMAIN_CAPABILITY_SEAL: Final[str] = "role-radar:f10.1f:capability-seal:v1"
CAPABILITIES_DIRNAME: Final[str] = "capabilities"

KIND_PRIVATE: Final[str] = "private"
KIND_PILOT: Final[str] = "pilot"
KIND_SEALED_HOLDOUT: Final[str] = "sealed_holdout"
VALID_KINDS: Final[tuple[str, ...]] = (KIND_PRIVATE, KIND_PILOT, KIND_SEALED_HOLDOUT)

MIN_ARTIFACT_COUNT: Final[int] = 1
MAX_ARTIFACT_COUNT: Final[int] = 64
MAX_NAMESPACE_LENGTH: Final[int] = 128
MAX_ROOT_LENGTH: Final[int] = 512

_SEAL_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "artifact_count",
        "dataset_id",
        "domain",
        "kind",
        "namespace",
        "payloads_sha256",
        "root",
        "schema_version",
        "seal_sha256",
    }
)


class CapabilityError(ValueError):
    def __init__(self, code: str) -> None:
        self.code: str = code
        super().__init__(code)


def _require_hex64(value: str, code: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise CapabilityError(code)
    if any(c not in "0123456789abcdef" for c in value):
        raise CapabilityError(code)


def _require_kind(kind: str) -> None:
    if not isinstance(kind, str) or kind not in VALID_KINDS:
        raise CapabilityError("capability_kind_invalid")


def _require_namespace(namespace: str) -> None:
    if not isinstance(namespace, str) or not namespace:
        raise CapabilityError("capability_namespace_invalid")
    if len(namespace) > MAX_NAMESPACE_LENGTH or not namespace.isascii():
        raise CapabilityError("capability_namespace_invalid")


def _require_root(root: str) -> None:
    if not isinstance(root, str) or not root.startswith("/"):
        raise CapabilityError("capability_root_invalid")
    if len(root) > MAX_ROOT_LENGTH:
        raise CapabilityError("capability_root_invalid")


def _require_artifact_count(count: int) -> None:
    if not isinstance(count, int) or isinstance(count, bool):
        raise CapabilityError("capability_artifact_count_invalid")
    if count < MIN_ARTIFACT_COUNT or count > MAX_ARTIFACT_COUNT:
        raise CapabilityError("capability_artifact_count_invalid")


def _canonical_bytes(value: Any) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CapabilityError("capability_canonical_invalid") from exc
    return text.encode("utf-8")


def _domain_hash(domain: str, canonical: bytes) -> str:
    if not domain.isascii():
        raise CapabilityError("capability_domain_invalid")
    h = hashlib.sha256()
    h.update(domain.encode("ascii"))
    h.update(b"\x00")
    h.update(canonical)
    return h.hexdigest()


@dataclass(frozen=True, slots=True)
class CapabilitySeal:
    """Immutable capability descriptor bound to one destination and checksum."""

    dataset_id: str
    namespace: str
    root: str
    kind: str
    payloads_sha256: str
    artifact_count: int
    seal_sha256: str
    canonical_bytes: bytes

    def __post_init__(self) -> None:
        _require_hex64(self.dataset_id, "capability_dataset_invalid")
        _require_namespace(self.namespace)
        _require_root(self.root)
        _require_kind(self.kind)
        _require_hex64(self.payloads_sha256, "capability_hash_invalid")
        _require_artifact_count(self.artifact_count)
        _require_hex64(self.seal_sha256, "capability_hash_invalid")
        if not isinstance(self.canonical_bytes, bytes):
            raise CapabilityError("capability_bytes_invalid")


def _seal_preimage(
    *,
    dataset_id: str,
    namespace: str,
    root: str,
    kind: str,
    payloads_sha256: str,
    artifact_count: int,
) -> dict[str, Any]:
    return {
        "artifact_count": artifact_count,
        "dataset_id": dataset_id,
        "domain": DOMAIN_CAPABILITY_SEAL,
        "kind": kind,
        "namespace": namespace,
        "payloads_sha256": payloads_sha256,
        "root": root,
        "schema_version": CAPABILITY_SCHEMA_VERSION,
    }


def build_capability_seal(
    *,
    dataset_id: str,
    namespace: str,
    root: str,
    kind: str,
    payloads_sha256: str,
    artifact_count: int,
) -> CapabilitySeal:
    """Construct and hash one capability descriptor; no IO."""
    _require_hex64(dataset_id, "capability_dataset_invalid")
    _require_namespace(namespace)
    _require_root(root)
    _require_kind(kind)
    _require_hex64(payloads_sha256, "capability_hash_invalid")
    _require_artifact_count(artifact_count)
    preimage = _seal_preimage(
        dataset_id=dataset_id,
        namespace=namespace,
        root=root,
        kind=kind,
        payloads_sha256=payloads_sha256,
        artifact_count=artifact_count,
    )
    canonical = _canonical_bytes(preimage)
    digest = _domain_hash(DOMAIN_CAPABILITY_SEAL, canonical)
    stored: dict[str, Any] = dict(preimage)
    stored["seal_sha256"] = digest
    return CapabilitySeal(
        dataset_id=dataset_id,
        namespace=namespace,
        root=root,
        kind=kind,
        payloads_sha256=payloads_sha256,
        artifact_count=artifact_count,
        seal_sha256=digest,
        canonical_bytes=_canonical_bytes(stored),
    )


def capability_seal_path(root: Path, dataset_id: str, kind: str) -> Path:
    """Validated no-follow path of one capability descriptor under root."""
    _require_hex64(dataset_id, "capability_dataset_invalid")
    _require_kind(kind)
    try:
        return resolve_nofollow(Path(root), dataset_id, CAPABILITIES_DIRNAME, f"{kind}.json")
    except FilesystemError as exc:
        raise CapabilityError(exc.code) from exc


def write_capability_seal(seal: CapabilitySeal) -> Path:
    """No-replace write of one seal; idempotent for identical bytes.

    Caller either holds the freeze fence or accepts standalone sealing via
    :func:`seal_capability`.
    """
    path = capability_seal_path(Path(seal.root), seal.dataset_id, seal.kind)
    try:
        write_no_replace(path, seal.canonical_bytes)
    except FilesystemError as exc:
        raise CapabilityError(exc.code) from exc
    try:
        os.chmod(path, 0o600)
    except OSError as exc:
        raise CapabilityError("capability_chmod_failed") from exc
    return path


def seal_capability(seal: CapabilitySeal) -> Path:
    """Standalone sealing under the root fence."""
    try:
        with fenced_lock(Path(seal.root)):
            return write_capability_seal(seal)
    except FilesystemError as exc:
        raise CapabilityError(exc.code) from exc


def _field_str(obj: Mapping[str, Any], key: str, code: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str):
        raise CapabilityError(code)
    return value


def _field_int(obj: Mapping[str, Any], key: str, code: str) -> int:
    value = obj.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise CapabilityError(code)
    return value


def _load_seal_file(path: Path) -> dict[str, Any]:
    try:
        raw = bounded_read(path)
    except FilesystemError as exc:
        raise CapabilityError(exc.code) from exc
    try:
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise CapabilityError("capability_seal_json_invalid") from exc
    if not isinstance(value, dict):
        raise CapabilityError("capability_seal_json_invalid")
    if set(value.keys()) != set(_SEAL_FIELDS):
        raise CapabilityError("capability_seal_fields_invalid")
    # Noncanonical persisted bytes fail closed.
    if _canonical_bytes(value) != raw:
        raise CapabilityError("capability_seal_noncanonical")
    return value


def verify_capability_seal(
    *,
    root: Path,
    dataset_id: str,
    kind: str,
    expected_payloads_sha256: str,
    expected_artifact_count: int,
    expected_namespace: str,
) -> CapabilitySeal:
    """Post-publication verification of one sealed capability descriptor."""
    _require_hex64(dataset_id, "capability_dataset_invalid")
    _require_kind(kind)
    _require_hex64(expected_payloads_sha256, "capability_hash_invalid")
    _require_artifact_count(expected_artifact_count)
    _require_namespace(expected_namespace)
    path = capability_seal_path(root, dataset_id, kind)
    obj = _load_seal_file(path)
    stored_root = _field_str(obj, "root", "capability_root_invalid")
    _require_root(stored_root)
    stored_domain = _field_str(obj, "domain", "capability_domain_invalid")
    if stored_domain != DOMAIN_CAPABILITY_SEAL:
        raise CapabilityError("capability_domain_mismatch")
    stored_schema = _field_str(obj, "schema_version", "capability_schema_invalid")
    if stored_schema != CAPABILITY_SCHEMA_VERSION:
        raise CapabilityError("capability_schema_mismatch")
    preimage = _seal_preimage(
        dataset_id=_field_str(obj, "dataset_id", "capability_dataset_invalid"),
        namespace=_field_str(obj, "namespace", "capability_namespace_invalid"),
        root=stored_root,
        kind=_field_str(obj, "kind", "capability_kind_invalid"),
        payloads_sha256=_field_str(obj, "payloads_sha256", "capability_hash_invalid"),
        artifact_count=_field_int(obj, "artifact_count", "capability_artifact_count_invalid"),
    )
    recomputed_digest = _domain_hash(DOMAIN_CAPABILITY_SEAL, _canonical_bytes(preimage))
    stored_digest = _field_str(obj, "seal_sha256", "capability_hash_invalid")
    if recomputed_digest != stored_digest:
        raise CapabilityError("capability_seal_hash_mismatch")
    seal = CapabilitySeal(
        dataset_id=preimage["dataset_id"],
        namespace=preimage["namespace"],
        root=stored_root,
        kind=preimage["kind"],
        payloads_sha256=preimage["payloads_sha256"],
        artifact_count=int(preimage["artifact_count"]),
        seal_sha256=stored_digest,
        canonical_bytes=_canonical_bytes(obj),
    )
    if seal.dataset_id != dataset_id:
        raise CapabilityError("capability_dataset_mismatch")
    if seal.kind != kind:
        raise CapabilityError("capability_kind_mismatch")
    if seal.payloads_sha256 != expected_payloads_sha256:
        raise CapabilityError("capability_payload_hash_mismatch")
    if seal.artifact_count != expected_artifact_count:
        raise CapabilityError("capability_artifact_count_mismatch")
    if seal.namespace != expected_namespace:
        raise CapabilityError("capability_namespace_mismatch")
    if seal.root != str(root):
        raise CapabilityError("capability_root_mismatch")
    return seal


def verify_capability_set(
    *,
    root: Path,
    dataset_id: str,
    expected_namespace: str,
    group_payload_hashes: Mapping[str, str],
    group_artifact_counts: Mapping[str, int],
) -> tuple[str, ...]:
    """Verify all three capability kinds; returns the verified kinds in order."""
    verified: list[str] = []
    for kind in VALID_KINDS:
        if kind not in group_payload_hashes or kind not in group_artifact_counts:
            raise CapabilityError("capability_group_missing")
        verify_capability_seal(
            root=root,
            dataset_id=dataset_id,
            kind=kind,
            expected_payloads_sha256=group_payload_hashes[kind],
            expected_artifact_count=group_artifact_counts[kind],
            expected_namespace=expected_namespace,
        )
        verified.append(kind)
    return tuple(verified)


__all__ = [
    "CAPABILITIES_DIRNAME",
    "CAPABILITY_SCHEMA_VERSION",
    "DOMAIN_CAPABILITY_SEAL",
    "KIND_PILOT",
    "KIND_PRIVATE",
    "KIND_SEALED_HOLDOUT",
    "VALID_KINDS",
    "CapabilityError",
    "CapabilitySeal",
    "build_capability_seal",
    "capability_seal_path",
    "seal_capability",
    "verify_capability_seal",
    "verify_capability_set",
    "write_capability_seal",
]
