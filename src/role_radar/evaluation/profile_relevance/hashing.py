"""Canonical JSON, domain-separated SHA-256, opaque IDs, blind-order keys."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Final

from role_radar.evaluation.profile_relevance.policy import (
    DOMAIN_BLIND_ORDER,
    DOMAIN_DATASET_ID,
    DOMAIN_OPAQUE_ID,
)

_CANONICAL_SEPARATORS: Final = (",", ":")


def _reject_floats(obj: Any) -> None:
    if isinstance(obj, float):
        raise ValueError("floats are forbidden in canonical JSON")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError("non-string map keys are forbidden")
            _reject_floats(v)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _reject_floats(item)


def canonical_json_bytes(value: Any) -> bytes:
    """UTF-8, ensure_ascii=False, key-sorted, compact, reject floats/NaN."""
    # Reject floats early, including NaN/Infinity.
    _reject_floats(value)
    # Disallow NaN/Infinity via json allow_nan=False; also reject duplicate keys
    # is handled by caller providing dicts (Python dicts cannot have duplicates).
    # We explicitly check for float after json dumps would error.
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=_CANONICAL_SEPARATORS,
            allow_nan=False,
        )
    except ValueError as exc:
        # json raises for NaN/Infinity or non-serializable
        raise ValueError("canonical_json_invalid") from exc
    # Reject duplicate keys detection: json.loads with object_pairs_hook would detect,
    # but since we serialize from Python dicts, duplicates are already lost.
    # We enforce by refusing to parse raw strings with duplicates elsewhere.
    # Ensure no floats leaked via int subclass bool check already done.
    # Also reject non-canonical trailing .0 floats represented as ints already fine.
    return text.encode("utf-8")


def domain_hash(domain: str, value: Any) -> str:
    """SHA-256(domain ASCII + NUL + canonical bytes)."""
    if not domain.isascii():
        raise ValueError("domain must be ASCII")
    payload = canonical_json_bytes(value)
    h = hashlib.sha256()
    h.update(domain.encode("ascii"))
    h.update(b"\x00")
    h.update(payload)
    return h.hexdigest()


def domain_hash_bytes(domain: str, canonical_bytes: bytes) -> str:
    """Hash already-canonical bytes under domain."""
    if not domain.isascii():
        raise ValueError("domain must be ASCII")
    h = hashlib.sha256()
    h.update(domain.encode("ascii"))
    h.update(b"\x00")
    h.update(canonical_bytes)
    return h.hexdigest()


def aggregate_root(domain: str, items: tuple[str, ...]) -> str:
    """Sorted aggregate hash for membership roots."""
    sorted_items = tuple(sorted(items))
    return domain_hash(domain, list(sorted_items))


def membership_root(domain: str, pairs: tuple[tuple[str, str], ...]) -> tuple[bytes, str]:
    """Canonical bytes and hash for sorted (semantic, strong) pairs.

    Returns (canonical_bytes_without_LF, hex_hash).
    """
    sorted_pairs = sorted(pairs)
    # Compact JSON array of pairs, no LF.
    canonical = canonical_json_bytes([list(p) for p in sorted_pairs])
    digest = domain_hash_bytes(domain, canonical)
    return canonical, digest


def dataset_id_hash(preimage: Any) -> str:
    """Dataset ID = domain hash over preimage."""
    return domain_hash(DOMAIN_DATASET_ID, preimage)


def opaque_id(dataset_id: str, item_semantic_sha256: str) -> str:
    """First 24 hex of opaque-id domain hash over dataset_id + semantic."""
    # domain ASCII + NUL + canonical bytes of [dataset_id, semantic]
    payload = canonical_json_bytes([dataset_id, item_semantic_sha256])
    full = hashlib.sha256(DOMAIN_OPAQUE_ID.encode("ascii") + b"\x00" + payload).hexdigest()
    return full[:24]


def blind_order_key(domain: str, dataset_id: str, item_semantic_sha256: str, split: str) -> str:
    """Split-specific blind order key under blind-order domain."""
    # Use provided domain or default blind-order domain if generic
    d = domain if domain else DOMAIN_BLIND_ORDER
    payload = canonical_json_bytes([dataset_id, item_semantic_sha256, split])
    return hashlib.sha256(d.encode("ascii") + b"\x00" + payload).hexdigest()


def selection_rank_hash(
    domain: str,
    selection_seed: str,
    source_unit: str,
    stratum: str,
    company_key: str,
    item_semantic_sha256: str,
) -> str:
    """SHA-256 over domain + NUL + seed + NUL + source + NUL + stratum + company + semantic."""
    if not domain.isascii():
        raise ValueError("domain must be ASCII")
    h = hashlib.sha256()
    h.update(domain.encode("ascii"))
    h.update(b"\x00")
    h.update(selection_seed.encode("ascii"))
    h.update(b"\x00")
    h.update(source_unit.encode("utf-8"))
    h.update(b"\x00")
    h.update(stratum.encode("utf-8"))
    h.update(b"\x00")
    h.update(company_key.encode("utf-8"))
    h.update(b"\x00")
    h.update(item_semantic_sha256.encode("ascii"))
    return h.hexdigest()


def partition_rank_hash(
    domain: str,
    partition_seed: str,
    source_unit: str,
    stratum: str,
    item_semantic_sha256: str,
) -> str:
    if not domain.isascii():
        raise ValueError("domain must be ASCII")
    h = hashlib.sha256()
    h.update(domain.encode("ascii"))
    h.update(b"\x00")
    h.update(partition_seed.encode("ascii"))
    h.update(b"\x00")
    h.update(source_unit.encode("utf-8"))
    h.update(b"\x00")
    h.update(stratum.encode("utf-8"))
    h.update(b"\x00")
    h.update(item_semantic_sha256.encode("ascii"))
    return h.hexdigest()


def verify_no_floats(value: Any) -> None:
    _reject_floats(value)
    # also reject NaN as float
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        raise ValueError("non-finite floats forbidden")
