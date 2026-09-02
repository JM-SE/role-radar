"""In-memory synthetic Gate F publication verifier for R3 Gate A."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, NoReturn

from role_radar.evaluation.blind_labeling.contracts import PilotItem, PilotSnapshot
from role_radar.evaluation.r3_labeling_authorization import (
    R2GateFBinding,
    R3AuthorizationError,
    R3BlockCode,
)

ALLOWED_DISPLAY_FIELDS: Final[tuple[str, ...]] = (
    "opaque_id",
    "title",
    "company",
    "location",
    "description",
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _domain_hash(domain: str, value: bytes) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\x00" + value).hexdigest()


@dataclass(frozen=True, slots=True)
class SyntheticGateFPublication:
    binding: R2GateFBinding
    receipt: Mapping[str, Any]
    manifest: Mapping[str, Any]
    checksums: Mapping[str, str]
    capability: Mapping[str, Any]
    pilot_view: tuple[Mapping[str, Any], ...]
    receipt_bytes: bytes = b""
    sealed_pool_manifest_bytes: bytes = b""
    dataset_manifest_bytes: bytes = b""
    checksums_bytes: bytes = b""
    pilot_view_jsonl: bytes = b""
    capability_seal_bytes: tuple[bytes, ...] = ()


def _block() -> NoReturn:
    raise R3AuthorizationError(R3BlockCode.BINDING_INVALID)


def adapt_pilot_view(
    publication: SyntheticGateFPublication, binding: R2GateFBinding
) -> PilotSnapshot:
    """Verify and project only the canonical display-safe pilot view."""
    try:
        if not all(
            isinstance(value, bytes) and value
            for value in (
                publication.receipt_bytes,
                publication.sealed_pool_manifest_bytes,
                publication.dataset_manifest_bytes,
                publication.checksums_bytes,
                publication.pilot_view_jsonl,
            )
        ):
            _block()
        if publication.binding != binding:
            _block()
        if set(publication.receipt) != {"receipt_sha256", "manifest_sha256", "dataset_id"}:
            _block()
        if publication.receipt != {
            "receipt_sha256": binding.receipt_sha256,
            "manifest_sha256": binding.manifest_sha256,
            "dataset_id": binding.dataset_id,
        }:
            _block()
        receipt_preimage = {
            key: value for key, value in publication.receipt.items() if key != "receipt_sha256"
        }
        if (
            _canonical(receipt_preimage) != publication.receipt_bytes
            or _domain_hash("role-radar:f10.1f:freeze-receipt:v1", publication.receipt_bytes)
            != binding.receipt_sha256
        ):
            _block()
        manifest_fields = {
            "dataset_id",
            "pilot_sha256",
            "pilot_view_sha256",
            "count",
            "profile_id",
            "profile_sha256",
            "rubric_version",
            "protocol_version",
            "destination",
        }
        if set(publication.manifest) != manifest_fields:
            _block()
        expected_manifest = {
            "dataset_id": binding.dataset_id,
            "pilot_sha256": binding.pilot_sha256,
            "pilot_view_sha256": binding.pilot_view_sha256,
            "count": binding.count,
            "profile_id": binding.profile_id,
            "profile_sha256": binding.profile_sha256,
            "rubric_version": binding.rubric_version,
            "protocol_version": binding.protocol_version,
            "destination": binding.destination,
        }
        if dict(publication.manifest) != expected_manifest:
            _block()
        if (
            _canonical(publication.manifest) != publication.sealed_pool_manifest_bytes
            or _domain_hash(
                "role-radar:f10.1f:sealed-pool-manifest:v1",
                publication.sealed_pool_manifest_bytes,
            )
            != binding.manifest_sha256
        ):
            _block()
        dataset_manifest = json.loads(publication.dataset_manifest_bytes.decode("utf-8"))
        if (
            not isinstance(dataset_manifest, dict)
            or set(dataset_manifest)
            != {
                "dataset_id",
                "sealed_pool_manifest_sha256",
                "pilot_group_sha256",
                "pilot_view_sha256",
            }
            or dataset_manifest
            != {
                "dataset_id": binding.dataset_id,
                "sealed_pool_manifest_sha256": binding.manifest_sha256,
                "pilot_group_sha256": binding.pilot_group_sha256,
                "pilot_view_sha256": binding.pilot_view_sha256,
            }
            or _canonical(dataset_manifest) != publication.dataset_manifest_bytes
        ):
            _block()
        checksums = json.loads(publication.checksums_bytes.decode("utf-8"))
        if (
            not isinstance(checksums, dict)
            or set(checksums) != {"manifest", "dataset_manifest", "pilot_group", "pilot_view"}
            or checksums != dict(publication.checksums)
            or _canonical(checksums) != publication.checksums_bytes
        ):
            _block()
        if (
            checksums["manifest"]
            != hashlib.sha256(publication.sealed_pool_manifest_bytes).hexdigest()
            or checksums["dataset_manifest"]
            != hashlib.sha256(publication.dataset_manifest_bytes).hexdigest()
            or checksums["pilot_group"] != binding.pilot_group_sha256
            or checksums["pilot_view"] != binding.pilot_view_sha256
        ):
            _block()
        if not publication.capability_seal_bytes or not binding.capability_seal_hashes:
            _block()
        capability_hashes = binding.capability_seal_hashes
        if len(publication.capability_seal_bytes) != len(capability_hashes):
            _block()
        expected_kinds = ("private", "pilot", "sealed_holdout")
        if len(publication.capability_seal_bytes) != len(expected_kinds):
            _block()
        for raw, expected_hash in zip(
            publication.capability_seal_bytes,
            capability_hashes,
            strict=True,
        ):
            seal = json.loads(raw.decode("utf-8"))
            if (
                not isinstance(seal, dict)
                or set(seal)
                != {
                    "dataset_id",
                    "namespace",
                    "kind",
                    "payloads_sha256",
                    "artifact_count",
                    "seal_sha256",
                }
                or _canonical(seal) != raw
                or seal["dataset_id"] != binding.dataset_id
                or seal["kind"] != expected_kinds[publication.capability_seal_bytes.index(raw)]
            ):
                _block()
            if (
                binding.capability_artifact_counts is not None
                and seal["artifact_count"]
                != binding.capability_artifact_counts[publication.capability_seal_bytes.index(raw)]
            ):
                _block()
            seal_preimage = {key: value for key, value in seal.items() if key != "seal_sha256"}
            if (
                seal["seal_sha256"] != expected_hash
                or _domain_hash("role-radar:f10.1f:capability-seal:v1", _canonical(seal_preimage))
                != expected_hash
            ):
                _block()
        if (
            publication.pilot_view_jsonl
            != b"".join(_canonical(record) + b"\n" for record in publication.pilot_view)
            or hashlib.sha256(publication.pilot_view_jsonl).hexdigest() != binding.pilot_view_sha256
            or hashlib.sha256(publication.pilot_view_jsonl).hexdigest()
            != binding.pilot_group_sha256
        ):
            _block()
        if len(publication.pilot_view) != binding.count:
            _block()
        items: list[PilotItem] = []
        for record in publication.pilot_view:
            if tuple(record) != ALLOWED_DISPLAY_FIELDS:
                _block()
            if any(
                not isinstance(record[key], str)
                for key in ("opaque_id", "title", "company", "description")
            ):
                _block()
            location = record["location"]
            if location is not None and not isinstance(location, str):
                _block()
            items.append(
                PilotItem(
                    record["opaque_id"],
                    record["title"],
                    record["company"],
                    location,
                    record["description"],
                )
            )
        ids = tuple(item.opaque_id for item in items)
        if ids != tuple(sorted(ids)) or len(set(ids)) != binding.count:
            _block()
        return PilotSnapshot(
            tuple(items), binding.dataset_id, binding.pilot_sha256, binding.pilot_view_sha256
        )
    except R3AuthorizationError:
        raise
    except (KeyError, TypeError, ValueError):
        raise R3AuthorizationError(R3BlockCode.BINDING_INVALID) from None


__all__ = ["ALLOWED_DISPLAY_FIELDS", "SyntheticGateFPublication", "adapt_pilot_view"]
