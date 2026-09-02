"""In-memory synthetic Gate F publication verifier for R3 Gate A."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

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


@dataclass(frozen=True, slots=True)
class SyntheticGateFPublication:
    binding: R2GateFBinding
    receipt: Mapping[str, Any]
    manifest: Mapping[str, Any]
    checksums: Mapping[str, str]
    capability: Mapping[str, Any]
    pilot_view: tuple[Mapping[str, Any], ...]


def _block() -> None:
    raise R3AuthorizationError(R3BlockCode.BINDING_INVALID)


def adapt_pilot_view(
    publication: SyntheticGateFPublication, binding: R2GateFBinding
) -> PilotSnapshot:
    """Verify and project only the canonical display-safe pilot view."""
    try:
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
            publication.checksums.get("manifest")
            != hashlib.sha256(_canonical(publication.manifest)).hexdigest()
        ):
            _block()
        if (
            publication.checksums.get("pilot_view")
            != hashlib.sha256(_canonical(publication.pilot_view)).hexdigest()
        ):
            _block()
        if (
            publication.capability.get("seal_sha256") != binding.capability_seal_sha256
            or publication.capability.get("dataset_id") != binding.dataset_id
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
