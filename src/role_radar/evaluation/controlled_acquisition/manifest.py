"""Private manifest and independently allowlisted operator projection."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from role_radar.evaluation.controlled_acquisition.protocols import (
    EXTERNAL_MANIFEST_FIELDS,
    PROTOCOL_VERSION,
)


def private_manifest(**values: Any) -> dict[str, Any]:
    return {"schema_version": 1, "protocol_version": PROTOCOL_VERSION, **values}


def sanitized_manifest(values: Mapping[str, Any]) -> dict[str, Any]:
    """Project only aggregate/operator identity fields; never recursively copy."""
    output = {key: values[key] for key in EXTERNAL_MANIFEST_FIELDS if key in values}
    output.setdefault("schema_version", 1)
    output.setdefault("protocol_version", PROTOCOL_VERSION)
    return output
