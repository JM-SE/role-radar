"""Allowlist-only external projection for F10.1C bundles."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from role_radar.evaluation.cohort_freeze.policy import (
    EXTERNAL_MANIFEST_SCHEMA,
    MATERIALIZATION_PROTOCOL,
    PREVIEW_SCHEMA,
    SELECTION_PROTOCOL,
    SNAPSHOT_SCHEMA,
)


def build_external_manifest(internal: Mapping[str, Any]) -> dict[str, Any]:
    profile = internal.get("profile", {})
    deployment = internal.get("deployment", {})
    aggregates = internal.get("aggregates", {})
    return {
        "schema_version": EXTERNAL_MANIFEST_SCHEMA,
        "status": "frozen",
        "dataset_id": internal.get("dataset_id"),
        "count": 50,
        "aggregates": {
            "source_types": dict(aggregates.get("source_types", {})),
            "run_count": aggregates.get("run_count"),
            "observation_date_utc": aggregates.get("observation_date_utc"),
        },
        "hashes": {
            "dataset_sha256": internal.get("dataset_sha256"),
            "provenance_sha256": internal.get("provenance_sha256"),
            "label_view_sha256": internal.get("label_view_sha256"),
            "semantic_root_sha256": internal.get("semantic_root_sha256"),
        },
        "profile": {key: profile.get(key) for key in ("id", "version", "schema", "sha256")},
        "protocol": {
            "selection": internal.get("selection_protocol", SELECTION_PROTOCOL),
            "materialization": internal.get("materialization_protocol", MATERIALIZATION_PROTOCOL),
            "snapshot_schema": internal.get("schema_version", SNAPSHOT_SCHEMA),
            "preview_schema": PREVIEW_SCHEMA,
        },
        "deployment": {
            "code_commit": deployment.get("code_commit"),
            "alembic_head": deployment.get("alembic_head"),
        },
        "frozen_at": internal.get("frozen_at"),
    }


def validate_external_manifest(manifest: Mapping[str, Any]) -> None:
    allowed = {
        "schema_version",
        "status",
        "dataset_id",
        "count",
        "aggregates",
        "hashes",
        "profile",
        "protocol",
        "deployment",
        "frozen_at",
    }
    if (
        set(manifest) != allowed
        or manifest.get("status") != "frozen"
        or manifest.get("count") != 50
    ):
        raise ValueError("external_manifest_allowlist_violation")
    forbidden_fragments = (
        "title",
        "company",
        "description",
        "url",
        "query",
        "secret",
        "hostname",
        "path",
        "job_id",
        "link_id",
        "run_id",
        "operation_id",
        "source_key",
        "opaque_id",
    )

    def walk(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                lowered = str(key).lower()
                if any(fragment in lowered for fragment in forbidden_fragments):
                    raise ValueError("external_manifest_allowlist_violation")
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
        elif isinstance(value, str) and any(
            fragment in value.lower() for fragment in ("password=", "token=")
        ):
            raise ValueError("external_manifest_secret")

    walk(manifest)


sanitized_manifest = build_external_manifest

__all__ = ["build_external_manifest", "sanitized_manifest", "validate_external_manifest"]
