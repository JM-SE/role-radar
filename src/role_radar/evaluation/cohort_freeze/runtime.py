"""Orchestration only for status, preview, freeze and verify."""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Mapping
from dataclasses import replace
from typing import Any, Protocol

from role_radar.evaluation.cohort_freeze.contracts import (
    DeploymentIdentity,
    FrozenBundle,
    PreviewResult,
    RepositorySnapshot,
)
from role_radar.evaluation.cohort_freeze.manifest import (
    build_external_manifest,
    validate_external_manifest,
)
from role_radar.evaluation.cohort_freeze.materialization import _blind_key, _opaque_id, materialize
from role_radar.evaluation.cohort_freeze.policy import (
    ALEMBIC_HEAD,
    BASELINE_PROFILE_ID,
    BASELINE_PROFILE_SCHEMA,
    BASELINE_PROFILE_SHA256,
    BASELINE_PROFILE_VERSION,
    EXTERNAL_MANIFEST_SCHEMA,
    MATERIALIZATION_PROTOCOL,
    PREVIEW_SCHEMA,
    SELECTION_PROTOCOL,
    TARGET_COUNT,
    acknowledgement,
    canonical_hash,
    profile_sha256,
)
from role_radar.evaluation.cohort_freeze.selection import select_candidates
from role_radar.evaluation.snapshot_store import SnapshotStore, canonical_line, sha256_bytes

ACK_PATTERN = re.compile(
    rf"FREEZE F10\.1C preview_sha256=([0-9a-f]{{64}}) profile_sha256={BASELINE_PROFILE_SHA256} "
    rf"protocol={SELECTION_PROTOCOL} count={TARGET_COUNT}\Z",
    re.ASCII,
)


class SnapshotRepository(Protocol):
    def load(self) -> RepositorySnapshot: ...


class RuntimeErrorCode(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _profile_identity(snapshot: RepositorySnapshot) -> dict[str, Any]:
    profile = snapshot.profile
    return {
        "id": profile.get("id"),
        "version": profile.get("version"),
        "schema": profile.get("schema_version"),
        "sha256": profile.get("sha256") or profile_sha256(profile.get("profile_json", {})),
    }


def _public_preview(snapshot: RepositorySnapshot, selection: Any) -> dict[str, Any]:
    profile = _profile_identity(snapshot)
    rejection = dict(selection.rejection_counts)
    for key, value in selection.ignored_link_counts.items():
        rejection[key] = rejection.get(key, 0) + value
    return {
        "schema_version": PREVIEW_SCHEMA,
        "status": selection.status.value,
        "eligible_count": selection.eligible_count,
        "selected_count": selection.selected_count,
        "rejection_counts": dict(sorted(rejection.items())),
        "boundary_run_id": snapshot.boundary.run_id,
        "boundary_inclusive": snapshot.boundary.inclusive,
        "profile_id": profile["id"],
        "profile_version": profile["version"],
        "profile_schema": profile["schema"],
        "profile_sha256": profile["sha256"],
        "selection_protocol": SELECTION_PROTOCOL,
        "materialization_protocol": MATERIALIZATION_PROTOCOL,
        "candidate_cohort_sha256": selection.candidate_cohort_sha256,
        **({"selection_sha256": selection.selection_sha256} if selection.selection_sha256 else {}),
    }


class CohortFreezeRuntime:
    def __init__(
        self,
        repository: SnapshotRepository,
        store: SnapshotStore,
        *,
        deployment: DeploymentIdentity | None = None,
    ) -> None:
        self.repository = repository
        self.store = store
        self.deployment = deployment or DeploymentIdentity()

    def _preview(self) -> PreviewResult:
        snapshot = self.repository.load()
        selection = select_candidates(snapshot.candidates)
        payload = _public_preview(snapshot, selection)
        hash_input = {
            "schema_version": PREVIEW_SCHEMA,
            "selection_protocol": SELECTION_PROTOCOL,
            "materialization_protocol": MATERIALIZATION_PROTOCOL,
            "boundary": {
                "run_id": snapshot.boundary.run_id,
                "started_at_utc": snapshot.boundary.started_at_utc,
                "inclusive": snapshot.boundary.inclusive,
            },
            "deployment": {
                "code_commit": self.deployment.code_commit,
                "clean": self.deployment.clean,
                "alembic_head": snapshot.alembic_version,
            },
            "profile": _profile_identity(snapshot),
            "snapshot_fingerprint": snapshot.fingerprint,
            "candidate_cohort_sha256": selection.candidate_cohort_sha256,
            "counts": {
                "eligible": selection.eligible_count,
                "selected": selection.selected_count,
                "rejection": dict(sorted(selection.rejection_counts.items())),
                "ignored": dict(sorted(selection.ignored_link_counts.items())),
            },
            "selection_sha256": selection.selection_sha256,
            "item_semantic_sha256": selection.item_semantic_sha256,
        }
        preview_hash = canonical_hash(hash_input)
        return PreviewResult(
            payload={**payload, "preview_sha256": preview_hash},
            preview_sha256=preview_hash,
            selection=selection,
            snapshot=snapshot,
        )

    def status(self) -> PreviewResult:
        result = self._preview()
        payload = {
            key: value
            for key, value in result.payload.items()
            if key not in {"selection_sha256", "preview_sha256"}
        }
        return replace(result, payload=payload)

    def preview(self) -> PreviewResult:
        return self._preview()

    @staticmethod
    def _parse_acknowledgement(value: str) -> str:
        match = ACK_PATTERN.fullmatch(value)
        if match is None or not value.isascii():
            raise RuntimeErrorCode("acknowledgement_mismatch")
        return match.group(1)

    def freeze(self, supplied_acknowledgement: str) -> FrozenBundle:
        preview = self._preview()
        supplied_preview = self._parse_acknowledgement(supplied_acknowledgement)
        if not secrets.compare_digest(supplied_preview, preview.preview_sha256 or ""):
            raise RuntimeErrorCode("stale_preview")
        if preview.selection.selected_count != TARGET_COUNT:
            raise RuntimeErrorCode("cohort_waiting")
        profile = _profile_identity(preview.snapshot)
        if (
            profile["id"] != BASELINE_PROFILE_ID
            or profile["version"] != BASELINE_PROFILE_VERSION
            or profile["schema"] != BASELINE_PROFILE_SCHEMA
            or profile["sha256"] != BASELINE_PROFILE_SHA256
        ):
            raise RuntimeErrorCode("profile_baseline_mismatch")
        if preview.snapshot.alembic_version != ALEMBIC_HEAD:
            raise RuntimeErrorCode("alembic_head_mismatch")
        if not self.deployment.clean or self.deployment.code_commit == "unknown":
            raise RuntimeErrorCode("deployment_not_clean")
        dataset_lines, provenance_lines, label_lines, internal, dataset_id = materialize(
            preview.snapshot,
            preview.selection,
            deployment=replace(self.deployment, alembic_head=preview.snapshot.alembic_version),
        )
        target = self.store.root / dataset_id
        if target.exists() or target.is_symlink():
            if not self.store.verify(dataset_id):
                raise RuntimeErrorCode("snapshot_id_conflict")
            try:
                existing = json.loads(
                    (target / "internal-manifest.json").read_text(encoding="utf-8")
                )
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise RuntimeErrorCode("snapshot_id_conflict") from exc
            if existing.get("dataset_id") != dataset_id:
                raise RuntimeErrorCode("snapshot_id_conflict")
            internal = existing
        else:
            target = self.store.publish(
                dataset_id=dataset_id,
                dataset_lines=dataset_lines,
                provenance_lines=provenance_lines,
                label_lines=label_lines,
                internal=internal,
            )
        if not self.store.verify(dataset_id):
            raise RuntimeErrorCode("snapshot_verification_failed")
        external = build_external_manifest(internal)
        validate_external_manifest(external)
        return FrozenBundle(
            dataset_id=dataset_id,
            path=str(target),
            internal_manifest=internal,
            external_manifest=external,
            dataset_sha256=internal["dataset_sha256"],
            provenance_sha256=internal["provenance_sha256"],
            label_view_sha256=internal["label_view_sha256"],
        )

    def verify(self, dataset_id: str) -> Mapping[str, Any]:
        if not self.store.verify(dataset_id):
            raise RuntimeErrorCode("snapshot_verification_failed")
        target = self.store.root / dataset_id
        try:
            internal = json.loads((target / "internal-manifest.json").read_text(encoding="utf-8"))
            external = build_external_manifest(internal)
            validate_external_manifest(external)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeErrorCode("snapshot_manifest_invalid") from exc
        if internal.get("dataset_id") != dataset_id or internal.get("count") != TARGET_COUNT:
            raise RuntimeErrorCode("snapshot_dataset_id_invalid")
        try:
            dataset_lines = (target / "dataset.jsonl").read_bytes().splitlines()
            provenance_lines = (target / "provenance.jsonl").read_bytes().splitlines()
            label_lines = (target / "label-view.jsonl").read_bytes().splitlines()
            if not all(
                len(lines) == TARGET_COUNT
                for lines in (dataset_lines, provenance_lines, label_lines)
            ):
                raise RuntimeErrorCode("snapshot_cardinality_invalid")
            if internal.get("dataset_sha256") != sha256_bytes(
                (target / "dataset.jsonl").read_bytes()
            ):
                raise RuntimeErrorCode("snapshot_hash_invalid")
            if internal.get("provenance_sha256") != sha256_bytes(
                (target / "provenance.jsonl").read_bytes()
            ):
                raise RuntimeErrorCode("snapshot_hash_invalid")
            if internal.get("label_view_sha256") != sha256_bytes(
                (target / "label-view.jsonl").read_bytes()
            ):
                raise RuntimeErrorCode("snapshot_hash_invalid")
            preimage = internal.get("preimage")
            expected_id = sha256_bytes(b"f10.1c:dataset-id-v1\0" + canonical_line(preimage))
            if expected_id != dataset_id:
                raise RuntimeErrorCode("snapshot_dataset_id_invalid")
            item_hashes = internal.get("item_semantic_sha256")
            if not isinstance(item_hashes, list) or len(item_hashes) != TARGET_COUNT:
                raise RuntimeErrorCode("snapshot_items_invalid")
            opaque_ids = [item.get("opaque_id") for item in item_hashes]
            if len(set(opaque_ids)) != TARGET_COUNT:
                raise RuntimeErrorCode("opaque_id_collision")
            if any(
                _opaque_id(dataset_id, item.get("sha256")) != item.get("opaque_id")
                for item in item_hashes
            ):
                raise RuntimeErrorCode("opaque_id_invalid")
            dataset_records = [json.loads(line) for line in dataset_lines]
            provenance_records = [json.loads(line) for line in provenance_lines]
            label_records = [json.loads(line) for line in label_lines]
            if [item.get("opaque_id") for item in dataset_records] != opaque_ids:
                raise RuntimeErrorCode("snapshot_order_invalid")
            if {item.get("opaque_id") for item in label_records} != set(opaque_ids):
                raise RuntimeErrorCode("label_view_invalid")
            if [item.get("opaque_id") for item in provenance_records] != opaque_ids:
                raise RuntimeErrorCode("provenance_order_invalid")
            if [item.get("opaque_id") for item in label_records] != sorted(
                opaque_ids, key=lambda item: _blind_key(dataset_id, item)
            ):
                raise RuntimeErrorCode("blind_order_invalid")
        except RuntimeErrorCode:
            raise
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeErrorCode("snapshot_content_invalid") from exc
        return {"schema_version": EXTERNAL_MANIFEST_SCHEMA, **external}


Runtime = CohortFreezeRuntime

__all__ = ["CohortFreezeRuntime", "Runtime", "RuntimeErrorCode", "acknowledgement"]
