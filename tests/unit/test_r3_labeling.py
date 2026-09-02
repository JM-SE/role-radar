import hashlib
import json
from pathlib import Path

import pytest

from role_radar.evaluation.blind_labeling.contracts import Decision, Label
from role_radar.evaluation.blind_labeling.materialization import rubric_hash
from role_radar.evaluation.r3_labeling_authorization import (
    R2GateFBinding,
    R3Authorization,
    R3AuthorizationError,
    R3BlockCode,
    R3Operation,
)
from role_radar.evaluation.r3_labeling_input_adapter import SyntheticGateFPublication
from role_radar.evaluation.r3_labeling_service import R3LabelingService


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _fixture() -> tuple[R2GateFBinding, SyntheticGateFPublication]:
    dataset_id = "c" * 64
    view = tuple(
        {
            "opaque_id": f"{index:024x}",
            "title": "title",
            "company": "company",
            "location": None,
            "description": "description",
        }
        for index in range(2)
    )
    jsonl = b"".join(_canonical(record) + b"\n" for record in view)
    pilot_view_sha256 = hashlib.sha256(jsonl).hexdigest()
    pilot_group_sha256 = pilot_view_sha256
    manifest = {
        "dataset_id": dataset_id,
        "pilot_sha256": "d" * 64,
        "pilot_view_sha256": pilot_view_sha256,
        "count": 2,
        "profile_id": "synthetic-profile",
        "profile_sha256": "f" * 64,
        "rubric_version": "synthetic-rubric",
        "protocol_version": "synthetic-protocol",
        "destination": "synthetic://r2-gate-f/pilot",
    }
    manifest_bytes = _canonical(manifest)
    manifest_sha256 = hashlib.sha256(
        b"role-radar:f10.1f:sealed-pool-manifest:v1\x00" + manifest_bytes
    ).hexdigest()
    receipt = {"receipt_sha256": "", "manifest_sha256": manifest_sha256, "dataset_id": dataset_id}
    receipt_bytes = _canonical(
        {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    )
    receipt_sha256 = hashlib.sha256(
        b"role-radar:f10.1f:freeze-receipt:v1\x00" + receipt_bytes
    ).hexdigest()
    seals: list[bytes] = []
    seal_hashes: list[str] = []
    for kind in ("private", "pilot", "sealed_holdout"):
        preimage = {
            "dataset_id": dataset_id,
            "namespace": "synthetic://r2-gate-f/pilot",
            "kind": kind,
            "payloads_sha256": hashlib.sha256(kind.encode()).hexdigest(),
            "artifact_count": 1,
        }
        digest = hashlib.sha256(
            b"role-radar:f10.1f:capability-seal:v1\x00" + _canonical(preimage)
        ).hexdigest()
        seals.append(_canonical(preimage | {"seal_sha256": digest}))
        seal_hashes.append(digest)
    dataset_manifest = {
        "dataset_id": dataset_id,
        "sealed_pool_manifest_sha256": manifest_sha256,
        "pilot_group_sha256": pilot_group_sha256,
        "pilot_view_sha256": pilot_view_sha256,
    }
    dataset_bytes = _canonical(dataset_manifest)
    checksums = {
        "manifest": hashlib.sha256(manifest_bytes).hexdigest(),
        "dataset_manifest": hashlib.sha256(dataset_bytes).hexdigest(),
        "pilot_group": pilot_group_sha256,
        "pilot_view": pilot_view_sha256,
    }
    binding = R2GateFBinding(
        receipt_sha256,
        manifest_sha256,
        dataset_id,
        manifest["pilot_sha256"],
        pilot_view_sha256,
        "synthetic-profile",
        1,
        1,
        "f" * 64,
        "synthetic-rubric",
        "synthetic-protocol",
        2,
        "synthetic://r2-gate-f/pilot",
        "1" * 64,
        "2" * 64,
        "3" * 64,
        rubric_hash(version="synthetic-rubric", protocol="synthetic-protocol"),
        "4" * 64,
        "5" * 64,
        "synthetic://r2-gate-f/pilot",
        tuple(seal_hashes),
        (1, 1, 1),
        pilot_group_sha256,
    )
    return binding, SyntheticGateFPublication(
        binding,
        {
            "receipt_sha256": binding.receipt_sha256,
            "manifest_sha256": binding.manifest_sha256,
            "dataset_id": binding.dataset_id,
        },
        manifest,
        {
            **checksums,
        },
        {"dataset_id": binding.dataset_id, "seal_sha256": binding.capability_seal_sha256},
        view,
        receipt_bytes,
        manifest_bytes,
        dataset_bytes,
        _canonical(checksums),
        jsonl,
        tuple(seals),
    )


def test_real_operation_is_blocked_before_runtime(tmp_path: Path) -> None:
    binding, publication = _fixture()
    with pytest.raises(R3AuthorizationError) as error:
        R3LabelingService(R3Authorization(R3Operation.REAL, binding), publication, root=tmp_path)
    assert error.value.code == R3BlockCode.AUTHORIZATION_REQUIRED.value
    assert not list(tmp_path.iterdir())


def test_synthetic_service_reuses_one_full_workflow_and_is_idempotent(tmp_path: Path) -> None:
    binding, publication = _fixture()
    service = R3LabelingService(
        R3Authorization(R3Operation.SYNTHETIC_OFFLINE, binding, synthetic_fixture=True),
        publication,
        root=tmp_path,
    )
    assert service.start() == {"status": "labeling", "dataset_id": binding.dataset_id, "count": 2}
    for record in publication.pilot_view:
        service.save_first_pass(record["opaque_id"], Decision(Label.MAYBE, "role_scope_unclear"))
    service.begin_review()
    service.save_review(
        publication.pilot_view[0]["opaque_id"], Decision(Label.REJECT, "role_mismatch")
    )
    service.save_review(
        publication.pilot_view[1]["opaque_id"], Decision(Label.MAYBE, "role_scope_unclear")
    )
    service.adjudicate(
        publication.pilot_view[0]["opaque_id"], Decision(Label.MAYBE, "role_scope_unclear")
    )
    assert service.preview_finalize()["count"] == binding.count
    first = service.finalize()
    assert service.finalize() == first
    assert set(first) == {"status", "labelset_id", "count"}
