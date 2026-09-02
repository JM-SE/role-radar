import hashlib
import json
from pathlib import Path

import pytest

from role_radar.evaluation.blind_labeling.contracts import Decision, Label
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
    binding = R2GateFBinding(
        "a" * 64,
        "b" * 64,
        "c" * 64,
        "d" * 64,
        "e" * 64,
        "synthetic-profile",
        1,
        1,
        "f" * 64,
        "synthetic-rubric",
        "synthetic-protocol",
        2,
        "synthetic://r2-gate-f/pilot",
        "1" * 64,
    )
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
    manifest = {
        key: getattr(binding, key)
        for key in (
            "dataset_id",
            "pilot_sha256",
            "pilot_view_sha256",
            "profile_id",
            "profile_sha256",
            "rubric_version",
            "protocol_version",
            "destination",
        )
    } | {"count": 2}
    return binding, SyntheticGateFPublication(
        binding,
        {
            "receipt_sha256": binding.receipt_sha256,
            "manifest_sha256": binding.manifest_sha256,
            "dataset_id": binding.dataset_id,
        },
        manifest,
        {
            "manifest": hashlib.sha256(_canonical(manifest)).hexdigest(),
            "pilot_view": hashlib.sha256(_canonical(view)).hexdigest(),
        },
        {"dataset_id": binding.dataset_id, "seal_sha256": binding.capability_seal_sha256},
        view,
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
    for record in publication.pilot_view:
        service.save_review(record["opaque_id"], Decision(Label.MAYBE, "role_scope_unclear"))
    first = service.finalize()
    assert service.finalize() == first
    assert set(first) == {"status", "labelset_id", "count"}
