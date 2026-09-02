"""Focused, offline coverage for the authoritative Post-C preregistration seam."""

from __future__ import annotations

import ast
import hashlib
from argparse import Namespace
from dataclasses import fields, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from role_radar.cli import evaluation_f10_1f
from role_radar.evaluation.profile_relevant_acquisition.contracts import SeedInputs
from role_radar.evaluation.profile_relevant_acquisition.gate_c_service import (
    GateCPublicResult,
    GateCResult,
)
from role_radar.evaluation.profile_relevant_acquisition.post_c_preregistration_contracts import (
    PostCPreregistrationError,
    PostCPreregistrationRequest,
    build_seal,
    parse_post_c_preregistration_request,
)
from role_radar.evaluation.profile_relevant_acquisition.post_c_preregistration_service import (
    preregister_post_c,
)
from role_radar.evaluation.profile_relevant_acquisition.source_plan import (
    SourcePlanBudget,
    build_source_plan,
)
from tests.unit.test_gate_c_report_only import _accepted, _authorization, _plan


class MemoryWriter:
    def __init__(self, root: Path) -> None:
        self.approved_root = str(root)
        self.data: dict[str, bytes] = {}
        self.writes = 0
        self.reads = 0

    def write(self, seal: Any) -> None:
        self.writes += 1
        self.data[seal.operation_id] = seal.canonical_bytes

    def read(self, operation_id: str) -> bytes | None:
        self.reads += 1
        return self.data.get(operation_id)


def _request(root: Path) -> PostCPreregistrationRequest:
    plan = _plan()
    accepted = _accepted(root, plan)
    auth = _authorization(root, plan)
    packet = accepted.packet
    source = build_source_plan(
        namespace=packet.namespace,
        root=str(root),
        per_board_cap=auth.per_board_cap,
        per_company_cap=auth.per_company_cap,
        budget=SourcePlanBudget(accepted.packet_sha256, auth.budget_units),
        seed=SeedInputs(packet.selection_seed, packet.partition_seed),
        operation_id=auth.operation_id,
        lineage_id=auth.lineage_id,
        source_configs=(
            {
                "family": "greenhouse",
                "source_key": "greenhouse:acme",
                "configuration_version": 1,
                "configuration": {"board_token": "acme"},
            },
        ),
    )
    report = SimpleNamespace(report_sha256="d" * 64)
    public = GateCPublicResult(
        auth.operation_id,
        plan.plan_sha256,
        source.source_plan_sha256,
        report.report_sha256,
        4,
        1,
        {},
        "within_bound",
        "completed",
        None,
    )
    return PostCPreregistrationRequest(
        operation_id=auth.operation_id,
        lineage_id=auth.lineage_id,
        authorization=auth,
        accepted_gate_b=accepted,
        query_plan=plan,
        gate_c_result=GateCResult(public, source, cast(Any, report)),
        source_plan=source,
        gate_c_report=report,
        provenance=auth.provenance,
        seeds=SeedInputs(packet.selection_seed, packet.partition_seed),
        artifact_class="offline_private_report_only",
        target_corpus_count=packet.corpus_count,
        target_pilot_count=packet.pilot_count,
        target_holdout_count=packet.holdout_count,
    )


def test_valid_injected_flow_is_allowlisted_and_writes_once(tmp_path: Path) -> None:
    writer = MemoryWriter(tmp_path)
    request = _request(tmp_path)
    result = preregister_post_c(request=request, writer=writer)

    assert writer.writes == 1
    assert writer.data[request.operation_id] == build_seal(request).canonical_bytes
    assert set(result.as_dict()) == {
        "operation_id",
        "preregistration_sha256",
        "source_plan_sha256",
        "report_sha256",
        "status",
        "result",
        "code",
    }
    assert not {"seed", "root", "path", "query", "provider", "count", "exception"} & set(
        result.as_dict()
    )


def test_seal_is_deterministic_and_parse_is_strict(tmp_path: Path) -> None:
    request = _request(tmp_path)
    first, second = build_seal(request), build_seal(request)
    assert first == second
    assert hashlib.sha256(first.canonical_bytes).hexdigest() == first.preregistration_sha256
    parsed_fields = {field.name: getattr(request, field.name) for field in fields(request)}
    parsed_fields["schema_version"] = "f10.1f-post-c-preregistration-v1"
    assert parse_post_c_preregistration_request(parsed_fields) == request
    with pytest.raises(PostCPreregistrationError, match="post_c_request_fields_invalid"):
        parse_post_c_preregistration_request(parsed_fields | {"unexpected": True})


def test_exact_repeat_is_idempotent_and_conflict_is_blocked(tmp_path: Path) -> None:
    writer = MemoryWriter(tmp_path)
    request = _request(tmp_path)
    preregister_post_c(request=request, writer=writer)
    preregister_post_c(request=request, writer=writer)
    assert writer.writes == 1

    other_report = SimpleNamespace(report_sha256="e" * 64)
    conflicting = replace(
        request,
        gate_c_report=other_report,
        gate_c_result=GateCResult(
            replace(request.gate_c_result.public, report_sha256=other_report.report_sha256),
            request.source_plan,
            cast(Any, other_report),
        ),
    )
    with pytest.raises(PostCPreregistrationError, match="post_c_conflicting_repeat"):
        preregister_post_c(request=conflicting, writer=writer)
    assert writer.writes == 1


@pytest.mark.parametrize(
    ("binding", "field"),
    (
        ("missing", "authorization"),
        ("wrong_gate", "authorization"),
        ("operation", "operation_id"),
        ("lineage", "lineage_id"),
        ("plan", "query_plan"),
        ("report", "gate_c_report"),
        ("provenance", "provenance"),
        ("commit", "provenance"),
        ("profile", "provenance"),
        ("policy", "provenance"),
        ("root", "source_plan"),
        ("window", "provenance"),
        ("seed", "seeds"),
        ("cap", "source_plan"),
        ("quota", "query_plan"),
        ("budget", "source_plan"),
        ("artifact", "artifact_class"),
        ("substitution", "gate_c_result"),
        ("nonofficial", "source_plan"),
    ),
)
def test_invalid_bound_inputs_never_write(tmp_path: Path, binding: str, field: str) -> None:
    """Every named boundary failure happens before the injected effect boundary."""
    request = _request(tmp_path)
    writer = MemoryWriter(tmp_path)
    with pytest.raises((PostCPreregistrationError, ValueError)):
        bad = replace(cast(Any, request), **cast(Any, {field: object()}))
        preregister_post_c(request=bad, writer=writer)
    assert writer.writes == 0


def test_missing_default_is_rejected_by_strict_parser(tmp_path: Path) -> None:
    request = _request(tmp_path)
    values = {field.name: getattr(request, field.name) for field in fields(request)}
    values["schema_version"] = "f10.1f-post-c-preregistration-v1"
    values.pop("seeds")
    with pytest.raises(PostCPreregistrationError, match="post_c_request_fields_invalid"):
        parse_post_c_preregistration_request(values)


@pytest.mark.parametrize(
    "field",
    (
        "operation_id",
        "lineage_id",
        "target_corpus_count",
        "target_pilot_count",
        "target_holdout_count",
    ),
)
def test_binding_cardinality_and_identity_mismatches_stop_before_writer(
    tmp_path: Path, field: str
) -> None:
    request = _request(tmp_path)
    writer = MemoryWriter(tmp_path)
    value = "wrong" if field in {"operation_id", "lineage_id"} else -1
    with pytest.raises((PostCPreregistrationError, ValueError)):
        bad = replace(cast(Any, request), **cast(Any, {field: value}))
        preregister_post_c(request=bad, writer=writer)
    assert writer.writes == 0


def test_root_writer_mismatch_and_bad_writer_are_pre_effect(tmp_path: Path) -> None:
    request = _request(tmp_path)
    writer = MemoryWriter(tmp_path / "different")
    with pytest.raises(PostCPreregistrationError, match="post_c_root_mismatch"):
        preregister_post_c(request=request, writer=writer)
    with pytest.raises(PostCPreregistrationError, match="post_c_writer_invalid"):
        preregister_post_c(request=request, writer=object())  # type: ignore[arg-type]


def test_cli_post_c_is_lazy_block_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert evaluation_f10_1f.run(Namespace(f10_1f_command="preregister")) == 2
    output = capsys.readouterr().out
    assert '"code":"BLOCK-0"' in output


def test_post_c_modules_have_single_authority_and_no_effectful_successors() -> None:
    root = Path(__file__).parents[2] / "src/role_radar/evaluation/profile_relevant_acquisition"
    source = "\n".join(
        (root / name).read_text(encoding="utf-8")
        for name in (
            "post_c_preregistration_contracts.py",
            "post_c_preregistration_service.py",
        )
    )
    forbidden = ("sqlalchemy", "materialization", "freeze", "gate_d", "gate_e", "gate_f")
    tree = ast.parse(source)
    imports = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert not any(any(word in item.lower() for word in forbidden) for item in imports)
    assert source.count("def preregister_post_c(") == 1
    assert "run_post_c_preregistration_runtime" not in source
