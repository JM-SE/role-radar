"""Focused, offline coverage for the authoritative Post-C preregistration seam."""

from __future__ import annotations

import ast
import hashlib
import os
from argparse import Namespace
from dataclasses import fields, replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from role_radar.cli import evaluation_f10_1f
from role_radar.evaluation.profile_relevant_acquisition import (
    post_c_preregistration_service as post_c_service,
)
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
    RecoveredFilesystemPrivateSealWriter,
    preregister_post_c,
    preregister_recovered_post_c,
)
from role_radar.evaluation.profile_relevant_acquisition.post_c_recovery_authorization import (
    RECOVERED_EVIDENCE_SHA256,
    RECOVERED_OFFICIAL_REQUEST_IDENTITIES,
    RECOVERED_OPERATION_ID,
    RECOVERED_OPERATION_SHA256,
    RECOVERED_PLAN_SHA256,
    RECOVERED_POLICY_SHA256,
    RECOVERED_PROFILE_ID,
    RECOVERED_PROFILE_SHA256,
    RECOVERED_PROFILE_VERSION,
    RECOVERED_REPORT_SHA256,
    RECOVERED_SEARCH_REQUEST_IDENTITIES,
    RECOVERED_SOURCE_KEYS,
    RECOVERED_SOURCE_PLAN_SHA256,
    PostCAuthorization,
    PostCRecoveryAuthorizationError,
)
from role_radar.evaluation.profile_relevant_acquisition.post_c_recovery_filesystem import (
    RecoveryFilesystemError,
    pinned_root,
    read_json,
    write_no_replace,
)
from role_radar.evaluation.profile_relevant_acquisition.post_c_recovery_loader import (
    RecoveredGateCPublicResult,
    RecoveredGateCResult,
    RecoveredPostCData,
    load_recovered_post_c,
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


def test_candidate_commit_identity_mismatch_stops_before_writer(tmp_path: Path) -> None:
    request = _request(tmp_path)
    writer = MemoryWriter(tmp_path)
    provenance = replace(request.provenance, candidate_commit_sha256="f" * 64)
    with pytest.raises(PostCPreregistrationError, match="post_c_candidate_commit_mismatch"):
        preregister_post_c(request=replace(request, provenance=provenance), writer=writer)
    assert writer.writes == 0


def test_policy_id_identity_mismatch_stops_before_writer(tmp_path: Path) -> None:
    request = _request(tmp_path)
    writer = MemoryWriter(tmp_path)
    provenance = replace(request.provenance, policy_id="other-policy")
    with pytest.raises(PostCPreregistrationError, match="post_c_policy_id_mismatch"):
        preregister_post_c(request=replace(request, provenance=provenance), writer=writer)
    assert writer.writes == 0


def test_root_writer_mismatch_and_bad_writer_are_pre_effect(tmp_path: Path) -> None:
    request = _request(tmp_path)
    writer = MemoryWriter(tmp_path / "different")
    with pytest.raises(PostCPreregistrationError, match="post_c_root_mismatch"):
        preregister_post_c(request=request, writer=writer)
    with pytest.raises(PostCPreregistrationError, match="post_c_writer_invalid"):
        preregister_post_c(request=request, writer=object())  # type: ignore[arg-type]


def test_ordinary_filesystem_writer_still_creates_private_root(tmp_path: Path) -> None:
    root = tmp_path / "ordinary-output"
    request = _request(root)

    result = preregister_post_c(
        request=request, writer=post_c_service.FilesystemPrivateSealWriter(str(root))
    )

    assert result.result == "completed"
    assert root.is_dir()
    assert root.stat().st_mode & 0o777 == 0o700
    assert (root / "post-c" / f"{request.operation_id}.json").is_file()


@pytest.mark.parametrize("relative", [("..", "escape"), ("post-c", ".."), ("post-c/escape",)])
def test_recovered_writer_rejects_unsafe_relative_paths(
    tmp_path: Path, relative: tuple[str, ...]
) -> None:
    root = tmp_path / "output"
    root.mkdir(mode=0o700)

    with pytest.raises(RecoveryFilesystemError, match="post_c_recovery_artifact_path_invalid"):
        write_no_replace(root, relative, b"payload")


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


def test_recovered_partial_path_is_typed_and_uses_fresh_output_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorization = PostCAuthorization(
        action="offline_preregistration",
        approval_reference="post-c-test",
        operator_id="operator-test",
        window_start_utc="2026-09-11T00:00:00Z",
        expires_at_utc="2026-09-12T00:00:00Z",
        historical_root=str(tmp_path / "historical"),
        recovery_root=str(tmp_path / "recovery"),
        output_root=str(tmp_path / "output"),
        operation_id="ca3fbc4d-7f8e-49a6-8263-c1fdd69bbad5",
        operation_sha256="a" * 64,
        profile_id="818eded4-2f69-4e66-ad12-cd0749e4ab3e",
        profile_version=2,
        profile_sha256="b" * 64,
        policy_sha256="c" * 64,
        plan_sha256="d" * 64,
        report_sha256="e" * 64,
        source_plan_sha256="f" * 64,
        evidence_sha256="1" * 64,
        historical_approval_reference="r2-gate-c-test",
        source_keys=tuple(f"{index + 1:064x}" for index in range(6)),
        search_request_identities=(),
        official_request_identities=tuple(f"{index + 7:064x}" for index in range(6)),
    )
    data = RecoveredPostCData(
        authorization,
        RecoveredGateCResult(
            RecoveredGateCPublicResult(
                authorization.operation_id,
                authorization.plan_sha256,
                "f" * 64,
                authorization.report_sha256,
                4,
                6,
                {"greenhouse": 6},
                "multiple_budgets_exhausted",
                "completed_partial",
                "multiple_budgets_exhausted",
            ),
            SimpleNamespace(source_plan_sha256="f" * 64),
            SimpleNamespace(),
        ),
        SimpleNamespace(
            verified_sources=(object(),) * 6,
            state="completed_partial",
            terminal_code="multiple_budgets_exhausted",
        ),
        SimpleNamespace(source_plan_sha256="f" * 64),
        "1" * 64,
        b"evidence",
    )
    Path(authorization.output_root).mkdir(mode=0o700)
    writer = MemoryWriter(Path(authorization.output_root))
    monkeypatch.setattr(
        post_c_service,
        "load_recovered_post_c",
        lambda _authorization, clock=None: data,
    )
    result = preregister_recovered_post_c(
        authorization=authorization,
        writer=writer,
        clock=lambda: datetime(2026, 9, 11, 12, tzinfo=UTC),
    )
    assert result.result == "completed_partial"
    assert writer.writes == 1
    with pytest.raises(
        PostCRecoveryAuthorizationError, match="post_c_recovery_authorization_invalid"
    ):
        replace(authorization, source_keys=list(authorization.source_keys))
    with pytest.raises(
        PostCRecoveryAuthorizationError, match="post_c_recovery_authorization_invalid"
    ):
        replace(
            authorization,
            official_request_identities=list(authorization.official_request_identities),
        )
    with pytest.raises(PostCRecoveryAuthorizationError, match="post_c_recovery_roots_overlap"):
        PostCAuthorization(
            action=authorization.action,
            approval_reference=authorization.approval_reference,
            operator_id=authorization.operator_id,
            window_start_utc=authorization.window_start_utc,
            expires_at_utc=authorization.expires_at_utc,
            historical_root=authorization.historical_root,
            recovery_root=authorization.recovery_root,
            output_root=authorization.recovery_root,
            operation_id=authorization.operation_id,
            operation_sha256=authorization.operation_sha256,
            profile_id=authorization.profile_id,
            profile_version=authorization.profile_version,
            profile_sha256=authorization.profile_sha256,
            policy_sha256=authorization.policy_sha256,
            plan_sha256=authorization.plan_sha256,
            report_sha256=authorization.report_sha256,
            source_plan_sha256=authorization.source_plan_sha256,
            evidence_sha256=authorization.evidence_sha256,
            historical_approval_reference=authorization.historical_approval_reference,
            source_keys=authorization.source_keys,
            search_request_identities=authorization.search_request_identities,
            official_request_identities=authorization.official_request_identities,
        )


def test_recovered_loader_reconstructs_fixture_without_writing(tmp_path: Path) -> None:
    authorization = PostCAuthorization(
        action="offline_preregistration",
        approval_reference="post-c-fixture-test",
        operator_id="operator-test",
        window_start_utc="2026-09-11T00:00:00Z",
        expires_at_utc="2026-09-12T00:00:00Z",
        historical_root="/home/jmse/r2-evidence/r2-discover-20260911-clean-024003",
        recovery_root="/home/jmse/r2-evidence/r2-discover-20260911-recovered-024003",
        output_root=str(tmp_path / "output"),
        operation_id=RECOVERED_OPERATION_ID,
        operation_sha256=RECOVERED_OPERATION_SHA256,
        profile_id=RECOVERED_PROFILE_ID,
        profile_version=RECOVERED_PROFILE_VERSION,
        profile_sha256=RECOVERED_PROFILE_SHA256,
        policy_sha256=RECOVERED_POLICY_SHA256,
        plan_sha256=RECOVERED_PLAN_SHA256,
        report_sha256=RECOVERED_REPORT_SHA256,
        source_plan_sha256=RECOVERED_SOURCE_PLAN_SHA256,
        evidence_sha256=RECOVERED_EVIDENCE_SHA256,
        historical_approval_reference="r2-gate-c-20260911",
        source_keys=RECOVERED_SOURCE_KEYS,
        search_request_identities=RECOVERED_SEARCH_REQUEST_IDENTITIES,
        official_request_identities=RECOVERED_OFFICIAL_REQUEST_IDENTITIES,
    )

    data = load_recovered_post_c(
        authorization,
        clock=lambda: datetime(2026, 9, 11, 12, tzinfo=UTC),
    )

    assert data.gate_c_result.public.result == "completed_partial"
    assert len(data.terminal.verified_sources) == 6
    assert data.source_plan.source_plan_sha256 == authorization.source_plan_sha256
    assert not (tmp_path / "output").exists()


def test_recovered_filesystem_writer_enforces_boundary_and_durability(tmp_path: Path) -> None:
    root = tmp_path / "output"
    root.mkdir(mode=0o700)
    writer = RecoveredFilesystemPrivateSealWriter(str(root))
    payload = b"{}"
    seal = post_c_service.PostCPreregistrationSeal(
        "ca3fbc4d-7f8e-49a6-8263-c1fdd69bbad5", payload, hashlib.sha256(payload).hexdigest()
    )

    writer.write(seal)

    target = root / "post-c" / f"{seal.operation_id}.json"
    assert writer.read(seal.operation_id) == payload
    assert root.stat().st_mode & 0o777 == 0o700
    assert (root / "post-c").stat().st_mode & 0o777 == 0o700
    assert target.stat().st_mode & 0o777 == 0o600
    (root / "unexpected").write_bytes(b"x")
    with pytest.raises(PostCPreregistrationError, match="post_c_recovery_output_conflict"):
        writer.write(seal)


def test_recovery_json_rejects_canonical_json_with_newline(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    target = root / "artifact.json"
    target.write_bytes(b'{"value":1}\n')
    target.chmod(0o600)

    with (
        pinned_root(root) as root_fd,
        pytest.raises(RecoveryFilesystemError, match="post_c_recovery_artifact_invalid"),
    ):
        read_json(root_fd, root, target)


def test_recovery_publication_does_not_expose_partial_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    target = root / "post-c" / "operation.json"
    observed: list[bool] = []
    original_write = os.write

    def observe_write(fd: int, payload: bytes) -> int:
        observed.append(target.exists())
        return original_write(fd, payload)

    monkeypatch.setattr(os, "write", observe_write)
    write_no_replace(root, ("post-c", "operation.json"), b'{"sealed":true}')

    assert observed
    assert not any(observed)
    assert target.read_bytes() == b'{"sealed":true}'
