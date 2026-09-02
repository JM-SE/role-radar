"""Focused, offline acceptance tests for the Gate D service boundary."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from role_radar.evaluation.profile_relevant_acquisition.acquisition_runtime import (
    SourceCheckpoint,
    SyntheticTransport,
)
from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    SeedInputs,
    synthetic_test_adapter,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_c_service import (
    execute_gate_c_report_only,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_d_authorization import (
    GateDAuthorizationRequest,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_d_service import (
    GateDServiceError,
    execute_gate_d_bounded_acquisition,
)
from role_radar.evaluation.profile_relevant_acquisition.journal import AcquisitionJournal
from role_radar.evaluation.profile_relevant_acquisition.post_c_preregistration_contracts import (
    PostCPreregistrationRequest,
    build_seal,
)
from tests.integration.test_profile_relevant_acquisition_gate_d import _fake_collector
from tests.unit.test_gate_c_report_only import (
    _accepted,
    _authorization,
    _candidate,
    _OfficialProvider,
    _plan,
)


def _request(root: Path) -> GateDAuthorizationRequest:
    plan = _plan()
    authorization = _authorization(root, plan)
    gate_c = execute_gate_c_report_only(
        authorization=authorization,
        accepted_b=_accepted(root, plan),
        plan=plan,
        provider=_OfficialProvider(
            (
                _candidate("greenhouse", "greenhouse:acme", {"board_token": "acme"}),
                _candidate("lever", "lever:global:acme", {"site": "acme", "region": "global"}),
            )
        ),
        evidence_root=root,
    )
    assert gate_c.source_plan is not None and gate_c.report is not None
    post = PostCPreregistrationRequest(
        operation_id=authorization.operation_id,
        lineage_id=authorization.lineage_id,
        authorization=authorization,
        accepted_gate_b=_accepted(root, plan),
        query_plan=plan,
        gate_c_result=gate_c,
        source_plan=gate_c.source_plan,
        gate_c_report=gate_c.report,
        provenance=authorization.provenance,
        seeds=SeedInputs("a" * 64, "b" * 64),
        artifact_class="offline_private_report_only",
        target_corpus_count=10,
        target_pilot_count=2,
        target_holdout_count=8,
    )
    return GateDAuthorizationRequest(
        operation_id=post.operation_id,
        lineage_id=post.lineage_id,
        post_c_request=post,
        post_c_seal=build_seal(post),
        current_commit_sha256=authorization.provenance.candidate_commit_sha256,
        evidence_root=root,
        namespace=post.source_plan.namespace,
        window_start_utc=post.provenance.window_start_utc,
        window_end_utc=post.provenance.window_end_utc,
        cutoff_utc=post.provenance.cutoff_utc,
        seeds=post.seeds,
        per_board_cap=post.source_plan.per_board_cap,
        per_company_cap=post.source_plan.per_company_cap,
        quotas=dict(plan.limits),
        cardinality={"corpus": 10, "pilot": 2, "holdout": 8},
        budget_id=post.source_plan.budget.budget_id,
        budget_units=post.source_plan.budget.maximum,
        artifact_class=post.artifact_class,
        test_only_adapter=synthetic_test_adapter(),
    )


@pytest.mark.asyncio
async def test_valid_offline_operation_is_bounded_sealed_sanitized_and_terminal(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    delegate = SyntheticTransport()
    journal = AcquisitionJournal(operation_id=request.operation_id, root=tmp_path)
    state: dict[str, object] = {"sources": 0, "jobs": 0, "runs": 0}

    result = await execute_gate_d_bounded_acquisition(
        request=request,
        delegate=delegate,
        collector_factory=cast(Any, _fake_collector),
        journal=journal,
        before_after=lambda: (state.copy(), state.copy()),
    )

    assert delegate.calls == 2
    assert result.runtime.source_count == 2
    assert result.runtime.sealed_pool_path is not None and result.runtime.sealed_pool_path.is_file()
    assert result.runtime.sealed_manifest_path is not None
    assert result.runtime.sealed_manifest_path.is_file()
    assert result.public.as_dict()["code"] == "gate_d_bounded_acquisition_completed"
    assert result.public.as_dict()["budget_status"] == "within_bound"
    assert not {"root", "seed", "query", "raw", "provider", "exception"} & set(
        result.public.as_dict()
    )
    assert state == {"sources": 0, "jobs": 0, "runs": 0}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field",
    (
        "operation_id",
        "lineage_id",
        "current_commit_sha256",
        "namespace",
        "window_start_utc",
        "window_end_utc",
        "cutoff_utc",
        "seeds",
        "per_board_cap",
        "per_company_cap",
        "quotas",
        "cardinality",
        "budget_id",
        "budget_units",
        "artifact_class",
        "post_c_seal",
    ),
)
async def test_every_request_binding_fails_before_effects(tmp_path: Path, field: str) -> None:
    request = _request(tmp_path)
    bad: Any = object()
    if field == "budget_units" or field in {"per_board_cap", "per_company_cap"}:
        bad = 0
    elif field == "quotas":
        bad = {"wrong": 1}
    elif field == "cardinality":
        bad = {"corpus": 1, "pilot": 2, "holdout": 8}
    elif field == "seeds":
        bad = SeedInputs("c" * 64, "b" * 64)
    elif field == "post_c_seal":
        bad = object()
    invalid = replace(cast(Any, request), **{field: bad})
    delegate = SyntheticTransport()
    factory_calls = 0

    def factory(*_args: object, **_kwargs: object) -> object:
        nonlocal factory_calls
        factory_calls += 1
        raise AssertionError("collector must not be reached")

    with pytest.raises(GateDServiceError):
        await execute_gate_d_bounded_acquisition(
            request=invalid,
            delegate=delegate,
            collector_factory=factory,  # type: ignore[arg-type]
            journal=object(),  # type: ignore[arg-type]
        )
    assert delegate.calls == 0
    assert factory_calls == 0
    assert not (tmp_path / "journal").exists()


def test_public_dto_is_a_strict_sanitized_allowlist() -> None:
    from role_radar.evaluation.profile_relevant_acquisition.gate_d_service import GateDPublicResult

    assert set(GateDPublicResult.__dataclass_fields__) == {
        "operation_id",
        "preregistration_sha256",
        "source_plan_sha256",
        "pool_sha256",
        "manifest_sha256",
        "source_count",
        "attempted_count",
        "wire_attempts",
        "budget_status",
        "result",
        "code",
    }


def test_cli_gate_d_is_lazy_block_zero(capsys: pytest.CaptureFixture[str]) -> None:
    from argparse import Namespace

    from role_radar.cli import evaluation_f10_1f

    assert evaluation_f10_1f.run(Namespace(f10_1f_command="acquire")) == 2
    assert '"code":"BLOCK-0"' in capsys.readouterr().out


@pytest.mark.asyncio
async def test_pending_and_reconciliation_mismatch_stop_without_delegate(tmp_path: Path) -> None:
    request = _request(tmp_path)
    journal = AcquisitionJournal(operation_id=request.operation_id, root=tmp_path)
    source_id = "ephemeral:" + "0" * 32
    journal.record_intent(
        source_id=source_id, ordinal=1, destination_fingerprint="a" * 16, budget_ordinal=1
    )
    with pytest.raises(GateDServiceError) as error:
        await execute_gate_d_bounded_acquisition(
            request=request,
            delegate=SyntheticTransport(),
            collector_factory=cast(Any, _fake_collector),
            journal=journal,
            checkpoints={source_id: SourceCheckpoint(source_id, 1, "d" * 64)},
        )
    assert error.value.code in {
        "acquisition_source_blocked_pending",
        "acquisition_indeterminate_pending",
        "gate_d_reconciliation_mismatch",
    }


@pytest.mark.asyncio
async def test_exact_replay_is_idempotent_and_conflicting_replay_is_terminal(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    delegate = SyntheticTransport()
    journal = AcquisitionJournal(operation_id=request.operation_id, root=tmp_path)
    first = await execute_gate_d_bounded_acquisition(
        request=request,
        delegate=delegate,
        collector_factory=cast(Any, _fake_collector),
        journal=journal,
    )
    calls = delegate.calls
    replay = await execute_gate_d_bounded_acquisition(
        request=request,
        delegate=delegate,
        collector_factory=cast(Any, _fake_collector),
        journal=journal,
        checkpoints=first.runtime.checkpoints,
    )
    assert replay.public.as_dict() == first.public.as_dict()
    assert delegate.calls == calls


@pytest.mark.asyncio
async def test_expiry_is_revalidated_at_execution_before_effects(tmp_path: Path) -> None:
    request = _request(tmp_path)
    delegate = SyntheticTransport()
    with pytest.raises(GateDServiceError) as error:
        await execute_gate_d_bounded_acquisition(
            request=request,
            delegate=delegate,
            collector_factory=cast(Any, _fake_collector),
            journal=object(),  # type: ignore[arg-type]
            clock=lambda: datetime(2100, 1, 1, tzinfo=UTC),
        )
    assert error.value.code == "authorization_expired"
    assert delegate.calls == 0
    assert not (tmp_path / "journal").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("artifact", ("sealed_pool.jsonl", "manifest.json"))
async def test_conflicting_existing_seal_blocks_replay_without_delegate_effects(
    tmp_path: Path, artifact: str
) -> None:
    request = _request(tmp_path)
    delegate = SyntheticTransport()
    journal = AcquisitionJournal(operation_id=request.operation_id, root=tmp_path)
    first = await execute_gate_d_bounded_acquisition(
        request=request,
        delegate=delegate,
        collector_factory=cast(Any, _fake_collector),
        journal=journal,
    )
    calls = delegate.calls
    path = tmp_path / request.operation_id / artifact
    path.write_bytes(b"conflicting sealed bytes")

    with pytest.raises(GateDServiceError) as error:
        await execute_gate_d_bounded_acquisition(
            request=request,
            delegate=delegate,
            collector_factory=cast(Any, _fake_collector),
            journal=journal,
            checkpoints=first.runtime.checkpoints,
        )
    assert error.value.code == "filesystem_no_replace_conflict"
    assert delegate.calls == calls

    conflicting = {item.source_id: item for item in first.runtime.checkpoints}
    source_id = next(iter(conflicting))
    conflicting[source_id] = replace(conflicting[source_id], checkpoint_sha256="e" * 64)
    with pytest.raises(GateDServiceError) as error:
        await execute_gate_d_bounded_acquisition(
            request=request,
            delegate=delegate,
            collector_factory=cast(Any, _fake_collector),
            journal=journal,
            checkpoints=conflicting,
        )
    assert error.value.code == "acquisition_replay_checkpoint_mismatch"
    assert delegate.calls == calls


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("post_c_request", object()),
        ("post_c_seal", object()),
        ("current_commit_sha256", "d" * 64),
        ("evidence_root", Path("/production/root")),
        ("test_only_adapter", object()),
    ),
)
@pytest.mark.asyncio
async def test_protected_paths_and_untyped_adapters_are_never_reached(
    tmp_path: Path, name: str, value: object
) -> None:
    request = _request(tmp_path)
    invalid = replace(cast(Any, request), **{name: value})
    delegate = SyntheticTransport()
    with pytest.raises(GateDServiceError):
        await execute_gate_d_bounded_acquisition(
            request=invalid,
            delegate=delegate,
            collector_factory=object(),  # type: ignore[arg-type]
            journal=object(),  # type: ignore[arg-type]
        )
    assert delegate.calls == 0


@pytest.mark.parametrize(
    "source_config",
    (
        {
            "family": "unknown",
            "source_key": "unknown:x",
            "configuration_version": 1,
            "configuration": {},
        },
        {
            "family": "greenhouse",
            "source_key": "greenhouse:other",
            "configuration_version": 1,
            "configuration": {"board_token": "acme"},
        },
        {
            "family": "greenhouse",
            "source_key": "greenhouse:acme",
            "configuration_version": 2,
            "configuration": {"board_token": "acme"},
        },
        {
            "family": "greenhouse",
            "source_key": "greenhouse:acme",
            "configuration_version": 1,
            "configuration": {"board_token": "adaptive"},
        },
    ),
)
def test_nonofficial_substituted_adaptive_and_default_source_configs_are_rejected(
    tmp_path: Path, source_config: dict[str, object]
) -> None:
    request = _request(tmp_path)
    post = request.post_c_request
    bad_plan = replace(post.source_plan)
    object.__setattr__(bad_plan, "source_configs", (source_config,))
    bad_result = replace(post.gate_c_result, source_plan=bad_plan)
    with pytest.raises(ValueError):
        PostCPreregistrationRequest(
            **{
                **{name: getattr(post, name) for name in post.__dataclass_fields__},
                "source_plan": bad_plan,
                "gate_c_result": bad_result,
            }
        )
    assert not (tmp_path / "journal").exists()
