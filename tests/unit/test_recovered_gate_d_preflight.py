from dataclasses import replace
from datetime import UTC, datetime

import pytest

from role_radar.evaluation.profile_relevant_acquisition import (
    recovered_gate_d_adaptation_authorization as adaptation_auth,
)
from role_radar.evaluation.profile_relevant_acquisition.recovered_gate_d_adaptation import (
    RecoveredGateDAdaptationBinding,
)
from role_radar.evaluation.profile_relevant_acquisition.recovered_gate_d_adaptation_service import (
    authorize_recovered_gate_d,
    run_recovered_gate_d_synthetic,
)
from role_radar.evaluation.profile_relevant_acquisition.recovered_gate_d_authorization import (
    RecoveredGateDPreflightAuthorization,
)
from role_radar.evaluation.profile_relevant_acquisition.recovered_gate_d_compatibility import (
    assess_recovered_gate_d_compatibility,
)
from role_radar.evaluation.profile_relevant_acquisition.recovered_gate_d_loader import (
    RecoveredGateDLoadError,
    load_recovered_gate_d_preflight,
)


def _authorization() -> RecoveredGateDPreflightAuthorization:
    def fixed_clock() -> datetime:
        return datetime(2026, 9, 12, 12, tzinfo=UTC)

    return RecoveredGateDPreflightAuthorization(
        action="offline_compatibility_preflight",
        approval_reference="r2-gate-d-preflight-20260912-001",
        operator_id="jmse",
        window_start_utc="2026-09-12T00:00:00Z",
        expires_at_utc="2026-09-13T00:00:00Z",
        historical_root="/home/jmse/r2-evidence/r2-discover-20260911-clean-024003",
        recovery_root="/home/jmse/r2-evidence/r2-discover-20260911-recovered-024003",
        post_c_root="/home/jmse/r2-evidence/r2-post-c-20260912-001",
        operation_id="ca3fbc4d-7f8e-49a6-8263-c1fdd69bbad5",
        seal_sha256="2c5e7a867d1c06eeaf5720e2e04ca95f2af862a91b0a0e86d10e3fb0c6bf322d",
        source_plan_sha256="def7b57e24be9eb0f360c4b06ede67de9f71e105657afad8efc8820b69dd9846",
        report_sha256="3f816b91d078e9f91ed78422f44189d61f265dee582a1daa4387337638817de0",
        post_c_authorization_sha256="9e10082c0b4d8c69cef5ff21922540c319c22874eed7b8d8849a5af9722a1289",
        source_keys=(
            "greenhouse:twilio",
            "greenhouse:grafanalabs",
            "greenhouse:similarweb",
            "greenhouse:stackline",
            "greenhouse:postman",
            "greenhouse:figma",
        ),
        clock=fixed_clock,
    )


def _adapted_authorization() -> adaptation_auth.RecoveredGateDAdaptationAuthorization:
    authorization = _authorization()
    return adaptation_auth.RecoveredGateDAdaptationAuthorization(
        action=adaptation_auth.ACTION,
        approval_reference="r2-gate-d-adaptation-20260912-001",
        operator_id="jmse",
        window_start_utc=authorization.window_start_utc,
        expires_at_utc=authorization.expires_at_utc,
        historical_root=authorization.historical_root,
        recovery_root=authorization.recovery_root,
        post_c_root=authorization.post_c_root,
        operation_id=authorization.operation_id,
        seal_sha256=authorization.seal_sha256,
        source_plan_sha256=authorization.source_plan_sha256,
        report_sha256=authorization.report_sha256,
        post_c_authorization_sha256=authorization.post_c_authorization_sha256,
        source_keys=authorization.source_keys,
        clock=authorization.clock,
    )


def test_fixture_is_read_only_and_reports_normal_gate_d_incompatibility() -> None:
    authorization = _authorization()

    def clock() -> datetime:
        return datetime(2026, 9, 12, 12, tzinfo=UTC)

    state, terminal, count = load_recovered_gate_d_preflight(authorization, clock=clock)
    verdict = assess_recovered_gate_d_compatibility(
        authorization,
        predecessor_state=state,
        predecessor_terminal=terminal,
        source_count=count,
    )
    assert verdict.result == "blocked"
    assert verdict.expected_source_count == 6
    assert verdict.effect == "disabled"
    assert "completed_predecessor_required" in verdict.gate_d_compatibility_reasons


def test_preflight_rejects_expired_window_before_loading() -> None:
    authorization = _authorization()
    with pytest.raises(RecoveredGateDLoadError, match="authorization_expired"):
        load_recovered_gate_d_preflight(
            authorization,
            clock=lambda: datetime(2026, 9, 13, tzinfo=UTC),
        )


def test_recovered_adaptation_revalidates_fixture_and_accepts_only_synthetic_delegate() -> None:
    seen: list[str] = []

    def delegate(binding: RecoveredGateDAdaptationBinding) -> str:
        seen.append(binding.predecessor_state)
        return "synthetic-ok"

    # Use the adaptation's explicit action/approval while preserving the
    # exact immutable artifact anchors from the preflight fixture.
    adapted = _adapted_authorization()
    assert run_recovered_gate_d_synthetic(adapted, delegate) == "synthetic-ok"
    assert seen == ["completed_partial"]
    assert authorize_recovered_gate_d(adapted).source_count == 6


def test_recovered_binding_cannot_be_forged_directly() -> None:
    with pytest.raises(ValueError, match="not_loader_issued"):
        RecoveredGateDAdaptationBinding(
            _adapted_authorization(), "completed_partial", "multiple_budgets_exhausted", 6
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("operation_id", "different-operation"),
        ("seal_sha256", "0" * 64),
        ("source_plan_sha256", "1" * 64),
        ("report_sha256", "2" * 64),
        ("post_c_authorization_sha256", "3" * 64),
        ("source_keys", ("greenhouse:other",) * 6),
    ],
)
def test_recovered_adaptation_rejects_changed_trust_anchor(field: str, value: object) -> None:
    with pytest.raises(ValueError, match=r"anchor|sources"):
        replace(_adapted_authorization(), **{field: value})


def test_recovered_adaptation_rejects_subclass_and_never_calls_delegate() -> None:
    class ForgedAuthorization(adaptation_auth.RecoveredGateDAdaptationAuthorization):
        def validate_current(self, now: datetime) -> None:
            return None

    base = _adapted_authorization()
    forged = ForgedAuthorization(
        **{name: getattr(base, name) for name in base.__dataclass_fields__ if name != "_token"}
    )
    called = False

    def delegate(_: RecoveredGateDAdaptationBinding) -> None:
        nonlocal called
        called = True

    with pytest.raises(ValueError, match="authorization_invalid"):
        run_recovered_gate_d_synthetic(forged, delegate)
    assert not called
