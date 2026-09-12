from datetime import UTC, datetime

import pytest

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
