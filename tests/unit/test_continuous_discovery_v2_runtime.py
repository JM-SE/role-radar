"""Gate A offline runtime sequencing and live hard-block checks."""

from __future__ import annotations

from argparse import Namespace

import pytest

from role_radar.continuous_acquisition.runtime_discovery_v2 import (
    DISCOVERY_V2_LIVE_GATE_BLOCKED,
    RuntimeCompositionError,
    build_search_runtime,
    run_continuous_discovery_v2,
    run_discovery_v2,
)


def test_live_modes_block_before_any_injected_precondition() -> None:
    for mode in ("report_only", "register"):
        result = run_discovery_v2(mode=mode)
        assert result.exit_code == 2
        assert result.payload["code"] == DISCOVERY_V2_LIVE_GATE_BLOCKED


def test_provider_runtime_constructor_is_gate_a_blocked() -> None:
    with pytest.raises(RuntimeCompositionError) as error:
        build_search_runtime(object(), object())
    assert error.value.code == DISCOVERY_V2_LIVE_GATE_BLOCKED


def test_legacy_acknowledgement_and_scheduled_switches_cannot_authorize_v2() -> None:
    for values in (
        {"acknowledgement": "I_ACKNOWLEDGE_LIVE_PROVIDER_CALLS"},
        {"manual_canary": True},
        {"scheduled": True},
    ):
        result = run_continuous_discovery_v2(
            Namespace(continuous_discovery_v2_command="run-report-only", **values)
        )
        assert result.exit_code == 2
        assert result.payload["code"] == "discovery_v2_authorization_invalid"


def test_unknown_v2_command_is_sanitized() -> None:
    result = run_continuous_discovery_v2(Namespace(continuous_discovery_v2_command="unknown"))
    assert result.payload == {
        "schema_version": "continuous-discovery-v2-result-v1",
        "result": "blocked",
        "code": "command_invalid",
    }
