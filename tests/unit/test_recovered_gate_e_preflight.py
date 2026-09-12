from datetime import UTC, datetime
from pathlib import Path

import pytest

from role_radar.evaluation.profile_relevant_acquisition import (
    recovered_gate_e_preflight_authorization as gate_e_auth,
)
from role_radar.evaluation.profile_relevant_acquisition import (
    recovered_gate_e_preflight_loader as gate_e_loader,
)
from role_radar.evaluation.profile_relevant_acquisition.recovered_gate_d_authorization import (
    EXPECTED_SOURCE_KEYS,
)
from role_radar.evaluation.profile_relevant_acquisition.recovered_gate_e_compatibility import (
    assess_recovered_gate_e_compatibility,
)
from role_radar.evaluation.profile_relevant_acquisition.recovered_gate_e_preflight_loader import (
    load_recovered_gate_e_preflight,
)

NOW = datetime(2026, 9, 12, 18, 0, tzinfo=UTC)


def _clock() -> datetime:
    return NOW


def _authorization() -> gate_e_auth.RecoveredGateEPreflightAuthorization:
    return gate_e_auth.RecoveredGateEPreflightAuthorization(
        action=gate_e_auth.ACTION,
        approval_reference="r2-gate-e-preflight-20260912-001",
        candidate_commit_sha256="734f5c08f23a3e2a97032c54cabef0f324a2bf94",
        window_start_utc="2026-09-12T00:00:00Z",
        expires_at_utc="2026-09-13T00:00:00Z",
        historical_root="/home/jmse/r2-evidence/r2-discover-20260911-clean-024003",
        recovery_root="/home/jmse/r2-evidence/r2-discover-20260911-recovered-024003",
        post_c_root="/home/jmse/r2-evidence/r2-post-c-20260912-001",
        gate_d_root="/home/jmse/r2-evidence/r2-gate-d-20260912-001",
        operation_id="ca3fbc4d-7f8e-49a6-8263-c1fdd69bbad5",
        seal_sha256="2c5e7a867d1c06eeaf5720e2e04ca95f2af862a91b0a0e86d10e3fb0c6bf322d",
        source_plan_sha256="def7b57e24be9eb0f360c4b06ede67de9f71e105657afad8efc8820b69dd9846",
        report_sha256="3f816b91d078e9f91ed78422f44189d61f265dee582a1daa4387337638817de0",
        post_c_authorization_sha256="9e10082c0b4d8c69cef5ff21922540c319c22874eed7b8d8849a5af9722a1289",
        gate_d_manifest_sha256="ffe183ed040d6a090ff33b6ab0743a1cd5df33c384ad9e810847ebe3381b88fd",
        source_keys=EXPECTED_SOURCE_KEYS,
        clock=_clock,
    )


def test_fixture_preflight_is_read_only_and_blocked() -> None:
    root = Path("/home/jmse/r2-evidence/r2-gate-d-20260912-001")
    before = tuple(sorted((path.name, path.stat().st_mtime_ns) for path in root.iterdir()))
    provenance = load_recovered_gate_e_preflight(_authorization())
    verdict = assess_recovered_gate_e_compatibility(provenance)
    after = tuple(sorted((path.name, path.stat().st_mtime_ns) for path in root.iterdir()))
    assert verdict.as_dict() == {
        "result": "blocked_no_candidates",
        "effect": "disabled",
        "downstream": "disabled",
        "reason": "blocked_no_candidates",
        "source_count": 6,
        "parent_pool_count": 0,
        "manifest_sha256": "ffe183ed040d6a090ff33b6ab0743a1cd5df33c384ad9e810847ebe3381b88fd",
    }
    assert provenance.source_keys == EXPECTED_SOURCE_KEYS
    assert before == after


def test_preflight_rejects_expired_authorization_before_read() -> None:
    authorization = _authorization()
    with pytest.raises(gate_e_auth.RecoveredGateEPreflightAuthorizationError):
        authorization.validate_current(datetime(2026, 9, 13, tzinfo=UTC))


def test_preflight_sanitizes_unknown_internal_loader_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_loader(*args: object, **kwargs: object) -> object:
        raise gate_e_loader.RecoveredGateEPreflightLoadError("private_internal_code")

    monkeypatch.setattr(gate_e_loader, "_load_pinned", fail_loader)
    with pytest.raises(gate_e_loader.RecoveredGateEPreflightLoadError) as error:
        load_recovered_gate_e_preflight(_authorization())
    assert error.value.code == "gate_e_preflight_invalid"
