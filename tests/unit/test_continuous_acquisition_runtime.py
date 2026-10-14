"""Offline composition tests for the final continuous runtime entrypoints."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from role_radar.acquisition.configuration import AcquisitionConfig
from role_radar.collectors.outcomes import CollectionMetrics, CollectionSuccess
from role_radar.config import Settings
from role_radar.continuous_acquisition.runtime import (
    EXIT_PRECONDITION,
    LIVE_ACKNOWLEDGEMENT,
    RuntimeCompositionError,
    provider_summary,
    require_mode_authorization,
    run_acquisition_once,
    run_discovery_once,
)
from role_radar.db.models import Source

AS_OF = datetime(2026, 8, 14, 12, tzinfo=UTC)


def test_authorization_is_exact_and_scheduled_activation_is_strict() -> None:
    with pytest.raises(RuntimeCompositionError) as missing:
        require_mode_authorization(mode="manual-canary", acknowledgement="--yes")
    assert missing.value.code == "live_ack_required"

    with pytest.raises(RuntimeCompositionError) as missing_id:
        require_mode_authorization(mode="manual-canary", acknowledgement=LIVE_ACKNOWLEDGEMENT)
    assert missing_id.value.code == "canary_id_required"

    with pytest.raises(RuntimeCompositionError) as disabled:
        require_mode_authorization(
            mode="scheduled",
            acknowledgement=None,
            environment={"ROLE_RADAR_CONTINUOUS_ENABLED": "TRUE"},
        )
    assert disabled.value.code == "continuous_activation_required"

    require_mode_authorization(
        mode="manual-canary",
        acknowledgement=LIVE_ACKNOWLEDGEMENT,
        canary_id="greenhouse-fix-01",
        environment={},
    )
    with pytest.raises(RuntimeCompositionError) as scheduled_id:
        require_mode_authorization(
            mode="scheduled",
            acknowledgement=None,
            canary_id="greenhouse-fix-01",
            environment={"ROLE_RADAR_CONTINUOUS_ENABLED": "true"},
        )
    assert scheduled_id.value.code == "canary_id_not_allowed"
    require_mode_authorization(
        mode="scheduled",
        acknowledgement=None,
        environment={"ROLE_RADAR_CONTINUOUS_ENABLED": "true"},
    )


def test_provider_summary_is_allowlisted_and_omits_secrets() -> None:
    config = AcquisitionConfig(config_version="test")
    summary = provider_summary(config, "discovery")

    assert summary["providers"] == {"brave": "omitted", "tavily": "omitted"}
    assert summary["jobicy"] == "omitted"
    assert "credential" not in str(summary).casefold()


def test_legacy_discovery_runtime_is_zero_network_and_zero_write(
    db_session: Session, settings: Settings
) -> None:
    config = AcquisitionConfig(config_version="test")
    result = run_discovery_once(
        db_session,
        settings=settings,
        config=config,
        now=AS_OF,
        owner="runtime-test",
    )

    assert result.exit_code == EXIT_PRECONDITION
    assert result.payload == {
        "schema_version": "continuous-discovery-v2-result-v1",
        "result": "blocked",
        "code": "discovery_v2_command_required",
    }
    assert db_session.query(Source).count() == 0


def test_acquisition_runtime_requires_profile_first_worker(
    db_session: Session, settings: Settings
) -> None:
    with pytest.raises(RuntimeCompositionError) as blocked:
        run_acquisition_once(
            db_session,
            settings=settings,
            now=AS_OF,
            owner="runtime-test",
            canary_id="zero-jobs",
        )
    assert blocked.value.code == "profile_first_worker_required"


class _EmptyCollector:
    async def collect(self, _snapshot: object, _runtime: object) -> CollectionSuccess:
        return CollectionSuccess(status="ok", jobs=(), metrics=CollectionMetrics())
