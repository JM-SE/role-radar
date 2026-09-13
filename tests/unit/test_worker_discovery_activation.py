"""Composition seam for daily discovery activation in the worker."""

from __future__ import annotations

from role_radar.acquisition.configuration import AcquisitionConfig
from role_radar.acquisition.discovery_policy import DiscoveryPolicyFileError
from role_radar.services.search_routing_service import SearchRoutingService
from role_radar.worker.main import compose_discovery_provider, load_discovery_policy_v1

SECRET = b"0123456789abcdef0123456789abcdef"


def _factory() -> None:
    raise AssertionError("session factory must not be touched without providers")


def test_missing_secret_keeps_discovery_disabled() -> None:
    config = AcquisitionConfig(config_version="test")
    assert (
        compose_discovery_provider(
            _factory,  # type: ignore[arg-type]
            brave_search=object(),
            query_hmac=None,
            acquisition_config=config,
        )
        is None
    )


def test_missing_providers_keeps_discovery_disabled() -> None:
    config = AcquisitionConfig(config_version="test")
    assert (
        compose_discovery_provider(
            _factory,  # type: ignore[arg-type]
            query_hmac=SECRET,
            acquisition_config=config,
        )
        is None
    )


def test_missing_config_keeps_discovery_disabled() -> None:
    assert (
        compose_discovery_provider(
            _factory,  # type: ignore[arg-type]
            brave_search=object(),
            query_hmac=SECRET,
            acquisition_config=None,
        )
        is None
    )


def test_complete_capabilities_compose_provider(db_session) -> None:
    config = AcquisitionConfig(config_version="test")
    provider = compose_discovery_provider(
        lambda: db_session,
        brave_search=object(),
        query_hmac=SECRET,
        acquisition_config=config,
    )
    assert isinstance(provider, SearchRoutingService)


def test_policy_load_failure_degrades_to_none(monkeypatch) -> None:
    def _missing(*args: object, **kwargs: object) -> object:
        raise DiscoveryPolicyFileError("discovery_policy_unavailable")

    monkeypatch.setattr("role_radar.worker.main.load_discovery_policy", _missing)
    assert load_discovery_policy_v1() is None
