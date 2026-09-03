import inspect

from role_radar.collectors.greenhouse import GreenhouseCollector
from role_radar.collectors.lever import LeverCollector
from role_radar.evaluation.r2_greenhouse_lever_factory import R2GreenhouseLeverFactory


def test_factory_has_only_named_provider_constructors() -> None:
    source = inspect.getsource(R2GreenhouseLeverFactory)
    assert "GreenhouseCollector" in source
    assert "LeverCollector" in source
    assert "create_collector" not in source
    assert "registry" not in source
    assert GreenhouseCollector is not LeverCollector
