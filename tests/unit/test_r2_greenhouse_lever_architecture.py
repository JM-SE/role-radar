from pathlib import Path

ROOT = Path(__file__).parents[2] / "src/role_radar/evaluation"


def test_bridge_has_no_jobicy_or_live_acquisition_route() -> None:
    for name in ("r2_greenhouse_lever_capability.py", "r2_greenhouse_lever_factory.py"):
        text = (ROOT / name).read_text()
        assert "Jobicy" not in text
        assert "LiveAcquisition" not in text
        assert "sqlalchemy" not in text.lower()
