"""Static, offline checks for the continuous systemd units."""

from pathlib import Path

ROOT = Path(__file__).parents[2]


def unit(name: str) -> str:
    return (ROOT / "deploy/systemd" / name).read_text(encoding="utf-8")


def test_continuous_timers_schedule_buenos_aires_and_persist() -> None:
    discovery = unit("role-radar-continuous-discovery.timer")
    acquisition = unit("role-radar-continuous-acquisition.timer")
    assert "OnCalendar=*-*-* 07:00:00 America/Argentina/Buenos_Aires" in discovery
    assert "OnCalendar=*-*-* 08:00:00 America/Argentina/Buenos_Aires" in acquisition
    assert discovery.count("Persistent=true") == 1
    assert acquisition.count("Persistent=true") == 1


def test_continuous_services_are_disabled_by_default_and_do_not_receive_credentials() -> None:
    for name in (
        "role-radar-continuous-discovery.service",
        "role-radar-continuous-acquisition.service",
    ):
        content = unit(name)
        assert "disabled by default" in content
        assert "ConditionPathExists=/etc/role-radar/disabled" not in content
        assert "EnvironmentFile=" not in content
        assert "NoNewPrivileges=true" in content
        assert "ProtectHome=true" in content
    discovery = unit("role-radar-continuous-discovery.service")
    acquisition = unit("role-radar-continuous-acquisition.service")
    assert discovery.count("LoadCredential=") == 3
    assert "LoadCredential=" not in acquisition
