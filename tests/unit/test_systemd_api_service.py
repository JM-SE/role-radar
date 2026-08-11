"""Static checks for the F10.0 API systemd contract."""

from pathlib import Path

ROOT = Path(__file__).parents[2]
UNIT = (ROOT / "deploy/systemd/role-radar-api.service").read_text()
ENV_EXAMPLE = (ROOT / "deploy/systemd/role-radar.env.example").read_text()

def test_api_unit_requires_environment_file_and_expands_port() -> None:
    assert "EnvironmentFile=/etc/role-radar/role-radar.env" in UNIT
    assert "--port ${ROLE_RADAR_API_PORT}" in UNIT
    assert "--port 8000" not in UNIT
    assert "ExecStart=/bin/sh" not in UNIT



def test_api_port_example_is_operational_and_bounded() -> None:
    line = next(
        line for line in ENV_EXAMPLE.splitlines() if line.startswith("ROLE_RADAR_API_PORT=")
    )
    port = int(line.partition("=")[2])
    assert 1 <= port <= 65535
    assert port == 8010
