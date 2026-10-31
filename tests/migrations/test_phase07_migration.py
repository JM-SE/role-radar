"""File-backed migration smoke for the F6 -> F7 chain."""

import os
import subprocess
import sys
from pathlib import Path


def _alembic(
    database: Path, *arguments: str, check: bool = True
) -> subprocess.CompletedProcess[str]:
    environment = {**os.environ, "ROLE_RADAR_DATABASE_URL": f"sqlite:///{database}"}
    return subprocess.run(
        [sys.executable, "-m", "alembic", *arguments],
        check=check,
        cwd=Path(__file__).parents[2],
        env=environment,
        capture_output=True,
        text=True,
    )


def test_fresh_upgrade_and_data_loss_downgrade_guard(tmp_path: Path) -> None:
    database = tmp_path / "phase07.db"
    _alembic(database, "upgrade", "head")
    downgrade = _alembic(database, "downgrade", "577682b6d35a", check=False)
    assert downgrade.returncode == 1
    assert (
        "Cannot downgrade: retired threshold values and legacy member states were discarded"
        in downgrade.stderr
    )
