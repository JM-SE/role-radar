"""File-backed migration smoke for the F6 -> F7 chain."""

import os
import subprocess
import sys
from pathlib import Path


def _alembic(database: Path, *arguments: str) -> None:
    environment = {**os.environ, "ROLE_RADAR_DATABASE_URL": f"sqlite:///{database}"}
    subprocess.run(
        [sys.executable, "-m", "alembic", *arguments],
        check=True,
        cwd=Path(__file__).parents[2],
        env=environment,
        capture_output=True,
        text=True,
    )


def test_fresh_and_f6_upgrade_downgrade_smoke(tmp_path: Path) -> None:
    database = tmp_path / "phase07.db"
    _alembic(database, "upgrade", "head")
    _alembic(database, "downgrade", "577682b6d35a")
    _alembic(database, "upgrade", "head")
