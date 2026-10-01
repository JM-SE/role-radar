from pathlib import Path

ROOT = Path(__file__).parents[2]
SEARCH_CREDENTIALS = {
    "query-hmac:/etc/role-radar/credentials/query-hmac",
    "brave-free:/etc/role-radar/credentials/brave-free",
    "tavily-free:/etc/role-radar/credentials/tavily-free",
}


def _credential_directives(path: Path) -> set[str]:
    return {
        line.removeprefix("LoadCredential=")
        for line in path.read_text().splitlines()
        if line.startswith("LoadCredential=")
    }


def test_worker_units_mount_only_existing_search_credentials() -> None:
    worker = ROOT / "deploy/systemd/role-radar-worker.service"
    canary = ROOT / "deploy/systemd/role-radar-canary-worker@.service"

    assert _credential_directives(worker) == SEARCH_CREDENTIALS
    assert _credential_directives(canary) == SEARCH_CREDENTIALS


def test_canary_worker_is_exact_run_oneshot_without_restart() -> None:
    unit = (ROOT / "deploy/systemd/role-radar-canary-worker@.service").read_text()

    assert "Type=oneshot" in unit
    assert "ExecStart=/usr/bin/env role-radar worker --run-id %i" in unit
    assert "Restart=no" in unit
    assert "Restart=on-failure" not in unit
