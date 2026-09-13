"""Secret scan sobre artefactos Broker versionados (Slice B, offline)."""

from __future__ import annotations

import re
from pathlib import Path

BASE = Path("src/role_radar/broker/consumer-compat/v1")
FILES = (
    BASE / "structured-extraction.json",
    BASE / "deep-job-evaluation.json",
    BASE / "broker-dual-route-config.json",
)

SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9]{8,}"),
    re.compile(r"ghp_[A-Za-z0-9]+"),
    re.compile(r"gsk_[A-Za-z0-9]+"),
    re.compile(r"AKIA[0-9A-Z]{8,}"),
    re.compile(r"xoxb-[0-9A-Za-z-]+"),
    re.compile(r"-----BEGIN [A-Z ]+-----"),
    re.compile(r"[A-Za-z0-9_.~-]+:[^@\s/]+@[A-Za-z0-9.-]+"),
)

ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


def test_broker_artifacts_exist() -> None:
    for path in FILES:
        assert path.is_file(), f"missing broker artifact {path}"


def test_broker_artifacts_contain_no_secret_values() -> None:
    for path in FILES:
        text = path.read_text(encoding="utf-8")
        for pattern in SECRET_PATTERNS:
            assert pattern.search(text) is None, f"{path} matches {pattern.pattern}"


def test_credential_and_url_references_are_names_only() -> None:
    import json

    for path in FILES:
        payload = json.loads(path.read_text(encoding="utf-8"))
        backends = payload.get("backends", {}) if isinstance(payload, dict) else {}
        for name, backend in backends.items():
            assert isinstance(backend, dict), name
            for key in ("credential_env", "base_url", "model"):
                value = backend.get(key)
                if value is None:
                    continue
                assert isinstance(value, str), (name, key)
                if key == "credential_env":
                    assert ENV_NAME.fullmatch(value), (name, key, value)
                if key == "base_url":
                    assert value.startswith(("http://", "https://")), (name, value)
                    assert "@" not in value, (name, value)
        database = payload.get("database") if isinstance(payload, dict) else None
        if isinstance(database, dict):
            for key, value in database.items():
                if key.endswith("_env") and value is not None:
                    assert ENV_NAME.fullmatch(value), (key, value)
