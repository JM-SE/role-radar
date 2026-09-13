"""Aislamiento del adaptador Broker y del verificador offline (Slice B)."""

from __future__ import annotations

import ast
from pathlib import Path

FACTORY = "src/role_radar/broker/factory.py"
COMPAT_CHECK = "src/role_radar/broker/compat_check.py"

ALLOWED_FACTORY_ROLE_RADAR = frozenset(
    {
        "role_radar.broker.client",
        "role_radar.broker.fake",
        "role_radar.broker.protocols",
        "role_radar.config",
    }
)

FORBIDDEN_FACTORY_TOKENS = ("openai", "anthropic", "os.environ", "getenv")


def _source(relative: str) -> str:
    return Path(relative).read_text(encoding="utf-8")


def test_broker_factory_has_no_direct_model_clients() -> None:
    tree = ast.parse(_source(FACTORY))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.startswith("role_radar."):
                assert node.module in ALLOWED_FACTORY_ROLE_RADAR, (
                    f"factory imports unexpected module {node.module}"
                )
            else:
                assert node.module.split(".")[0] in {"typing", "httpx"}, (
                    f"factory imports unexpected third party {node.module}"
                )
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in {"typing", "httpx"}, (
                    f"factory imports unexpected module {alias.name}"
                )
    text = _source(FACTORY)
    for token in FORBIDDEN_FACTORY_TOKENS:
        assert token not in text, f"factory must not reference {token}"


def test_compat_check_is_stdlib_only() -> None:
    tree = ast.parse(_source(COMPAT_CHECK))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in {"sqlalchemy", "role_radar"}, (
                "compat_check must stay dependency-free"
            )
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in {"sqlalchemy", "role_radar"}, (
                    "compat_check must stay dependency-free"
                )


def test_consumer_compat_manifests_share_one_workload() -> None:
    import json

    base = Path("src/role_radar/broker/consumer-compat/v1")
    manifests = [
        json.loads((base / "structured-extraction.json").read_text(encoding="utf-8")),
        json.loads((base / "deep-job-evaluation.json").read_text(encoding="utf-8")),
    ]
    assert {item["version"] for item in manifests} == {"consumer-compat/v1"}
    assert {item["workload"] for item in manifests} == {"role-radar"}
    assert {item["capability"] for item in manifests} == {
        "structured-extraction",
        "deep-job-evaluation",
    }
