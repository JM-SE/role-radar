"""Static architecture guards for F10.2 offline isolation."""

from pathlib import Path

PACKAGE = Path("src/role_radar/evaluation/blind_labeling")


def test_blind_labeling_package_does_not_reference_forbidden_runtime_integrations() -> None:
    forbidden = (
        "V2BundleStore",
        "SnapshotStore",
        "sqlalchemy",
        "requests",
        "httpx",
        "socket",
        "subprocess",
        "Broker",
        "llama",
    )
    for path in PACKAGE.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert not any(token in source for token in forbidden), path


def test_cli_registers_f10_2_without_application_settings_in_dispatch_path() -> None:
    source = Path("src/role_radar/cli/main.py").read_text(encoding="utf-8")
    assert 'evaluation_command == "f10-2"' in source
    dispatch = source[
        source.index('if args.evaluation_command == "f10-2"') : source.index(
            'if args.evaluation_command != "f10-1"'
        )
    ]
    assert "Settings()" not in dispatch
