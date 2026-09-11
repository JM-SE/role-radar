"""Operator CLI for the explicitly authorized real R2 Gate C operation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, cast

from role_radar.config import Settings
from role_radar.evaluation.r2_real_gate_c_runner import (
    DEFAULT_LIVE_TTL_SECONDS,
    RealGateCOperationError,
    open_runtime_inputs,
    prepare_live_packet,
    run_live_gate_c,
)


def register_parser(subparsers: Any) -> argparse.ArgumentParser:
    parser = subparsers.add_parser("r2-real-gate-c")
    commands = parser.add_subparsers(dest="r2_real_gate_c_command", required=True)

    prepare = commands.add_parser("prepare")
    prepare.add_argument("--template", required=True)
    prepare.add_argument("--packet", required=True)
    prepare.add_argument("--evidence-root", required=True)
    prepare.add_argument("--approval-reference", required=True)
    prepare.add_argument("--repo", default=".")
    prepare.add_argument("--ttl-seconds", type=int, default=DEFAULT_LIVE_TTL_SECONDS)

    run = commands.add_parser("run")
    run.add_argument("--packet", required=True)
    run.add_argument("--approval-reference", required=True)
    run.add_argument("--repo", default=".")
    run.add_argument("--history-root", action="append", dest="history_roots", required=True)
    run.add_argument("--verdict", required=True)
    run.add_argument("--policy", default="/etc/role-radar/discovery-policy.toml")
    run.add_argument("--acquisition-config", default="/etc/role-radar/acquisition.toml")
    run.add_argument("--database-url")
    return cast(argparse.ArgumentParser, parser)


def _print_error(code: str) -> int:
    print(json.dumps({"result": "blocked", "code": code, "gate": "C"}, sort_keys=True))
    return 2


def run(args: argparse.Namespace) -> int:
    try:
        command = args.r2_real_gate_c_command
        if command == "prepare":
            payload = prepare_live_packet(
                template_path=Path(args.template),
                output_path=Path(args.packet),
                evidence_root=Path(args.evidence_root),
                approval_reference=args.approval_reference,
                repo_path=Path(args.repo),
                ttl_seconds=args.ttl_seconds,
            )
            print(json.dumps(payload, sort_keys=True))
            return 0
        if command != "run":
            return _print_error("r2_gate_c_command_invalid")

        settings = Settings(database_url=args.database_url) if args.database_url else Settings()
        engine, session, config, plan = open_runtime_inputs(
            database_url=settings.database_url,
            policy_path=Path(args.policy),
            acquisition_config_path=Path(args.acquisition_config),
        )
        try:
            roots = tuple(Path(item) for item in args.history_roots)
            execution = run_live_gate_c(
                packet_path=Path(args.packet),
                repo_path=Path(args.repo),
                history_roots=roots,
                verdict_path=Path(args.verdict),
                approval_reference=args.approval_reference,
                config=config,
                plan=plan,
                session=session,
            )
        finally:
            session.close()
            engine.dispose()
        print(json.dumps(execution.as_dict(), sort_keys=True))
        return 0
    except RealGateCOperationError as exc:
        return _print_error(exc.code)
    except Exception:
        return _print_error("r2_gate_c_failed")


__all__ = ["register_parser", "run"]
