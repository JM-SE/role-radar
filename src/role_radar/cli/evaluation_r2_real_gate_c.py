"""Operator CLI for the explicitly authorized real R2 Gate C operation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, cast

from role_radar.evaluation.profile_relevant_acquisition.gate_c_recovery import (
    GateCRecoveryError,
    RecoveryTrustAnchor,
    recover_completed_partial,
)

DEFAULT_LIVE_TTL_SECONDS = 90 * 60


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

    recover = commands.add_parser("recover")
    recover.add_argument("--historical-root", required=True)
    recover.add_argument("--packet", required=True)
    recover.add_argument("--operation", required=True)
    recover.add_argument("--terminal-report", required=True)
    recover.add_argument("--recovery-root", required=True)
    recover.add_argument("--verdict", required=True)
    recover.add_argument("--approval-reference", required=True)
    recover.add_argument("--expected-operation-id", required=True)
    recover.add_argument("--expected-profile-id", required=True)
    recover.add_argument("--expected-profile-version", type=int, required=True)
    recover.add_argument("--expected-profile-sha256", required=True)
    recover.add_argument("--expected-policy-sha256", required=True)
    recover.add_argument("--expected-plan-sha256", required=True)
    recover.add_argument("--expected-report-sha256", required=True)
    recover.add_argument("--expected-state", required=True)
    recover.add_argument("--expected-terminal-code", required=True)
    recover.add_argument("--expected-source-key", action="append", required=True)
    recover.add_argument("--expected-search-request-identity", action="append", required=True)
    recover.add_argument("--expected-official-request-identity", action="append", required=True)
    return cast(argparse.ArgumentParser, parser)


def _print_error(code: str) -> int:
    print(json.dumps({"result": "blocked", "code": code, "gate": "C"}, sort_keys=True))
    return 2


def run(args: argparse.Namespace) -> int:
    try:
        command = args.r2_real_gate_c_command
        if command == "prepare":
            from role_radar.evaluation.r2_real_gate_c_runner import (
                RealGateCOperationError,
                prepare_live_packet,
            )

            try:
                payload = prepare_live_packet(
                    template_path=Path(args.template),
                    output_path=Path(args.packet),
                    evidence_root=Path(args.evidence_root),
                    approval_reference=args.approval_reference,
                    repo_path=Path(args.repo),
                    ttl_seconds=args.ttl_seconds,
                )
            except RealGateCOperationError as exc:
                return _print_error(exc.code)
            print(json.dumps(payload, sort_keys=True))
            return 0
        if command == "recover":
            anchor = RecoveryTrustAnchor(
                operation_id=args.expected_operation_id,
                profile_id=args.expected_profile_id,
                profile_version=args.expected_profile_version,
                profile_sha256=args.expected_profile_sha256,
                policy_sha256=args.expected_policy_sha256,
                plan_sha256=args.expected_plan_sha256,
                report_sha256=args.expected_report_sha256,
                state=args.expected_state,
                terminal_code=args.expected_terminal_code,
                source_keys=tuple(args.expected_source_key),
                search_request_identities=tuple(args.expected_search_request_identity),
                official_request_identities=tuple(args.expected_official_request_identity),
            )
            result = recover_completed_partial(
                historical_root=Path(args.historical_root),
                packet_path=Path(args.packet),
                operation_path=Path(args.operation),
                terminal_report_path=Path(args.terminal_report),
                recovery_root=Path(args.recovery_root),
                verdict_path=Path(args.verdict),
                approval_reference=args.approval_reference,
                trusted_anchor=anchor,
            )
            print(json.dumps(result.as_dict(), sort_keys=True))
            return 0
        if command != "run":
            return _print_error("r2_gate_c_command_invalid")

        from role_radar.config import Settings
        from role_radar.evaluation.r2_real_gate_c_runner import (
            open_runtime_inputs,
            run_live_gate_c,
        )

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
    except GateCRecoveryError as exc:
        return _print_error(exc.code)
    except Exception as exc:
        code = getattr(exc, "code", None)
        if isinstance(code, str) and code.startswith("r2_gate_c_"):
            return _print_error(code)
        return _print_error("r2_gate_c_failed")


__all__ = ["register_parser", "run"]
