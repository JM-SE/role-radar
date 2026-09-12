"""Explicit, lazy CLI adapter for one recovered Post-C preregistration."""

from __future__ import annotations

import argparse
import json
from importlib import import_module
from typing import Any, cast


def register_parser(subparsers: Any) -> argparse.ArgumentParser:
    parser = subparsers.add_parser("r2-post-c")
    commands = parser.add_subparsers(dest="r2_post_c_command", required=True)
    recover = commands.add_parser("recover")
    for name in (
        "approval-reference",
        "operator-id",
        "window-start-utc",
        "expires-at-utc",
        "historical-root",
        "recovery-root",
        "output-root",
        "operation-id",
        "operation-sha256",
        "profile-id",
        "profile-sha256",
        "policy-sha256",
        "plan-sha256",
        "report-sha256",
        "source-plan-sha256",
        "evidence-sha256",
        "historical-approval-reference",
    ):
        recover.add_argument(f"--{name}", required=True)
    recover.add_argument("--profile-version", type=int, required=True)
    recover.add_argument("--source-key", action="append", required=True)
    recover.add_argument("--search-request-identity", action="append", required=True)
    recover.add_argument("--official-request-identity", action="append", required=True)
    return cast(argparse.ArgumentParser, parser)


def _error(code: str) -> int:
    print(json.dumps({"result": "blocked", "code": code}, sort_keys=True))
    return 2


def run(args: argparse.Namespace) -> int:
    if args.r2_post_c_command != "recover":
        return _error("r2_post_c_command_invalid")
    try:
        authorization_module = import_module(
            "role_radar.evaluation.profile_relevant_acquisition.post_c_recovery_authorization"
        )
        service_module = import_module(
            "role_radar.evaluation.profile_relevant_acquisition.post_c_preregistration_service"
        )
        PostCAuthorization = authorization_module.PostCAuthorization
        RecoveredFilesystemPrivateSealWriter = service_module.RecoveredFilesystemPrivateSealWriter
        preregister_recovered_post_c = service_module.preregister_recovered_post_c

        authorization = PostCAuthorization(
            action="offline_preregistration",
            approval_reference=args.approval_reference,
            operator_id=args.operator_id,
            window_start_utc=args.window_start_utc,
            expires_at_utc=args.expires_at_utc,
            historical_root=args.historical_root,
            recovery_root=args.recovery_root,
            output_root=args.output_root,
            operation_id=args.operation_id,
            operation_sha256=args.operation_sha256,
            profile_id=args.profile_id,
            profile_version=args.profile_version,
            profile_sha256=args.profile_sha256,
            policy_sha256=args.policy_sha256,
            plan_sha256=args.plan_sha256,
            report_sha256=args.report_sha256,
            source_plan_sha256=args.source_plan_sha256,
            evidence_sha256=args.evidence_sha256,
            historical_approval_reference=args.historical_approval_reference,
            source_keys=tuple(args.source_key),
            search_request_identities=tuple(args.search_request_identity),
            official_request_identities=tuple(args.official_request_identity),
        )
        result = preregister_recovered_post_c(
            authorization=authorization,
            writer=RecoveredFilesystemPrivateSealWriter(args.output_root),
        )
    except Exception as exc:
        return _error(getattr(exc, "code", "r2_post_c_recovery_failed"))
    print(json.dumps(result.as_dict(), sort_keys=True, separators=(",", ":")))
    return 0


__all__ = ["register_parser", "run"]
