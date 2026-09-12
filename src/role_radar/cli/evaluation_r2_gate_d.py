"""Lazy, read-only CLI adapter for recovered Gate D compatibility preflight."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from importlib import import_module
from typing import Any, cast

PUBLIC_ERRORS = frozenset(
    {
        "gate_d_preflight_authorization_expired",
        "gate_d_preflight_trust_anchor_mismatch",
        "gate_d_preflight_artifact_invalid",
        "gate_d_preflight_provenance_mismatch",
        "gate_d_preflight_seal_hash_mismatch",
        "gate_d_preflight_seal_binding_mismatch",
        "gate_d_preflight_window_invalid",
        "gate_d_preflight_root_invalid",
        "gate_d_preflight_roots_overlap",
    }
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def register_parser(subparsers: Any) -> argparse.ArgumentParser:
    parser = subparsers.add_parser("r2-gate-d")
    commands = parser.add_subparsers(dest="r2_gate_d_command", required=True)
    preflight = commands.add_parser("preflight-recovered")
    for name in (
        "approval-reference",
        "operator-id",
        "window-start-utc",
        "expires-at-utc",
        "historical-root",
        "recovery-root",
        "post-c-root",
        "operation-id",
        "seal-sha256",
        "source-plan-sha256",
        "report-sha256",
        "post-c-authorization-sha256",
    ):
        preflight.add_argument(f"--{name}", required=True)
    preflight.add_argument("--source-key", action="append", required=True)
    return cast(argparse.ArgumentParser, parser)


def _blocked(code: str) -> int:
    print(json.dumps({"result": "blocked", "code": code}, sort_keys=True, separators=(",", ":")))
    return 2


def run(args: argparse.Namespace) -> int:
    if args.r2_gate_d_command != "preflight-recovered":
        return _blocked("gate_d_preflight_command_invalid")
    try:
        auth_module = import_module(
            "role_radar.evaluation.profile_relevant_acquisition.recovered_gate_d_authorization"
        )
        loader_module = import_module(
            "role_radar.evaluation.profile_relevant_acquisition.recovered_gate_d_loader"
        )
        assessor = import_module(
            "role_radar.evaluation.profile_relevant_acquisition.recovered_gate_d_compatibility"
        )
        authorization = auth_module.RecoveredGateDPreflightAuthorization(
            action=auth_module.ACTION,
            approval_reference=args.approval_reference,
            operator_id=args.operator_id,
            window_start_utc=args.window_start_utc,
            expires_at_utc=args.expires_at_utc,
            historical_root=args.historical_root,
            recovery_root=args.recovery_root,
            post_c_root=args.post_c_root,
            operation_id=args.operation_id,
            seal_sha256=args.seal_sha256,
            source_plan_sha256=args.source_plan_sha256,
            report_sha256=args.report_sha256,
            post_c_authorization_sha256=args.post_c_authorization_sha256,
            source_keys=tuple(args.source_key),
            clock=_utc_now,
        )
        result, terminal, count = loader_module.load_recovered_gate_d_preflight(
            authorization, clock=_utc_now
        )
        verdict = assessor.assess_recovered_gate_d_compatibility(
            authorization,
            predecessor_state=result,
            predecessor_terminal=terminal,
            source_count=count,
        )
        authorization.validate_current(_utc_now())
        print(json.dumps(verdict.as_dict(), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as exc:
        code = getattr(exc, "code", "gate_d_preflight_failed")
        return _blocked(code if code in PUBLIC_ERRORS else "gate_d_preflight_artifact_invalid")


__all__ = ["register_parser", "run"]
