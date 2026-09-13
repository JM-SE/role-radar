"""CLI del collector F2: wiring fino, sin lógica de pipeline.

The parser and the F10.1F fail-closed boundary are intentionally import-safe.
Application providers, database sessions, and runtime bodies are loaded only
inside the command that needs them.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy import Engine
    from sqlalchemy.orm import Session

    from role_radar.acquisition.configuration import AcquisitionConfig
    from role_radar.acquisition.readiness import CapabilityMetadata
    from role_radar.config import Settings as SettingsType
    from role_radar.discovery.protocols import SearchProvider
    from role_radar.services.linkedin_link_host_audit_service import LinkedInLinkHostAuditReport

DISCOVERY_QUERY = "greenhouse job board software engineer"


def Settings(*args: Any, **kwargs: Any) -> SettingsType:
    """Compatibility lazy constructor; importing this CLI imports no settings."""

    from role_radar.config import Settings as RealSettings

    return RealSettings(*args, **kwargs)


def _fixtures_dir() -> Path:
    cwd_fixtures = Path.cwd() / "fixtures"
    if cwd_fixtures.is_dir():
        return cwd_fixtures
    return Path(__file__).resolve().parents[3] / "fixtures"


def _open_session(settings: SettingsType) -> tuple[Engine, Session]:
    from role_radar.db.engine import get_engine
    from role_radar.db.session import get_session_factory

    engine = get_engine(settings.database_url)
    if settings.database_url.startswith("sqlite:///"):
        Path(settings.database_url.removeprefix("sqlite:///")).parent.mkdir(
            parents=True, exist_ok=True
        )
    return engine, get_session_factory(engine)()


def _seed_boards(settings: SettingsType, fixtures_dir: Path) -> int:
    from role_radar.domain.enums import SourceType
    from role_radar.services.source_service import SourceService, SourceServiceError

    engine, session = _open_session(settings)
    try:
        boards = json.loads((fixtures_dir / "greenhouse_boards.json").read_text())
        service = SourceService(session)
        for board in boards:
            config = {"board_token": board["board_token"]}
            if board.get("company") is not None:
                config["company"] = board["company"]
            try:
                service.create(
                    source_type=SourceType.GREENHOUSE,
                    name=board["name"],
                    configuration=config,
                )
            except SourceServiceError as exc:
                if exc.code != "source_key_conflict":
                    raise
        session.commit()
        return 0
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
        engine.dispose()


async def _run_collect(settings: SettingsType, reason: str) -> tuple[str, str, dict[str, int]]:
    from role_radar.services.collection_service import CollectionService

    engine, session = _open_session(settings)
    try:
        run = await CollectionService(session).run_collect(reason=reason)
        session.commit()
        return run.id, run.status.value, run.stats_json or {}
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
        engine.dispose()


async def _run_extract(settings: SettingsType, job_id: str) -> dict[str, object]:
    from role_radar.broker.factory import create_llm_provider
    from role_radar.services.extraction_service import ExtractionService

    engine, session = _open_session(settings)
    provider = create_llm_provider(settings)
    try:
        extraction = await ExtractionService(session, provider=provider).extract_job(job_id=job_id)
        session.commit()
        return {
            "extraction_id": extraction.id,
            "job_id": extraction.job_id,
            "status": extraction.validation_status.value,
            "attempt_count": extraction.attempt_count,
        }
    except Exception:
        session.rollback()
        raise
    finally:
        close = getattr(provider, "aclose", None)
        if close is not None:
            await close()
        session.close()
        engine.dispose()


async def _run_extract_pending(settings: SettingsType, limit: int) -> list[dict[str, object]]:
    from role_radar.broker.factory import create_llm_provider
    from role_radar.services.extraction_service import ExtractionService

    engine, session = _open_session(settings)
    provider = create_llm_provider(settings)
    try:
        extractions = await ExtractionService(session, provider=provider).extract_pending(
            limit=limit
        )
        session.commit()
        return [
            {
                "extraction_id": extraction.id,
                "job_id": extraction.job_id,
                "status": extraction.validation_status.value,
                "attempt_count": extraction.attempt_count,
            }
            for extraction in extractions
        ]
    except Exception:
        session.rollback()
        raise
    finally:
        close = getattr(provider, "aclose", None)
        if close is not None:
            await close()
        session.close()
        engine.dispose()


async def _run_discover(
    settings: SettingsType, provider: SearchProvider, query_text: str, max_results: int
) -> int:
    from role_radar.discovery.contracts import (
        KnownOfficialCandidate,
        ProviderIntent,
        SearchRequest,
        UnknownCandidate,
    )
    from role_radar.discovery.url_classifier import classify_url

    # Deprecated local preview only.  It intentionally does not open a DB,
    # does not fetch a URL, and never turns a result title/snippet into a
    # Source.  F8.5 owns real provider wiring.
    response = await provider.search(
        SearchRequest(
            operation_key="local-preview",
            query=query_text,
            query_key="local-preview",
            planner_version="local-preview",
            query_version="local-preview",
            max_results=min(max_results, 10),
            provider_intent=ProviderIntent.EXACT,
        )
    )
    known = unknown = rejected = 0
    for result in response.hits[:max_results]:
        classified = classify_url(result.url)
        if isinstance(classified, KnownOfficialCandidate):
            known += 1
        elif isinstance(classified, UnknownCandidate):
            unknown += 1
        else:
            rejected += 1
    print(
        json.dumps(
            {
                "candidates": len(response.hits[:max_results]),
                "known": known,
                "unknown": unknown,
                "rejected": rejected,
            }
        )
    )
    return 0


def _run_score(settings: SettingsType, job_id: str, profile_id: str | None) -> dict[str, object]:
    from role_radar.services.matching_service import MatchingService

    engine, session = _open_session(settings)
    try:
        score = MatchingService(session).score_job(job_id=job_id, profile_id=profile_id)
        session.commit()
        return {
            "score_id": score.id,
            "job_id": score.job_id,
            "profile_id": score.profile_id,
            "extraction_id": score.extraction_id,
            "scoring_version": score.scoring_version,
            "policy_version": score.policy_version,
            "score": score.preliminary_score,
            "eligible": score.eligible,
            "blocker_codes": [item["code"] for item in score.hard_blocker_json],
            "ambiguity_codes": [item["code"] for item in score.ambiguity_json],
        }
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
        engine.dispose()


def _run_score_pending(
    settings: SettingsType, limit: int, profile_id: str | None
) -> list[dict[str, object]]:
    from sqlalchemy import select

    from role_radar.db.models import Job
    from role_radar.services.matching_service import MatchingService

    engine, session = _open_session(settings)
    try:
        service = MatchingService(session)
        profile = service.resolve_profile(profile_id)
        from sqlalchemy import select

        from role_radar.db.models import Job

        jobs = list(
            session.scalars(select(Job).order_by(Job.first_seen_at.desc(), Job.id).limit(limit))
        )
        output: list[dict[str, object]] = []
        for job in jobs:
            score = service.score_job(job_id=job.id, profile_id=profile.id)
            session.commit()
            output.append(
                {
                    "score_id": score.id,
                    "job_id": score.job_id,
                    "profile_id": score.profile_id,
                    "extraction_id": score.extraction_id,
                    "scoring_version": score.scoring_version,
                    "policy_version": score.policy_version,
                    "score": score.preliminary_score,
                    "eligible": score.eligible,
                    "blocker_codes": [item["code"] for item in score.hard_blocker_json],
                    "ambiguity_codes": [item["code"] for item in score.ambiguity_json],
                }
            )
        return output
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
        engine.dispose()


def _parser() -> argparse.ArgumentParser:
    from role_radar.domain.enums import SourceType

    parser = argparse.ArgumentParser(prog="role-radar")
    subparsers = parser.add_subparsers(dest="command", required=True)
    collect = subparsers.add_parser("collect", help="colecta y persiste ofertas habilitadas")
    collect.add_argument("--reason", default="cli_collect")
    subparsers.add_parser("seed-boards", help="carga boards Greenhouse curados")
    discover = subparsers.add_parser("discover-boards", help="propone boards sin activarlos")
    discover.add_argument("--query", default=DISCOVERY_QUERY)
    discover.add_argument("--max-results", type=int, default=10)
    source = subparsers.add_parser("source", help="administra el catálogo local de sources")
    source_commands = source.add_subparsers(dest="source_command", required=True)
    source_list = source_commands.add_parser("list")
    source_list.add_argument(
        "--type", dest="source_type", choices=[item.value for item in SourceType]
    )
    source_list.add_argument("--enabled", choices=["true", "false"])
    source_list.add_argument("--archived", choices=["true", "false"])
    source_list.add_argument("--limit", type=int, default=50)
    source_list.add_argument("--offset", type=int, default=0)
    source_show = source_commands.add_parser("show")
    source_show.add_argument("id")
    source_create = source_commands.add_parser("create")
    source_create.add_argument(
        "--type",
        required=True,
        choices=[
            SourceType.GREENHOUSE.value,
            SourceType.LEVER.value,
            SourceType.EMAIL.value,
            SourceType.JOBICY.value,
        ],
    )
    source_create.add_argument("--name", required=True)
    source_create.add_argument("--board-token")
    source_create.add_argument("--site")
    source_create.add_argument("--region", choices=["global", "eu"])
    source_create.add_argument("--company")
    source_create.add_argument("--connection-alias")
    source_create.add_argument("--parser-profile")
    source_update = source_commands.add_parser("update")
    source_update.add_argument("id")
    source_update.add_argument("--revision", required=True, type=int)
    source_update.add_argument("--name")
    source_update.add_argument("--board-token")
    source_update.add_argument("--site")
    source_update.add_argument("--region", choices=["global", "eu"])
    source_update.add_argument("--company")
    source_update.add_argument("--connection-alias")
    source_update.add_argument("--parser-profile")
    for command in ("enable", "disable", "archive"):
        action = source_commands.add_parser(command)
        action.add_argument("id")
        action.add_argument("--revision", required=True, type=int)
        if command == "enable":
            action.add_argument("--config", default="/etc/role-radar/acquisition.toml")
    extract = subparsers.add_parser("extract", help="extrae un Job de forma estructurada")
    extract.add_argument("--job-id", required=True)
    pending = subparsers.add_parser("extract-pending", help="extrae Jobs pendientes")
    pending.add_argument("--limit", type=int, default=10)
    score = subparsers.add_parser("score", help="calcula el score determinista de un Job")
    score.add_argument("--job-id", required=True)
    score.add_argument("--profile-id")
    score_pending = subparsers.add_parser("score-pending", help="calcula scores pendientes")
    score_pending.add_argument("--limit", type=int, default=10)
    score_pending.add_argument("--profile-id")
    run = subparsers.add_parser("run", help="crea y consulta intents persistentes")
    run_commands = run.add_subparsers(dest="run_command", required=True)
    run_create = run_commands.add_parser("create")
    run_create.add_argument("--reason", default="manual")
    run_create.add_argument("--profile-id")
    run_create.add_argument("--idempotency-key")
    run_create.add_argument("--schedule-id")
    run_list = run_commands.add_parser("list")
    run_list.add_argument("--limit", type=int, default=50)
    run_list.add_argument("--offset", type=int, default=0)
    run_list.add_argument("--status")
    run_list.add_argument("--profile-id")
    run_show = run_commands.add_parser("show")
    run_show.add_argument("--run-id", required=True)
    run_retry = run_commands.add_parser("retry")
    run_retry.add_argument("--run-id", required=True)
    run_retry.add_argument("--idempotency-key")
    subparsers.add_parser("worker", help="procesa runs pending/recoverables")
    discovery = subparsers.add_parser("discovery", help="estado local de adquisición (read-only)")
    discovery_commands = discovery.add_subparsers(dest="discovery_command", required=True)
    discovery_commands.add_parser("status")
    discovery_commands.add_parser("budget")
    mailbox = subparsers.add_parser("mailbox", help="operaciones locales read-only del mailbox")
    mailbox_commands = mailbox.add_subparsers(dest="mailbox_command", required=True)
    mailbox_status = mailbox_commands.add_parser("status")
    mailbox_status.add_argument("source")
    mailbox_preflight = mailbox_commands.add_parser("preflight")
    mailbox_preflight.add_argument("source")
    mailbox_preflight.add_argument("--config", default="/etc/role-radar/acquisition.toml")
    mailbox_preflight.add_argument("--ack-live", action="store_true")
    mailbox_smoke = mailbox_commands.add_parser("smoke")
    mailbox_smoke.add_argument("source")
    mailbox_smoke.add_argument("--config", default="/etc/role-radar/acquisition.toml")
    mailbox_smoke.add_argument("--ack-live", action="store_true")
    mailbox_audit = mailbox_commands.add_parser("linkedin-host-audit")
    mailbox_audit.add_argument("source")
    mailbox_audit.add_argument("--config", default="/etc/role-radar/acquisition.toml")
    mailbox_audit.add_argument("--ack-live", action="store_true")
    mailbox_resolution = mailbox_commands.add_parser("linkedin-head-resolution")
    mailbox_resolution.add_argument("source")
    mailbox_resolution.add_argument("--config", default="/etc/role-radar/acquisition.toml")
    mailbox_resolution.add_argument("--ack-live", action="store_true")
    mailbox_reconcile = mailbox_commands.add_parser("reconcile")
    mailbox_reconcile.add_argument("source")
    mailbox_reconcile.add_argument("--revision", required=True, type=int)
    mailbox_reconcile.add_argument("--uidvalidity", required=True, type=int)
    mailbox_reconcile.add_argument("--ack", required=True)
    mailbox_reconcile.add_argument("--strategy", default="bounded-lookback")
    acquisition = subparsers.add_parser("acquisition", help="validación offline de adquisición")
    acquisition_commands = acquisition.add_subparsers(dest="acquisition_command", required=True)
    validate = acquisition_commands.add_parser("validate")
    validate.add_argument("--config", default="/etc/role-radar/acquisition.toml")
    validate.add_argument("--runtime", action="store_true")
    validate.add_argument("--require-ready")
    smoke = acquisition_commands.add_parser("smoke")
    smoke.add_argument("capability", choices=["jobicy", "brave", "tavily"])
    smoke.add_argument("--ack-live", action="store_true")
    smoke.add_argument("--confirmation")
    gate_b = acquisition_commands.add_parser("gate-b")
    gate_b.add_argument("--config", default="/etc/role-radar/acquisition.toml")
    gate_b.add_argument("--ack-live", action="store_true")
    gate_b.add_argument("--confirmation")
    for command_name in ("continuous-discovery", "continuous-acquisition"):
        continuous = subparsers.add_parser(
            command_name, help="continuous daily discovery/acquisition"
        )
        continuous_commands = continuous.add_subparsers(dest="continuous_command", required=True)
        run_continuous = continuous_commands.add_parser("run")
        run_continuous.add_argument("--manual-canary", action="store_true")
        run_continuous.add_argument("--scheduled", action="store_true")
        run_continuous.add_argument("--canary-id")
        run_continuous.add_argument("--acknowledgement")
        continuous_commands.add_parser("status")
        continuous_commands.add_parser("recover")
    from role_radar.cli.continuous_discovery_v2 import register_continuous_discovery_v2_parser

    register_continuous_discovery_v2_parser(subparsers)
    from role_radar.cli.feedback import register_feedback_parser

    register_feedback_parser(subparsers)
    evaluation = subparsers.add_parser(
        "evaluation", help="operaciones offline/controladas de evaluación"
    )
    evaluation_commands = evaluation.add_subparsers(dest="evaluation_command", required=True)
    f10_1 = evaluation_commands.add_parser("f10-1")
    f10_1_commands = f10_1.add_subparsers(dest="f10_1_command", required=True)
    f10_1_commands.add_parser("preflight")
    discover = f10_1_commands.add_parser("discover")
    discover.add_argument("--confirmation", required=True)
    plan = f10_1_commands.add_parser("plan")
    plan.add_argument("--file", required=True)
    f10_1_commands.add_parser("status")
    verify = f10_1_commands.add_parser("verify")
    verify.add_argument("--dataset-id", required=True)
    f10_1_commands.add_parser("abort")
    acquire = f10_1_commands.add_parser("acquire")
    acquire.add_argument("--file", required=True)
    acquire.add_argument("--plan-sha256", required=True)
    acquire.add_argument("--acknowledgement", required=True)
    f10_1c = evaluation_commands.add_parser("f10-1c")
    f10_1c_commands = f10_1c.add_subparsers(dest="f10_1c_command", required=True)
    f10_1c_commands.add_parser("preflight")
    f10_1c_plan = f10_1c_commands.add_parser("plan")
    f10_1c_plan.add_argument("--file")
    f10_1c_commands.add_parser("status")
    f10_1c_commands.add_parser("preview")
    freeze_f10_1c = f10_1c_commands.add_parser("freeze")
    freeze_f10_1c.add_argument("--acknowledgement", required=True)
    verify_f10_1c = f10_1c_commands.add_parser("verify")
    verify_f10_1c.add_argument("--dataset-id")
    f10_1c_commands.add_parser("abort")
    f10_2 = evaluation_commands.add_parser("f10-2")
    f10_2_commands = f10_2.add_subparsers(dest="f10_2_command", required=True)
    for command in ("status", "label", "review", "adjudicate", "preview-finalize"):
        command_parser = f10_2_commands.add_parser(command)
        command_parser.add_argument("--dataset-id", required=True)
    start_f10_2 = f10_2_commands.add_parser("start")
    start_f10_2.add_argument("--dataset-id", required=True)
    start_f10_2.add_argument("--acknowledgement", required=True)
    reopen_f10_2 = f10_2_commands.add_parser("reopen-first-pass")
    reopen_f10_2.add_argument("--dataset-id", required=True)
    reopen_f10_2.add_argument("--acknowledgement", required=True)
    finalize_f10_2 = f10_2_commands.add_parser("finalize")
    finalize_f10_2.add_argument("--dataset-id", required=True)
    finalize_f10_2.add_argument("--acknowledgement", required=True)
    verify_f10_2 = f10_2_commands.add_parser("verify")
    verify_f10_2.add_argument("--labelset-id", required=True)
    from role_radar.cli.evaluation_f10_1f import register_parser

    register_parser(evaluation_commands)
    # New namespace is registered lazily and is deliberately independent of
    # every historical F10.1 route.  Its runner remains BLOCK-0 until a
    # separately authorized runtime is supplied.
    from role_radar.cli.evaluation_r2_operation import register_parser as register_r2_parser

    register_r2_parser(evaluation_commands)
    from role_radar.cli.evaluation_r2_real_gate_c import (
        register_parser as register_real_gate_c_parser,
    )

    register_real_gate_c_parser(evaluation_commands)
    from role_radar.cli.evaluation_r2_post_c import register_parser as register_post_c_parser

    register_post_c_parser(evaluation_commands)
    from role_radar.cli.evaluation_r2_gate_d import register_parser as register_gate_d_parser

    register_gate_d_parser(evaluation_commands)
    return parser


def _run_evaluation(args: argparse.Namespace) -> int:
    """Gate-A CLI surface; live acquisition is deliberately fail-closed here."""
    if args.evaluation_command == "r2-operation":
        from role_radar.cli.evaluation_r2_operation import run

        return run(args)
    if args.evaluation_command == "r2-real-gate-c":
        from role_radar.cli.evaluation_r2_real_gate_c import run

        return run(args)
    if args.evaluation_command == "r2-post-c":
        from role_radar.cli.evaluation_r2_post_c import run

        return run(args)
    if args.evaluation_command == "r2-gate-d":
        from role_radar.cli.evaluation_r2_gate_d import run

        return run(args)
    if args.evaluation_command in {"f10-1", "f10-1c"}:
        # Both names are historical aliases.  Block every subcommand before
        # settings, filesystem, database, provider, or old runtime imports.
        print(
            json.dumps(
                {
                    "schema_version": "f10.1-historical-cli-v1",
                    "result": "blocked",
                    "code": "historical_command_non_executable",
                    "historical": True,
                },
                sort_keys=True,
            )
        )
        return 2
    if args.evaluation_command == "f10-2":
        from role_radar.cli.evaluation_f10_2 import run

        return run(args)
    if args.evaluation_command == "f10-1f":
        from role_radar.cli.evaluation_f10_1f import run

        return run(args)
    if args.evaluation_command != "f10-1":
        return 2
    # These commands belong to the historical F10.1 implementation.  Keep
    # their parser and internal test seams available, but remove operator
    # reachability before settings, database, filesystem, or providers are
    # constructed.  F10.1F never delegates to this namespace.
    if args.f10_1_command in {"discover", "acquire", "verify"}:
        print(
            json.dumps(
                {
                    "schema_version": "f10.1-historical-cli-v1",
                    "result": "blocked",
                    "code": "historical_command_non_executable",
                    "historical": True,
                },
                sort_keys=True,
            )
        )
        return 2
    from role_radar.acquisition.configuration import ProductionAcquisitionFilePolicy
    from role_radar.acquisition.jobicy_terms_evidence import JobicyEvidenceError
    from role_radar.evaluation.controlled_acquisition.configuration import (
        ConfigurationError,
        ControlledAcquisitionConfig,
    )
    from role_radar.evaluation.controlled_acquisition.source_plan import (
        PlanError,
        SourcePlan,
        load_plan,
        validate_live_plan_v2,
    )

    command = args.f10_1_command
    if command == "preflight":
        try:
            config = ControlledAcquisitionConfig.from_env()
            config.require_approved_run()
            print(
                json.dumps(
                    {
                        "schema_version": "f10.1-preflight-v1",
                        "result": "ready_for_plan",
                        "lookback_days": config.lookback_days,
                        "live_acquisition": "not_authorized",
                    },
                    sort_keys=True,
                )
            )
            return 0
        except ConfigurationError as exc:
            print(json.dumps({"result": "blocked", "code": exc.code}, sort_keys=True))
            return 2
    if command == "discover":
        try:
            from role_radar.acquisition.configuration import load_acquisition_config
            from role_radar.acquisition.credentials import CredentialResolver
            from role_radar.acquisition.gate_b import build_search_runtime
            from role_radar.db.session import get_session_factory
            from role_radar.evaluation.controlled_acquisition.discovery import (
                DiscoveryOrchestrator,
                DiscoveryReport,
                LazyDiscoverySearchProvider,
                OfficialBoardVerifier,
                require_discovery_confirmation,
                write_discovery_artifacts,
            )
            from role_radar.evaluation.controlled_acquisition.journal import Journal
            from role_radar.evaluation.controlled_acquisition.protocols import (
                BASELINE_PROFILE_ID,
                BASELINE_PROFILE_SCHEMA_VERSION,
                BASELINE_PROFILE_SHA256,
                BASELINE_PROFILE_VERSION,
            )
            from role_radar.evaluation.controlled_acquisition.runtime import (
                SqlAlchemyHistoricalInventory,
                SqlAlchemyRuntimeSafety,
                SystemdServiceGuard,
                active_profile_identity,
                open_readonly_engine,
                read_deployment_identity,
                verify_deployment_provenance,
                verify_profile_identity,
            )

            require_discovery_confirmation(args.confirmation)
            config = ControlledAcquisitionConfig.from_env()
            config.require_approved_run()
            settings = Settings()
            engine = open_readonly_engine(settings.database_url)
            session = get_session_factory(engine)()
            guard = SystemdServiceGuard()
            guard.assert_inactive()
            SqlAlchemyRuntimeSafety(session).assert_no_active_normal_runs()
            inventory = SqlAlchemyHistoricalInventory(session)
            inventory.capture_before_requests()
            profile_id, profile_version, profile_schema, profile_sha = active_profile_identity(
                session
            )
            if (
                profile_id != BASELINE_PROFILE_ID
                or profile_version != BASELINE_PROFILE_VERSION
                or profile_schema != BASELINE_PROFILE_SCHEMA_VERSION
                or profile_sha != BASELINE_PROFILE_SHA256
            ):
                raise ValueError("profile_baseline_mismatch")
            markers = read_deployment_identity()
            if (
                markers[".deployed-diff-sha256"]
                != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                or markers[".deployed-status-sha256"]
                != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                or markers[".deployed-alembic-head"] != "e7a4c9f1b2d3"
            ):
                raise ValueError("deployment_provenance_invalid")
            acquisition = load_acquisition_config(policy=ProductionAcquisitionFilePolicy())
            if acquisition.discovery is None:
                raise ValueError("query_hmac_config_missing")
            resolver = CredentialResolver()
            query_hmac = resolver.resolve(
                acquisition.discovery.query_hmac_handle, text=False
            ).get_secret_value()
            brave_runtime = build_search_runtime("brave", acquisition, resolver)
            tavily_runtime = LazyDiscoverySearchProvider(
                lambda: build_search_runtime("tavily", acquisition, resolver).provider,
                provider="tavily",
            )
            as_of = datetime.now(UTC).replace(microsecond=0)
            discovery_journal = Journal(Path(config.snapshot_root) / "discovery-journal.json")
            try:

                async def run_discovery() -> tuple[DiscoveryReport, SourcePlan]:
                    async with brave_runtime.provider as brave:
                        try:
                            return await DiscoveryOrchestrator(
                                query_hmac=query_hmac,
                                verifier=OfficialBoardVerifier(journal=discovery_journal),
                                journal=discovery_journal,
                            ).run(
                                brave=brave,
                                tavily=tavily_runtime,
                                selection_as_of_utc=as_of,
                                profile_sha256=profile_sha,
                                profile_id=profile_id,
                                profile_version=profile_version,
                                profile_schema_version=profile_schema,
                                source_commit=markers[".deployed-commit"],
                                source_diff_sha256=markers[".deployed-diff-sha256"],
                                source_status_sha256=markers[".deployed-status-sha256"],
                                alembic_head=markers[".deployed-alembic-head"],
                            )
                        finally:
                            await tavily_runtime.aclose()

                report, plan = asyncio.run(run_discovery())
                write_discovery_artifacts(config.snapshot_root, report, plan)
                print(
                    json.dumps(
                        report.sanitized_dict() | {"plan_sha256": plan.sha256}, sort_keys=True
                    )
                )
                return 0
            finally:
                session.close()
                engine.dispose()
        except (OSError, ConfigurationError, ValueError, JobicyEvidenceError) as exc:
            print(
                json.dumps(
                    {"result": "blocked", "code": getattr(exc, "code", "discovery_failed")},
                    sort_keys=True,
                )
            )
            return 3
    if command == "plan":
        try:
            payload = json.loads(Path(args.file).read_text(encoding="utf-8"))
            plan = load_plan(payload)
            print(json.dumps({"result": "valid", "plan_sha256": plan.sha256}, sort_keys=True))
            return 0
        except (OSError, json.JSONDecodeError, PlanError, TypeError, ValueError):
            print(json.dumps({"result": "invalid", "code": "plan_invalid"}, sort_keys=True))
            return 2
    if command == "verify":
        from role_radar.evaluation.controlled_acquisition.snapshot import SnapshotStore

        result = SnapshotStore(Path("/opt/role-radar/data/evaluation/f10.1")).verify(
            args.dataset_id
        )
        print(json.dumps({"result": "verified" if result else "failed"}, sort_keys=True))
        return 0 if result else 3
    if command == "status":
        print(json.dumps({"result": "offline_status", "live_acquisition": "not_authorized"}))
        return 0
    if command == "abort":
        print(json.dumps({"result": "offline_abort_requires_operator_recovery"}))
        return 3
    if command == "acquire":
        try:
            from role_radar.acquisition.credentials import CredentialResolver
            from role_radar.collectors.policy import CollectionRunBudget
            from role_radar.collectors.protocols import CollectorRuntime
            from role_radar.collectors.registry import CollectorContext
            from role_radar.db.session import get_session_factory
            from role_radar.evaluation.controlled_acquisition.acquisition import (
                EphemeralCollectorTaskFactory,
            )
            from role_radar.evaluation.controlled_acquisition.live import (
                LiveAcquisition,
                LiveAdapters,
            )
            from role_radar.evaluation.controlled_acquisition.runtime import (
                SqlAlchemyHistoricalInventory,
                SqlAlchemyRuntimeSafety,
                SystemdServiceGuard,
                open_readonly_engine,
                verify_deployment_provenance,
                verify_jobicy_plan_terms,
                verify_profile_identity,
            )
            from role_radar.evaluation.controlled_acquisition.snapshot import SnapshotStore
            from role_radar.evaluation.controlled_acquisition.source_plan import load_plan

            config = ControlledAcquisitionConfig.from_env()
            config.require_approved_run()
            plan_payload = json.loads(Path(args.file).read_text(encoding="utf-8"))
            plan = load_plan(plan_payload)
            if plan.sha256 != args.plan_sha256:
                raise PlanError("plan_hash_mismatch")
            selection_as_of = validate_live_plan_v2(plan)
            verify_jobicy_plan_terms(plan)
            settings = Settings()
            verify_deployment_provenance(plan)
            engine = open_readonly_engine(settings.database_url)
            session = get_session_factory(engine)()
            guard = SystemdServiceGuard()
            inventory = SqlAlchemyHistoricalInventory(session)
            task_factory = EphemeralCollectorTaskFactory(context=CollectorContext())
            guard.assert_inactive()
            try:
                verify_profile_identity(
                    session,
                    profile_id=plan.profile_id or "",
                    profile_version=plan.profile_version or 0,
                    profile_schema_version=plan.profile_schema_version or 0,
                    profile_sha256=plan.profile_sha256 or "",
                )
                run_result = asyncio.run(
                    LiveAcquisition(
                        config=config,
                        adapters=LiveAdapters(
                            source_state=None,
                            inventory=inventory,
                            tasks=task_factory.build,
                            runtime=CollectorRuntime(
                                budget=CollectionRunBudget(config.max_wire_attempts),
                            ),
                            snapshot_store=SnapshotStore(Path(config.snapshot_root)),
                            journal=Journal(Path(config.snapshot_root) / "operation-journal.json"),
                            prepare_services=lambda: None,
                            restore_services=lambda: None,
                            assert_runtime_safe=lambda: SqlAlchemyRuntimeSafety(
                                session
                            ).assert_no_active_normal_runs(),
                            assert_profile=lambda approved_plan: verify_profile_identity(
                                session,
                                profile_id=approved_plan.profile_id or "",
                                profile_version=approved_plan.profile_version or 0,
                                profile_schema_version=approved_plan.profile_schema_version or 0,
                                profile_sha256=approved_plan.profile_sha256 or "",
                            ),
                            assert_deployment=lambda approved_plan: verify_deployment_provenance(
                                approved_plan
                            ),
                        ),
                    ).run(
                        plan=plan,
                        profile_sha256=plan.profile_sha256 or "",
                        acknowledgement=args.acknowledgement,
                        source_ids=(),
                        selection_as_of_utc=selection_as_of,
                    )
                )
                print(json.dumps({"result": run_result.state.value}, sort_keys=True))
                return 0 if run_result.state.value == "completed" else 3
            finally:
                guard.restore()
                session.close()
                engine.dispose()
        except (OSError, json.JSONDecodeError, ConfigurationError, PlanError, ValueError) as exc:
            print(
                json.dumps(
                    {"result": "blocked", "code": getattr(exc, "code", "gate_b_blocked")},
                    sort_keys=True,
                )
            )
            return 3
    return 2


def _source_payload(source: object) -> dict[str, object]:
    from role_radar.sources.public import project_public_configuration

    row = source
    public = project_public_configuration(row.type, row.configuration_version, row.configuration)  # type: ignore[attr-defined]
    return {
        "id": row.id,  # type: ignore[attr-defined]
        "source_type": row.type.value,  # type: ignore[attr-defined]
        "source_key": row.source_key,  # type: ignore[attr-defined]
        "name": row.name,  # type: ignore[attr-defined]
        "configuration_version": row.configuration_version,  # type: ignore[attr-defined]
        "public_configuration": public.as_dict() if hasattr(public, "as_dict") else public,
        "enabled": row.enabled,  # type: ignore[attr-defined]
        "revision": row.revision,  # type: ignore[attr-defined]
        "archived_at": row.archived_at.isoformat() if row.archived_at else None,  # type: ignore[attr-defined]
    }


def _run_acquisition(settings: SettingsType, args: argparse.Namespace) -> int:
    """Offline validation only; no engine, provider, socket, or secret value."""
    from role_radar.acquisition.activation import ActivationError, validate_jobicy_activation
    from role_radar.acquisition.configuration import (
        DevelopmentAcquisitionFilePolicy,
        ProductionAcquisitionFilePolicy,
        load_acquisition_config,
    )
    from role_radar.acquisition.jobicy_terms_evidence import (
        JobicyEvidenceError,
        load_jobicy_terms_evidence,
    )
    from role_radar.acquisition.readiness import CapabilityMetadata, calculate_readiness

    policy = (
        ProductionAcquisitionFilePolicy()
        if args.config == "/etc/role-radar/acquisition.toml"
        else DevelopmentAcquisitionFilePolicy()
    )
    try:
        config = load_acquisition_config(args.config, policy=policy)
        metadata: dict[str, CapabilityMetadata] = {}
        if args.runtime:
            metadata = _runtime_acquisition_metadata(config)
        if config.jobicy is not None:
            try:
                evidence = load_jobicy_terms_evidence(config.jobicy.terms_sha256)
                validate_jobicy_activation(
                    evidence,
                    terms_sha256=config.jobicy.terms_sha256,
                    reviewed_at=config.jobicy.reviewed_at,
                    fair_use_ack=config.jobicy.fair_use_ack,
                    preserve_destination_ack=config.jobicy.preserve_destination_ack,
                    no_redistribution_ack=config.jobicy.no_redistribution_ack,
                    now=datetime.now(UTC),
                )
                metadata["jobicy"] = CapabilityMetadata()
            except (JobicyEvidenceError, ActivationError) as exc:
                metadata["jobicy"] = CapabilityMetadata(terms_code=exc.code)
        report = calculate_readiness(
            config,
            metadata=metadata,
            policy=policy.name,
            runtime=args.runtime,
        )
        print(json.dumps(report.as_dict(), sort_keys=True))
        if args.require_ready is not None:
            target = next(
                (item for item in report.capabilities if item.capability == args.require_ready),
                None,
            )
            return 0 if target is not None and target.state == "ready" else 3
        return 0
    except Exception as exc:
        code = getattr(exc, "code", "config_invalid")
        print(
            json.dumps(
                {
                    "schema_version": "acquisition-readiness-v1",
                    "state": "blocked",
                    "codes": [code],
                }
            )
        )
        return 2


def _runtime_acquisition_metadata(
    config: AcquisitionConfig,
) -> dict[str, CapabilityMetadata]:
    """Inspect every enabled capability without returning secret material."""
    from role_radar.acquisition.activation import ActivationError, parse_xoauth_expiry
    from role_radar.acquisition.credentials import CredentialError, CredentialResolver
    from role_radar.acquisition.readiness import CapabilityMetadata

    metadata: dict[str, CapabilityMetadata] = {}
    try:
        resolver = CredentialResolver()
    except CredentialError as exc:
        code = exc.code
        if config.discovery is not None and (
            config.brave_free.enabled or config.tavily_free.enabled or config.brave_paid.enabled
        ):
            metadata["query_hmac"] = CapabilityMetadata(config_code=code)
        for name, enabled in (
            ("brave", config.brave_free.enabled or config.brave_paid.enabled),
            ("tavily", config.tavily_free.enabled),
        ):
            if enabled:
                metadata[name] = CapabilityMetadata(config_code=code)
        for alias in config.mailboxes:
            metadata[f"mailbox:{alias}"] = CapabilityMetadata(config_code=code)
        return metadata

    def check_handles(
        capability: str,
        handles: tuple[str, ...],
        *,
        expiry_handle: str | None = None,
    ) -> None:
        available: set[str] = set()
        error_code: str | None = None
        for handle in handles:
            try:
                resolver.resolve(handle, text=True)
                available.add(handle)
            except CredentialError as exc:
                error_code = error_code or exc.code
        if expiry_handle is not None and expiry_handle in available:
            try:
                parse_xoauth_expiry(
                    resolver.resolve(expiry_handle, text=True).get_secret_value(),
                    now=datetime.now(UTC),
                )
            except (CredentialError, ActivationError) as exc:
                error_code = error_code or getattr(exc, "code", "oauth_expiry_invalid")
        metadata[capability] = CapabilityMetadata(
            frozenset(available),
            oauth_code=error_code if expiry_handle is not None else None,
            config_code=error_code if expiry_handle is None else None,
        )

    if config.discovery is not None and (
        config.brave_free.enabled or config.tavily_free.enabled or config.brave_paid.enabled
    ):
        check_handles("query_hmac", (config.discovery.query_hmac_handle,))
    if config.brave_free.enabled or config.brave_paid.enabled:
        assert config.brave_free.credential_handle is not None
        check_handles("brave", (config.brave_free.credential_handle,))
    if config.tavily_free.enabled:
        assert config.tavily_free.credential_handle is not None
        check_handles("tavily", (config.tavily_free.credential_handle,))
    for alias, descriptor in config.mailboxes.items():
        auth_handle = (
            descriptor.oauth2_handle
            if descriptor.auth_mode == "xoauth2"
            else descriptor.app_password_handle
        )
        handles = tuple(
            item
            for item in (
                descriptor.username_handle,
                auth_handle,
                descriptor.oauth2_expiry_handle if descriptor.auth_mode == "xoauth2" else None,
                descriptor.message_hmac_handle,
                descriptor.content_hmac_handle,
            )
            if item is not None
        )
        check_handles(
            f"mailbox:{alias}",
            handles,
            expiry_handle=descriptor.oauth2_expiry_handle
            if descriptor.auth_mode == "xoauth2"
            else None,
        )
    return metadata


def _run_smoke(args: argparse.Namespace) -> int:
    from role_radar.services.acquisition_smoke_service import AcquisitionSmokeService

    result = asyncio.run(
        AcquisitionSmokeService().run(
            args.capability,
            ack_live=args.ack_live,
            confirmation=args.confirmation,
        )
    )
    print(json.dumps(result.as_dict(), sort_keys=True))
    return 0 if result.state == "ok" else 4 if result.code == "live_ack_required" else 3


def _run_gate_b(args: argparse.Namespace) -> int:
    from role_radar.acquisition.activation import (
        ActivationError,
        require_live_smoke_ack,
    )
    from role_radar.acquisition.configuration import (
        ProductionAcquisitionFilePolicy,
        load_acquisition_config,
    )
    from role_radar.acquisition.credentials import CredentialError, CredentialResolver
    from role_radar.acquisition.gate_b import (
        GateBSmokeConfigurationError,
        build_jobicy_collector,
        build_search_runtime,
        validate_jobicy_smoke_config,
    )
    from role_radar.services.acquisition_gate_b_smoke import (
        AcquisitionGateBSmokeService,
        GateBSmokeReport,
        GateBSmokeResult,
    )

    try:
        require_live_smoke_ack(
            ack_live=args.ack_live,
            confirmation=args.confirmation,
            capability="gate-b",
        )
        config = load_acquisition_config(
            args.config,
            policy=ProductionAcquisitionFilePolicy(),
        )
        validate_jobicy_smoke_config(config)
        resolver = CredentialResolver()
        brave = build_search_runtime("brave", config, resolver)
        tavily = build_search_runtime("tavily", config, resolver)
    except ActivationError as exc:
        print(
            json.dumps(
                {
                    "schema_version": "acquisition-gate-b-v1",
                    "state": "blocked",
                    "code": exc.code,
                }
            )
        )
        return 4
    except (GateBSmokeConfigurationError, CredentialError, OSError, ValueError) as exc:
        code = getattr(exc, "code", "config_invalid")
        print(
            json.dumps(
                {
                    "schema_version": "acquisition-gate-b-v1",
                    "state": "blocked",
                    "code": code,
                }
            )
        )
        return 3

    async def run() -> GateBSmokeReport:
        service = AcquisitionGateBSmokeService()
        jobicy = build_jobicy_collector()

        async def run_brave() -> GateBSmokeResult:
            async with brave.provider:
                return await service.run_search("brave", brave.provider, brave.request)

        async def run_tavily() -> GateBSmokeResult:
            async with tavily.provider:
                return await service.run_search("tavily", tavily.provider, tavily.request)

        return await service.run_sequence(
            (
                ("jobicy", lambda: service.run_jobicy(jobicy)),
                ("brave", run_brave),
                ("tavily", run_tavily),
            )
        )

    try:
        report = asyncio.run(run())
    except Exception:
        print(
            json.dumps(
                {
                    "schema_version": "acquisition-gate-b-v1",
                    "state": "failed",
                    "code": "smoke_failed",
                }
            )
        )
        return 3
    print(json.dumps(report.as_dict(), sort_keys=True))
    return 0 if report.state == "ok" else 3


def _run_source(settings: SettingsType, args: argparse.Namespace) -> int:
    from role_radar.acquisition.activation import validate_jobicy_activation
    from role_radar.acquisition.configuration import (
        ProductionAcquisitionFilePolicy,
        load_acquisition_config,
    )
    from role_radar.acquisition.jobicy_terms_evidence import load_jobicy_terms_evidence
    from role_radar.db.models import Source
    from role_radar.domain.enums import SourceType
    from role_radar.services.source_service import (
        RevisionConflict,
        SourceNotFound,
        SourceService,
        SourceServiceError,
    )

    engine, session = _open_session(settings)
    acceptance = None
    try:
        if args.source_command == "enable":
            current = session.get(Source, args.id)
            if current is not None and current.type is SourceType.JOBICY:
                config = load_acquisition_config(
                    args.config, policy=ProductionAcquisitionFilePolicy()
                )
                if config.jobicy is None:
                    raise SourceServiceError("terms_missing")
                evidence = load_jobicy_terms_evidence(config.jobicy.terms_sha256)
                acceptance = validate_jobicy_activation(
                    evidence,
                    terms_sha256=config.jobicy.terms_sha256,
                    reviewed_at=config.jobicy.reviewed_at,
                    fair_use_ack=config.jobicy.fair_use_ack,
                    preserve_destination_ack=config.jobicy.preserve_destination_ack,
                    no_redistribution_ack=config.jobicy.no_redistribution_ack,
                    now=datetime.now(UTC),
                )
    except Exception:
        session.close()
        engine.dispose()
        raise
    service = SourceService(session, jobicy_terms=acceptance)
    try:
        if args.source_command == "list":

            def parse_bool(value: str | None) -> bool | None:
                return None if value is None else value == "true"

            rows, _total = service.list_sources(
                source_type=SourceType(args.source_type) if args.source_type else None,
                enabled=parse_bool(args.enabled),
                archived=parse_bool(args.archived),
                limit=args.limit,
                offset=args.offset,
            )
            print(json.dumps([_source_payload(row) for row in rows]))
            return 0
        if args.source_command == "show":
            print(json.dumps(_source_payload(service.get(args.id))))
            return 0
        if args.source_command == "create":
            source_type = SourceType(args.type)
            if source_type is SourceType.JOBICY:
                if any(
                    value is not None
                    for value in (
                        args.board_token,
                        args.site,
                        args.region,
                        args.company,
                        args.connection_alias,
                        args.parser_profile,
                    )
                ):
                    raise SourceServiceError("invalid_source_config")
                configuration = {"region": "latam", "remote_only": True}
            elif source_type is SourceType.GREENHOUSE:
                if args.site is not None or args.region is not None or args.board_token is None:
                    raise SourceServiceError("invalid_source_config")
                configuration = {"board_token": args.board_token}
            elif source_type is SourceType.EMAIL:
                if args.connection_alias is None or args.parser_profile is None:
                    raise SourceServiceError("invalid_source_config")
                configuration = {
                    "connection_alias": args.connection_alias,
                    "parser_profile": args.parser_profile,
                }
            else:
                if args.board_token is not None or args.site is None or args.region is None:
                    raise SourceServiceError("invalid_source_config")
                configuration = {"site": args.site, "region": args.region}
            if args.company is not None:
                configuration["company"] = args.company
            row = service.create(
                source_type=source_type, name=args.name, configuration=configuration
            )
        elif args.source_command == "update":
            current = service.get(args.id)
            if (
                args.name is None
                and args.board_token is None
                and args.site is None
                and args.region is None
                and args.company is None
                and args.connection_alias is None
                and args.parser_profile is None
            ):
                raise SourceServiceError("invalid_source_config")
            configuration = dict(current.configuration or {})
            if current.type is SourceType.GREENHOUSE and (
                args.site is not None or args.region is not None
            ):
                raise SourceServiceError("invalid_source_config")
            if current.type is SourceType.LEVER and args.board_token is not None:
                raise SourceServiceError("invalid_source_config")
            if args.board_token is not None:
                configuration["board_token"] = args.board_token
            if args.site is not None:
                configuration["site"] = args.site
            if args.region is not None:
                configuration["region"] = args.region
            if args.company is not None:
                configuration["company"] = args.company
            if args.connection_alias is not None:
                configuration["connection_alias"] = args.connection_alias
            if args.parser_profile is not None:
                configuration["parser_profile"] = args.parser_profile
            config_changed = any(
                value is not None
                for value in (
                    args.board_token,
                    args.site,
                    args.region,
                    args.company,
                    args.connection_alias,
                    args.parser_profile,
                )
            )
            row = service.update(
                args.id,
                expected_revision=args.revision,
                name=args.name,
                configuration=configuration if config_changed else None,
            )
        else:
            row = getattr(service, args.source_command)(args.id, expected_revision=args.revision)
        session.commit()
        print(json.dumps(_source_payload(row)))
        return 0
    except SourceNotFound as exc:
        session.rollback()
        print(f"role-radar: {exc.code}", file=sys.stderr)
        return 3
    except (RevisionConflict, SourceServiceError) as exc:
        session.rollback()
        print(f"role-radar: {exc.code}", file=sys.stderr)
        return 4 if exc.code == "revision_conflict" else 2
    finally:
        session.close()
        engine.dispose()


def _run_control(settings: SettingsType, args: argparse.Namespace) -> int:
    from role_radar.domain.enums import DiscoveryMode
    from role_radar.scheduler import latest_slot
    from role_radar.services.run_service import RunConflict, RunNotFound, RunService

    engine, session = _open_session(settings)
    try:
        service = RunService(session)
        if args.run_command == "create":
            reason = args.reason
            key = args.idempotency_key
            profile_id = args.profile_id
            if reason == "scheduled":
                profile_id = service.resolve_profile_id(profile_id)
                slot = latest_slot(
                    datetime.now(UTC),
                    schedule_id=args.schedule_id or settings.schedule_id,
                    hour_local=settings.schedule_hour_local,
                    minute_local=settings.schedule_minute_local,
                    timezone_name=settings.schedule_timezone,
                )
                key = (
                    key
                    or f"scheduler:{args.schedule_id or settings.schedule_id}:{slot}:{profile_id}"
                )
            run = service.create(
                reason=reason,
                profile_id=profile_id,
                idempotency_key=key,
                notification_mode="daily_digest" if reason == "scheduled" else "none",
                schedule_slot=slot if reason == "scheduled" else None,
                discovery_mode=(
                    DiscoveryMode.SCHEDULED_DUE if reason == "scheduled" else DiscoveryMode.NONE
                ),
            )
        elif args.run_command == "list":
            from role_radar.domain.enums import JobSearchRunStatus

            status = JobSearchRunStatus(args.status) if args.status else None
            runs = service.list(
                limit=args.limit, offset=args.offset, status=status, profile_id=args.profile_id
            )
            print(json.dumps([{"id": item.id, "status": item.status.value} for item in runs]))
            return 0
        elif args.run_command == "show":
            run = service.get(args.run_id)
        else:
            run = service.retry(args.run_id, idempotency_key=args.idempotency_key)
        session.commit()
        print(json.dumps({"id": run.id, "status": run.status.value}))
        return 0
    except (RunConflict, RunNotFound, ValueError) as exc:
        session.rollback()
        print(f"role-radar: {exc}", file=sys.stderr)
        return 1
    finally:
        session.close()
        engine.dispose()


def _run_discovery_readonly(settings: SettingsType, command: str) -> int:
    """Local, sanitized acquisition observability; never triggers a call."""
    from role_radar.repositories.acquisition import AcquisitionRepository

    engine, session = _open_session(settings)
    try:
        repository = AcquisitionRepository(session)
        now = datetime.now(UTC)
        periods = repository.list_periods(utc_month=now.strftime("%Y-%m"))
        if command == "budget":
            print(
                json.dumps(
                    [
                        {
                            "provider": row.provider,
                            "tier": row.tier,
                            "utc_month": row.utc_month,
                            "config_version": row.config_version,
                            "unit_limit": row.unit_limit,
                            "units_used": row.units_used,
                            "units_reserved": row.units_reserved,
                            "micro_usd_limit": row.micro_usd_limit,
                            "micro_usd_used": row.micro_usd_used,
                            "micro_usd_reserved": row.micro_usd_reserved,
                        }
                        for row in periods
                    ]
                )
            )
            return 0
        latest = repository.latest_call()
        budgets = [
            {
                "provider": row.provider,
                "tier": row.tier,
                "config_version": row.config_version,
                "enabled": row.unit_limit > 0 or row.micro_usd_limit > 0,
                "utc_month": row.utc_month,
                "unit_limit": row.unit_limit,
                "units_used": row.units_used,
                "units_reserved": row.units_reserved,
                "micro_usd_limit": row.micro_usd_limit,
                "micro_usd_used": row.micro_usd_used,
                "micro_usd_reserved": row.micro_usd_reserved,
            }
            for row in periods
        ]
        print(
            json.dumps(
                {
                    "periods": len(periods),
                    "budgets": budgets,
                    "latest_status": latest.status if latest else None,
                    "latest_error_code": latest.error_code if latest else None,
                    "freshness": latest.completed_at.isoformat()
                    if latest and latest.completed_at
                    else None,
                }
            )
        )
        return 0
    finally:
        session.close()
        engine.dispose()


def _run_mailbox(settings: SettingsType, args: argparse.Namespace) -> int:
    from role_radar.acquisition.configuration import (
        ProductionAcquisitionFilePolicy,
        load_acquisition_config,
    )
    from role_radar.acquisition.credentials import CredentialResolver, resolve_mailbox_credentials
    from role_radar.domain.enums import SourceType
    from role_radar.mailbox.configuration import EmailSourceConfigV1
    from role_radar.mailbox.imap_provider import GmailImapProvider
    from role_radar.repositories.mailbox_states import MailboxStateRepository
    from role_radar.services.mailbox_smoke_service import MailboxSmokeService

    if args.mailbox_command == "linkedin-head-resolution":
        return _run_linkedin_head_resolution(settings, args)
    if args.mailbox_command == "linkedin-host-audit":
        return _run_linkedin_host_audit(settings, args)
    if args.mailbox_command == "smoke" and not args.ack_live:
        print("role-radar: live_ack_required", file=sys.stderr)
        return 4
    engine, session = _open_session(settings)
    try:
        from role_radar.db.models import Source

        source = session.get(Source, args.source)
        if source is None or source.type is not SourceType.EMAIL:
            print("role-radar: source_not_found", file=sys.stderr)
            return 3
        if args.mailbox_command == "smoke":
            if source.enabled:
                print("role-radar: source_must_be_disabled", file=sys.stderr)
                return 3
            policy = ProductionAcquisitionFilePolicy()
            config = load_acquisition_config(args.config, policy=policy)
            email_config = EmailSourceConfigV1.model_validate(dict(source.configuration or {}))
            alias = email_config.connection_alias
            descriptor = config.mailboxes.get(alias)
            if descriptor is None:
                raise ValueError("mailbox descriptor unavailable")
            mailbox_descriptor = descriptor.descriptor()
            resolver = CredentialResolver()
            credentials = resolve_mailbox_credentials(mailbox_descriptor, resolver)
            provider = GmailImapProvider(mailbox_descriptor, credentials)
            session.close()
            engine.dispose()
            result = asyncio.run(
                MailboxSmokeService(provider, parser_profile=email_config.parser_profile).run()
            )
            print(json.dumps(result.as_dict(), sort_keys=True))
            return 0 if result.validated else 3
        if args.mailbox_command == "status":
            state = MailboxStateRepository(session).get(source.id)
            print(
                json.dumps(
                    {
                        "source_id": source.id,
                        "source_key": source.source_key,
                        "enabled": source.enabled,
                        "uidvalidity": state.uidvalidity if state else None,
                        "highest_terminal_uid": state.highest_terminal_uid if state else 0,
                        "revision": state.revision if state else None,
                        "last_error_code": state.last_error_code if state else None,
                    }
                )
            )
            return 0
        if args.mailbox_command == "preflight":
            if not args.ack_live:
                print("role-radar: live_ack_required", file=sys.stderr)
                return 4
            policy = ProductionAcquisitionFilePolicy()
            config = load_acquisition_config(args.config, policy=policy)
            alias = EmailSourceConfigV1.model_validate(
                dict(source.configuration or {})
            ).connection_alias
            descriptor = config.mailboxes.get(alias)
            if descriptor is None:
                raise ValueError("mailbox descriptor unavailable")
            mailbox_descriptor = descriptor.descriptor()
            resolver = CredentialResolver()
            credentials = resolve_mailbox_credentials(mailbox_descriptor, resolver)
            provider = GmailImapProvider(mailbox_descriptor, credentials)
            session.close()
            engine.dispose()
            try:
                preflight = asyncio.run(provider.preflight())
            finally:
                asyncio.run(provider.close())
            print(
                json.dumps(
                    {
                        "source_id": source.id,
                        "connection_alias": descriptor.connection_alias,
                        "uidvalidity": preflight.uidvalidity,
                        "readonly": preflight.readonly,
                        "validated": True,
                    }
                )
            )
            return 0
        state = MailboxStateRepository(session).reconcile(
            source.id,
            expected_revision=args.revision,
            observed_uidvalidity=args.uidvalidity,
            acknowledgement=args.ack,
            strategy=args.strategy,
            now=datetime.now(UTC),
        )
        session.commit()
        print(
            json.dumps(
                {
                    "source_id": source.id,
                    "uidvalidity": state.uidvalidity,
                    "revision": state.revision,
                }
            )
        )
        return 0
    except Exception as exc:
        session.rollback()
        print(f"role-radar: {exc}", file=sys.stderr)
        return 2
    finally:
        session.close()
        engine.dispose()


def _run_linkedin_host_audit(settings: SettingsType, args: argparse.Namespace) -> int:
    from role_radar.acquisition.configuration import (
        ProductionAcquisitionFilePolicy,
        load_acquisition_config,
    )
    from role_radar.acquisition.credentials import (
        CredentialError,
        CredentialResolver,
        resolve_mailbox_credentials,
    )
    from role_radar.db.models import Source
    from role_radar.domain.enums import SourceType
    from role_radar.mailbox.configuration import EmailSourceConfigV1
    from role_radar.mailbox.imap_provider import GmailImapProvider
    from role_radar.services.linkedin_link_host_audit_service import (
        LinkedInLinkHostAuditService,
    )

    try:
        engine, session = _open_session(settings)
    except Exception:
        report = _audit_failure_report("config")
        print(json.dumps(report.as_dict(), sort_keys=True))
        return 3
    provider: GmailImapProvider | None = None
    email_config: EmailSourceConfigV1 | None = None
    try:
        source = session.get(Source, args.source)
        if source is None or source.type is not SourceType.EMAIL:
            report = _audit_failure_report("source_not_found")
            print(json.dumps(report.as_dict(), sort_keys=True))
            return 3
        if source.enabled:
            report = _audit_failure_report("source_must_be_disabled")
            print(json.dumps(report.as_dict(), sort_keys=True))
            return 3
        try:
            email_config = EmailSourceConfigV1.model_validate(dict(source.configuration or {}))
            config = load_acquisition_config(
                args.config,
                policy=ProductionAcquisitionFilePolicy(),
            )
            descriptor = config.mailboxes.get(email_config.connection_alias)
            if descriptor is None:
                raise ValueError("mailbox descriptor unavailable")
            mailbox_descriptor = descriptor.descriptor()
            credentials = resolve_mailbox_credentials(mailbox_descriptor, CredentialResolver())
            provider = GmailImapProvider(mailbox_descriptor, credentials)
        except CredentialError:
            report = _audit_failure_report("credentials")
            print(json.dumps(report.as_dict(), sort_keys=True))
            return 3
        except (OSError, ValueError):
            report = _audit_failure_report("config")
            print(json.dumps(report.as_dict(), sort_keys=True))
            return 3
    except Exception:
        report = _audit_failure_report("protocol")
        print(json.dumps(report.as_dict(), sort_keys=True))
        return 3
    finally:
        session.close()
        engine.dispose()

    assert provider is not None
    assert email_config is not None
    try:
        report = asyncio.run(
            LinkedInLinkHostAuditService(
                provider,
                parser_profile=email_config.parser_profile,
            ).run()
        )
    except Exception:
        report = _audit_failure_report("protocol")
    print(json.dumps(report.as_dict(), sort_keys=True))
    return 0 if report.validated else 3


def _audit_failure_report(code: str) -> LinkedInLinkHostAuditReport:
    from role_radar.services.linkedin_link_host_audit_service import LinkedInLinkHostAuditReport

    return LinkedInLinkHostAuditReport(False, 0, 0, "unknown", "unknown", 0, 0, (), code)


def _run_linkedin_head_resolution(settings: SettingsType, args: argparse.Namespace) -> int:
    from role_radar.acquisition.configuration import (
        ProductionAcquisitionFilePolicy,
        load_acquisition_config,
    )
    from role_radar.acquisition.credentials import (
        CredentialError,
        CredentialResolver,
        resolve_mailbox_credentials,
    )
    from role_radar.db.models import Source
    from role_radar.domain.enums import SourceType
    from role_radar.mailbox.configuration import EmailSourceConfigV1
    from role_radar.mailbox.imap_provider import GmailImapProvider
    from role_radar.mailbox.linkedin_resolution.dns import (
        AttestedDNSResolver,
        AttestedEgressGuard,
        SystemdAttestationStore,
    )
    from role_radar.mailbox.linkedin_resolution.pinned_imap import pinned_gmail_session_factory
    from role_radar.mailbox.linkedin_resolution.resolver import LinkedInHeadResolver
    from role_radar.mailbox.linkedin_resolution.transport import PinnedHeadTransport
    from role_radar.services.linkedin_resolution_service import LinkedInResolutionMailboxService

    try:
        engine, session = _open_session(settings)
    except Exception:
        print(json.dumps(_resolution_failure("config"), sort_keys=True))
        return 3
    provider: GmailImapProvider | None = None
    email_config: EmailSourceConfigV1 | None = None
    attestation_store: SystemdAttestationStore | None = None
    try:
        source = session.get(Source, args.source)
        if source is None:
            print(json.dumps(_resolution_failure("source_not_found"), sort_keys=True))
            return 3
        if source.type is not SourceType.EMAIL:
            print(json.dumps(_resolution_failure("source_type_invalid"), sort_keys=True))
            return 3
        if (
            source.source_key != "email:role-radar"
            or source.archived_at is not None
            or source.enabled
        ):
            print(json.dumps(_resolution_failure("source_must_be_disabled"), sort_keys=True))
            return 3
        try:
            email_config = EmailSourceConfigV1.model_validate(dict(source.configuration or {}))
            config = load_acquisition_config(
                args.config,
                policy=ProductionAcquisitionFilePolicy(),
            )
            descriptor = config.mailboxes.get(email_config.connection_alias)
            if descriptor is None:
                raise ValueError("mailbox descriptor unavailable")
            mailbox_descriptor = descriptor.descriptor()
            credentials = resolve_mailbox_credentials(mailbox_descriptor, CredentialResolver())
            attestation_store = SystemdAttestationStore()
            attestation = attestation_store.load()
            provider = GmailImapProvider(
                mailbox_descriptor,
                credentials,
                session_factory=pinned_gmail_session_factory(
                    attestation.hosts.get("imap.gmail.com", ())
                ),
            )
        except CredentialError:
            print(json.dumps(_resolution_failure("config"), sort_keys=True))
            return 3
        except (OSError, ValueError):
            print(json.dumps(_resolution_failure("config"), sort_keys=True))
            return 3
    finally:
        session.close()
        engine.dispose()
    assert provider is not None
    assert email_config is not None
    assert attestation_store is not None
    try:
        resolver = LinkedInHeadResolver(
            PinnedHeadTransport(),
            AttestedDNSResolver(attestation_store),
            AttestedEgressGuard(attestation_store),
        )
    except Exception:
        provider_close = provider.close
        asyncio.run(provider_close())
        print(json.dumps(_resolution_failure("internal"), sort_keys=True))
        return 3
    try:
        report = asyncio.run(
            LinkedInResolutionMailboxService(
                provider,
                resolver,
                parser_profile=email_config.parser_profile,
                source_id=source.id,
                source_revision=source.revision,
            ).run()
        )
        payload = report.as_dict()
    except Exception:
        payload = _resolution_failure("internal")
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload["result"] == "intake" else 3


def _resolution_failure(code: str) -> dict[str, object]:
    return {
        "schema_version": "linkedin-head-resolution-v1",
        "policy_version": "linkedin-head-resolution-v1",
        "mode": "report_only",
        "source_state": "disabled",
        "proposal_state": "authenticated_linkedin",
        "result": "review",
        "request_count": 0,
        "redirect_count": 0,
        "final_ats": None,
        "terminal_code": code,
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "evaluation":
        return _run_evaluation(args)
    if args.command == "continuous-discovery-v2":
        return _run_continuous_discovery_v2(args)
    if args.command == "feedback":
        return _run_feedback(args)
    if args.command == "continuous-discovery":
        return _run_legacy_discovery_deprecated()
    if args.command == "continuous-acquisition":
        return _run_continuous_gate_a(args)
    if (
        args.command == "mailbox"
        and args.mailbox_command in {"linkedin-host-audit", "linkedin-head-resolution"}
        and not args.ack_live
    ):
        if args.mailbox_command == "linkedin-head-resolution":
            payload = _resolution_failure("live_ack_required")
        else:
            payload = _audit_failure_report("live_ack_required").as_dict()
        print(json.dumps(payload, sort_keys=True))
        return 4
    try:
        settings = Settings()
    except Exception:
        if args.command == "mailbox" and args.mailbox_command in {
            "linkedin-host-audit",
            "linkedin-head-resolution",
        }:
            if args.mailbox_command == "linkedin-head-resolution":
                payload = _resolution_failure("config")
            else:
                payload = _audit_failure_report("config").as_dict()
            print(json.dumps(payload, sort_keys=True))
            return 3
        raise
    try:
        if args.command == "run":
            return _run_control(settings, args)
        if args.command == "worker":
            from role_radar.worker.main import run_worker

            run_worker(settings)
            return 0
        if args.command == "discovery":
            return _run_discovery_readonly(settings, args.discovery_command)
        if args.command == "mailbox":
            return _run_mailbox(settings, args)
        if args.command == "source":
            return _run_source(settings, args)
        if args.command == "acquisition":
            if args.acquisition_command == "smoke":
                return _run_smoke(args)
            if args.acquisition_command == "gate-b":
                return _run_gate_b(args)
            return _run_acquisition(settings, args)
        direct_commands = {"collect", "extract", "extract-pending", "score", "score-pending"}
        if args.command in direct_commands and not settings.allow_direct_pipeline_writes:
            print(
                "direct pipeline writes are disabled; use `run create` followed by `worker`",
                file=sys.stderr,
            )
            return 1
        if args.command == "seed-boards":
            return _seed_boards(settings, _fixtures_dir())
        if args.command == "discover-boards":
            from role_radar.discovery.null_provider import NullSearchProvider

            return asyncio.run(
                _run_discover(settings, NullSearchProvider(), args.query, args.max_results)
            )
        if args.command == "collect":
            run_id, status, stats = asyncio.run(_run_collect(settings, args.reason))
            print(json.dumps({"run_id": run_id, "status": status, "stats": stats}))
            return 0 if status == "completed" else 1
        if args.command == "extract":
            print(json.dumps(asyncio.run(_run_extract(settings, args.job_id))))
            return 0
        if args.command == "extract-pending":
            print(json.dumps(asyncio.run(_run_extract_pending(settings, args.limit))))
            return 0
        if args.command == "score":
            print(json.dumps(_run_score(settings, args.job_id, args.profile_id)))
            return 0
        if args.command == "score-pending":
            print(json.dumps(_run_score_pending(settings, args.limit, args.profile_id)))
            return 0
    except Exception as exc:
        print(f"role-radar: {exc}", file=sys.stderr)
        return 1
    return 2


def _run_legacy_discovery_deprecated() -> int:
    """Keep the historical command fail-closed and network-free."""

    print(
        json.dumps(
            {
                "schema_version": "continuous-discovery-v2-result-v1",
                "result": "blocked",
                "code": "discovery_v2_command_required",
            },
            sort_keys=True,
        )
    )
    return 2


def _run_continuous_discovery_v2(args: argparse.Namespace) -> int:
    """Lazy, thin dispatch to the dedicated v2 CLI adapter."""

    from role_radar.cli.continuous_discovery_v2 import run_continuous_discovery_v2

    return run_continuous_discovery_v2(args)


def _run_feedback(args: argparse.Namespace) -> int:
    """Lazy, thin dispatch to the current product feedback adapter."""

    from role_radar.cli.feedback import run_feedback

    return run_feedback(Settings(), args)


def _run_continuous_gate_a(args: argparse.Namespace) -> int:
    """Thin dispatch for the bounded continuous runtime composition."""
    from role_radar.continuous_acquisition.runtime import (
        EXIT_INTERNAL,
        RuntimeCompositionError,
        load_runtime_config,
        open_runtime,
        provider_summary,
        recover,
        require_mode_authorization,
        run_acquisition_once,
        run_discovery_once,
        status,
    )

    workflow = "discovery" if args.command == "continuous-discovery" else "acquisition"
    try:
        settings = Settings()
        if args.continuous_command == "status":
            result = status(settings, workflow=workflow)
            print(json.dumps(result.payload, sort_keys=True))
            return result.exit_code
        if args.continuous_command == "recover":
            result = recover(settings)
            print(json.dumps(result.payload, sort_keys=True))
            return result.exit_code

        mode = "manual-canary" if args.manual_canary else "scheduled" if args.scheduled else ""
        config = load_runtime_config(settings)
        print(json.dumps(provider_summary(config, workflow), sort_keys=True))
        require_mode_authorization(
            mode=mode,
            acknowledgement=args.acknowledgement,
            canary_id=args.canary_id,
        )
        engine, session = open_runtime(settings)
        try:
            if workflow == "discovery":
                result = run_discovery_once(
                    session,
                    settings=settings,
                    config=config,
                    owner=settings.worker_id,
                    canary_id=args.canary_id,
                )
            else:
                result = run_acquisition_once(
                    session,
                    settings=settings,
                    owner=settings.worker_id,
                    canary_id=args.canary_id,
                )
            print(json.dumps(result.payload, sort_keys=True))
            return result.exit_code
        finally:
            session.close()
            engine.dispose()
    except RuntimeCompositionError as exc:
        print(json.dumps({"result": "blocked", "code": exc.code}, sort_keys=True))
        return exc.exit_code
    except Exception:
        print(json.dumps({"result": "failed", "code": "internal_error"}, sort_keys=True))
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
