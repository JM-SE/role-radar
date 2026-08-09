"""CLI del collector F2: wiring fino, sin lógica de pipeline."""

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from role_radar.broker.factory import create_llm_provider
from role_radar.config import Settings
from role_radar.db.engine import get_engine
from role_radar.db.session import get_session_factory
from role_radar.discovery.contracts import (
    KnownOfficialCandidate,
    ProviderIntent,
    SearchRequest,
    UnknownCandidate,
)
from role_radar.discovery.null_provider import NullSearchProvider
from role_radar.discovery.protocols import SearchProvider
from role_radar.discovery.url_classifier import classify_url
from role_radar.domain.enums import DiscoveryMode, SourceType
from role_radar.mailbox.configuration import (
    EmailSourceConfigV1,
    FileCredentialResolver,
    load_acquisition_configuration,
)
from role_radar.mailbox.imap_provider import GmailImapProvider
from role_radar.repositories.mailbox_states import MailboxStateRepository
from role_radar.scheduler import latest_slot
from role_radar.services.collection_service import CollectionService
from role_radar.services.extraction_service import ExtractionService
from role_radar.services.matching_service import MatchingService
from role_radar.services.run_service import RunConflict, RunNotFound, RunService
from role_radar.services.source_service import (
    RevisionConflict,
    SourceNotFound,
    SourceService,
    SourceServiceError,
)
from role_radar.sources.public import project_public_configuration
from role_radar.worker.main import run_worker

DISCOVERY_QUERY = "greenhouse job board software engineer"


def _fixtures_dir() -> Path:
    cwd_fixtures = Path.cwd() / "fixtures"
    if cwd_fixtures.is_dir():
        return cwd_fixtures
    return Path(__file__).resolve().parents[3] / "fixtures"


def _open_session(settings: Settings) -> tuple[Engine, Session]:
    engine = get_engine(settings.database_url)
    if settings.database_url.startswith("sqlite:///"):
        Path(settings.database_url.removeprefix("sqlite:///")).parent.mkdir(
            parents=True, exist_ok=True
        )
    return engine, get_session_factory(engine)()


def _seed_boards(settings: Settings, fixtures_dir: Path) -> int:
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


async def _run_collect(settings: Settings, reason: str) -> tuple[str, str, dict[str, int]]:
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


async def _run_extract(settings: Settings, job_id: str) -> dict[str, object]:
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


async def _run_extract_pending(settings: Settings, limit: int) -> list[dict[str, object]]:
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
    settings: Settings, provider: SearchProvider, query_text: str, max_results: int
) -> int:
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


def _run_score(settings: Settings, job_id: str, profile_id: str | None) -> dict[str, object]:
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
    settings: Settings, limit: int, profile_id: str | None
) -> list[dict[str, object]]:
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
        choices=[SourceType.GREENHOUSE.value, SourceType.LEVER.value, SourceType.EMAIL.value],
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
    mailbox_reconcile = mailbox_commands.add_parser("reconcile")
    mailbox_reconcile.add_argument("source")
    mailbox_reconcile.add_argument("--revision", required=True, type=int)
    mailbox_reconcile.add_argument("--uidvalidity", required=True, type=int)
    mailbox_reconcile.add_argument("--ack", required=True)
    mailbox_reconcile.add_argument("--strategy", default="bounded-lookback")
    return parser


def _source_payload(source: object) -> dict[str, object]:
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


def _run_source(settings: Settings, args: argparse.Namespace) -> int:
    engine, session = _open_session(settings)
    service = SourceService(session)
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
            if source_type is SourceType.GREENHOUSE:
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
                if (
                    args.board_token is not None
                    or args.site is None
                    or args.region is None
                ):
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


def _run_control(settings: Settings, args: argparse.Namespace) -> int:
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


def _run_discovery_readonly(settings: Settings, command: str) -> int:
    """Local, sanitized acquisition observability; never triggers a call."""
    engine, session = _open_session(settings)
    try:
        from role_radar.repositories.acquisition import AcquisitionRepository

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


def _run_mailbox(settings: Settings, args: argparse.Namespace) -> int:
    engine, session = _open_session(settings)
    try:
        from role_radar.db.models import Source

        source = session.get(Source, args.source)
        if source is None or source.type is not SourceType.EMAIL:
            print("role-radar: source_not_found", file=sys.stderr)
            return 3
        if args.mailbox_command == "status":
            state = MailboxStateRepository(session).get(source.id)
            print(json.dumps({
                "source_id": source.id,
                "source_key": source.source_key,
                "enabled": source.enabled,
                "uidvalidity": state.uidvalidity if state else None,
                "highest_terminal_uid": state.highest_terminal_uid if state else 0,
                "revision": state.revision if state else None,
                "last_error_code": state.last_error_code if state else None,
            }))
            return 0
        if args.mailbox_command == "preflight":
            config = load_acquisition_configuration(args.config)
            alias = EmailSourceConfigV1.model_validate(
                dict(source.configuration or {})
            ).connection_alias
            descriptor = config.mailboxes.get(alias)
            if descriptor is None:
                raise ValueError("mailbox descriptor unavailable")
            mailbox_descriptor = descriptor.descriptor()
            credential_dir = Path(
                os.environ.get("CREDENTIALS_DIRECTORY", "/etc/role-radar/credentials")
            )
            handles = {
                handle
                for handle in (
                    mailbox_descriptor.username_handle,
                    mailbox_descriptor.oauth2_handle,
                    mailbox_descriptor.app_password_handle,
                )
                if handle is not None
            }
            resolver = FileCredentialResolver(
                {handle: credential_dir / handle for handle in handles}
            )
            credentials = resolver(mailbox_descriptor)
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


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    settings = Settings()
    try:
        if args.command == "run":
            return _run_control(settings, args)
        if args.command == "worker":
            run_worker(settings)
            return 0
        if args.command == "discovery":
            return _run_discovery_readonly(settings, args.discovery_command)
        if args.command == "mailbox":
            return _run_mailbox(settings, args)
        if args.command == "source":
            return _run_source(settings, args)
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


if __name__ == "__main__":
    raise SystemExit(main())
