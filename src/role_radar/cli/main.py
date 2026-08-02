"""CLI del collector F2: wiring fino, sin lógica de pipeline."""

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from role_radar.broker.factory import create_llm_provider
from role_radar.collectors.greenhouse import GreenhouseCollector
from role_radar.config import Settings
from role_radar.db.engine import get_engine
from role_radar.db.session import get_session_factory
from role_radar.discovery.null_provider import NullSearchProvider
from role_radar.discovery.protocols import SearchProvider, SearchQuery
from role_radar.repositories.sources import SourceRepository
from role_radar.services.collection_service import CollectionService
from role_radar.services.extraction_service import ExtractionService

DISCOVERY_QUERY = "greenhouse job board software engineer"
_GREENHOUSE_HOSTS = {"boards.greenhouse.io", "job-boards.greenhouse.io"}


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
        repo = SourceRepository(session)
        for board in boards:
            repo.upsert_greenhouse_board(
                name=board["name"],
                board_token=board["board_token"],
                company=board.get("company"),
                enabled=board.get("enabled", False),
            )
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
        async with GreenhouseCollector(
            timeout=settings.http_timeout_seconds,
            user_agent=settings.http_user_agent,
        ) as collector:
            run = await CollectionService(session, collector=collector).run_collect(reason=reason)
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
        extractions = await ExtractionService(
            session, provider=provider
        ).extract_pending(limit=limit)
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


def _extract_board_token(url: str) -> str | None:
    parsed = urlsplit(url)
    if parsed.hostname not in _GREENHOUSE_HOSTS:
        return None
    segments = [segment for segment in parsed.path.split("/") if segment]
    if not segments:
        return None
    token = segments[0]
    if token.lower() in {"jobs", "job-boards"}:
        return None
    return token


async def _run_discover(
    settings: Settings, provider: SearchProvider, query_text: str, max_results: int
) -> int:
    engine, session = _open_session(settings)
    try:
        results = await provider.search(SearchQuery(query=query_text, max_results=max_results))
        repo = SourceRepository(session)
        for result in results:
            token = _extract_board_token(result.url)
            if token is None:
                continue
            repo.upsert_greenhouse_board(
                name=result.title or f"Greenhouse {token}",
                board_token=token,
                enabled=False,
            )
        session.commit()
        return 0
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
        engine.dispose()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="role-radar")
    subparsers = parser.add_subparsers(dest="command", required=True)
    collect = subparsers.add_parser("collect", help="colecta y persiste ofertas Greenhouse")
    collect.add_argument("--reason", default="cli_collect")
    subparsers.add_parser("seed-boards", help="carga boards Greenhouse curados")
    discover = subparsers.add_parser("discover-boards", help="propone boards sin activarlos")
    discover.add_argument("--query", default=DISCOVERY_QUERY)
    discover.add_argument("--max-results", type=int, default=10)
    extract = subparsers.add_parser("extract", help="extrae un Job de forma estructurada")
    extract.add_argument("--job-id", required=True)
    pending = subparsers.add_parser("extract-pending", help="extrae Jobs pendientes")
    pending.add_argument("--limit", type=int, default=10)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    settings = Settings()
    try:
        if args.command == "seed-boards":
            return _seed_boards(settings, _fixtures_dir())
        if args.command == "collect":
            run_id, status, stats = asyncio.run(_run_collect(settings, args.reason))
            print(json.dumps({"run_id": run_id, "status": status, "stats": stats}))
            return 0 if status == "completed" else 1
        if args.command == "discover-boards":
            return asyncio.run(
                _run_discover(settings, NullSearchProvider(), args.query, args.max_results)
            )
        if args.command == "extract":
            print(json.dumps(asyncio.run(_run_extract(settings, args.job_id))))
            return 0
        if args.command == "extract-pending":
            print(json.dumps(asyncio.run(_run_extract_pending(settings, args.limit))))
            return 0
    except Exception as exc:
        print(f"role-radar: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
