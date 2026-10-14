"""Thin CLI adapter for the current product feedback loop."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, cast

SCHEMA_VERSION = "feedback-result-v1"


def _payload(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def register_feedback_parser(subparsers: Any) -> argparse.ArgumentParser:
    """Register only syntax; behavior lives in the feedback services."""

    parser = cast(argparse.ArgumentParser, subparsers.add_parser("feedback"))
    parser.description = (
        "Label the current run's candidates. The standard workflow is the "
        "interactive 'review' command; the remaining commands are automation "
        "and reporting seams."
    )
    commands = parser.add_subparsers(dest="feedback_command", required=True)
    review = commands.add_parser(
        "review",
        help="Label candidates interactively, one at a time (standard workflow).",
        description=(
            "Walk the run's feedback surface one candidate at a time, render "
            "each with display v2, and record a confirmed apply/maybe/reject "
            "decision. Decided items are skipped so an interrupted session "
            "resumes; Ctrl-D or 'q' stops and keeps prior decisions."
        ),
    )
    review.add_argument("--run", required=True)
    review.add_argument(
        "--relabel",
        action="store_true",
        help="Revisit already-decided items to correct them.",
    )
    review.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Label at most N items this session.",
    )
    review.add_argument("--scope", choices=("current", "reprocessed", "all"), default="all")
    status = commands.add_parser("status")
    status.add_argument("--run", required=True)
    status.add_argument("--scope", choices=("current", "reprocessed", "all"), default="all")
    show = commands.add_parser("show")
    show.add_argument("--run", required=True)
    show.add_argument("--job", required=True)
    show.add_argument("--scope", choices=("current", "reprocessed", "all"), default="all")
    next_item = commands.add_parser("next")
    next_item.add_argument("--run", required=True)
    next_item.add_argument("--scope", choices=("current", "reprocessed", "all"), default="all")
    decide = commands.add_parser("decide")
    decide.add_argument("--run", required=True)
    decide.add_argument("--job", required=True)
    decide.add_argument("--label", required=True)
    decide.add_argument("--reason", required=True)
    decide.add_argument("--secondary", action="append", default=[])
    decide.add_argument("--note")
    decide.add_argument("--expected-revision", type=int)
    summary = commands.add_parser("summary")
    summary.add_argument("--run", required=True)
    summary.add_argument("--scope", choices=("current", "reprocessed", "all"), default="all")
    propose = commands.add_parser("propose")
    propose.add_argument("--run", required=True)
    propose.add_argument("--policy", required=True)
    propose.add_argument("--min-decisions", type=int, default=3)
    apply = commands.add_parser("apply")
    apply.add_argument("--run", required=True)
    apply.add_argument("--policy", required=True)
    apply.add_argument("--output", required=True)
    apply.add_argument("--new-policy-version", required=True)
    apply.add_argument("--confirm", action="store_true")
    return parser


def _open_feedback_session(settings: Any) -> tuple[Any, Any]:
    from role_radar.db.engine import get_engine
    from role_radar.db.session import get_session_factory

    engine = get_engine(settings.database_url)
    if settings.database_url.startswith("sqlite:///"):
        Path(settings.database_url.removeprefix("sqlite:///")).parent.mkdir(
            parents=True, exist_ok=True
        )
    return engine, get_session_factory(engine)()


def _blocked(code: str) -> tuple[dict[str, Any], int]:
    return {"schema_version": SCHEMA_VERSION, "result": "blocked", "code": code}, 2


def _load_policy_file(path: str) -> Any:
    from role_radar.acquisition.discovery_policy import (
        load_discovery_policy,
        test_discovery_policy_file_policy,
    )

    # CLI and worker share the same strict TOML/hash contract; the only
    # difference is the file-metadata policy: the worker enforces the
    # root-owned production file, while this operator CLI accepts a
    # current-user 0600 file (tests use tmp files).
    return load_discovery_policy(path, file_policy=test_discovery_policy_file_policy())


def _run_review(session: Any, args: Any) -> int:
    """Run the standard interactive labeling session on a TTY."""

    from role_radar.evaluation.blind_labeling.interaction import StdTerminalIO
    from role_radar.services.feedback_review import run_review

    if not sys.stdin.isatty():
        payload, code = _blocked("review_requires_tty")
        print(_payload(payload))
        return code
    if args.limit is not None and args.limit < 1:
        payload, code = _blocked("review_limit_invalid")
        print(_payload(payload))
        return code
    io = StdTerminalIO(
        input_fn=lambda prompt: input(prompt),
        output_fn=lambda value: sys.stdout.write(value),
        is_tty=True,
    )
    try:
        run_review(
            session,
            args.run,
            io,
            relabel=args.relabel,
            limit=args.limit,
            scope=args.scope,
        )
    except LookupError:
        session.rollback()
        payload, code = _blocked("run_not_found")
        print(_payload(payload))
        return code
    except KeyboardInterrupt:
        session.rollback()
        print("\nSession interrupted; prior decisions were kept.")
        return 130
    except Exception:
        session.rollback()
        payload, code = _blocked("internal_error")
        print(_payload(payload))
        return 1
    return 0


def run_feedback(settings: Any, args: Any) -> int:
    """Dispatch one feedback subcommand and print canonical JSON."""

    from role_radar.acquisition.discovery_policy import DiscoveryPolicyFileError
    from role_radar.db.models import JobSearchRun
    from role_radar.evaluation.blind_labeling.display_policy import DisplayError
    from role_radar.evaluation.blind_labeling.validation import ValidationError
    from role_radar.repositories.feedback import FeedbackConflictError
    from role_radar.services.feedback_refinement import apply_refinement, propose_refinement
    from role_radar.services.feedback_service import (
        build_surface,
        collect_candidates,
        render_candidate,
        submit_feedback,
        summarize,
    )

    engine, session = _open_feedback_session(settings)
    try:
        command = args.feedback_command
        if command == "review":
            return _run_review(session, args)
        if command == "status":
            run = session.get(JobSearchRun, args.run)
            if run is None:
                payload, code = _blocked("run_not_found")
                print(_payload(payload))
                return code
            surface = build_surface(session, args.run, scope=args.scope)
            print(
                _payload(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "result": "ok",
                        "run_id": run.id,
                        "run_status": run.status.value,
                        "cycle_id": surface.cycle_id,
                        "planner_version": surface.planner_version,
                        "policy_version": surface.policy_version,
                        "candidates": len(surface.items),
                        "unrelated_count": surface.unrelated_count,
                        "excluded_count": surface.excluded_count,
                        "eligibility": surface.eligibility,
                    }
                )
            )
            return 0
        if command in {"show", "next"}:
            surface = build_surface(session, args.run, scope=args.scope)
            candidates = {
                item.job_id: item
                for item in collect_candidates(session, args.run, scope=args.scope)
            }
            if command == "show":
                wanted = args.job
            else:
                pending = [item for item in surface.items if item.decision is None]
                if not pending:
                    payload, code = _blocked("feedback_complete")
                    print(_payload(payload))
                    return code
                wanted = pending[0].job_id
            selected = next((item for item in surface.items if item.job_id == wanted), None)
            candidate = candidates.get(wanted)
            if selected is None or candidate is None:
                payload, code = _blocked("feedback_job_not_found")
                print(_payload(payload))
                return code
            index = surface.items.index(selected) + 1
            print(
                _payload(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "result": "ok",
                        "run_id": surface.run_id,
                        "job_id": selected.job_id,
                        "index": index,
                        "total": len(surface.items),
                        "band": selected.band,
                        "matched_phrases": list(selected.matched_phrases),
                        "revision": selected.revision,
                        "decision": selected.decision,
                        "rendered": render_candidate(
                            candidate, index=index, total=len(surface.items)
                        ),
                    }
                )
            )
            return 0
        if command == "decide":
            try:
                row, created = submit_feedback(
                    session,
                    run_id=args.run,
                    job_id=args.job,
                    label=args.label,
                    primary_reason=args.reason,
                    secondary_reasons=tuple(args.secondary or ()),
                    note=args.note,
                    expected_revision=args.expected_revision,
                )
            except FeedbackConflictError:
                session.rollback()
                payload, code = _blocked("feedback_decision_conflict")
                print(_payload(payload))
                return code
            except ValidationError as exc:
                session.rollback()
                payload, code = _blocked("feedback_decision_invalid")
                print(_payload({**payload, "reason": exc.args[0] if exc.args else "invalid"}))
                return code
            except LookupError:
                session.rollback()
                payload, code = _blocked("feedback_job_not_found")
                print(_payload(payload))
                return code
            session.commit()
            print(
                _payload(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "result": "decided" if created else "unchanged",
                        "run_id": args.run,
                        "job_id": row.job_id,
                        "revision": row.revision,
                        "label": row.label,
                    }
                )
            )
            return 0
        if command == "summary":
            report = summarize(session, args.run, scope=args.scope)
            print(_payload({"schema_version": SCHEMA_VERSION, "result": "ok", **report}))
            return 0
        if command == "propose":
            loaded = _load_policy_file(args.policy)
            proposal = propose_refinement(
                session, args.run, loaded.policy, min_decisions=args.min_decisions
            )
            print(_payload({"schema_version": SCHEMA_VERSION, "result": "ok", **proposal}))
            return 0
        if command == "apply":
            if not args.confirm:
                payload, code = _blocked("confirmation_required")
                print(_payload(payload))
                return code
            source = Path(args.policy).resolve()
            target = Path(args.output).resolve()
            if source == target:
                payload, code = _blocked("refinement_output_matches_input")
                print(_payload(payload))
                return code
            loaded = _load_policy_file(args.policy)
            proposal = propose_refinement(session, args.run, loaded.policy)
            if not proposal["removals"]:
                payload, code = _blocked("refinement_no_removals")
                print(_payload(payload))
                return code
            text = apply_refinement(
                loaded.policy,
                proposal["removals"],
                new_policy_version=args.new_policy_version,
            )
            target.write_text(text, encoding="utf-8")
            os.chmod(target, 0o600)
            reloaded = _load_policy_file(str(target))
            print(
                _payload(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "result": "applied",
                        "run_id": args.run,
                        "removals": proposal["removals"],
                        "new_policy_version": reloaded.policy.policy_version,
                        "policy_sha256": reloaded.policy_sha256,
                        "output": str(target),
                    }
                )
            )
            return 0
        payload, code = _blocked("feedback_command_invalid")
        print(_payload(payload))
        return code
    except RuntimeError as exc:
        session.rollback()
        if str(exc).startswith("product_eligibility_"):
            payload, code = _blocked("product_eligibility_blocked")
            print(_payload(payload))
            return code
        payload, code = _blocked("internal_error")
        print(_payload(payload))
        return 1
    except DiscoveryPolicyFileError as exc:
        session.rollback()
        payload, code = _blocked("discovery_policy_unavailable")
        print(_payload({**payload, "reason": exc.code}))
        return code
    except LookupError:
        session.rollback()
        payload, code = _blocked("run_not_found")
        print(_payload(payload))
        return code
    except DisplayError:
        session.rollback()
        payload, code = _blocked("feedback_display_invalid")
        print(_payload(payload))
        return code
    except Exception:
        session.rollback()
        payload, code = _blocked("internal_error")
        print(_payload(payload))
        return 1
    finally:
        session.close()
        engine.dispose()


run = run_feedback
register_parser = register_feedback_parser

__all__ = [
    "register_feedback_parser",
    "register_parser",
    "run",
    "run_feedback",
]
