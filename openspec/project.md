# RoleRadar SDD Project Context

## Project

- **Name:** role-radar
- **Stack:** Python 3.13, FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, SQLite, httpx, structlog.
- **Purpose:** Personal software-engineering job-search pipeline that collects, normalizes, deduplicates, extracts, scores, evaluates, and notifies on job opportunities.
- **Architecture:** Single-user application with one server, one worker, and one SQLite writer; pipeline flow is collect → normalize → deduplicate → extract → score → deep-evaluate → notify.

## SDD and testing configuration

- **Artifact store:** openspec.
- **Strict TDD:** enabled.
- **Execution mode:** auto.
- **Delivery strategy:** ask-on-risk.
- **Review budget:** 400 changed lines; chain strategy deferred until chaining is selected.
- **Primary test command:** `make test` (pytest via Makefile).
- **Quality commands:** `make lint`, `make typecheck`, `make fmt`, and `make check`.
- **Integration tests:** none detected.
- **E2E tests:** none detected.
- **Phase rules:** proposals require a problem statement; specs require acceptance criteria; designs require tradeoffs; tasks protect review workload; apply and verify use `make test`.

## Existing conventions and constraints

- Business logic is organized under `src/role_radar/`; persistence uses repositories and Alembic migrations.
- The worker is the pipeline's sole writer; direct pipeline writes are development/test-only and gated by configuration.
- Deterministic code computes compatibility scores; model output is validated and cannot override hard blockers.
- Security, consent, authorization, destructive/publishing, ambiguous-scope, and review-budget exception gates remain human-controlled.
- No product code was changed during SDD initialization.

## New change

**Profile-aware remote job eligibility and acquisition.** Subsequent SDD phases should explore the current profile, matching/eligibility, and acquisition flows before proposing or specifying changes. Scope, business rules, and acceptance criteria remain to be established by the appropriate SDD phases.

## Skill registry

`.atl/skill-registry.md` exists and is available to the delegating orchestrator. It currently indexes no project/user skills.
