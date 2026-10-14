# MVP closure roadmap — RoleRadar functional MVP to production (broker + deploy + telegram)

## Context

Functional MVP authority is `functional-mvp-product-loop.spec.md` (§4, 12 acceptance items, all unchecked) with delivery route `planned/blocked` (Slice A/B specified, Slice C planned/unauthorized). Benchmark/holdout path (R3–R8) is superseded and explicitly non-goal. Current repo state: profile v3 active (`Perfil CV principal` v3, id `e5ca4168-e362-468c-9214-8e6344b945f5`, 14 titles, 5 roles, no AI exploratory, skills intact), intake-first persistence (`profile-intake-v1`), post-extraction `product-eligibility-v1`, scoped feedback CLI with propose/apply, multipart Telegram reservation (provider `disabled`, 3 Nortal jobs eligible from run `726afc71-24ff-47be-8188-d2d1b2f5a26f`, batch `UNKNOWN/telegram_disabled`), migration head `f12_profile_first_mvp`, 1018 tests green. Missing for closure: human labels + accepted refinement, live broker dual-route (instruct + thinking via llama-swap, same homelab host), systemd deploy + scheduled observation, Telegram bot + http enablement. Each T3 step (live data, credentials, broker, deploy, telegram, timers) needs explicit operator authorization at its gate; this plan authorizes nothing by itself.

## Approach

### Phase 0 — Freeze and record the intake-first deviation (agent, offline, no sudo)

1. Write decision note `decisions/2026-09-16-intake-first-vs-relevance-surface.md` in `/home/jmse/homelab/ai/projects/role-radar/` stating: implementation persists only intake-admitted jobs (`AcquiredJobWriter.write` + `evaluate_profile_intake`), which supersedes spec §3.2 "acquisition may remain broad + separate relevance surface" for this MVP; feedback `scope=reprocessed` therefore reviews admitted history, not a broad pool. Update `specs/functional-mvp-delivery-index.md` Slice A exit line to reference the intake-first evidence (run `726afc71`, 3/365 admitted). If operator rejects the deviation, do Y instead: restore broad persist by removing the intake gate in `AcquiredJobWriter.write` (keep counters), add a versioned relevance module under `src/role_radar/discovery/relevance.py` reusing `role_match` + `evaluate_hard_filters`, and gate only the feedback surface on it.
2. Verify: `uv run pytest -q tests/unit/test_matching_core.py tests/unit/test_feedback_eligibility.py` passes; decision file exists.

### Phase 0b — Close silent-fallback and provenance gaps (agent, offline, no sudo)

1. Remove the silent v1 discovery fallback: in `src/role_radar/services/pipeline_discovery.py` (`_profile_bound_v2_queries` returns `None` on absent policy/binding mismatch/invalid mapping) and `src/role_radar/worker/main.py` (policy-file errors swallowed to `None`), fail the discovery leg visibly with a stable error code instead of falling back to `QueryPlannerV1` (which ignores `target_titles`). Safe degradation of ATS/free/mailbox collection stays. This satisfies spec §4 items 1–2 (no unrelated generic fallback).
2. Persist full feedback provenance: extend `FeedbackDecision` (`src/role_radar/db/models.py`, plus Alembic migration) with `profile_id`, `row_version`, `schema_version`, `canonical_profile_sha256`, `policy_hash`, `relevance_version`, `text_sha256`, reviewer identity; populate them in `submit_feedback`; widen idempotent-replay comparison in `FeedbackRepository.submit` beyond label/reasons/note; add primary/secondary reason counts to `summarize`. This satisfies spec §4 items 5–6 provenance and summary requirements.
3. Harden refinement: include `maybe` decisions and reason codes in `propose_refinement` output with supporting job ids; reject `apply_refinement` when `new_policy_version` equals the input version; record proposal identity/confirmation linkage for the successor policy file. Unify CLI vs worker discovery-policy file contracts (`test_discovery_policy_file_policy` vs `production_discovery_policy_file_policy`).
4. Verify: `uv run pytest -q tests/unit/test_feedback_surface.py tests/unit/test_feedback_review.py tests/unit/test_feedback_cli.py tests/unit/test_feedback_refinement.py` passes; new migration upgrades/downgrades cleanly.

### Phase 1 — Human labeling + refinement on current runs (OPERATOR, TTY, no sudo)

3. [OPERATOR] Label the 3 Nortal jobs of run `726afc71-24ff-47be-8188-d2d1b2f5a26f`: `uv run role-radar feedback review --run 726afc71-24ff-47be-8188-d2d1b2f5a26f --scope current`. Requires TTY; `q` quits keeping progress, rerun resumes. Then after every future curated acquisition run, repeat `review --scope current` for that run id.
4. [OPERATOR] Inspect `uv run role-radar feedback summary --run <RUN> --scope current`, then `propose --run <RUN> --policy <discovery-policy.toml> --min-decisions 1`. If proposal removals look wrong, stop and replan policy vocabulary; never hand-edit labels (revisions only via `--relabel`).
5. [OPERATOR] Only on explicit approval of the proposal: `apply --policy <in> --output <successor.toml> --new-policy-version <v> --confirm`, then point the next run at the successor policy. Record the accepted version. Later runs bind it; history is never mutated. This satisfies spec §4 items 5–7 (no statistics needed).
6. Verify: `feedback summary` shows `decided_jobs=3` (or current batch size), `labels` nonzero, successor policy file exists with new version.

### Phase 2 — Broker + llama-swap readiness (llm-broker repo, same host; mostly OPERATOR/T3)

7. [OPERATOR] In a dedicated llm-broker session (repo `/home/jmse/labs/llm-broker`, unverified — confirm first), complete the handoff checklist (`task-context/role-radar-llm-broker-llama-swap-handoff.md` §6–§7): register workload `role-radar` with capabilities `structured-extraction` + `deep-job-evaluation`; map them to one instruct alias and one thinking alias (names operator-private, never in RoleRadar repo); dedicated Bearer credential, grants for both capabilities; generation bounds compatible with `src/role_radar/broker/consumer-compat/v1/*.json`; synthetic smoke per capability; alternating-switch proof with max one global inference; idempotent-submit + wait/poll + retention + rollback evidence. No Go toolchain on host per ACTIVE.md (unverified — confirm first); if `compat` binary missing, install Go toolchain or run `check_desired_compat` replica and record the substitution.
8. [OPERATOR] Record effective (not fixture) compat PASS and both canary outputs as sanitized evidence; keep model files/aliases/URLs out of git. If Broker cannot serve thinking route, do Y instead: freeze MVP on extraction-only path, mark spec §4 item 9 openly failing, and do not route deep evaluation anywhere except `FakeLLMProvider` in dev.
9. Verify: `consumer-compat/v1` desired+e effective checks pass against the live topology; two sanitized canary transcripts exist.
### Phase 3 — Point RoleRadar at live broker and run bounded E2E (agent + OPERATOR)
11. Agent: create scheduled run `uv run role-radar run create --reason scheduled --idempotency-key <unique>`, run worker once, confirm one real `structured-extraction` task (instruct route, `rr-extract-…` key) and one real `deep-job-evaluation` task (thinking route, `rr-deep-…` key) in broker logs, deterministic scores persisted, blockers still code-owned, API shows current/effective ranking. If either task fails open or hits a direct provider URL, stop: Broker exclusivity violated, replan.
12. Verify: `job_extractions`/`job_scores` rows reference broker operation keys; no `FakeLLMProvider` in the run path; `GET /jobs` shows effective scores.

### Phase 4 — Telegram bot + http enablement (OPERATOR manual, then agent)

13. [OPERATOR] Create the bot via BotFather (phone app, outside this environment), obtain token; obtain chat id via `curl https://api.telegram.org/bot<TOKEN>/getUpdates` after sending the bot one message. Install both mode-0600 in `/etc/role-radar/role-radar.env` (or dev `.env` for pre-prod smoke only): `ROLE_RADAR_TELEGRAM_PROVIDER=http`, `ROLE_RADAR_TELEGRAM_BOT_TOKEN=<t>`, `ROLE_RADAR_TELEGRAM_CHAT_ID=<c>`. Never commit values.
14. Agent: rerun worker on the E2E run id; the reserved `UNKNOWN/telegram_disabled` batch stays terminal (at-most-once: never auto-resent); new eligible unseen jobs reserve fresh `part:NNNN` batches and deliver via `TelegramClient` (`https://api.telegram.org/bot{token}/sendMessage`, HTML, 4096 UTF-16 units, `protect_content=true`). Confirm `SENT` + `telegram_message_id` set.
15. Verify: `notification_batches.status=SENT`, `notification_items.status=SENT`, exactly one POST per batch in broker/gateway logs.

### Phase 5 — Systemd deploy + scheduled observation (OPERATOR sudo, then agent verify)

16. [OPERATOR with sudo] Instantiate templates: replace `ROLE_RADAR_USER`/`ROLE_RADAR_APP_DIR` in `deploy/systemd/role-radar-api.service`, `role-radar-worker.service`, `role-radar-scheduler.service`, `role-radar-scheduler.timer`; copy to `/etc/systemd/system/`; code to `/opt/role-radar`; write protected `/etc/role-radar/role-radar.env` (`ROLE_RADAR_API_PORT`, database URL, broker vars, telegram http vars). Commands: `sudo cp deploy/systemd/role-radar-{api,worker,scheduler}.{service,timer} /etc/systemd/system/`, `sudo systemd-analyze verify role-radar-worker.service role-radar-scheduler.timer`, `sudo systemctl daemon-reload`, `ROLE_RADAR_DATABASE_URL=<prod-db> uv run alembic upgrade head` (migrate every runtime DB f11→f12 first), `sudo systemctl enable --now role-radar-api.service role-radar-scheduler.timer`, `curl -s localhost:$PORT/health`.
17. Agent: after the next 08:00 America/Argentina/Buenos_Aires tick (timer `OnCalendar` hardcoded; env hour/minute alone does not change it), verify one scheduled cycle: run row `COMPLETED`, stats (`collected/new_jobs/profile_rejected/scored/notified_jobs/digests_sent`), failures visible, notification outcome recorded. Record run id + counts as the Slice C observation.
18. Verify: `systemctl is-active role-radar-scheduler.timer` active; scheduled run present with terminal notification batches.

### Phase 6 — MVP acceptance sign-off (OPERATOR)

19. [OPERATOR] Check each `functional-mvp-product-loop.spec.md` §4 item 1–12 against the evidence above; mark PASS with run ids/hashes or openly failing. Confirm ordinary-use acceptance (item 7, no statistics). Record in `ACTIVE.md` successor or decision file; R3–R8 stay deferred, no benchmark/holdout work starts.

## Critical files & anchors

- `specs/functional-mvp-product-loop.spec.md` §4 — the 12 binding acceptance items; every phase maps to them.
- `src/role_radar/services/acquired_job_writer.py` (`write`, intake gate + evidence persist) — intake-first deviation point.
- `src/role_radar/broker/factory.py` (`create_llm_provider`, `create_deep_llm_provider`) — fake-vs-broker switch, fail-closed guards.
- `src/role_radar/broker/consumer-compat/v1/` (3 JSON manifests) — desired-compat contract for Phase 2.
- `deploy/systemd/` (worker/scheduler units, timer `OnCalendar`, `role-radar.env.example`) — all Phase 5 substitution targets.

## Verification

- Phase 0: decision file exists; `uv run pytest -q tests/unit/test_matching_core.py tests/unit/test_feedback_eligibility.py` green.
- Phase 1: `feedback summary --scope current` shows all current items decided; successor policy file versioned and bound by a later run.
- Phase 2: effective compat PASS recorded; sanitized instruct + thinking canary transcripts exist; no model/backend identity in RoleRadar repo.
- Phase 3: one run id with real broker extraction + deep rows, code-owned blockers intact, API effective scores visible.
- Phase 4: new batches `SENT` with message ids; old `UNKNOWN` batch untouched; one POST per batch.
- Phase 5: timer active; one scheduled run `COMPLETED` with full stats; `curl /health` 200.
- Phase 6: 12/12 items dispositioned in writing. Full suite `make test` (1018 passed baseline) + `make lint` + targeted `mypy` on touched paths after any code change.

## Assumptions & contingencies

- llm-broker repo at `/home/jmse/labs/llm-broker` and no Go toolchain on host are taken from harness notes, unverified — confirm first; if paths differ, substitute actual paths, same steps.
- Labeling queue is the 3 Nortal jobs of run `726afc71` plus each future curated acquisition (per operator choice); the 173-job backend corpus is never labeled.
- Broker and llama-swap run on the same homelab host (per operator choice); if remote, Phase 2 operator steps move to that host, RoleRadar side unchanged.
- If thinking route proves unavailable, freeze MVP extraction-only and record §4 item 9 failing rather than adding any direct model adapter.
- If operator rejects intake-first, execute the Phase 0 fallback (broad persist + versioned relevance module) before any labeling, since it changes what the surface contains.
- sudo/systemctl/BotFather/llm-broker-session steps are operator-only; the agent never runs them and never handles raw tokens (hashes/codes only in evidence).
