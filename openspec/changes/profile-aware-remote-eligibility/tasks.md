# Tasks: Profile-aware remote eligibility

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 1,000–1,500 lines across 14–16 files |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1: pure eligibility contract → PR 2: restart-safe reprocessing and scoring checkpoints → PR 3: feedback admission, CLI observability, and end-to-end safeguards |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

Implementation must pause before apply until a human selects a chain strategy. Each PR below is an autonomous work unit with its own tests, verification, and rollback boundary; later PRs depend on earlier PRs.

## PR 1 — Pure eligibility contract and canonical facts

**Boundary:** Start with the existing matching DTOs and fact builder; finish with a deterministic, side-effect-free eligibility decision. Verify only matching-focused tests. Roll back by removing the new DTO/module and the region-conflict propagation without touching persisted data.

### RED

- [x] Add failing decision-matrix tests in `tests/unit/test_feedback_eligibility.py` for completed extraction, known `remote`/`hybrid`/`onsite`, unknown or unsupported remote policy, `remote_only`, `allowed_remote_policies`, empty profile regions, exact canonical region match, incompatible region, and explicit worldwide. <!-- sdd-owner: implementation -->
- [x] Add failing conflict/provenance tests in `tests/unit/test_feedback_eligibility.py` and `tests/unit/test_matching_core.py` for remote/region ATS conflicts, extraction conflicts, location-derived region conflict, unrelated ambiguities, and the rule that free-form `Worldwide` cannot manufacture worldwide eligibility. <!-- sdd-owner: implementation -->
- [x] Add failing deterministic-contract tests in `tests/unit/test_feedback_eligibility.py` for ordered reason codes, profile binding fields, nullable extraction ID only on excluded outcomes, stable canonical input SHA-256, and hash changes when policy/profile/facts change. <!-- sdd-owner: implementation -->

### GREEN

- [x] Add the minimal immutable `ProfileBinding` and `FeedbackEligibilityDecision` DTOs to `src/role_radar/matching/contracts.py`, reusing `CandidateProfileV1` and `canonical_profile_sha256` rather than adding a parallel profile representation. <!-- sdd-owner: implementation -->
- [x] Create `src/role_radar/matching/feedback_eligibility.py` with `feedback-remote-eligibility-v1`, stable reason constants, canonical JSON hashing, and `evaluate_feedback_eligibility` implementing the design’s exact fail-closed decision order. <!-- sdd-owner: implementation -->
- [x] Update `src/role_radar/matching/facts.py` so location fallback derived from conflicting location evidence emits a region-specific ambiguity, while preserving ATS precedence and the existing exclusion of `remote`, `worldwide`, and `global` fallback tokens. <!-- sdd-owner: implementation -->

### TRIANGULATE

- [x] Extend `tests/unit/test_feedback_eligibility.py` with equivalent canonical aliases, multiple simultaneous exclusion reasons, reordered inputs/ambiguities, and extraction-backed versus ATS-backed explicit worldwide cases; make only the smallest production changes needed for deterministic parity. <!-- sdd-owner: implementation -->

### REFACTOR

- [x] Remove duplicate canonicalization or compatibility logic from `src/role_radar/matching/feedback_eligibility.py` by reusing `src/role_radar/matching/policy.py`, `src/role_radar/matching/hard_filters.py`, and `src/role_radar/domain/profile.py`; verify `tests/unit/test_feedback_eligibility.py` and `tests/unit/test_matching_core.py`. <!-- sdd-owner: implementation -->

## PR 2 — Shared scoring decision and restart-safe current-corpus barrier

**Boundary:** Start from PR 1’s pure decision; finish when current jobs are checkpointed before producer I/O and new jobs carry the same decision. Verify matching/pipeline tests. Roll back by removing the barrier/service and additive checkpoint JSON; no schema or corpus deletion is required.

### RED

- [x] Add failing service tests in `tests/unit/test_matching_core.py` for one `MatchingService` call returning the persisted `JobScore` and exact feedback decision from a single loaded `JobFacts` snapshot and frozen profile binding. <!-- sdd-owner: implementation -->
- [x] Add failing reprocessing tests in `tests/integration/test_phase05_pipeline.py` for a write-once cutoff/profile/policy manifest, deterministic `(created_at, id)` traversal of all cutoff jobs, successful excluded checkpoints after terminal extraction failure, per-job commits, and malformed or mismatched terminal `PREFILTERED` rows blocking the run. <!-- sdd-owner: implementation -->
- [x] Add failing interruption/resume tests in `tests/integration/test_phase05_pipeline.py` proving completed `purpose: feedback_eligibility_reprocess` checkpoints are skipped, pending counts are recomputed rather than trusted, and acquisition remains blocked until `pending == 0` and `complete == true`. <!-- sdd-owner: implementation -->
- [x] Add failing ordering and preservation tests in `tests/integration/test_phase05_pipeline.py` proving `_collection.prepare`, discovery, Jobicy, mailbox, and collector external I/O occur only after reprocessing, while restrictive profile regions do not alter source snapshots, requests, parent counts, acquired jobs, or source references. <!-- sdd-owner: implementation -->
- [x] Add failing current/new parity tests in `tests/integration/test_phase05_pipeline.py` for identical decision shape/reasons, plus `SCORED` retry tests ensuring a successful checkpoint missing or carrying stale eligibility metadata is not silently accepted. <!-- sdd-owner: implementation -->

### GREEN

- [x] Refactor `src/role_radar/services/matching_service.py` minimally so profile resolution, profile binding, snapshot loading, fact building, normal scoring, and feedback eligibility are computed once and returned together without changing `JobScore.eligible`. <!-- sdd-owner: implementation -->
- [x] Create `src/role_radar/services/eligibility_reprocessing.py` to capture/validate the run manifest, enumerate `Job.created_at <= cutoff`, reuse `PipelineExtractionService` and `MatchingService`, persist one terminal `RunJobStage.PREFILTERED` outcome per job, and recompute sorted totals/reason counts after each committed job. <!-- sdd-owner: implementation -->
- [x] Update `src/role_radar/services/pipeline_scoring.py` to persist the exact `feedback_eligibility` decision beside existing `job_score_id`, general `eligible`, and `score` fields for newly processed jobs, failing closed on malformed successful retries. <!-- sdd-owner: implementation -->
- [x] Update `src/role_radar/worker/pipeline.py` to invoke reprocessing before `_collection.prepare` and every acquisition producer, reuse its extraction helper safely, and prevent all producer calls when profile binding, persistence, or checkpoint validation fails. <!-- sdd-owner: implementation -->
- [x] Update `src/role_radar/worker/checkpoints.py` and the completion/failure paths in `src/role_radar/worker/pipeline.py` to preserve `stats_json.feedback_eligibility_reprocessing` and exclude purpose-tagged baseline checkpoints from source-prefilter counts. <!-- sdd-owner: implementation -->

### TRIANGULATE

- [x] Extend `tests/integration/test_phase05_pipeline.py` with jobs inserted after the cutoff, all job statuses, same-timestamp UUID ordering, retried terminal runs, and profile/policy/cutoff drift; make the minimum changes needed to preserve the single-worker/single-writer model. <!-- sdd-owner: implementation -->

### REFACTOR

- [x] Consolidate only duplicated checkpoint validation and decision serialization across `src/role_radar/services/eligibility_reprocessing.py` and `src/role_radar/services/pipeline_scoring.py`, then verify `tests/unit/test_matching_core.py` and `tests/integration/test_phase05_pipeline.py`. <!-- sdd-owner: implementation -->

## PR 3 — Feedback admission, observability, and control-boundary coverage

**Boundary:** Start from run-local decisions emitted by PR 2; finish when feedback and summaries admit only valid eligible jobs and existing human controls remain intact. Verify feedback and integration tests. Roll back by removing the admission predicate and aggregate output while leaving additive checkpoint metadata intact.

### RED

- [x] Add failing admission tests in `tests/unit/test_feedback_surface.py` for same-run `SCORED/SUCCEEDED` requirements and fail-closed missing, malformed, excluded, wrong-policy, wrong-profile-version/hash/schema, stale-input, conflicting, and cross-run decisions before renderability or relevance ranking. <!-- sdd-owner: implementation -->
- [x] Add failing behavior tests in `tests/unit/test_feedback_surface.py` proving exact-region and worldwide jobs retain existing deterministic ranking/rendering, excluded jobs return the existing `feedback job not in run` boundary on decision attempts, and eligibility never creates a feedback decision or mutates a profile. <!-- sdd-owner: implementation -->
- [x] Add failing CLI tests in `tests/unit/test_feedback_cli.py` for `feedback status` and `feedback summary` eligibility totals and sorted exclusion reasons, plus blocked output for malformed/mismatched run bindings without exposing job text. <!-- sdd-owner: implementation -->
- [x] Add failing end-to-end cases in `tests/integration/test_feedback_discovery_smoke.py` spanning extraction → `SCORED` eligibility → feedback for exact, worldwide, unknown, conflicting, and incompatible jobs. <!-- sdd-owner: implementation -->
- [x] Add failing architecture safeguards in `tests/unit/test_feedback_architecture.py` and the existing acquisition architecture tests under `tests/unit/test_profile_relevant_acquisition_architecture.py` to prohibit imports/calls from collectors, query planners, Gate D, quotas, authorization, consent, journals, or budgets into feedback eligibility. <!-- sdd-owner: implementation -->

### GREEN

- [x] Update `src/role_radar/services/feedback_service.py` to validate the run’s frozen binding and same-run successful `SCORED` decision, admit only `eligible == true` candidates before renderability/ranking, expose aggregate eligibility counts/reasons, and preserve existing feedback validation/revision behavior. <!-- sdd-owner: implementation -->
- [x] Update `src/role_radar/cli/feedback.py` to include the aggregate `eligibility` object in existing status/summary JSON and map invalid binding state to the existing blocked/error shape without adding commands or arguments. <!-- sdd-owner: implementation -->

### TRIANGULATE

- [x] Extend `tests/unit/test_feedback_surface.py` and `tests/integration/test_feedback_discovery_smoke.py` with mixed eligible/excluded ordering, unrelated candidates, duplicate discovery rows, and retries under one frozen profile; make only minimal fixes required for stable counts and ordering. <!-- sdd-owner: implementation -->

### REFACTOR

- [x] Remove duplicate decision-validation/counting code between `src/role_radar/services/feedback_service.py` and the checkpoint producers by reusing the smallest shared pure helper from `src/role_radar/matching/feedback_eligibility.py`, without introducing an eligibility API, repository, table, scheduler, or policy configuration system. <!-- sdd-owner: implementation -->
- [x] Run focused tests after each PR, then run `make test`, `make lint`, and `make typecheck`; confirm no migration files changed and inspect the final diff for unchanged collector, Gate B–F, authorization, consent, profile mutation, journal, budget, and human-decision boundaries. <!-- sdd-owner: implementation -->
