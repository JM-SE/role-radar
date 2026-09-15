# Design: Gate feedback with profile-aware remote eligibility

## Decision summary

Add one deterministic remote/location eligibility decision beside the existing matching core, built from `JobFacts`, fact-building ambiguities, and the run-bound `CandidateProfileV1`. Apply it after extraction in both paths:

1. A restart-safe pre-acquisition pass evaluates every job that existed when the run began.
2. Normal run scoring evaluates newly acquired jobs with the same function.
3. Feedback admits only discovery candidates whose exact run checkpoint contains an eligible, identity-valid decision.

No collector, discovery query, source plan, Gate D parent pool, quota, authorization, consent, hash gate, or human feedback rule changes. No new database table or migration is required: immutable extraction and score rows remain authoritative inputs, while existing per-run `RunJob` checkpoints and `JobSearchRun.stats_json` record eligibility outcomes and progress.

## Goals and non-goals

### Goals

- Require completed, current extraction before feedback eligibility.
- Require a known remote policy and a known exact canonical region, except for explicit worldwide jobs.
- Fail closed on relevant ambiguity or conflict.
- Reprocess the existing corpus completely before any acquisition producer performs external I/O.
- Resume safely after worker interruption without repeating completed eligibility decisions.
- Make pending, eligible, excluded, and exclusion-reason counts observable.
- Preserve the run's frozen profile identity and existing control boundaries.

### Non-goals

- Filtering acquisition inputs or changing acquisition coverage.
- Adding fuzzy geographic inference or deriving worldwide from free-form location text.
- Replacing general matching eligibility, scoring, or profile-relevance strata.
- Mutating profiles or inferring human feedback decisions.
- Adding an eligibility API resource, table, scheduler, or policy configuration system.

## Architecture

### Components

| Component | Responsibility |
|---|---|
| `matching/feedback_eligibility.py` | Pure decision function and stable policy/reason codes. No ORM, clock, network, or randomness. |
| `matching/facts.py` | Continue building canonical `JobFacts` with ATS precedence and current valid extraction; identify region ambiguity when regions were derived from conflicting location evidence. |
| `services/matching_service.py` | Load one job/profile, build facts once, score normally, and return the shared feedback-eligibility decision with the persisted score. |
| `services/eligibility_reprocessing.py` | Capture/resume the current-corpus pass, reuse extraction and matching services, checkpoint one terminal outcome per job, and recompute progress. |
| `worker/pipeline.py` | Run reprocessing before collection, discovery, Jobicy, mailbox, or ATS acquisition; evaluate newly acquired jobs during normal scoring. |
| `services/pipeline_scoring.py` | Persist the exact eligibility decision used for each newly processed run job. |
| `services/feedback_service.py` | Join discovery candidates to their run-local scoring checkpoint and discard absent, malformed, stale, conflicting, or excluded decisions before relevance ranking/rendering. |
| Existing API/CLI | Expose eligibility progress and counts through existing run stats and feedback status/summary output. |

This is not a third matching system. It reuses:

- `CandidateProfileV1` canonical regions, `remote_only`, and `allowed_remote_policies`;
- `JobFacts` canonical values, provenance, extraction identity, and ATS/extraction precedence;
- matching hard-filter semantics for known remote-policy incompatibility;
- profile-relevance's fail-closed distinction between match, conflict, and indeterminate evidence;
- `RunJob`'s effectively-once, per-run checkpoint convention.

General `JobScore.eligible` remains unchanged. The stricter decision controls feedback admission only, avoiding accidental changes to deep evaluation, digest selection, or historical score meaning.

## Eligibility contract

Introduce immutable `FeedbackEligibilityDecision` data with:

- `policy_version` (`feedback-remote-eligibility-v1`);
- `profile_binding` (`profile_id`, row `version`, `schema_version`, canonical profile SHA-256);
- `input_sha256`, hashing the policy version, profile binding, canonical `JobFacts`, and sorted relevant ambiguities;
- `eligible: bool`;
- ordered `reason_codes`;
- `extraction_id` (nullable only for excluded outcomes).

The pure function accepts a canonical profile, `JobFacts`, fact-building ambiguities, and the explicit profile binding. It returns one terminal decision and never mutates matching results.

### Decision order

Checks run in this order so the first reason is stable while all applicable reasons remain visible:

1. `extraction_incomplete`: `facts.extraction_id` is absent. ATS-only or location-fallback facts cannot pass this boundary.
2. `remote_policy_conflict`: relevant fact ambiguities affect `remote_policy`.
3. `remote_policy_unknown`: canonical remote policy is not exactly `remote`, `hybrid`, or `onsite`.
4. Existing remote compatibility:
   - `remote_policy_not_allowed` when a non-empty profile allowlist excludes the known policy;
   - `remote_only_incompatible` when `remote_only` meets `hybrid` or `onsite`.
5. `region_conflict`: relevant ambiguities affect `regions`, or regions were derived from conflicting location evidence.
6. `profile_region_unknown`: the bound profile has no canonical regions. This fails closed rather than treating an unconstrained profile as universally eligible.
7. Job region:
   - `worldwide` is eligible only when it is an explicit canonical `JobFacts.regions` value from ATS `regions` or evidence-validated extraction;
   - `region_unknown` when no region remains and worldwide is absent;
   - `exact_region_match` when set intersection with profile regions is non-empty;
   - otherwise `region_incompatible`.

Any exclusion reason makes `eligible` false. Eligible decisions contain one positive reason, `worldwide` or `exact_region_match`, for observability.

No country-to-continent, city-to-country, timezone, neighboring-region, substring, or fuzzy expansion is performed. Existing `canonical_region` aliases still apply on both sides. Existing location fallback may produce an exact canonical region, but it cannot manufacture `worldwide`; `facts.py` already excludes `remote`, `worldwide`, and `global` location tokens from fallback regions.

### Conflict handling

Relevant `Ambiguity` values are those on `remote_policy` and `regions`. When `build_job_facts` falls back from location to regions and location has conflicting ATS evidence, it emits a region-specific ambiguity so the decision fails closed. Unrelated ambiguities (for title, skills, employment, or legacy exclusions) do not block remote/location eligibility.

## Data flow

### Existing-corpus reprocessing

```text
worker claims run
  -> resolve run.profile_id
  -> validate CandidateProfileV1 and freeze profile binding/hash
  -> atomically persist reprocessing cutoff and binding in run.stats_json
  -> select jobs created_at <= cutoff, ordered by (created_at, id)
  -> for each job without a valid terminal PREFILTERED checkpoint:
       PipelineExtractionService prepare/execute/finalize
       (terminal invalid/missing extraction is allowed to continue)
       MatchingService builds JobFacts and normal JobScore
       shared feedback eligibility decision
       commit one RunJob(PREFILTERED, SUCCEEDED) outcome
  -> recompute totals/reasons from checkpoints
  -> only when pending == 0 mark reprocessing complete
  -> begin all normal acquisition producers and existing gates
```

The historical `PREFILTERED` stage is reused only as the run-local eligibility checkpoint for the pre-acquisition corpus. The outcome explicitly carries `purpose: "feedback_eligibility_reprocess"`, so consumers do not confuse it with source-side filtering. This avoids an enum/schema migration while retaining a durable unique key `(run_id, job_id, stage)`.

The corpus boundary is `Job.created_at <= cutoff`, where `cutoff` is captured before acquisition starts. UUID ordering is not used as a cursor. Jobs inserted after the cutoff are handled by normal post-acquisition processing. All job statuses are included because exclusion must not delete or silently omit corpus records.

Each checkpoint outcome has this shape:

```json
{
  "purpose": "feedback_eligibility_reprocess",
  "decision": {
    "policy_version": "feedback-remote-eligibility-v1",
    "profile_binding": {},
    "input_sha256": "...",
    "eligible": false,
    "reason_codes": ["remote_policy_unknown"],
    "extraction_id": null
  },
  "job_score_id": "..."
}
```

A terminal extraction failure is not a reprocessing failure: the shared decision records `extraction_incomplete` and the eligibility checkpoint succeeds with an excluded outcome. Database corruption, an invalid profile binding, or inability to persist a checkpoint fails the run before acquisition.

### Newly acquired jobs

```text
broad acquisition (unchanged)
  -> normalize/deduplicate/persist (unchanged)
  -> extraction (unchanged)
  -> build JobFacts + normal score
  -> shared feedback eligibility decision
  -> RunJob(SCORED) stores score id + exact decision
  -> later feedback selection
```

The `SCORED` checkpoint remains the source of truth for newly acquired candidates. Its outcome adds a `feedback_eligibility` object but preserves `job_score_id`, `eligible` (general matching), and `score` for existing consumers.

### Feedback

```text
run's DEDUPLICATED discovery candidates
  -> require run.profile_id and unchanged stored profile binding
  -> require same-run SCORED/SUCCEEDED checkpoint
  -> require well-formed feedback_eligibility decision
  -> verify policy/profile binding and eligible == true
  -> existing renderability check
  -> existing phrase relevance ranking/order
  -> existing display, feedback decision, and refinement flows
```

Feedback never falls back to the latest score or another run's outcome. Missing or invalid eligibility metadata is excluded, not inferred. This keeps retry/profile/hash boundaries exact and prevents old policy results from leaking into a new surface.

## Persistence and restart safety

### Run-level manifest

`JobSearchRun.stats_json["feedback_eligibility_reprocessing"]` stores:

- `policy_version`;
- `profile_binding`;
- `cutoff_utc`;
- `total`, `pending`, `completed`, `eligible`, `excluded`;
- sorted `reason_counts`;
- `complete`.

The cutoff and binding are write-once for a run. On resume, a different profile hash, row version, schema version, policy version, or cutoff is a hard failure. Counts are recomputed from `PREFILTERED` checkpoints and the cutoff query; they are not trusted as the checkpoint itself.

`worker/checkpoints.recompute_stats` must merge/preserve this namespaced object when final run stats are written, rather than dropping it.

### Per-job checkpoints

- Existing valid extraction operations remain idempotent by job, description hash, schema, and prompt version.
- Existing immutable `JobScore` operations remain idempotent and are reused.
- The `PREFILTERED` row is terminal only if its purpose, policy version, profile binding, and decision hash are valid for the run manifest.
- Malformed or mismatched terminal rows block the run; they are not silently accepted or overwritten.
- Commits occur per job, so a process interruption loses at most the active job's uncommitted work.
- On restart, valid completed rows are counted and skipped; pending jobs resume in deterministic order.
- Reacquisition cannot begin until the recomputed pending count is zero and `complete` is persisted.

Because the project has one worker and one SQLite writer, no distributed lock or new lease type is added. The existing run claim/lease protects execution. A retried terminal run gets a new manifest but reuses immutable extraction/score work; it records new run-local eligibility checkpoints.

## API and CLI behavior

### Run API

`POST /runs` and retry behavior remain unchanged (`202 Accepted`). The worker may keep the run in its existing pre-collection state while reprocessing. `GET /runs/{id}` already returns `stats`; clients can inspect `stats.feedback_eligibility_reprocessing` without a response-schema change.

No endpoint can bypass reprocessing or force collection to start. Existing idempotency and profile selection behavior remains intact.

### Feedback CLI

Existing commands and arguments remain unchanged.

- `feedback status` and `feedback summary` add an `eligibility` object containing eligible/excluded counts and sorted exclusion reasons.
- `feedback show`, `next`, `review`, `decide`, and refinement operate only on admitted surface items.
- Asking to show or decide an excluded/missing-eligibility job returns the existing `feedback_job_not_found` boundary; reasons are aggregate operational metadata, not a way to submit a decision for an excluded job.
- A malformed/mismatched run binding produces a blocked result rather than an empty, apparently successful surface.

### Acquisition behavior

All collection/discovery configuration, queries, parent pools, source snapshots, budgets, journals, capability checks, authorizations, and quotas are unchanged. The only orchestration change is temporal: the eligibility reprocessing barrier completes before calling any acquisition producer.

## Affected files and symbols

| File | Planned change |
|---|---|
| `src/role_radar/matching/contracts.py` | Add `ProfileBinding`/`FeedbackEligibilityDecision` immutable DTOs, or keep the binding as a validated mapping if that is smaller during implementation. |
| `src/role_radar/matching/feedback_eligibility.py` | Add policy version, reason constants, canonical hash, and pure `evaluate_feedback_eligibility`. |
| `src/role_radar/matching/facts.py` | Emit region ambiguity when location-derived regions depend on conflicting evidence. |
| `src/role_radar/services/matching_service.py` | Factor current snapshot loading so one call returns persisted `JobScore` plus decision without rebuilding facts twice. |
| `src/role_radar/services/eligibility_reprocessing.py` | Add cutoff/binding manifest, deterministic corpus iteration, extraction reuse, `PREFILTERED` checkpoints, and progress recomputation. |
| `src/role_radar/services/pipeline_scoring.py` | Add the decision to each new job's `SCORED` outcome. |
| `src/role_radar/worker/pipeline.py` | Invoke the barrier before `_collection.prepare` and all other acquisition producers; preserve namespaced stats at completion. |
| `src/role_radar/worker/checkpoints.py` | Preserve/merge eligibility manifest and avoid counting reprocessing checkpoints as source prefiltering. |
| `src/role_radar/services/feedback_service.py` | Validate run-local eligibility checkpoints before renderability and relevance ranking; expose aggregate counts. |
| `src/role_radar/cli/feedback.py` | Include aggregate eligibility status in existing status/summary JSON and map binding errors to blocked output. |
| `tests/unit/test_feedback_eligibility.py` | Pure eligibility matrix and deterministic hashes/reasons. |
| `tests/unit/test_feedback_surface.py` | Admission, fail-closed missing/stale outcomes, ordering after filtering, and decision rejection. |
| `tests/unit/test_feedback_cli.py` | Existing command shape plus aggregate eligibility output and blocked binding behavior. |
| `tests/integration/test_phase05_pipeline.py` | Reprocessing-before-collector ordering, interruption/resume, current/new parity, and broad acquisition preservation. |
| `tests/integration/test_feedback_discovery_smoke.py` | Extraction through scoring checkpoint to feedback surface with exact/worldwide/unknown cases. |

No Alembic migration, public profile schema change, collector change, Gate B-F change, or feedback-decision schema change is planned.

## Test strategy

Strict TDD applies during implementation; the design phase does not run tests.

### Unit tests

1. Exact canonical region plus known compatible remote policy is eligible.
2. Explicit extraction/ATS `regions=["worldwide"]` is eligible for a profile with regions.
3. Free-form location `Worldwide` does not create worldwide eligibility.
4. Unknown, unsupported, empty, or absent remote policy is excluded.
5. Empty region, empty profile regions, non-exact region, and location-derived unknown region are excluded.
6. ATS-vs-extraction and ATS-vs-ATS conflicts on remote/region fail closed.
7. Unrelated ambiguities do not affect this decision.
8. `remote_only` and `allowed_remote_policies` retain existing compatibility semantics.
9. Equivalent canonical inputs produce the same decision hash; changed profile/facts/policy change it.
10. Existing `JobScore.eligible` tests remain unchanged, proving the feedback rule does not redefine matching.

### Service and integration tests

1. Seed current jobs before a run; assert no collector/discovery/free-source/mailbox call occurs until every cutoff job has a terminal `PREFILTERED` decision.
2. Interrupt after one committed job, resume the same run, and assert the completed decision is reused and pending jobs continue.
3. Assert unknown/conflicting current jobs finish as excluded rather than leaving the barrier pending.
4. Assert a database/persistence failure prevents all acquisition calls.
5. Assert jobs acquired after the cutoff receive the same decision shape/function in their `SCORED` checkpoint.
6. Assert equivalent current and new facts yield identical eligibility and reason codes under one profile binding.
7. Assert restrictive profile regions do not change collector snapshots, requests, parent counts, or acquired job/source-reference persistence.
8. Assert feedback excludes missing, malformed, wrong-profile, wrong-policy, unknown, conflicting, and incompatible outcomes before ranking/rendering.
9. Assert exact and worldwide jobs remain orderable/reviewable and human decisions still require existing validation/revision checks.
10. Assert run API stats and feedback CLI status/summary report pending/completed/eligible/excluded/reason counts without exposing job text.
11. Keep architecture tests proving Gate D and authorization/hash boundaries have no new dependency on feedback eligibility.

Implementation verification uses the configured `make test`; `make lint` and the repository's normal check command should follow once tests pass.

## Rollout

1. Deploy code with the barrier enabled as the new policy version; no migration is needed.
2. Pause the scheduled worker before deployment so no old process starts the next acquisition cycle concurrently.
3. Start one worker and create/allow the next run. Observe `stats.feedback_eligibility_reprocessing` until `complete=true`.
4. Verify reason counts, especially `extraction_incomplete`, `remote_policy_unknown`, and `region_unknown`, before acquisition starts.
5. Confirm source snapshot/request and acquired-parent counts remain consistent with prior broad acquisition.
6. Confirm feedback totals decrease only by recorded eligibility reasons and eligible jobs retain normal ranking and human review behavior.

The implementation is likely near the 400-line review budget once tests are included. During task/apply planning, forecast the actual slices; under `ask-on-risk`, pause before implementation if the forecast exceeds 400 lines rather than inventing a chain strategy.

## Rollback

- Stop the worker before rolling back, preserving the existing operational control boundary.
- Revert the code that enforces the pre-acquisition barrier and feedback checkpoint filter.
- Leave `PREFILTERED` outcomes, added `SCORED` JSON keys, extraction rows, scores, jobs, source references, and human feedback decisions intact; older code ignores the extra JSON.
- Resume the prior pipeline and feedback behavior only after existing deployment authorization/consent checks.
- Never rewrite profile hashes, source observations, gate artifacts, journals, budgets, or human decisions during rollback.

Because there is no schema migration and all added persistence is additive JSON/checkpoint data, rollback requires no destructive data operation.

## Tradeoffs

| Choice | Benefit | Cost / accepted limit |
|---|---|---|
| Separate feedback decision from `JobScore.eligible` | Avoids changing deep-evaluation, digest, and historical score behavior. | Adds one small pure contract beside matching rather than folding every eligibility meaning into one boolean. |
| Reuse `RunJob.PREFILTERED` for baseline checkpoints | No schema migration; unique, durable, restart-safe per run/job. | The historical stage name is imperfect, so the outcome purpose must be explicit and consumers must not interpret it as source-side filtering. |
| Store run manifest in namespaced `stats_json` | Uses an existing observable API field and avoids a batch table. | Relies on the documented single-worker/single-writer architecture; add a dedicated batch table only if multi-worker global coordination becomes a real requirement. |
| Fixed `created_at` cutoff | Defines a stable corpus without persisting a potentially large job-id list. | Jobs created concurrently after the cutoff are handled as new work, not part of that baseline. |
| Fail closed on empty profile regions | Keeps exact-match semantics deterministic and safe. | Profiles without regions produce zero eligible feedback until a human creates a valid successor profile. |
| Aggregate exclusion reasons in CLI/API | Operationally explainable without exposing job text. | Per-job reasons remain in internal run checkpoints; no new public eligibility endpoint is added. |

## Invariants for review

- No eligibility call is reachable from collectors, query planners, source snapshots, Gate D, or acquisition quota calculation.
- No acquisition producer executes before the current-corpus manifest is complete.
- Every feedback item references a same-run successful scoring checkpoint with a valid, eligible decision for the frozen profile/policy identity.
- Unknown or conflicting remote/location evidence cannot pass.
- Worldwide must be explicit; all other geography is exact canonical equality.
- Eligibility never creates, changes, or submits a human decision and never mutates a profile.
