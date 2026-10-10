# Discovery Verification Diagnostics

## Objective
Persist privacy-safe public counters that distinguish board collection failure, empty collection, and invalid normalized fields before the discovery writer. This is an offline observability work unit, not a fix to filters or proof of MVP success.

## Authorization and boundaries
The user authorized starting this proposed step on 2026-10-10. Worktree: `/tmp/opencode/role-radar-functional-mvp-closure`, feature branch `feat/functional-mvp-closure`, baseline `9f29f7c4c9b37f3058d57b9b69da066a159fa6f0`. Preserve the existing `.gitignore` modification. Parent feature: `odd/tasks/functional-mvp-closure.md`.

- Only public repository source and synthetic offline tests are in scope.
- No sudo, installation, production files or databases, environment/credential reads, private evidence, profile/job payloads, logs, restarts, provider calls, or live canary.
- All four previous canary attempts remain consumed and untouched. Additional live execution requires a new exact bounded human grant.
- Preserve filters, normalization, exact accepted collector job tuples, writer decisions, registration, budgets, reservation/call ordering, cycle status and error codes. No schema, configuration, dependencies, or Broker/model changes.
- Counters contain fixed public keys and nonnegative integer quantities only; never arbitrary collector messages, URLs, UUIDs, hashes, or payloads.

## Evidence and uncertainty
The consumed attempt recorded known=1, verified_sources=0, blocked=0, verified_jobs=0 and writer counters=0. Public source mapping establishes empty verified batches and no writer call. `_verify` returns None for failed/empty collection or missing normalized minimum fields, but does not persist the distinguishing cause. Its historical cause cannot be reconstructed from synthetic fixtures. Operational cleanup was verified separately; MVP, Telegram delivery and feedback acceptance remain unproven.

## Task checklist
### VD-01 — Persist board verification counters with offline regressions
- Status: `in_progress` — independent verifier `mv2n44n8-1h-j6ln` verified the candidate; closing the work-unit commit.
- Route: delegated explorer, then one bounded writer; multi-file write and preparation-reading triggers apply. Verification follows native ASSESS; uncertain/high assessment requires a separate verifier.
- Implement three fixed counters for failure, empty collection, and invalid normalized fields in existing discovery statistics; include zero values on applicable successful fresh executions.
- Keep diagnostic state local to each execution, prevent service reuse/concurrent execution leakage, and retain reused-cycle compatibility.
- Test first: observe meaningful RED for missing persisted counters, then GREEN with synthetic deterministic collector results, then focused regression checks.
- Acceptance: distinguish the three branches, preserve successful acceptance and original job tuple, persist counters in cycle stats, omit private/untrusted data, and prove independent executions do not leak counts. Preserve status/error behavior, decisions and budgets.
- Verification: clear inherited ROLE_RADAR_* variables, set UV_OFFLINE=1 and ROLE_RADAR_TEST_NETWORK_DENY=1; run `uv run --locked --group dev pytest -q tests/integration/test_canary_discovery.py tests/unit/test_acquired_job_writer_diagnostics.py tests/unit/test_pipeline_discovery_v2.py`, Ruff on the two changed source and two test files, and `git diff --check`. Never collect the unrestricted suite or private recovery evidence modules.
- Completion requires observed checks, parent/independent verification as required, one Conventional Commit with code and tests, and recorded commit identity.

## Progress
- 2026-10-10: resumed compact memory and reconciled current Git branch/HEAD and existing task-file closure evidence. Only `.gitignore` is modified. Authorized offline step is narrower than host deployment; sudo availability is not needed.
- Read-only mapping completed: two source files (`services/pipeline_discovery.py`, `discovery/contracts.py`) and two existing test files suffice. Use fixed keys `board_verification_failed`, `board_verification_empty`, `board_verification_invalid_fields`. Propagate per-execution immutable counter tuples, whitelist integer values at persistence, and keep diagnostic counts out of collector/writer decisions. Preserve reused plans' existing stats and return path rather than fabricating historical zeros. The four scoped source/test files now contain the implementation and regressions. No operational action has occurred.

## Verification evidence
- Writer reported meaningful RED for absent persisted counters, followed by 11 focused tests passing and `git diff --check` passing. Required Ruff failed with I001 in `pipeline_discovery.py`; baseline attribution was not established and no exception is accepted.
- Implementation: two source/two test files, 212 insertions and 7 deletions. Three positional integer counts are local to execute and carried by an immutable defaulted tuple. Persisted values are whitelist-only, nonnegative exact ints; malformed/bool values become zero. Acceptance still depends on batch presence. Reused-cycle early return is unchanged and the correction added its compatibility regression.
- One initial wrapper used unavailable `python`; subsequent checks used `python3`. No host or live effects were reported.
- Native ASSESS was unassessable because the task document is untracked and needs explicit declaration. RDD is off; returned plan requires writer self-verification AND independent verifier. No native approval exists.
- Correction `mv2n0pux-1g-oppd`: 12 focused tests, Ruff on all four changed paths, and diff check passed. I001 was resolved by targeted import ordering. Reused-cycle regression asserts historical stats/status/error unchanged and provider/collector sentinels not called. Intermediate synthetic fixture errors were corrected before final checks. Parent Git readback: actual work-unit diff is 260 insertions/7 deletions in four paths, excluding the existing `.gitignore` edit and task document. Full suite and live behavior remain intentionally untested. A fresh ASSESS still returned unassessable/high-equivalent and requires independent verification. No commit yet. Earlier cleanup evidence commits: `96e38374416572ab3cebf31b31bc0ddf8976aeba`, `9f29f7c4c9b37f3058d57b9b69da066a159fa6f0`. These prove neither new telemetry nor MVP acceptance.

## Independent verification
- Verifier `mv2n44n8-1h-j6ln`: VERIFIED, no material findings. Exact focused pytest command: 12 passed in 0.59s; Ruff on all four scoped paths passed; git diff --check passed. Environment was stripped of inherited ROLE_RADAR_* variables with offline/network-deny guards enabled.
- All four candidate source/test hashes were identical before and after verification; Git status was unchanged. No unexpected mutation, host access or provider call was reported.
- Source and tests prove all three distinct categories, per-execution isolation, success zeros, original accepted tuple identity, safe fixed-key integer persistence, and reused-cycle stats/status/error preservation without provider/collector work.
- Parent spot check reread the persistence guard and reran git diff --check successfully before committing.
- Limitations: initial RED is writer-reported, not independently re-observed. Short tuples are handled in source but lack explicit regression coverage; a non-sized value such as None lies outside the typed tuple contract and would raise. This was assessed as low risk, not a material finding. Unrestricted suite, build, installation and live/E2E checks were deliberately skipped. No historical live-cause reconstruction or MVP success is claimed.

## Next step
Close the verified offline work-unit commit and record its identity. The next operational step would be a separately authorized protected installation and installed verification; neither installation nor a new live canary is authorized by this task.
