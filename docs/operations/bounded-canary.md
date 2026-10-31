# Bounded canary adapter

## SYSTEMD isolation gate (T1a)

This first adapter is **only a read-only SYSTEMD isolation gate**, not overall
readiness and not authorization to operate a canary. It does not inspect the
application database, profiles, policy, installed-source provenance, or whether
a run ID was previously consumed. T1b and T1c supply separate gates; only a
later composition of all gates may report overall readiness.

From the installed application's virtual environment, the public invocation is:

```sh
.venv/bin/python -B scripts/bounded_canary_preflight.py --run-id 00000000-0000-4000-8000-000000000001
```

Use a syntactically valid future UUID. This validates syntax only: historical
consumption must be checked by a later lifecycle/database gate. The command
uses fixed `/usr/bin/systemctl show` and `list-units` calls, an allowlisted
set of unit names and properties, a 15-second timeout for each `show` and a
10-second timeout for `list-units`, and a clean locale/PATH environment. It never starts, stops, enables, disables, creates, or changes a
unit. It checks the API and the established active runtime baseline
`llm-broker-api.service`, `llm-broker-worker.service`, `llama-server.service`,
and `llama-swap.service`; these must be loaded, enabled, active/running, with a
canonical nonzero MainPID. The RoleRadar worker, scheduler, continuous
discovery/acquisition services and their timers must be quiescent. The gate
also lists every instantiated `role-radar-canary-worker@*.service`, then reads
and validates each instance plus the exact future instance. Any active or
nonzero-PID instance is rejected; historical failed instances with PID zero
are acceptable. Timer proofs do not require service-only PID or ExecStart
properties. Fixed properties and unit identities must all be present and
well-formed.

The exact canary worker must match the installed template contract: non-root
`role-radar` user, `/opt/role-radar` working directory, exact role-radar
`EnvironmentFile` and PATH, no `ExecStartPre`, oneshot type, no restart, and
exact `/usr/bin/env role-radar worker --run-id <instance-uuid>` argv. The
structured systemd `ExecStart` path and argv are parsed as data, never executed;
extra args and command-prefix lookalikes fail closed. Exactly the three expected
credential references are checked, never secret contents. This contract is
source-derived from `deploy/systemd/role-radar-canary-worker@.service` and the
established systemd snapshot guards in
`odd/operations/discovery-verification-diagnostics-promote.py`. Directory
ownership is not checked here; accepted operator/runtime trust remains the
boundary, and hashes are drift detection rather than immutable-code security.

Output is limited to fixed public gate codes. Any missing, malformed,
duplicate, unknown, or timed-out systemd proof fails closed. Do not interpret a
PASS as approval of the profile, policy, source/provenance, DB history, backup,
run creation, worker start, provider activity, or delivery. The four consumed
runs remain outside this gate and must not be retried or altered.

## Installed-source provenance gate (T1b)

This second gate checks **only 20 declared canary-critical source paths**. It is
not a reconstruction of the older 18-file installation manifest, an exhaustive
transitive-import inventory, an overall readiness decision, or authorization to
operate a canary. The expected bytes are pinned from the `a2d4d1ec15cdf620a99848660de07027d82ce821`
source tree, with only `src/role_radar/discovery/contracts.py` and
`src/role_radar/services/pipeline_discovery.py` pinned to their exact
`ec2fdac275d2a11799871cae65831c29b93a9866` blobs.

The declared paths are:

- `src/role_radar/cli/main.py`, `worker/main.py`, `worker/runner.py`,
  `worker/pipeline.py`, `worker/checkpoints.py`, `execution_budget.py`,
  `repositories/runs.py`, `services/eligibility_reprocessing.py`,
  `acquisition/discovery_policy.py`, `discovery/policy.py`, `domain/profile.py`,
  `matching/profile_intake.py`, `services/acquired_job_writer.py`,
  `services/pipeline_discovery.py`, `discovery/contracts.py`,
  `broker/client.py`, `broker/compat_check.py`,
  `broker/consumer-compat/v1/structured-extraction.json`, and `config.py`;
- `scripts/canary_supervisor.py`.

Run it from `/opt/role-radar` using the installed interpreter:

```sh
.venv/bin/python -B scripts/bounded_canary_provenance.py
```

The gate opens only paths beneath the fixed `/opt/role-radar` root. It follows
no symlinks, anchors directory traversal and file reads to descriptors, checks
stable directory and file identities before and after bounded reads, and hashes
the same descriptor whose metadata is checked. Files must be root-owned regular
files with one link and mode `0644` or `0664`; the two board-diagnostic leaves
retain their evidence-backed exact modes (`contracts.py` `0664`,
`pipeline_discovery.py` `0644`). No parent-owner/root-immutability claim is
made: existing operator/runtime parent trust is accepted. Missing/unreadable
sources, incompatible metadata, changed identities, or hash drift fail closed.
The gate does not import installed modules or read Git history at runtime.

Public output contains only the fixed PASS line or a fixed failure code; it
never prints source contents, hashes, raw exceptions, profiles, credentials, or
private payloads. A PASS means only that these 20 declared source leaves match
their expected public bytes and compatible metadata at read time. It does not
prove all imports, database/profile/policy state, T1a/T1c, backup readiness,
full canary readiness, immutable code, or successful delivery.

## SQLite database-history gate (T1c1)

This gate is a separate read-only check, not overall canary readiness and not
profile/policy binding (T1c2), backup/run creation (T2), or supervision (T3).
From the installed application directory, use the installed interpreter:

```sh
.venv/bin/python -B scripts/bounded_canary_database.py
```

The default target is the application's documented
`sqlite:///./data/role-radar.db`, resolved relative to the current working
directory. `--database-url` accepts relative and absolute SQLite file URLs;
supply the option at most once. Repeated options fail before any database open.
Other schemes, URI options/credentials, missing files, and detected symlinks
fail closed. The connection uses SQLite `mode=ro`, `query_only`, a read
transaction, a one-second busy timeout, and a SQL progress deadline that begins
before connection setup. The tool checks SQLite's file header without opening a
SQLite connection and requires existing regular `-wal` and `-shm` files when
the database is in WAL mode; an absent WAL resource or any rollback-journal
file fails before SQLite can create/recover sidecars. It does not import the
application or ORM, load dotenv/settings, create directories, migrate, or write
to the main database. Reading an active WAL can update `-shm` coordination
bytes; this is an explicit possible filesystem side effect, not a claim of
whole-filesystem nonmutation. Main-file identity checks reduce path-rebinding
risk, but the file-based SQLite URI cannot eliminate every concurrent
replacement race. The tool never uses `immutable=1`, which could hide current
WAL data.

The gate requires exactly one Alembic version row at either
`aa04_bounded_canary_execution` or `aa05_location_unconfirmed`. At aa04 it
requires the existing run/outbox schema and rejects a `location_unconfirmed`
table. At aa05 it additionally validates the review table's exact columns,
types, nullability, foreign keys, full (non-partial) identity uniqueness,
expected index, and effective CHECK behavior using a separate in-memory SQLite
probe; that probe does not write the target database. Both revisions run SQLite
integrity and foreign-key checks, then read only run identity/status/ownership/
timing/recovery metadata and notification outbox identity/status metadata.
Active, pending, claimed, or leased runs fail; a `deferred` run with ownership
cleared is retained as historical rather than presumed to be active. Unresolved
or unknown notification batch/item states fail closed; sent/failed terminal
states are accepted based on the official enums and repository lifecycle. No
UUIDs, profile IDs, message bodies, reasons, error text, policy, or payload
values are printed.

Public output is a fixed PASS line or a fixed failure code. The internal
`snapshot_history()` API is metadata-only and exists for a later before/after
comparison; a pass here does not prove preservation without that comparison.
A pass also does not establish whole-filesystem nonmutation, profile/policy
binding, backup, fresh run creation, source provenance, service isolation, or
permission hardening. It does not inspect profile or job payload tables.

## Official policy/profile binding gate (T1c2)

This separate read-only gate binds the official discovery policy to its exact
active profile row. Invoke from the installed application directory:

```sh
.venv/bin/python -B scripts/bounded_canary_binding.py
```

`--database-url` accepts the SQLite file URLs described above, and
`--policy-path` defaults to `/etc/role-radar/discovery-policy.toml`. The policy
is opened through the official bounded loader and production file metadata
policy. The gate validates the policy's full `ProfileBindingV1` against the
exact row selected by its bound profile ID, then calls the runtime's official
profile-row validator, including active status, row/schema versions and
canonical profile payload fingerprint. Transient profile JSON is used only for
canonicalization; it is never returned or printed. A policy hash by itself is
not active-profile authorization.

Output is a fixed public pass/failure code only. A pass proves only policy to
active-profile binding at inspection time; it is not overall readiness,
backup, run creation, worker start, supervision, Telegram state, or delivery.
The gate does not load application settings/dotenv, boot the ORM, mutate the
database, or access production data during offline reconstruction.

## Protected backup unit (T2a)

This offline-reconstructed unit composes the isolation, installed-source,
SQLite-history and official policy/profile-binding gates, then creates only a
protected backup. It does not create a canary run, start a worker, reset
consumed authority, authorize providers, or establish overall readiness. The
isolation gate receives a generated future UUID solely as its exact-instance
probe; no `run create` or worker CLI is called.

From `/opt/role-radar`, invoke with the installed interpreter:

```sh
.venv/bin/python -B -m scripts.bounded_canary_backup
```

The default SQLite URL is `sqlite:///./data/role-radar.db`, resolved from the
current working directory. `--database-url` may be supplied once to select a
SQLite file URL; it must be the same correct explicit target accepted by the
read-only database gate. There is no default-CWD guessing or URL abbreviation.
Help and rejected arguments perform no gate reads or backup mutations. All four
fresh gates run before backup mutations and are rechecked at the mutation
boundary. The systemd gate is only an isolation prerequisite, not start
authorization.

The operator must be effective UID 0 before any gate or private-file read.
The existing output root `/opt/role-radar/data/backups` must be a nonsymlink
`root:root 0755` directory. Its trusted ancestor ownership is not strengthened;
the nonsymlink directory chain and device/inode identities are held and
revalidated against descriptors through each operation. A planned random
recovery path and intent are recorded in memory before the first `mkdir`. A
unique child is exclusively created, changed only while new to `root:root
0700`, and validated before content is written. A collision is untouched.
Every new regular artifact is opened relative to the held child descriptor
with no-follow/exclusive flags, changed only while new to `root:root 0600`,
and verified single-link before writes, after writes and at completion. The
fixed environment source must be `root:root 0600`; the official policy loader
requires `root:role-radar 0640`. Both contents are descriptor-read, bounded,
identity-checked and rechecked through completion; their original parent-chain
identities are carried across gates and final checks. Only private copies are
retained. Neither contents nor raw errors are printed. A fixed free-space proof
based on the DB/WAL and config sizes plus a safety margin runs before backup
mutations; unavailable capacity proof fails closed. Before fresh gates, the
selected database file and its directory ancestors are anchored. Each gate and
the online-backup connection must identify that same source through completion;
a rebound leaf or parent fails closed, including a replacement with matching
history. The SQLite file is
copied with Python's SQLite online backup API from the read-only consistent
source view, not by copying the live main file/WAL pair. Its destination is
opened through the held file descriptor with an in-memory journal; if that
anchored procfs interface is unavailable, backup fails closed. Descriptor and
child-relative path identities are checked before and after copying and at
completion. The copy is integrity/FK/revision checked
and its metadata-only run/outbox history snapshot must equal its copied
snapshot. The exact metadata-only snapshot is retained in protected
`history.json` for T2b comparison; it excludes profile IDs, payload columns and
message contents, but still contains private run/outbox identifiers and must
remain protected. Version-2 `source-proof.json` privately binds the original
database identity, owner/group/link count and parent chain, plus environment
and policy identities/bytes, to the backup copies. T2b requires this proof
rather than inferring source identity from a backup created during retry. Source rows, payloads, counters and WAL are not intentionally
modified. SQLite may update `-shm` coordination bytes while reading a live WAL;
no whole-filesystem immutability claim is made.

The protected `intent.json` is flushed before artifact copying. Successful
completion is reported only after the protected files, final gate/config/history
checks, result record and directories are synced and revalidated. Failure
retains the recovery child and writes a fixed-schema `partial.json` only when
that child is safely verified; artifact states are `not_created`, `attempted`
or `created`. Failure before or during child creation reports `not_created`,
`collision` or `unknown` creation state and the planned recovery path. Artifacts
are never automatically removed, replaced, retried or rolled back. Failure to
persist partial evidence remains an operational risk. Public output uses fixed
gate/error codes and the recovery location, never profile/run identifiers,
database rows, payloads, credentials, policy contents, hashes, exception text,
or overall readiness claims.

The accepted trusted-ancestor boundary remains in force; this unit does not
change existing parent permissions or impose root ownership on every ancestor.
Passing T2a proves only this backup unit's checks and artifacts. T2b single-run
creation is a separate step described below; T3 supervision remains
unimplemented. Do not proceed to host operation based on a T2a or T2b pass alone.

## Protected artifact writer boundary (T2a1)

`scripts/bounded_canary_artifacts.py` is the independently testable protected
file boundary used by the backup orchestrator. Its descriptor-relative create
and write operations require exclusive no-follow regular files, apply owner and
mode before content, and revalidate the complete descriptor and named-entry
metadata immediately before the first private byte. The proof includes owner,
group, file type, mode, link count and descriptor/path identity; destination
SQLite pages use the same verifier immediately before online backup begins.
A changed proof fails closed and leaves the attempted artifact in place without
writing its payload. The caller retains responsibility for the trusted parent
chain, recovery evidence and fixed public error mapping.

T2a1 establishes only this reusable artifact-writer boundary and its synthetic
tests. T2a2 composes it with the SQLite/config orchestration, retaining original
source and ancestor identities and repairing the module entrypoint. Neither
unit is an overall backup-readiness or host-operation claim.

## Single canary run creation (T2b)

T2b accepts one exact, absolute recovery-child path produced by a completed
T2a backup. From `/opt/role-radar`, invoke the installed interpreter:

```sh
.venv/bin/python -B -m scripts.bounded_canary_create --backup /opt/role-radar/data/backups/canary-<32-lowercase-hex-digits>
```

This operation requires effective UID 0, validates the fixed protected backup
root, child and all required private artifacts, and verifies the source-proof
against the currently bound database, environment and policy. It revalidates
the completed T2a result and the source-proof digests for the retained SQLite
copy and metadata-only history, including that the history row counts match the
result. T2a had already checked the copy against that history before recording
completion. Fresh isolation, installed-source, database-history and official
policy/profile-binding gates must pass again. Source identity and configuration
bytes are checked again immediately before the durable attempt record. A
missing, changed, malformed or previously attempted backup fails closed and
is not repaired, replaced or retried.

Only after those checks does the adapter durably create `create-attempt.json`
inside the protected recovery child, then rechecks the original database/config
proof and every retained backup artifact immediately before dispatch. A drift
leaves the attempt and an uncertainty outcome and dispatches no child. It then
invokes exactly one clean
`runuser -u role-radar` child for `role-radar run create --canary --profile-id
<bound-profile-id>`, with only the fixed executable PATH, locale, app-root home
and proven database URL in the application environment. The root adapter does
not start a worker, import provider code, access credentials or authorize
provider consent. The existing application CLI creates the ordinary persisted
run, including its fixed canary budget and initial discovery checkpoint.

A zero exit plus the exact private JSON creation receipt is not sufficient by
itself: T2b reopens the held read-only database view and verifies exactly one
new pending run with the bound profile, exact canary budget/checkpoint, no
claim/lease/start, unchanged old run metadata/history and unchanged notification
outbox. Before writing a created outcome, it rechecks the original database's
device/inode/type/mode/owner/group/link count and parent chain, allowing only
SQLite payload/size/timestamp changes, then revalidates source config and all
retained backup artifacts. Any drift after dispatch is terminal uncertainty;
an already committed run is not rolled back or retried. On success it durably
writes `creation-outcome.json` as created and prints only
`CANARY_CREATION: PASS` with the recovery location. After the
attempt record, any timeout, nonzero exit, malformed or incomplete receipt, or
failed before/after comparison is terminally uncertain: the adapter records a
fixed uncertainty outcome and reports the recovery location. Child stdout/stderr
are captured before the 4 KiB length check, so that threshold rejects oversized
output but is not a hard memory-use bound. Do not run T2b again against that child or infer that no run was created. Inspect protected
evidence before any separately authorized recovery decision; no automatic
retry, database restore, worker start, supervision or delivery is included.

This is an offline-reconstructed creation boundary, not authorization to run it
on a host. T2b alone does not prove systemd supervision, provider budgets during
execution, Telegram cleanup/delivery or overall MVP readiness; T3/T4 remain
separate.

### Read-only successful-creation evidence (T3a)

The private `scripts.bounded_canary_create._open_creation_evidence(path)`
context manager is a narrow internal reader for a successfully created T2b
backup. It reuses the same anchored backup, strict result/history, version-2
source-proof, copied-artifact identity and digest validation as creation, then
requires exact protected attempt and `created` outcome records bound to the
same canonical profile UUID, backup path and backup-directory identity. It
returns private run/profile identities, verified retained history/proof and
held descriptor context only inside the context manager; all owned descriptors
close on exit or rejection. It performs no writes, timestamp updates, SQLite
opens or public output.

This reader does not claim host/run readiness, inspect current provider
settings, enforce that the run remains pending, or re-check live source
configuration. Uncertain, absent, malformed, mismatched or drifted evidence is
rejected. Successful evidence consumption does not make creation replayable:
the ordinary creation entry point continues to reject any existing attempt
before gates or child dispatch. Exact supervision and current-state checks are
separate T3 work; no start, stop, timer or provider operation is included.

### Pure Telegram provider-byte boundary (T3b1 prerequisite)

`prepare_telegram_provider_bytes(original)` is a pure byte transformation, not
an activation or filesystem API. It requires exactly one
`ROLE_RADAR_TELEGRAM_PROVIDER=disabled` assignment and returns bytes with only
that value changed to `http`; it never reads a path, loads settings, checks
credentials, calls a provider or emits output. Every other byte, including
comments, unrelated assignments and LF/CRLF/final-newline style, is preserved.

The accepted input is intentionally narrower than a general dotenv or shell
parser: blank lines; comments beginning with optional spaces/tabs and `#`; and
single-line ASCII assignments with an identifier key and an unquoted value
containing only letters, digits, `_./:@%+=,-`, with optional surrounding
horizontal whitespace. Quotes, backslashes, expansions, continuations, embedded
whitespace, malformed lines, non-ASCII assignment syntax and ambiguous
multiline forms fail with the fixed `provider_config_invalid` code. An
unsupported or initially enabled provider setting is rejected, never
normalized. A later anchored transaction must independently validate stored
T2b creation evidence and fresh pending-run/systemd/source/policy state before
any mutation; this helper accepts no ready-context boolean and proves none of
those facts. It does not check token/chat-ID presence. The eventual one-send
budget is not permission to activate Telegram now.

### Protected provider prepare and conditional restore (T3b1)

The offline transaction entry point is:

```sh
.venv/bin/python -B -m scripts.bounded_canary_telegram prepare --backup /opt/role-radar/data/backups/canary-<32-lowercase-hex-digits>
.venv/bin/python -B -m scripts.bounded_canary_telegram restore --backup /opt/role-radar/data/backups/canary-<32-lowercase-hex-digits>
```

`prepare` requires successful protected T2b creation evidence, revalidates the
exact pending run, fixed budget/checkpoint, prior-history/outbox invariance,
T1 isolation and source-provenance gates, official policy/profile binding, and
the original environment bytes/identity/ancestors. The generic DB history gate
intentionally rejects pending runs; this transaction applies its database
integrity/schema/outbox checks while separately admitting only the evidence-bound
pending canary. No stored receipt or caller-supplied readiness value substitutes
for these current checks.

The provider setting is the only changed value. A root-owned 0600 temporary
file is created in the environment file's held parent, protected before payload
bytes, synced and identity-checked. The fixed private `provider-intent.json`
receipt is durably created before the final gate/source recheck and atomic
same-parent replacement. `provider-outcome.json` records the resulting inode
identity only after replacement. Existing intent/outcome files are collisions:
there is no retry or automatic rollback. A crash or failed outcome persistence
can therefore leave an uncertain preparation requiring operator investigation.
The backup directory and all original T2b artifacts remain protected and
unchanged.

`restore` is a separate conditional operation. It requires matching successful
creation evidence, the fixed prepare intent/outcome, exact prepared bytes and
identity, original protected backup bytes, fresh gates and the original
ancestor chain. It atomically replaces the provider file only if the current
file still exactly matches the prepared identity and digest. A human edit,
replacement, or metadata drift is preserved and rejected; there is no blind
overwrite, automatic cleanup, or retry. Restore remains available after the
exact canary run has completed, failed, deferred, or stopped while retaining its
lease: it checks the run's identity, profile, budget, and modes, but does not
require `pending`, run pre-start isolation admission again, demand a stopped
state, or clear/assert lease ownership. It permits the run's legitimate database
and WAL changes while retaining the original database identity and policy
identity/bytes checks. It never changes run status or lease state. A fixed
restore-intent collision
prevents repeating an uncertain restore; `provider-restore-outcome.json` is
written only after the restored target and parent have been synced and checked.
This transaction neither invokes Telegram nor proves credential/destination
validity or authorizes sending.
T3b2 timer cleanup, T3c supervision, and integrated T4 verification remain
separate and pending.

### Fixed producer-timer cleanup (T3b2)

After a successful canary creation, invoke the offline-reconstructed cleanup
from `/opt/role-radar` with the installed interpreter:

```sh
.venv/bin/python -B -m scripts.bounded_canary_timers --backup /opt/role-radar/data/backups/canary-<32-lowercase-hex-digits>
```

This operation validates protected T2b creation evidence and binds its private
receipts to that exact backup identity, profile and run. It does not require
the run to remain pending and does not assert that a stopped worker released
its lease. Before dispatch, it snapshots the three fixed timers and the
Broker/model/API runtime baseline, then durably writes the exclusive private
`timer-cleanup-intent.json`. One bounded `systemctl disable --now` dispatch names
only `role-radar-scheduler.timer`, `role-radar-continuous-discovery.timer` and
`role-radar-continuous-acquisition.timer`; no other services are disabled or
stopped. A post-dispatch snapshot must show each timer loaded, inactive, dead
and disabled, and the unrelated runtime baseline must exactly match its
before-snapshot.

`timer-cleanup-outcome.json` records `completed`, `incomplete` or `uncertain`,
the bound intent digest and observed post-state when available. Both receipts
are exclusive root-owned mode-0600 files anchored beneath the protected
creation backup. Existing receipt names block all subsequent dispatches,
including after timeout or incomplete outcome; inspect protected evidence and
make a separate recovery decision rather than retrying. Command stderr is
captured and never exposed. A successful receipt proves only the observed
fixed timer state and preserved runtime baseline at that point; it is not a
worker-stop, ownership-release, overall-readiness or live-canary claim.
