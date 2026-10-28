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

The gate requires exactly one Alembic version row at
`aa04_bounded_canary_execution`, the revision introduced by
`alembic/versions/aa04_bounded_canary_execution.py`, and the inspected run and
notification tables/metadata columns. It runs SQLite integrity and foreign-key
checks, then reads only run identity/status/ownership/timing/recovery metadata
and notification outbox identity/status metadata. Active, pending, claimed, or
leased runs fail; a `deferred` run with ownership cleared is retained as
historical rather than presumed to be active. Unresolved or unknown notification
batch/item states fail closed; sent/failed terminal states are accepted based on
the official enums and repository lifecycle. No UUIDs, profile IDs, message
bodies, reasons, error text, policy, or payload values are printed.

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
Passing T2a
proves only this backup unit's checks and artifacts. T2b single-run creation
and T3 supervision remain separate, unimplemented tasks; do not proceed to
host operation based on this pass alone.

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
