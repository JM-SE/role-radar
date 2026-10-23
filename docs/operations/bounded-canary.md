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
