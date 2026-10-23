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
