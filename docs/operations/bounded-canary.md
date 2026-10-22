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
