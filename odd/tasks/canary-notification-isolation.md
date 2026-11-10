# Canary notification isolation
Objective: prevent notification processing during the newly authorized bounded canary while preserving non-canary behavior.
Branch: `feat/location-unconfirmed-review`; delivery: one reviewable Conventional Commit, no push.
Test runner: `uv run --locked --group dev pytest -q`.

## Specs

- S1 — The user approved the bounded-search proposal with the exact response: “Autorizado, avanza.” The accepted limits were:
  > Una ejecución nueva, sin retomar ninguna anterior.
  > Máximo 10 minutos de ejecución.
  > Una consulta Brave y un board Greenhouse, hasta 2 vacantes nuevas.
  > Hasta 4 intentos de Broker, contando consultas de estado y reintentos internos.
  > Telegram deshabilitado durante todo el proceso.
  > Ante error o límite alcanzado: detener esa ejecución, conservar evidencia y no relanzarla.
  > Después, revisar vacantes recolectadas, rechazos, ubicación sin confirmar y elegibilidad; no considerar `completed` como prueba suficiente.
- S2 — The user authorized the minimal change, tests, and protected installation: “Sí, cambio e instalación acotados”. The approved request was: “¿Autorizás el cambio mínimo, sus pruebas y su instalación protegida para que el canario use `notification_mode=none`? El comportamiento actual queda intacto por defecto; después ejecutaré los gates y, solo si pasan, la búsqueda ya autorizada.”
- S3 — Add an explicit `--no-notifications` opt-in that is valid only with `--canary`, and have the bounded canary creation adapter use it. Preserve the existing default `run create --canary` behavior (`match_alerts`), ordinary and scheduled run behavior, and existing default JSON output for create/show/retry. The opted-out bounded path must not deliver Telegram messages; exercise the public CLI/worker boundary with isolated state and a fake gateway, and verify public run results plus zero gateway calls rather than asserting notification mode by inspecting internal tables.
- S4 — Do not create/start the live run or make provider calls until fresh installed-source, active-profile, no-competing-worker, exact-cap, and Telegram-disabled gates pass. Install only the tested application source under a protected no-overwrite backup; verify hashes, ownership and modes. On any error or cap, stop and preserve evidence; never retry or reuse a consumed run.

## Tasks
- T1 [S2-S3] Add the opt-in app-CLI flag and adapter `--no-notifications` switch, pass the flag only for the bounded search, keep default canary behavior and CLI output, and add public-boundary regression coverage; update the provenance pin and operations documentation. Route: delegated `gentle-ai-worker` (context backstop), followed by parent review; status: `done`; commit: `9142853`.
- T2 [S1-S4] Run focused and full verification, Ruff and diff checks; obtain independent high-risk verification before host writes. Route: parent plus `gentle-ai-verify`; status: `done`; parent full suite, CLI differential and checks pass; independent static and runtime verification returned GO for S2-S3 (105 focused tests); native assess is unassessable due undeclared untracked files while RDD is off; candidate commit: `9142853`.
- T3 [S1,S4] Reconcile the provenance inventory with the already-installed approved source versions, test the gate-pin correction, then back up the CLI preimage and protectedly install the tested CLI plus its seven required runtime helpers. Verify hashes/modes and run fresh read-only gates; do not create/start a run in T3. Route: parent; status: `blocked`; the authorized one-shot metadata-only diagnosis is complete. Cause: the installed gate classifies the database file as WAL mode and requires regular `-wal` and `-shm` sidecars; both are absent. Preserve the installed eight files and protected backup unchanged. No further DB query, gate rerun, sidecar creation/removal, service action, restore, or run is authorized without a new user decision. Read-only diagnosis confirmed `systemctl show` omits empty `ExecStartPre` and redacts `LoadCredential` as `[unprintable]` even with sudo; base implementation commit: `9142853`; the three reported mismatches are gate-pin drift, not a reason to overwrite installed application files: `acquired_job_writer.py` matches the workspace/T5 commit but its pin was stale; `pipeline_discovery.py` and `discovery/contracts.py` contain previously authorized installed diagnostics absent from this workspace branch. The offline correction pins the exact deployed bytes and adds regression coverage. Independent review `mvy2mcgr-j-b0pv` returned GO only for T3's restricted no-run scope and NO-GO for the install plan because exact backup/install/gate commands were missing. The exact T3 procedure is now documented below and passed shell syntax checks; fresh review `mvy3kz3c-l-f9g5` returned NO-GO because its expected gate-output contract did not match the scripts' complete PASS lines; that was corrected and checked. The next review `mvy3uf6l-m-ahkw` confirmed those outputs but returned NO-GO because the binding gate's direct-script invocation cannot resolve its `scripts.*` import. Parent changed it to module execution (`python -m scripts.bounded_canary_binding`); `git diff --check` and `bash -n` over all eight blocks pass. Independent review `mvy49pcj-n-o48n` returned GO for T3's protected installation/no-run plan only, confirming module resolution, hashes, gate outputs and boundaries. It flagged a stale direct-script example at `docs/operations/bounded-canary.md:171`, now corrected to module execution. Final diff/shell checks pass. The pre-install isolation gate was run once and failed with `SYSTEMD_ISOLATION_GATE: FAIL (systemd_proof_unavailable)`; T3 stopped before backup/install. No host write, run, provider call, or search occurred. Review GO is not operational readiness. Follow-up inspection corrected that cap audit: the installed and workspace canary paths already truncate the discovery plan to its first query, route that query through Brave Free only, and allow at most one Greenhouse board for that single query. The remaining live-run gate is proof that the effective worker `TimeoutStartUSec` is finite and at most 600 seconds; verify it again for the actual run ID before worker start. No source-cap code change is needed.

- T4 [S1,S4] ~~Enforce canary-only run-wide source maxima~~; status: `dropped`. Follow-up code/source audit confirmed the installed and workspace implementation already uses one Brave-only planned query and at most one Greenhouse board for that query; no source-code change is needed. Keep the actual worker timeout proof as a pre-start gate in T3/T2b.
- T5 [S4] Correct the preflight worker-contract evidence without weakening isolation: accommodate omitted empty `ExecStartPre` and prove configured credentials despite `LoadCredential=[unprintable]`; add CLI regressions, update the install manifest/runbook, and obtain fresh independent review. Route: parent inline; status: `done`; whitespace-before-`=` bypass and deterministic runner gaps were fixed; independent re-review returned GO; focused modules pass 168/168 and the full suite passes 1553/1553; code/runbook commit: `e288ca9`; read-only native assessment was unassessable because unrelated untracked files require declaration while RDD is off; no host writes or run/provider activity.

## Verification
- Writer RED/GREEN and focused command: `uv run --locked --group dev pytest -q tests/unit/test_canary_run_creation.py tests/unit/test_bounded_canary_create.py tests/unit/test_bounded_canary_telegram.py tests/api/test_runs.py::test_cli_default_notification_modes_are_public tests/integration/test_canary_notifications.py tests/integration/test_canary_pipeline_resume.py tests/integration/test_source_activation_vertical.py`.
- Lint: `uv run --locked --group dev ruff check scripts/bounded_canary_create.py scripts/bounded_canary_provenance.py src/role_radar/cli/main.py tests/unit/test_bounded_canary_create.py tests/unit/test_canary_run_creation.py tests/api/test_runs.py tests/integration/test_canary_pipeline_resume.py`.
- Format: `uv run --locked --group dev ruff format --check src/role_radar/cli/main.py tests/unit/test_canary_run_creation.py tests/api/test_runs.py`, plus `ruff format --check --range=33-54 tests/integration/test_canary_pipeline_resume.py`; these pass. Formatter diffs in `scripts/bounded_canary_create.py`, `scripts/bounded_canary_provenance.py`, and `tests/unit/test_bounded_canary_create.py` reproduce on `HEAD`; changed sections were checked and unrelated reformatting removed.
- Parent closure: focused suite 105/105 and `uv run --locked --group dev pytest -q` 1530/1530 passed. Subsequent edits were formatting/documentation only. The base-vs-candidate CLI differential confirms unchanged default create/show/retry, ordinary, scheduled, and default-canary output/behavior; intended opt-out differences are explicit, and rejected input leaves the public run list unchanged. Ruff check, `git diff --check`, CLI help, documented invocation and provenance/hash consistency pass. The three legacy-file formatter diffs reproduce on HEAD; no unrelated reformatting is retained.
- High-risk item 2: the T5 change touches the security boundary for canary worker systemd isolation and credential sources. Independent T5 review returned GO; full-suite and focused checks pass. The work-unit's native ASSESS returned `nativeRisk=unassessable` due undeclared untracked files; RDD is off, so no lifecycle operation was run.
- T5 RED/GREEN: regressions for omitted/redacted values, source/drop-in/reload drift, cat failure, and extra credential sources (including space/tab before `=`) pass. The focused preflight/create/Telegram/T3b1 modules pass 168/168; Ruff check, script formatting, changed-test-range formatting, and `git diff --check` pass. LSP diagnostics were unavailable because configured Python servers are unavailable. The first full-suite run failed (1516 passed, 12 failed, 15 errors); investigation traced the composed-test failures to the deterministic systemd fake lacking new fields and a `cat` branch, and independent review found the whitespace bypass. Both are fixed. Independent re-review `mvydot4i-p-9i2n` returned GO for these correction blockers and confirmed manifest consistency. The fresh full suite passed 1553/1553. Fresh operational gates remain pending under T3; no live systemctl, host write, backup, service/database change, run, provider call, search, or Telegram activity occurred.

### T3 protected installation and read-only gates (approved procedure; fresh gates still required before writes)

T3 installs only the eight L17 files. It does not stop or restart services, perform SQL/schema/row writes or configuration changes, create a run, start a worker, call providers, prepare Telegram, or send messages. The post-install SQLite gate opens the database read-only/query-only but may update WAL/SHM coordination bytes; preserve the database and sidecars and do not claim whole-filesystem nonmutation. Stop on any failed check; preserve the protected preimage, partial files, and captured output. Do not clean up or restore automatically.

After independent plan approval and from the workspace root, run the candidate isolation gate before any backup/install writes; it is read-only and must return exactly `SYSTEMD_ISOLATION_GATE: PASS (gate only; not overall readiness)`. Then define the targets and run the lstat preflight below before creating the backup, and repeat it immediately before installation. It rejects symlinked parents, verifies the exact CLI preimage, and requires all seven new helper targets to remain absent:

```sh
set -euo pipefail
cd /home/jmse/labs/role-radar
PREINSTALL_RUN_ID=$(.venv/bin/python -B -c 'import uuid; print(uuid.uuid4())')
expected='SYSTEMD_ISOLATION_GATE: PASS (gate only; not overall readiness)'
if actual=$(.venv/bin/python -B scripts/bounded_canary_preflight.py --run-id "$PREINSTALL_RUN_ID" 2>&1); then
  :
else
  status=$?
  printf 'T3_PREINSTALL_ISOLATION: FAIL (exit=%s; output follows)\n%s\n' "$status" "$actual" >&2
  exit 1
fi
if [ "$actual" != "$expected" ]; then
  printf 'T3_PREINSTALL_ISOLATION: FAIL (expected=%s; actual=%s)\n' "$expected" "$actual" >&2
  exit 1
fi
printf '%s\n' "$actual"
```

```sh
set -euo pipefail
APP=/opt/role-radar
sudo -n /usr/bin/python3 -B - "$APP" <<'PY'
import grp
import hashlib
import os
import pwd
import stat
import sys
from pathlib import Path

app = Path(sys.argv[1])
directories = [
    Path("/opt"), app, app / "src", app / "src/role_radar",
    app / "src/role_radar/cli", app / "scripts", app / "data",
    app / "data/backups",
]
for path in directories:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise SystemExit(f"T3_TARGET_CHECK: FAIL (directory_invalid: {path})")
backup_root = app / "data/backups"
backup_info = backup_root.lstat()
if (backup_info.st_uid, backup_info.st_gid, stat.S_IMODE(backup_info.st_mode)) != (0, 0, 0o755):
    raise SystemExit("T3_TARGET_CHECK: FAIL (backup_root_metadata)")
scripts_info = (app / "scripts").lstat()
if (scripts_info.st_uid, scripts_info.st_gid, stat.S_IMODE(scripts_info.st_mode)) != (0, 0, 0o755):
    raise SystemExit("T3_TARGET_CHECK: FAIL (scripts_directory_metadata)")
cli_parent = (app / "src/role_radar/cli").lstat()
role_uid = pwd.getpwnam("role-radar").pw_uid
role_gid = grp.getgrnam("role-radar").gr_gid
if (cli_parent.st_uid, cli_parent.st_gid, stat.S_IMODE(cli_parent.st_mode)) != (role_uid, role_gid, 0o700):
    raise SystemExit("T3_TARGET_CHECK: FAIL (cli_parent_metadata)")
cli = app / "src/role_radar/cli/main.py"
fd = os.open(cli, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    before = os.fstat(fd)
    digest = hashlib.sha256()
    while chunk := os.read(fd, 1024 * 1024):
        digest.update(chunk)
    after = os.fstat(fd)
finally:
    os.close(fd)
named = cli.lstat()
identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
identity_named = (named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns, named.st_ctime_ns)
metadata_before = (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode), before.st_nlink)
metadata_after = (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode), after.st_nlink)
metadata_named = (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode), named.st_nlink)
if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
        or metadata_before != (0, 0, 0o644, 1)
        or metadata_before != metadata_after or metadata_after != metadata_named
        or identity_before != identity_after or identity_after != identity_named
        or digest.hexdigest() != "b038b6cafbb2d0dcf4ebb7525bfcb8dd4eb27d0912114ee2c106613cd99389ff"):
    raise SystemExit("T3_TARGET_CHECK: FAIL (cli_preimage_mismatch)")
helpers = [
    "bounded_canary_create.py", "bounded_canary_backup.py",
    "bounded_canary_database.py", "bounded_canary_artifacts.py",
    "bounded_canary_binding.py", "bounded_canary_preflight.py",
    "bounded_canary_provenance.py",
]
for name in helpers:
    target = app / "scripts" / name
    try:
        target.lstat()
    except FileNotFoundError:
        continue
    raise SystemExit(f"T3_TARGET_CHECK: FAIL (helper_target_exists: {target})")
print("T3_TARGET_CHECK: PASS")
PY
```

After that PASS, create a unique protected directory and preserve the CLI bytes without overwriting an existing artifact. The directory must be root-owned mode 0700 and the preimage root-owned mode 0600; both the file and directory are synced and rehashed before installation:

```sh
set -euo pipefail
APP=/opt/role-radar
BACKUP_DIR=$(sudo -n /usr/bin/mktemp -d "$APP/data/backups/role-radar-canary-notifications-preinstall.XXXXXXXX")
sudo -n /usr/bin/test ! -L "$BACKUP_DIR"
test "$(sudo -n /usr/bin/stat -c '%F %u:%g %a' "$BACKUP_DIR")" = 'directory 0:0 700'
sudo -n /usr/bin/test ! -e "$BACKUP_DIR/cli-main.py"
sudo -n /usr/bin/test ! -L "$BACKUP_DIR/cli-main.py"
sudo -n /usr/bin/cp --no-clobber "$APP/src/role_radar/cli/main.py" "$BACKUP_DIR/cli-main.py"
sudo -n /usr/bin/chown root:root "$BACKUP_DIR/cli-main.py"
sudo -n /usr/bin/chmod 0600 "$BACKUP_DIR/cli-main.py"
sudo -n /usr/bin/sync --data "$BACKUP_DIR/cli-main.py"
sudo -n /usr/bin/python3 -B -c 'import os,sys; fd=os.open(sys.argv[1], os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); os.fsync(fd); os.close(fd)' "$BACKUP_DIR"
test "$(sudo -n /usr/bin/sha256sum "$BACKUP_DIR/cli-main.py" | cut -d' ' -f1)" = b038b6cafbb2d0dcf4ebb7525bfcb8dd4eb27d0912114ee2c106613cd99389ff
test "$(sudo -n /usr/bin/stat -c '%F %u:%g %a %h' "$BACKUP_DIR/cli-main.py")" = 'regular file 0:0 600 1'
printf 'T3_PREIMAGE_BACKUP: PASS (%s)\n' "$BACKUP_DIR"
```

Immediately after the protected backup, rerun `T3_TARGET_CHECK`. Keep the exact `BACKUP_DIR` printed by the backup block; if using a new shell, set it to that recorded path. Then run this one-off installer from the workspace root. It stages each candidate in the destination directory, checks its exact L17 hash, installs the seven helpers first with no-clobber rename, and replaces the CLI last only after rechecking its base preimage. Each rename is atomic per file; the batch is not a rollback transaction.

```sh
set -euo pipefail
WORKSPACE=$PWD
APP=/opt/role-radar
: "${BACKUP_DIR:?set this to the exact path printed by the backup block}"
test -f "$WORKSPACE/odd/tasks/canary-notification-isolation.md"
CLI_BASE_SHA=b038b6cafbb2d0dcf4ebb7525bfcb8dd4eb27d0912114ee2c106613cd99389ff
declare -A EXPECTED=(
  [src/role_radar/cli/main.py]=9899763647e64e0a0b62e48f87d20c4bce19716d565bc04e469464d47166a3d9
  [scripts/bounded_canary_create.py]=8f5a289f32c5ca7a70f2384d3be92e051e71a945adade1a1dfc631cce99ed22d
  [scripts/bounded_canary_backup.py]=02a22f4131ad70a5f5c5864bb9b5304d1fec73208b8eee14c46c6bcb0a775e38
  [scripts/bounded_canary_database.py]=1fff736f9985e7c9b2f69cf6d98bd749d32c5a7267922190179482055e039c57
  [scripts/bounded_canary_artifacts.py]=072c77800b542a855ec7e9bc9daff967a071bff6701f3939ba1bbd47b9d6eba0
  [scripts/bounded_canary_binding.py]=9af27102f23c154f2041dd5944746df1d8fafe60b02c461429396ad977edf22e
  [scripts/bounded_canary_preflight.py]=73921757593e3980494e4b8287144d5479c71cb659ca474541db614d3aa767c9
  [scripts/bounded_canary_provenance.py]=90a575991cdfeaa44e99c2c2bc374d9e2652f42e4dbc45f40f3b5d73220b52ee
)
ORDER=(
  scripts/bounded_canary_artifacts.py scripts/bounded_canary_binding.py
  scripts/bounded_canary_database.py scripts/bounded_canary_preflight.py
  scripts/bounded_canary_provenance.py scripts/bounded_canary_backup.py
  scripts/bounded_canary_create.py src/role_radar/cli/main.py
)
for rel in "${ORDER[@]}"; do
  src="$WORKSPACE/$rel"
  dst="$APP/$rel"
  expected=${EXPECTED[$rel]}
  test -f "$src" && test ! -L "$src"
  test "$(sha256sum "$src" | cut -d' ' -f1)" = "$expected"
  parent=$(dirname "$dst")
  base=$(basename "$dst")
  tmp=$(sudo -n /usr/bin/mktemp "$parent/.$base.install.XXXXXXXX")
  sudo -n /usr/bin/install -o root -g root -m 0644 -- "$src" "$tmp"
  sudo -n /usr/bin/sync --data "$tmp"
  test "$(sudo -n /usr/bin/sha256sum "$tmp" | cut -d' ' -f1)" = "$expected"
  test "$(sudo -n /usr/bin/stat -c '%F %u:%g %a %h' "$tmp")" = 'regular file 0:0 644 1'
  if [ "$rel" = src/role_radar/cli/main.py ]; then
    sudo -n /usr/bin/test ! -L "$dst"
    test "$(sudo -n /usr/bin/sha256sum "$dst" | cut -d' ' -f1)" = "$CLI_BASE_SHA"
    test "$(sudo -n /usr/bin/stat -c '%F %u:%g %a %h' "$dst")" = 'regular file 0:0 644 1'
    test "$(sudo -n /usr/bin/sha256sum "$BACKUP_DIR/cli-main.py" | cut -d' ' -f1)" = "$CLI_BASE_SHA"
    sudo -n /usr/bin/mv -fT -- "$tmp" "$dst"
  else
    sudo -n /usr/bin/test ! -e "$dst"
    sudo -n /usr/bin/test ! -L "$dst"
    sudo -n /usr/bin/mv -nT -- "$tmp" "$dst"
    if sudo -n /usr/bin/test -e "$tmp" || sudo -n /usr/bin/test -L "$tmp"; then
      printf 'T3_INSTALL: FAIL (destination collision: %s)\n' "$dst" >&2
      exit 1
    fi
  fi
  test "$(sudo -n /usr/bin/sha256sum "$dst" | cut -d' ' -f1)" = "$expected"
  test "$(sudo -n /usr/bin/stat -c '%F %u:%g %a %h' "$dst")" = 'regular file 0:0 644 1'
  sudo -n /usr/bin/python3 -B -c 'import os,sys; fd=os.open(sys.argv[1], os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); os.fsync(fd); os.close(fd)' "$parent"
done
printf 'T3_INSTALL: PASS (8 files; backup=%s)\n' "$BACKUP_DIR"
```

If a helper appeared, a source hash changed, or any command failed, stop with the backup and partial artifacts preserved. Do not restart the API, run another gate against a partial install, create a run, or search. Record the output and recovery path; no automatic cleanup or restore.

After installation, from `/opt/role-radar`, run the following read-only gates with one fresh UUID. Each command must exit zero and emit exactly its listed complete PASS line on combined stdout/stderr; the wrapper fails closed on any extra text or mismatch (comparison ignores trailing newline delimiters). Record `T3_GATE_RUN_ID` so the timeout check below uses the same future unit instance. The database gate opens SQLite read-only/query-only and may update WAL/SHM coordination bytes; preserve database and sidecar evidence and do not infer row-level writes or whole-filesystem nonmutation from a gate pass.

```sh
set -euo pipefail
cd /opt/role-radar
RUN_ID=$(/usr/bin/python3 -B -c 'import uuid; print(uuid.uuid4())')
printf 'T3_GATE_RUN_ID=%s\n' "$RUN_ID"
expect_gate() {
  local expected=$1
  shift
  local output status
  if output=$("$@" 2>&1); then
    :
  else
    status=$?
    printf 'T3_GATE: FAIL (exit=%s; output follows)\n%s\n' "$status" "$output" >&2
    return 1
  fi
  if [ "$output" != "$expected" ]; then
    printf 'T3_GATE: FAIL (expected=%s; actual=%s)\n' "$expected" "$output" >&2
    return 1
  fi
  printf '%s\n' "$output"
}
expect_gate 'SYSTEMD_ISOLATION_GATE: PASS (gate only; not overall readiness)' sudo -n .venv/bin/python -B scripts/bounded_canary_preflight.py --run-id "$RUN_ID"
expect_gate 'SOURCE_PROVENANCE_GATE: PASS (20 declared critical paths; gate only)' sudo -n .venv/bin/python -B scripts/bounded_canary_provenance.py
expect_gate 'DATABASE_HISTORY_GATE: PASS (gate only; not overall readiness)' sudo -n .venv/bin/python -B scripts/bounded_canary_database.py --database-url sqlite:////opt/role-radar/data/role-radar.db
expect_gate 'PROFILE_BINDING_GATE: PASS (policy/profile binding only; not overall readiness)' sudo -n .venv/bin/python -B -m scripts.bounded_canary_binding --database-url sqlite:////opt/role-radar/data/role-radar.db --policy-path /etc/role-radar/discovery-policy.toml
```

These exact outputs prove only their named gates. Passing T3 does not authorize a run start.

For the approved time ceiling, check the effective start timeout of the same future unit instance; the preflight independently confirms `Type=oneshot`, no `ExecStartPre`, and `Restart=no`. If running this in a new shell, set `RUN_ID` to the exact `T3_GATE_RUN_ID` printed above. The following read-only check accepts only a finite timeout in `(0, 600]` seconds and fails on `infinity`, unknown formats, or larger values:

```sh
set -euo pipefail
: "${RUN_ID:?set this to the exact T3_GATE_RUN_ID from the read-only gate block}"
sudo -n /usr/bin/python3 -B - "role-radar-canary-worker@${RUN_ID}.service" <<'PY'
from decimal import Decimal
import re
import subprocess
import sys

unit = sys.argv[1]
result = subprocess.run(
    ["/usr/bin/systemctl", "show", unit, "--property=TimeoutStartUSec", "--value"],
    capture_output=True, text=True, timeout=15, check=False,
    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
)
value = result.stdout.strip()
if result.returncode != 0 or not value or value == "infinity":
    raise SystemExit("CANARY_RUNTIME_CAP: FAIL (timeout_unavailable)")
if value.isdecimal():
    usec = Decimal(value)
else:
    units = {
        "usec": Decimal(1), "us": Decimal(1),
        "msec": Decimal(1000), "ms": Decimal(1000),
        "sec": Decimal(1000000), "s": Decimal(1000000),
        "min": Decimal(60000000), "h": Decimal(3600000000),
        "d": Decimal(86400000000), "w": Decimal(604800000000),
    }
    tokens = list(re.finditer(r"(\d+(?:\.\d+)?)(usec|us|msec|ms|sec|min|s|h|d|w)", value))
    if not tokens or "".join(token.group(0) for token in tokens) != "".join(value.split()):
        raise SystemExit("CANARY_RUNTIME_CAP: FAIL (timeout_unparseable)")
    usec = sum(Decimal(token.group(1)) * units[token.group(2)] for token in tokens)
if usec <= 0 or usec > Decimal(600000000):
    raise SystemExit("CANARY_RUNTIME_CAP: FAIL (timeout_over_600_seconds)")
print("CANARY_RUNTIME_CAP: PASS (finite timeout <= 600 seconds)")
PY
```

Do not create a run if this timeout proof is unavailable or fails.

The installed CLI and adapter help are also read-only checks; both must show `--no-notifications`. This proves the option is available, not that a live run used it. In the later, separately authorized T2b run-creation step, the command must include `--no-notifications` and return `CANARY_CREATION: PASS`; the adapter validates `notification_mode=none` before any worker start. T2b is not part of T3.

```sh
set -euo pipefail
cd /opt/role-radar
.venv/bin/role-radar run create --help | grep -F -- '--no-notifications'
.venv/bin/python -B -m scripts.bounded_canary_create --help | grep -F -- '--no-notifications'
```

The aggregate application budget can be checked read-only; it does not by itself prove the exact source cap:

```sh
set -euo pipefail
cd /opt/role-radar
sudo -n .venv/bin/python -B - <<'PY'
from role_radar.execution_budget import CANARY_LIMITS
expected = {
    "source_http_attempts": 2,
    "accepted_items": 2,
    "broker_calls": 4,
    "broker_attempts": 4,
    "notification_batches": 1,
}
if CANARY_LIMITS != expected:
    raise SystemExit("CANARY_AGGREGATE_BUDGET: FAIL")
print("CANARY_AGGREGATE_BUDGET: PASS")
PY
```

This only verifies the aggregate two-HTTP-attempt, two-accepted-item and four-Broker-call/attempt ceilings. It does not by itself establish the logical source limits. The source code does: `PipelineDiscoveryService.prepare` truncates a canary plan to its first query; planner ordinal 1 targets `boards.greenhouse.io`; `search_canary` performs one Brave Free operation without fallback, and `BraveSearchProvider.search` issues one bounded HTTP request without an internal retry loop; `execute` allows one Greenhouse board per query. Since the canary has one query, it can verify at most one Greenhouse board. Read-only excerpts of the installed files confirmed the same behavior, and `tests/integration/test_canary_discovery.py::test_canary_discovery_searches_once_and_verifies_only_one_greenhouse` covers one provider call and one Greenhouse collector for a one-identity plan. The `broker_attempts=4` budget covers each submit retry and each result/status poll; the worker template itself has no explicit ten-minute timeout, so prove the effective `TimeoutStartUSec` is finite and no more than 600 seconds for the actual worker instance before start. Recheck the actual run ID after T2b creation and before starting the worker; if unavailable or over the limit, do not start or recreate the run. No run-creation command belongs in T3. The later T2b step is already authorized but only follows all installed gates; it must include `--no-notifications` and pass `CANARY_CREATION: PASS` before any worker start. Do not call `bounded_canary_telegram.py` for this path.

## Log
- L1 (user's original authorization): “Autorizado, avanza.”
- L2 (explicit code/install authorization): “Sí, cambio e instalación acotados”.
- L3 (tracking instruction): “El plan de tareas no se ha revisado durante varios turnos de herramientas. Verifica si todavía coincide con el trabajo realizado y actualiza las tareas cuando sea necesario. No marques una tarea como hecha sin evidencia verificable.”
- L4: The visible search task #65's prior “waiting for a decision” blocker is obsolete after L2. The search itself remains pending until this prerequisite and its gates pass. No new search or host operation has occurred.
- L5: Initial writer diff changed every `--canary` run to `none`; focused creation test passed, but the bounded creation adapter still requires `MATCH_ALERTS` at `scripts/bounded_canary_create.py:465`. Parent reproduced `test_public_cli_creates_one_pending_canary_and_preserves_history`: exit 1 with `CANARY_CREATION: FAIL (creation_uncertain)`. The reported full suite was 45 failed/1467 passed/15 errors, including bounded-create, Telegram and timer tests; attribution beyond the reproduced adapter mismatch remains open. The writer's no-gateway test is not yet present. `gentle_review assess` was rejected with an empty reason; no independent verification or host change occurred. Ruff format also reports an existing reformat at `scripts/bounded_canary_provenance.py:155-156`; unresolved.
- L6: To honor S2's “El comportamiento actual queda intacto por defecto” and retain the separate existing match-alerts canary path, the correction is an explicit opt-in: bounded creation passes `--no-notifications`; ordinary, scheduled, and default canary creation retain their current behavior.
- L7: Parent review of the completed writer diff found the shared run-control success response adds `notification_mode` for default create, show, and retry operations, and the rejected-option test does not compare public run-list output before/after. The bounded-adapter test also directly asserts the private mode column. Keep the mode field only where the explicit opt-out requires it, preserve all default output shapes, compare public run lists for rejected input, and rely on the adapter's public result rather than the redundant private-column assertion. Focused (104) and full (1529) suites were green before this correction; no install/search occurred.
- L8: Parent added regression assertions for unchanged default create/show/retry JSON, public API visibility of default canary/ordinary/scheduled notification modes, and exact rejected-input output with run-list state unchanged. Test-first RED reproduced the leaked `notification_mode` field in default CLI output. The success response now adds the field only for explicit `run create --canary --no-notifications`; the adapter expects the expanded JSON only for that opt-out, and the redundant test assertion on its private mode column was removed. Rerun the documented focused/full suite before independent verification; no host action.
- L9: The corrected focused command passes 105 tests. `ruff check` on all seven changed Python files passes; `ruff format --check` passes on the four formatted files; the CLI source SHA256 `9899763647e64e0a0b62e48f87d20c4bce19716d565bc04e469464d47166a3d9` matches the provenance pin. Base formatter checks for the three legacy files fail; their changed sections are being kept minimal. The full suite after parent corrections, shared-command differential, native assessment, and independent verification remain pending; no host action.
- L10 (user-reported independent review evidence): “Static review found an operations-doc mismatch: docs/operations/bounded-canary.md:281 invokes bounded_canary_create without --no-notifications, while new prose :302-310 claims that invocation dispatches opt-out. Adapter main defaults False (:641), so documented command still creates match_alerts. Provenance narrative :58-61 also still says only two exceptions to old source tree, omitting newly repinned CLI. Runtime independent probes blocked by workspace-only scratch restriction vs mandatory system-temp scratch; no tests rerun. Inspecting remaining evidence; no app-code defect found so far.”
- L11: Parent reproduced and corrected both documentation mismatches: the T2b wrapper example now includes `--no-notifications`, and the provenance narrative identifies the CLI SHA-256 pin. A structural check confirms adapter help, wrapper and child invocation, narrative, provenance constant and actual CLI digest agree. The independent reviewer returned static GO for S2-S3 with no other demonstrated defects, but its runtime-verification gate remains unverified; it noted two non-reproduced coverage limitations (fresh-pipeline branch and response/persisted-mode disagreement tests). Parent focused 105/105, full 1530/1530, CLI differential, Ruff check and diff check pass; final post-suite edits were formatting/documentation only. No installation, search, host access or provider calls occurred; native assessment remains pending.
- L12: To keep the work unit reviewable, parent reverted unrelated whole-file Ruff formatting in `scripts/bounded_canary_provenance.py`; its diff is now only the CLI digest pin. A base/current AST comparison confirms no other provenance pin changed and the CLI digest matches. Ruff check and `git diff --check` pass; changed integration-test range is formatted, while formatter differences in the three named legacy files reproduce on `HEAD`. The parent’s earlier one structural-check command had an over-specific newline-sensitive assertion; the corrected whitespace-normalized check passed. No app behavior changed after the 1530-test full suite.
- L13: T1 committed as `9142853` (`feat(cli): add canary-only notification opt-out`). Native read-only ASSESS for `HEAD^..HEAD` returned `risk=high`, `nativeRisk=unassessable`, no candidate and zero changed paths because repository untracked files require explicit declaration; with RDD off, no further native lifecycle action is authorized. The independent verifier returned static GO for S2-S3, but runtime proof remained unavailable under the workspace-only restriction. No host install, search or provider activity occurred.
- L14 (user authorization): The user selected “Authorize this exact path” for exactly `/tmp/role-radar-notification-review-mvy1abj3`, only if absent, for one offline independent runtime verification; production DB, host, network, provider calls, Telegram and search remain excluded.
- L15: Independent runtime verification completed GO for S2-S3: the exact focused pytest selection passed 105/105 in 7.17s with exit 0 and empty stderr, network-denial guard enabled, using the authorized scratch created mode 0700 and preserved. It reports no forbidden access and no repository status change. No full-suite rerun, host install, or live search occurred.
- L16: Read-only `/opt/role-radar` preflight found `src/role_radar/cli/main.py` is a regular root:root 0644 file with the exact base SHA-256 `b038b6cafbb2d0dcf4ebb7525bfcb8dd4eb27d0912114ee2c106613cd99389ff`; `scripts/bounded_canary_create.py` and `scripts/bounded_canary_provenance.py` are absent. Workspace base/candidate hashes were recorded for all three targets. No host files, DB, or services were changed; inspect adapter imports and host helper availability before finalizing T3 scope.
- L17: The import chain confirms `bounded_canary_create.py` requires `bounded_canary_artifacts.py`, `bounded_canary_backup.py`, and `bounded_canary_database.py`; backup in turn requires `bounded_canary_binding.py`, `bounded_canary_preflight.py`, and `bounded_canary_provenance.py`. All seven targets are absent in `/opt/role-radar/scripts`, so installing only the feature adapter would fail before gates. Read-only host state: `/opt/role-radar/scripts` and `/opt/role-radar/data/backups` are root:root 0755; the CLI parent is role-radar:role-radar 0700. The API was active; worker, scheduler, and continuous service inactive. No host write, DB operation, or service action occurred. Proposed protected install manifest (all source paths regular workspace files, root:root 0644; SHA-256): `src/role_radar/cli/main.py` `9899763647e64e0a0b62e48f87d20c4bce19716d565bc04e469464d47166a3d9`; `scripts/bounded_canary_create.py` `8f5a289f32c5ca7a70f2384d3be92e051e71a945adade1a1dfc631cce99ed22d`; `scripts/bounded_canary_backup.py` `02a22f4131ad70a5f5c5864bb9b5304d1fec73208b8eee14c46c6bcb0a775e38`; `scripts/bounded_canary_database.py` `1fff736f9985e7c9b2f69cf6d98bd749d32c5a7267922190179482055e039c57`; `scripts/bounded_canary_artifacts.py` `072c77800b542a855ec7e9bc9daff967a071bff6701f3939ba1bbd47b9d6eba0`; `scripts/bounded_canary_binding.py` `9af27102f23c154f2041dd5944746df1d8fafe60b02c461429396ad977edf22e`; `scripts/bounded_canary_preflight.py` `f586f4194324d43964c33aca00ee8024fb110427119977f6fb80de7130ce4cbe`; `scripts/bounded_canary_provenance.py` `90a575991cdfeaa44e99c2c2bc374d9e2652f42e4dbc45f40f3b5d73220b52ee`. Do not write until a static independent reviewer approves the exact backup/install/gate plan; then revalidate target preimages/absence immediately before protected writes. Keep API active; install CLI/helper files atomically, perform only read-only gates, and do not create/start a run as part of T3.
- L18: A read-only baseline-adjusted provenance diagnostic called the protected source checker across all 20 declared paths, overriding only the CLI pin to the deployed base hash. Result: 17/20 matched; three paths returned `source_hash_mismatch`. Follow-up SHA-256 comparison found `acquired_job_writer.py` is byte-identical between `/opt` and the current workspace/T5 commit `b16874d` (`dd351d737b921b8e0fd6b7d228e53626fa04dc590bd8d91b9c2a3fa6178ef958`), while its provenance pin is stale at the earlier `4c3d815` version (`db98adc5...`). `pipeline_discovery.py` and `discovery/contracts.py` contain previously authorized installed collector-diagnostic fields not present in this workspace branch; current host hashes are respectively `dd05f31105f935989357640565deb867a63cc950773e346b39c67313e144bd14` and `b051435802d3ef191ed738bf7b0977bc7f926e102dfb994108fd9d13e70af5a4`. Protected preinstall files under `mvp-search-20261029` match the current workspace pre-diagnostic versions (`6bedf540...`, `6b354b9e...`); the authorized install result for `4c3d815` records the diagnostic source paths and prior independent verification. Therefore preserve all three installed app files and update only the local provenance pins to these exact deployed hashes. This remains diagnostic evidence, not a candidate provenance pass; no host content, DB, or service was changed.
- L19: Test-first provenance-pin correction: the new exact-hash regression failed RED for all three stale pins, then the local pin-only correction passed the provenance/create/Telegram focused modules (130/130), Ruff check, changed test-block formatting, and `git diff --check`. A read-only baseline-adjusted source check passed 20/20 with only the CLI pin set to the currently installed base. A temporary in-project base snapshot and isolated public-gate differential then produced the expected outcome: base code returned exit 1 with `source_hash_mismatch`; candidate code returned exit 0 with `SOURCE_PROVENANCE_GATE: PASS (20 declared critical paths; gate only)`. The full suite passed 1,533/1,533. Whole-file formatter output points at unchanged legacy blocks; no unrelated formatting was applied. No host writes, DB or service operations, network, Telegram, or search occurred.
- L20 (independent T3 plan review, `mvy2mcgr-j-b0pv`): S1 is GO only for T3's restricted no-run scope; S4 is NO-GO because the executable protected backup/install/fresh-gate procedure was missing. The reviewer confirmed the three provenance pins and all eight manifest hashes, and did not access the host or run tests. No installation was approved or executed.
- L21 (read-only cap audit, `mvy3442y-k-e9kl`): the existing application enforces two accepted items and four Broker calls/attempts, but `source_http_attempts=2` is aggregate and does not guarantee one Brave query plus one Greenhouse board. The worker unit has no explicit ten-minute limit and `canary_supervisor.py` is observation-only. The isolation preflight does not verify these caps. Therefore the existing authorization cannot safely be used to create/start the search run until exact source-specific enforcement is available and independently verified. No host, database, service, network, provider, Telegram, or search operation occurred.
- L22: Parent documented the exact T3 preflight, protected CLI-preimage backup, per-file staged/no-clobber install, post-install read-only gates, expected outputs, and fail-stop/evidence handling. `docs/operations/bounded-canary.md` now records the corrected four provenance-pin origins and explicitly distinguishes aggregate budgets from the missing per-provider/elapsed-time limits. `git diff --check` and `bash -n` on all eight task-document shell blocks passed. Documentation-only; no host or application code was changed.
- L23 (independent review `mvy3kz3c-l-f9g5`): T3 plan review returned NO-GO because the documented acceptance rule expected bare PASS prefixes while three gates emit longer complete lines. It otherwise confirmed the eight-file import closure, preimage checks, protected backup, no-clobber helpers-first/CLI-last install, and the restricted no-run boundary; no commands, host access, or tests were performed. It also reiterated that aggregate limits do not prove exact provider caps, the timeout needs fresh proof, and read-only SQLite may update SHM coordination bytes.
- L24: Parent corrected the T3 procedure to compare each gate's complete exact output line and exit status, fail fast in shell blocks, use the installed working directory for CLI-help checks, and explicitly report that read-only WAL checks may alter SHM coordination bytes. `git diff --check` and `bash -n` over all eight shell blocks pass; a fresh independent review is required before any host write. No installation, host access, run creation, provider call, or search occurred.
- L25 (read-only CodeGraph audit): `PipelineDiscoveryService.execute` iterates all four planned query identities for canary runs, and `search_canary` makes a Brave-only operation for each; `canary_verified` resets inside the loop, permitting one Greenhouse board per query (up to four per run). `source_http_attempts=2` is aggregate, not the exact query cap. `LLMBrokerClient._submit` and `_poll` both reserve `broker_attempts`, so its four-attempt cap covers submit retries and status polls. Exact run-wide Brave/Greenhouse maxima and the fresh effective 600-second worker-timeout gate remain prerequisites; no code, host, DB, provider, or run operation occurred.
- L26 (independent plan review `mvy3uf6l-m-ahkw`): NO-GO for T3 because the binding gate used direct script execution although it imports `scripts.bounded_canary_database`; under the installed layout, use `python -m scripts.bounded_canary_binding` from `/opt/role-radar`. The reviewer confirmed exact PASS output content, fail-closed wrappers, the eight-file install controls and no-run boundary; no commands, host access, tests or edits were performed.
- L27 (cap-audit correction): Follow-up CodeGraph source and installed-source reads found the earlier L21/L25 conclusion missed `PipelineDiscoveryService.prepare`'s `queries = queries[:1]` canary branch. The installed planner's ordinal 1 is `boards.greenhouse.io`, and installed `search_canary` is Brave-Free-only with no fallback. `execute` limits Greenhouse verification to one candidate per query; the one-query plan therefore caps the run at one Greenhouse board. The integration regression asserts one provider call and one Greenhouse collector. The four Broker attempt reservations cover submit attempts/retries and every result/status poll. The installed `pipeline_discovery.py` SHA-256 `dd05f31105f935989357640565deb867a63cc950773e346b39c67313e144bd14` matches the candidate provenance pin. Thus no source-cap implementation is needed; only the effective <=600-second timeout proof and post-install operational gates remain. No code or production data changed.
- L28: Parent changed the post-install binding-gate invocation to `python -m scripts.bounded_canary_binding` from `/opt/role-radar`. `git diff --check`, `bash -n` on all eight fenced blocks, and a structural check rejecting the stale direct-script invocation pass. No host write, run, provider call, or search occurred; a fresh independent review is required.
- L29: Read-only inspection of installed `/opt/role-radar` confirmed the canary plan is truncated to its first query, ordinal 1 is `boards.greenhouse.io`, `search_canary` routes only to Brave Free, and one `BraveSearchProvider.search` call makes one `BoundedSearchHttpClient.request` with no retry loop. The installed pipeline source hash matches the provenance pin. Combined with the one-Greenhouse-per-query guard and existing integration test, no source-cap implementation is needed. Effective timeout proof and post-install gates remain pending. No database, service, provider, Telegram, or run operation occurred.
- L30: Read-only inspection of installed `broker/client.py` confirmed one logical `broker_calls` reservation per generation, while each `_submit` retry and every `_poll` status request reserves `broker_attempts`. The four-attempt budget therefore covers submit attempts, retries, and polling; no Broker call was made.
- L31: Corrected the operations runbook to state the installed one-query/one-board/Brave request behavior precisely. Final `git diff --check`, `bash -n` on all eight fenced shell blocks, the module-invocation structural check, and docs consistency assertion pass. No source change, host write, run, provider call, or Telegram action occurred; fresh independent T3 review remained required at that point.
- L32 (independent T3 review `mvy49pcj-n-o48n`): GO for S1 within T3's no-run scope and S4's protected-install procedure. Reviewer confirmed the module invocation resolves through the installed namespace-package layout, all eight candidate hashes match the manifest, full PASS lines and fail-closed wrapper match gate implementations, and backup/absence/failure boundaries are consistent. It did not access the host, execute tests or gates, or perform installation. Nonblocking advisory: the operations runbook still used direct-script binding invocation; parent corrected it to `python -m scripts.bounded_canary_binding` with an explanatory note. No host write or run has occurred; final post-correction checks must pass before installation.
- L33: The approved pre-install isolation gate was executed once with a generated future run ID and returned exit 1 with exact output `SYSTEMD_ISOLATION_GATE: FAIL (systemd_proof_unavailable)`. Per the fail-closed procedure, stopped before destination preflight, protected backup, installation, or further gates. No host files/database/services, run, provider, or Telegram action were touched. The public gate code intentionally maps systemctl errors and malformed/missing property proof to this generic code, so the precise cause is unknown from captured output. Do not rerun unchanged or proceed to writes; a decision on resolving the unavailable systemd proof was needed.
- L34: User selected “Authorize bounded diagnosis,” permitting one bounded read-only diagnosis of the underlying systemd query/parse failure. No writes, DB reads, service changes, run creation, or provider calls are authorized by this selection. Rerun the isolation gate once only if the diagnosis identifies a specific cause and it is corrected; otherwise stop with the exact missing proof.
- L35: The bounded read-only diagnosis found that service and timer queries, canary listing, and the `systemctl show` command itself succeed, but gate-style parsing of the synthetic canary instance fails because `ExecStartPre` is omitted from the response. `LoadCredential` is returned as `[unprintable]`; a privileged read-only query, both with and without `--all`, returned the same redaction and still omitted `ExecStartPre`. Thus the current gate cannot establish its worker contract from the requested properties; no gate retry, source/host write, DB access, service change, run, or provider call occurred. Recommend a bounded evidence-source correction with tests/docs, independent review, then one gate retry only if review and checks pass.
- L36: User selected “Authorize bounded gate fix.” This authorizes only a bounded correction to the preflight proof method, regression tests, install-manifest/runbook updates, and fresh independent review. No host writes, backup/install, service changes, run creation/start, provider calls, external searches, or Telegram activity may occur before that review and all fresh gates pass.
- L37: Offline T5 implementation now obtains worker-template evidence with `systemctl cat` after requiring the exact fragment path, no drop-ins, and no pending daemon reload; it validates the required credential references without trusting the redacted `show` value and rejects alternate credential-source directives. Added regressions for omitted/redacted values, template path/drop-in/reload drift, cat failure, and extra credential sources. The preflight module passed 50/50 at this checkpoint; Ruff check, script formatting, changed-test-range formatting, and `git diff --check` passed. The operations runbook and manifest hash were updated. Python LSP servers were unavailable. Full-suite verification and fresh independent review were pending. No live systemctl, host write, backup, service/database change, run, provider call, search, or Telegram activity occurred.
- L38: Fresh independent review `mvydfnik-o-j974` returned NO-GO. It found that whitespace before `=` left directive names unnormalized, allowing `ExecStartPre` and alternate credential sources to bypass checks; it also found the composed deterministic runner in `tests/unit/test_bounded_canary_create.py` lacked the new systemd properties and `cat` response. The initial parent full suite failed with 1516 passed, 12 failed, and 15 errors; inspection traced the composed tests to that fake runner, not live systemd. Added RED cases for space and tab variants of `ExecStartPre` and all four alternate credential directives; the parser now rejects whitespace in directive names. Updated the test records and fake runner. The affected five modules now pass 168/168, with Ruff and changed-range formatting checks clean. Fresh full-suite verification and independent re-review were pending. The reviewer reports retained scratch `/tmp/role-radar-t5-verify.NizJUlK0`; parent did not access or remove it because it is outside the workspace. No live systemctl, host write, database/service change, run, provider call, search, or Telegram activity occurred.
- L39: Follow-up independent review `mvydot4i-p-9i2n` returned GO for both T5 correction blockers: whitespace variants fail closed, and the composed test runner supplies synthetic metadata and `cat` output. It confirmed the runbook and eight-file manifest, reused parent evidence of 168/168 focused tests, and did not rerun tests or operational gates. At that point the full suite was still running; fresh operational gates and T5 closure remained pending. No new scratch, host access, systemctl, write, database/service change, run, provider call, search, or Telegram activity occurred.
- L40: The second full-suite run, `uv run --locked --offline --no-sync --group dev pytest -q`, passed 1553/1553 in 73.32s after the deterministic runner and parser fixes. The 168 focused tests and Ruff/format/diff checks also pass; independent T5 re-review is GO. T5 then awaited work-unit commit/read-only assessment; T3 gates and any host installation remained pending. No host/systemd, production DB, service, run, provider, search, or Telegram operation occurred.
- L41: T5 work-unit `e288ca9` (`fix(ops): verify canary worker unit config`) committed the preflight evidence correction, regression tests, composed-runner adaptation, and T5 runbook section. Read-only ASSESS for `HEAD^..HEAD` returned `nativeRisk=unassessable` because unrelated untracked files require explicit declaration; RDD is off, so no native lifecycle or selection operation was run. Independent T5 verification remains GO; full-suite 1553/1553 and focused 168/168 pass. T5 is closed; T3 remains pending its single corrected read-only isolation gate. No host or production operation occurred.
- L42: On resumption, `git status --short --branch` showed uncommitted T3 provenance-pin changes in `scripts/bounded_canary_provenance.py`, matching regression tests, and operations-doc updates; the installer manifest in this task file still names the older provenance-script hash. The reviewed `scripts/bounded_canary_preflight.py` itself is unchanged and its SHA-256 matches the reviewed manifest (`73921757593e3980494e4b8287144d5479c71cb659ca474541db614d3aa767c9`). Thus the single corrected isolation gate remains safe to run read-only, but any installation must wait until the changed provenance artifact and plan are reconciled and independently reviewed. No gate has yet been rerun; no host write, backup/install, database/service action, run, provider call, search, or Telegram occurred.
- L43: The corrected pre-install isolation gate ran once with a fresh UUID and returned exit 0 plus the exact required line `SYSTEMD_ISOLATION_GATE: PASS (gate only; not overall readiness)`. This proves only that gate, not overall readiness. No backup/install, DB write, service change, run creation/start, provider call, search, or Telegram occurred. Proceed only with the documented read-only target/preimage check; installation remains blocked until remaining gates pass.
- L44: Correction to L42: SHA-256 verification of all eight workspace install sources showed every digest matches the exact approved T3 manifest; the claimed stale installer hash was incorrect, and the independent T3 plan GO remains applicable to these candidate bytes. The documented read-only target/preimage check was attempted once, but `sudo -n` exited before running its Python checks with `sudo: a password is required`; no target state was established and no host write occurred. T3 is blocked only on refreshing sudo credentials for this read-only check; after that, resume the approved sequence and stop at any failed gate.
- L45: The offline provenance-pin unit passed its focused module (37/37); Ruff check and `git diff --check` passed. All eight install-source hashes match the approved manifest. The source, regression tests, and operations docs were committed as `117a85d` (`fix(ops): pin installed canary provenance sources`). The earlier 1553/1553 full-suite and independent T3 plan GO remain applicable. T3 is still blocked at the read-only host target check because `sudo -n` requires refreshed credentials; no installation, run, or provider activity occurred.
- L46: User resumed the blocked task with “Ya esta sudo actualizado”. Continue with the one documented read-only target/preimage check; do not treat credential refresh as evidence that the check, installation, or any later gate passed.
- L47: The documented read-only target/preimage check ran with refreshed sudo credentials and returned `T3_TARGET_CHECK: PASS` (exit 0). It confirmed directory types/metadata, CLI base preimage hash and identity, and absence of all seven helper targets. No host write, backup, install, DB/service action, run, provider call, search, or Telegram occurred. The next authorized step is the no-clobber protected CLI preimage backup; then repeat this target check before installation.
- L48: The approved protected CLI preimage backup completed as `T3_PREIMAGE_BACKUP: PASS` at `/opt/role-radar/data/backups/role-radar-canary-notifications-preinstall.C7S1PmL2`. The new directory is root:root mode 0700; `cli-main.py` is root:root mode 0600, single-link, and matches the exact installed base SHA-256; file data and directory metadata were synced. Next, repeat the target/preimage check as prescribed. No application source was installed and no run/provider activity occurred.
- L49: Immediately after the backup, the documented read-only target/preimage check ran again and returned `T3_TARGET_CHECK: PASS` (exit 0). The preimage and all seven absent helper targets remained valid. The approved next operation is the exact staged helper-first/CLI-last install; no source file had yet been installed at this checkpoint, and no run/provider activity occurred.
- L50: The approved staged helper-first/CLI-last installer returned `T3_INSTALL: PASS (8 files; backup=/opt/role-radar/data/backups/role-radar-canary-notifications-preinstall.C7S1PmL2)`. Each of the eight installed files matched its manifest SHA-256, root:root ownership and mode 0644; per-file destination-directory fsyncs completed. The API was not restarted and no database, run, provider, search, or Telegram activity occurred. Next run the four fresh post-install read-only gates and the effective timeout proof.
- L51: The post-install gate sequence used future worker UUID `af8eb9cd-99c5-4dbe-81e4-69ab9bcde7ae`. `SYSTEMD_ISOLATION_GATE: PASS (gate only; not overall readiness)` and `SOURCE_PROVENANCE_GATE: PASS (20 declared critical paths; gate only)` passed. The next gate stopped with exit 1 and exact output `DATABASE_HISTORY_GATE: FAIL (database_wal_resources_unavailable)`; the profile-binding gate and worker-timeout check were not run. The DB gate is read-only/query-only but may affect SQLite WAL/SHM coordination bytes; no row write is established. Per the approved fail-stop procedure, no further DB query, gate retry, binding/timeout probe, service action, restore, or run may occur without a new user decision. The installed eight files and protected backup remain preserved; no search, provider, run, or Telegram activity occurred.
- L52: User selected `authorize_readonly_diagnosis`: one bounded inspection of DB/WAL/SHM filesystem metadata and installed gate code only. No DB rows or file contents, writes, gate retries, service actions, restores, or run/provider activity are authorized. Stop and report if this evidence does not identify the cause.
- L53: Diagnosis completed within scope. Installed `_file_identity` classifies SQLite WAL mode from header bytes 18–19; `_require_wal_resources` then fails with `database_wal_resources_unavailable` if either regular `-wal` or `-shm` is absent (or metadata access/validation fails). A single sudo read-only `lstat` inspection found `/opt/role-radar/data/role-radar.db` present as a regular 0600 file, uid 999/gid 988, nlink 1, size 51,392,512 bytes; `-wal`, `-shm`, and `-journal` were absent. This explains the exact prior gate failure; the database contents/header were not read during diagnosis, and no gate was rerun. Do not infer why sidecars are absent or create them. Installed files and protected backup remain unchanged; no services, run, provider, search, or Telegram activity occurred. Await a separate user decision before any fix or further host check.
