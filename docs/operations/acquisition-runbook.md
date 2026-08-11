# Acquisition readiness and controlled activation

This runbook is Gate A documentation. It does not authorize Gate B or any
live call. All commands below must be run sequentially and outputs must remain
sanitized.

1. Confirm the 2026-08-09 backup, Alembic head/current `e7a4c9f1b2d3`, database
   integrity, and that the worker is stopped.
2. Recover outside RoleRadar both exact Jobicy pages: `terms-and-conditions`
   (the July 2026 general terms) and `jobs-rss-feed`. Review fair use,
   source/destination preservation, no redistribution to large boards,
   publication delay, and polling no more than once per hour. RoleRadar never
   downloads these pages.
3. Generate the canonical two-page manifest, calculate its SHA-256, and install
   the immutable bundle under `/etc/role-radar/evidence/jobicy/<digest>/` as
   `root:role-radar 0550`, with three `0440` regular files. Never edit a bundle
   in place or put it in Git/DB.
4. Install the TOML as `root:role-radar 0640`, with handles only. Verify the
   regular file, group membership, and supplementary group for the worker.
5. Install only the target capability's root-managed credentials and drop-in;
   run `systemd-analyze verify`, then `daemon-reload`.
6. Create Jobicy/Gmail disabled. Creation never enables a source or seeds live
   state.
7. Run `role-radar acquisition validate`; for runtime rollout use
   `--runtime --require-ready <capability>`. Validation is offline.
8. Gate B Gmail, if explicitly authorized later, uses `mailbox preflight
   SOURCE --ack-live`; it performs AUTH, LIST, readonly SELECT and LOGOUT only.
   After preflight PASS, run `mailbox smoke SOURCE --ack-live` exactly once
   through a systemd credential context. It selects at most the newest message
   from the 14-day lookback, fetches it with `BODY.PEEK`, parses it, returns
   only sanitized counters/codes and performs no DB/source/mailbox mutation.
9. F9.0 `mailbox linkedin-host-audit SOURCE --config <path> --ack-live` is a
    separate report-only audit of that newest message. It performs no HTTP or
    DNS against discovered links, follows no redirects, writes no DB state,
    and requires the email source to remain disabled. It is not a LinkedIn
    resolver and does not authorize Gmail rollout.
10. F9.1 `mailbox linkedin-head-resolution SOURCE --config <path> --ack-live`
    remains fail-closed until the runtime proves application DNS/IP pinning and
    infrastructure egress defense separately. Its report-only path must use
    `HEAD` only, never request the final ATS, and never write DB state.
11. For the F9.1 canary, run the local-only script under a transient scope with
    `IPAddressDeny=any` and loopback-only `IPAddressAllow`; it must report
    `external_requests=0`. For a later live gate, generate the short-lived
    root-owned attestation first with `f91-egress-attest.py`, then use only
    `f91-run-head-resolution.py`, which derives `IPAddressAllow` from that
    attestation and mounts it through `LoadCredential`. The attestation contains
    only the fixed Gmail IMAP origin required to read the alert plus the two
    audited LinkedIn origins; this does not expand the LinkedIn URL allowlist.
12. Prepare the Jobicy evidence bundle and the Brave/Tavily free credentials and
   config handles. Keep all database sources disabled; no source CAS is needed
   for this report-only smoke.
13. After offline validation, run `role-radar acquisition gate-b --ack-live
    --confirmation "LIVE GATE-B"` exactly once through a systemd credential
    context. It calls Jobicy once, Brave Free once, then Tavily Free once, stops
    on failure, and writes no DB/source/budget state. Paid Brave remains off.
14. Observe only sanitized codes/counters. Stop for any warning or failure.
15. Roll back only the affected capability: disable its free config, remove its drop-in,
     rotate/revoke credentials where applicable, daemon-reload, and restart the
     worker. Preserve receipts, ledgers, cursor and evidence history.
16. Consult `discovery status`, `discovery budget`, `mailbox status`, source
    state, worker journal codes, and DB integrity. Never print credentials,
    paths, URLs, digests, terms, queries, addresses, payloads, or exceptions.

## Credential and Gmail operations

XOAUTH2 metadata is strict JSON with only `schema_version` and UTC `expires_at`.
Rotation is atomic and requires a controlled worker restart when delivered by
`LoadCredential`; hot reload is not promised. RoleRadar does not implement
OAuth consent or refresh and stores no token. App passwords require 2FA,
mailbox-wide scope acknowledgement, revocation acknowledgement, and a strong
recommendation for a dedicated account. A RoleRadar label, readonly SELECT,
and `BODY.PEEK` do not reduce mailbox-wide credential scope.

## Explicit exclusions and stop conditions

No paid Brave, Telegram, HTTP trigger, parallel activation, real network during
Gate A, or production Alembic downgrade is permitted. Stop for any credential
or terms leakage, source/parser drift, repeated IMAP I/O, missing CAS, schema
insufficiency, or failed independent-capability isolation.

## Gate B evidence template (external workspace only)

Record only commit, UTC timestamp, capability, explicit acknowledgement and
hard limit, sanitized readiness codes/counters, result, and rollback action.
Never record secrets, account/email, expiry, query, mailbox content, URL,
provider result/payload, or raw exception.
