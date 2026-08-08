# ADR-0005: Source catalog and local control plane

F8.1 gives every `SourceType` a static public catalog entry while keeping
availability explicit. Greenhouse is the only registered factory. Its v1
configuration is a strict allowlist containing only the public board slug and
optional company display text; no URL, host, arbitrary headers, credentials or
network probe is accepted.

`source_key` is canonical identity (`greenhouse:<normalized-board-token>`),
not display name. Operator mutations are local CLI operations with revision
CAS. A source is archived rather than deleted, and references and run
snapshots remain historical records. HTTP exposes only sanitized GET catalog
and source projections; it has no source mutation routes under D9.

The F8.1 migration audits ambiguous configuration, identity collisions and
duplicate source references before DDL. Unsupported legacy rows receive a
deterministic `legacy:<type>:<id>` key, version 0 and disabled status. Resource
limits are metadata only in F8.1 (`resource_bounds_enforced=false`); quantitative
collector hardening is deferred to F8.2.
