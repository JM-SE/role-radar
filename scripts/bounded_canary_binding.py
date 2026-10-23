#!/usr/bin/env python3
"""Read-only official discovery-policy and active-profile binding gate."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from types import SimpleNamespace

from role_radar.acquisition.discovery_policy import (
    DEFAULT_DISCOVERY_POLICY_PATH,
    load_discovery_policy,
    production_discovery_policy_file_policy,
)
from role_radar.continuous_acquisition.runtime_discovery_v2 import _profile_from_row
from role_radar.discovery.policy import canonical_policy_sha256


class GateError(Exception):
    pass


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        raise GateError("arguments_invalid")


class _Capture:
    def __init__(self, output):
        self.output = output

    def write(self, value):
        self.output.append(value)
        return len(value)

    def flush(self):
        pass


def _connect_database(database_url: str) -> sqlite3.Connection:
    from scripts.bounded_canary_database import _connect_database as connect

    return connect(database_url)


def _load_policy(path):
    return load_discovery_policy(path, file_policy=production_discovery_policy_file_policy())


def inspect_binding(connection, policy):
    try:
        if connection.execute("PRAGMA query_only").fetchone() != (1,):
            raise GateError("database_readonly_unavailable")
        if canonical_policy_sha256(policy) != policy.sha256:
            raise GateError("policy_invalid")
        binding = policy.profile_binding
        columns = {row[1] for row in connection.execute('PRAGMA table_info("candidate_profiles")')}
        required = {"id", "version", "schema_version", "profile_json", "is_active"}
        if not required <= columns:
            raise GateError("profile_schema_invalid")
        rows = connection.execute(
            "SELECT id, version, schema_version, profile_json, is_active "
            "FROM candidate_profiles WHERE id = ?", (binding.profile_id,)
        ).fetchall()
        if len(rows) != 1:
            raise GateError("profile_binding_mismatch")
        row_id, version, schema_version, profile_json, active = rows[0]
        if not isinstance(profile_json, str):
            raise GateError("profile_invalid")
        if type(active) is not int or active not in (0, 1):
            raise GateError("profile_invalid")
        profile = json.loads(profile_json)
        row = SimpleNamespace(
            id=row_id,
            version=version,
            schema_version=schema_version,
            profile_json=profile,
            is_active=active == 1,
        )
        _profile_from_row(row, binding)
        return binding.profile_id
    except GateError:
        raise
    except Exception as exc:
        code = getattr(exc, "code", "profile_binding_mismatch")
        allowed = {"discovery_profile_invalid", "discovery_profile_binding_mismatch"}
        raise GateError(code if code in allowed else "profile_binding_mismatch") from None


def _reject_duplicates(argv):
    tokens = sys.argv[1:] if argv is None else argv
    for option in ("--database-url", "--policy-path"):
        count = sum(token == option or token.startswith(option + "=") for token in tokens)
        if count > 1:
            raise GateError("arguments_invalid")


def main(argv=None):
    connection = None
    failure = None
    try:
        _reject_duplicates(argv)
        parser = _SafeArgumentParser(
            description="Read-only official policy/profile binding gate only.",
            allow_abbrev=False,
        )
        parser.add_argument(
            "--database-url",
            default="sqlite:///./data/role-radar.db",
            help="SQLite file URL; relative paths resolve from current directory",
        )
        parser.add_argument(
            "--policy-path",
            default=str(DEFAULT_DISCOVERY_POLICY_PATH),
            help="Official discovery policy file",
        )
        args = parser.parse_args(argv)
        from scripts.bounded_canary_database import _database_url_path

        try:
            _database_url_path(args.database_url)
        except Exception:
            raise GateError("database_target_invalid") from None
        loaded = _load_policy(args.policy_path)
        connection = _connect_database(args.database_url)
        inspect_binding(connection, loaded.policy)
        from scripts.bounded_canary_database import _verify_target_stable
        _verify_target_stable(connection)
        current = _load_policy(args.policy_path)
        if (
            current.raw_bytes != loaded.raw_bytes
            or current.policy_sha256 != loaded.policy_sha256
            or canonical_policy_sha256(current.policy) != loaded.policy_sha256
        ):
            raise GateError("policy_changed")
    except GateError as exc:
        failure = str(exc)
    except Exception as exc:
        code = getattr(exc, "code", None)
        if code in {
            "discovery_policy_path_invalid",
            "discovery_policy_unavailable",
            "discovery_policy_not_regular",
            "discovery_policy_mode_invalid",
            "discovery_policy_link_invalid",
            "discovery_policy_owner_invalid",
            "discovery_policy_group_invalid",
            "discovery_policy_parent_invalid",
            "discovery_policy_too_large",
            "discovery_policy_changed",
            "discovery_policy_invalid",
            "discovery_policy_hash_mismatch",
        }:
            failure = code
        else:
            failure = "binding_unavailable"
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                failure = "binding_unavailable"
    if failure:
        print(f"PROFILE_BINDING_GATE: FAIL ({failure})", file=sys.stderr)
        return 1
    print("PROFILE_BINDING_GATE: PASS (policy/profile binding only; not overall readiness)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
