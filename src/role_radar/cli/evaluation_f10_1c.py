"""Thin, offline-only CLI adapter for F10.1C."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from role_radar.evaluation.cohort_freeze.bundle_store import V2BundleStore
from role_radar.evaluation.cohort_freeze.contracts import DeploymentIdentity
from role_radar.evaluation.cohort_freeze.policy import SNAPSHOT_ROOT
from role_radar.evaluation.cohort_freeze.repository import (
    BoundedSQLiteSnapshotRepository,
    RepositoryError,
)
from role_radar.evaluation.cohort_freeze.runtime import CohortFreezeRuntimeV2, RuntimeErrorCode


def _payload(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def run(args: Any) -> int:
    """Run one command; exception text and paths never enter the protocol."""

    database = os.environ.get("ROLE_RADAR_DATABASE_URL")
    if not database:
        print(_payload({"result": "blocked", "code": "database_missing"}))
        return 2
    try:
        repository = BoundedSQLiteSnapshotRepository(
            database,
            deployment={
                "code_commit": os.environ.get("ROLE_RADAR_CODE_COMMIT", "unknown"),
                "clean": os.environ.get("ROLE_RADAR_DEPLOYMENT_CLEAN", "0"),
            },
        )
        root = Path(os.environ.get("ROLE_RADAR_F10_1C_ROOT", SNAPSHOT_ROOT))
        runtime = CohortFreezeRuntimeV2(
            repository,
            V2BundleStore(root),
            deployment=DeploymentIdentity(
                code_commit=os.environ.get("ROLE_RADAR_CODE_COMMIT", "unknown"),
                clean=os.environ.get("ROLE_RADAR_DEPLOYMENT_CLEAN", "0") == "1",
            ),
        )
        if args.f10_1c_command in {"status", "preview"}:
            result = runtime.status() if args.f10_1c_command == "status" else runtime.preview()
            print(_payload(result.payload))
            return 0
        if args.f10_1c_command == "freeze":
            bundle = runtime.freeze(args.acknowledgement)
            print(_payload(bundle.external_manifest))
            return 0
        if args.f10_1c_command == "verify":
            print(_payload(runtime.verify(args.dataset_id)))
            return 0
        return 2
    except RuntimeErrorCode as exc:
        print(_payload({"result": "blocked", "code": exc.code}))
        return 2
    except RepositoryError as exc:
        print(_payload({"result": "blocked", "code": exc.code}))
        return 2
    except (ValueError, OSError):
        print(_payload({"result": "blocked", "code": "internal_error"}))
        return 2


__all__ = ["run"]
