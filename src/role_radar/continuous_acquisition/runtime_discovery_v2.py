"""Offline composition root for profile-driven continuous discovery v2.

The only executable v2 entrypoints in Gate A are planning and report-only
operation preparation.  The two network-capable modes intentionally return a
stable block before touching credentials, a database, DNS, HTTP, or a provider
adapter.  This module therefore has no dependency on the historical v1
authorization/runtime helpers.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, cast

from role_radar.acquisition.discovery_policy import (
    DEFAULT_DISCOVERY_POLICY_PATH,
    MAX_DISCOVERY_POLICY_BYTES,
    DiscoveryPolicyFileError,
    LoadedDiscoveryPolicyV1,
    production_discovery_policy_file_policy,
)
from role_radar.acquisition.discovery_policy import (
    load_discovery_policy as _load_discovery_policy,
)
from role_radar.continuous_acquisition.discovery_artifacts_v2 import (
    DiscoveryArtifactError,
    ReportOnlyTerminalReportV1,
    ensure_private_artifact_root,
    read_private_artifact_bytes,
    write_private_artifact,
)
from role_radar.continuous_acquisition.discovery_budget_v2 import DiscoveryBudgetV2
from role_radar.continuous_acquisition.providers import (
    BoundedSearchRuntime,
    SearchAuthorizationCapability,
    SearchQuotaAdapter,
)
from role_radar.continuous_acquisition.report_only_v2 import (
    ReportOnlyAuthorizationEvidence,
    ReportOnlyError,
    ReportOnlyOperationV1,
    ReportOnlyVerifier,
    execute_report_only,
    prepare_report_only_operation,
    quota_contexts_from_config,
)
from role_radar.discovery.planner_v2 import (
    DiscoveryQueryPlanV2,
    canonical_plan_bytes,
    canonical_plan_payload,
    plan_profile_discovery,
    validate_discovery_query_plan,
)
from role_radar.discovery.policy import (
    DiscoveryPolicyV1,
    ProfileBindingV1,
)
from role_radar.discovery.profile_terms import (
    FrozenCandidateProfileV1,
    compile_profile_terms,
)
from role_radar.domain.profile import CandidateProfileV1, canonical_profile_sha256
from role_radar.repositories.acquisition import DiscoveryQuotaContextV2Protocol

PLAN_DIRECTORY: Final = "plans"
PLAN_FILE_SUFFIX: Final = ".json"
DEFAULT_DISCOVERY_ARTIFACT_ROOT: Final = Path.cwd() / "data" / "discovery" / "v2"
RESULT_SCHEMA_VERSION: Final = "continuous-discovery-v2-result-v1"
DISCOVERY_V2_LIVE_GATE_BLOCKED: Final = "discovery_v2_live_gate_blocked"

EXIT_OK: Final = 0
EXIT_BLOCKED: Final = 2
EXIT_INTERNAL: Final = 70


class RuntimeCompositionError(ValueError):
    """Stable, path-free error exposed by the dedicated v2 CLI."""

    def __init__(self, code: str, *, exit_code: int = EXIT_BLOCKED) -> None:
        self.code = code
        self.exit_code = exit_code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class RuntimeResult:
    payload: dict[str, object]
    exit_code: int


def _policy_value(
    value: DiscoveryPolicyV1 | LoadedDiscoveryPolicyV1 | Mapping[str, object],
) -> DiscoveryPolicyV1:
    if isinstance(value, LoadedDiscoveryPolicyV1):
        return value.policy
    if isinstance(value, DiscoveryPolicyV1):
        return value
    if isinstance(value, Mapping):
        try:
            return DiscoveryPolicyV1.model_validate(value)
        except Exception as exc:
            raise RuntimeCompositionError("discovery_policy_invalid") from exc
    raise RuntimeCompositionError("discovery_policy_invalid")


def load_discovery_policy(
    path: str | os.PathLike[str] | None = None,
    *,
    policy: DiscoveryPolicyV1 | Mapping[str, object] | None = None,
    policy_bytes: bytes | None = None,
) -> LoadedDiscoveryPolicyV1:
    """Load one policy from an injected file or use an already validated DTO."""

    try:
        file_policy = (
            production_discovery_policy_file_policy()
            if policy is None and policy_bytes is None
            else None
        )
        return _load_discovery_policy(
            path, policy=policy, policy_bytes=policy_bytes, file_policy=file_policy
        )
    except DiscoveryPolicyFileError as exc:
        raise RuntimeCompositionError(exc.code) from None


def _binding(value: ProfileBindingV1 | Mapping[str, object]) -> ProfileBindingV1:
    if isinstance(value, ProfileBindingV1):
        return value
    try:
        return ProfileBindingV1.model_validate(value)
    except Exception as exc:
        raise RuntimeCompositionError("discovery_profile_binding_mismatch") from exc


def _profile_from_row(row: object, binding: ProfileBindingV1) -> FrozenCandidateProfileV1:
    try:
        row_id = row.id  # type: ignore[attr-defined]
        version = row.version  # type: ignore[attr-defined]
        schema_version = row.schema_version  # type: ignore[attr-defined]
        is_active = row.is_active  # type: ignore[attr-defined]
        payload = row.profile_json  # type: ignore[attr-defined]
        if (
            type(row_id) is not str
            or type(version) is not int
            or type(schema_version) is not int
            or type(is_active) is not bool
            or row_id != binding.profile_id
            or version != binding.row_version
            or schema_version != binding.schema_version
            or not is_active
            or not isinstance(payload, Mapping)
        ):
            raise RuntimeCompositionError("discovery_profile_binding_mismatch")
        profile_payload = dict(payload)
        profile = CandidateProfileV1.model_validate(profile_payload)
        if canonical_profile_sha256(profile_payload) != binding.canonical_profile_sha256:
            raise RuntimeCompositionError("discovery_profile_binding_mismatch")
        return FrozenCandidateProfileV1(binding, profile)
    except RuntimeCompositionError:
        raise
    except Exception as exc:
        raise RuntimeCompositionError("discovery_profile_invalid") from exc


def freeze_selected_profile(
    session: object, binding: ProfileBindingV1 | Mapping[str, object]
) -> FrozenCandidateProfileV1:
    """Freeze only the exact bound row; never fall back to an active-profile list."""

    selected = _binding(binding)
    try:
        from role_radar.repositories.profiles import ProfileRepository

        row = ProfileRepository(session).get(selected.profile_id)  # type: ignore[arg-type]
    except RuntimeCompositionError:
        raise
    except Exception as exc:
        raise RuntimeCompositionError("discovery_profile_unavailable") from exc
    if row is None:
        raise RuntimeCompositionError("discovery_profile_binding_mismatch")
    return _profile_from_row(row, selected)


def _profile_value(
    policy: DiscoveryPolicyV1,
    *,
    session: object | None,
    profile: FrozenCandidateProfileV1 | CandidateProfileV1 | object | None,
) -> FrozenCandidateProfileV1:
    if isinstance(profile, FrozenCandidateProfileV1):
        if profile.binding != policy.profile_binding:
            raise RuntimeCompositionError("discovery_profile_binding_mismatch")
        if (
            canonical_profile_sha256(profile.profile.model_dump(mode="json"))
            != policy.profile_binding.canonical_profile_sha256
        ):
            raise RuntimeCompositionError("discovery_profile_binding_mismatch")
        return profile
    if isinstance(profile, CandidateProfileV1):
        if (
            canonical_profile_sha256(profile.model_dump(mode="json"))
            != policy.profile_binding.canonical_profile_sha256
        ):
            raise RuntimeCompositionError("discovery_profile_binding_mismatch")
        return FrozenCandidateProfileV1(policy.profile_binding, profile)
    if session is None:
        raise RuntimeCompositionError("discovery_profile_unavailable")
    if profile is not None and hasattr(profile, "profile_json"):
        return _profile_from_row(profile, policy.profile_binding)
    return freeze_selected_profile(session, policy.profile_binding)


def build_discovery_plan(
    *,
    policy: DiscoveryPolicyV1 | LoadedDiscoveryPolicyV1 | Mapping[str, object],
    session: object | None = None,
    profile: FrozenCandidateProfileV1 | CandidateProfileV1 | object | None = None,
) -> DiscoveryQueryPlanV2:
    """Compose the existing pure policy/compiler/planner path, offline."""

    selected_policy = _policy_value(policy)
    frozen = _profile_value(selected_policy, session=session, profile=profile)
    try:
        compiled = compile_profile_terms(frozen, selected_policy)
        result = plan_profile_discovery(compiled, selected_policy)
        return validate_discovery_query_plan(result)
    except RuntimeCompositionError:
        raise
    except (TypeError, ValueError) as exc:
        raise RuntimeCompositionError(getattr(exc, "code", "discovery_plan_invalid")) from exc


def _private_directory(root: Path, name: str) -> Path:
    if not isinstance(root, Path) or not root.is_absolute() or root == Path(root.anchor):
        raise RuntimeCompositionError("artifact_root_invalid")
    ensure_private_artifact_root(root)
    directory = root / name
    try:
        directory.mkdir(mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
        metadata = directory.lstat()
    except OSError as exc:
        raise RuntimeCompositionError("artifact_root_invalid") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
        or directory.is_symlink()
    ):
        raise RuntimeCompositionError("artifact_root_not_private")
    return directory


def publish_plan(plan: DiscoveryQueryPlanV2, root: Path) -> Path:
    """Publish an immutable plan artifact, allowing identical byte replay."""

    try:
        validate_discovery_query_plan(plan)
        directory = _private_directory(root, PLAN_DIRECTORY)
        name = f"{plan.plan_sha256}{PLAN_FILE_SUFFIX}"
        payload = canonical_plan_bytes(plan)
        target = directory / name
        if target.exists():
            if read_private_artifact_bytes(directory, name) != payload:
                raise RuntimeCompositionError("artifact_conflict")
            return target
        try:
            return write_private_artifact(directory, name, canonical_plan_payload(plan))
        except DiscoveryArtifactError as exc:
            if (
                exc.code == "artifact_exists"
                and read_private_artifact_bytes(directory, name) == payload
            ):
                return target
            raise RuntimeCompositionError(exc.code) from exc
    except RuntimeCompositionError:
        raise
    except (TypeError, ValueError, OSError) as exc:
        raise RuntimeCompositionError(getattr(exc, "code", "discovery_plan_invalid")) from exc


def verify_plan(plan: DiscoveryQueryPlanV2) -> DiscoveryQueryPlanV2:
    """Validate a plan without introducing another planner or query source."""

    try:
        return validate_discovery_query_plan(plan)
    except (TypeError, ValueError) as exc:
        raise RuntimeCompositionError(getattr(exc, "code", "discovery_plan_invalid")) from exc


def plan_summary(plan: DiscoveryQueryPlanV2) -> dict[str, object]:
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "result": "planned",
        "plan_schema_version": plan.schema_version,
        "planner_version": plan.planner_version,
        "compiler_version": plan.compiler_version,
        "profile_id": plan.profile_binding.profile_id,
        "profile_version": plan.profile_binding.row_version,
        "profile_schema_version": plan.profile_binding.schema_version,
        "profile_sha256": plan.profile_binding.canonical_profile_sha256,
        "policy_version": plan.policy_version,
        "policy_sha256": plan.policy_sha256,
        "plan_sha256": plan.plan_sha256,
        "query_count": len(plan.queries),
        "host_count": len(plan.source_registry),
        "limits": dict(plan.limits),
    }


def prepare_operation(
    plan: DiscoveryQueryPlanV2,
    config: object,
    *,
    operation_id: str | None = None,
    clock: Callable[[], datetime] | datetime | None = None,
    nonce_source: Callable[[], bytes] | None = None,
    artifact_root: Path | None = None,
) -> ReportOnlyOperationV1:
    try:
        verify_plan(plan)
        return prepare_report_only_operation(
            plan,
            config,
            operation_id=operation_id,
            clock=clock,
            nonce_source=nonce_source,
            artifact_root=artifact_root,
        )
    except RuntimeCompositionError:
        raise
    except (ReportOnlyError, TypeError, ValueError) as exc:
        raise RuntimeCompositionError(getattr(exc, "code", "operation_invalid")) from exc


def build_search_runtime(
    config: object,
    verified_plan: DiscoveryQueryPlanV2 | object,
    authorization_capability: SearchAuthorizationCapability | None = None,
    execution_budget: DiscoveryBudgetV2 | None = None,
    quota_adapter: SearchQuotaAdapter | None = None,
) -> BoundedSearchRuntime:
    """Build the typed provider seam after explicit test/gate authorization.

    Gate A's production CLI never calls this function.  It is intentionally
    usable only with an already-created sealed capability and a durable quota
    adapter, which gives lower-level fake transports an executable seam without
    making generic acknowledgements or the CLI live-capable.
    """

    if (
        not isinstance(verified_plan, DiscoveryQueryPlanV2)
        and authorization_capability is None
        and execution_budget is None
        and quota_adapter is None
    ):
        raise RuntimeCompositionError(DISCOVERY_V2_LIVE_GATE_BLOCKED, exit_code=EXIT_BLOCKED)
    if not isinstance(verified_plan, DiscoveryQueryPlanV2):
        raise RuntimeCompositionError("discovery_plan_invalid")
    typed_plan = verified_plan
    if not isinstance(authorization_capability, SearchAuthorizationCapability):
        raise RuntimeCompositionError("discovery_v2_authorization_required")
    if execution_budget is None or not isinstance(execution_budget, DiscoveryBudgetV2):
        raise RuntimeCompositionError("discovery_budget_invalid")
    if quota_adapter is None or not (
        callable(getattr(quota_adapter, "reserve_and_start_v2", None))
        or callable(getattr(quota_adapter, "publish_reservation_and_ledger_start_v2", None))
    ):
        raise RuntimeCompositionError("discovery_quota_adapter_required")
    if (
        not (
            callable(getattr(quota_adapter, "finalize_v2", None))
            or callable(getattr(quota_adapter, "finalize_reservation_and_ledger_v2", None))
        )
        or not callable(getattr(quota_adapter, "revalidate_context_v2", None))
        or not callable(getattr(quota_adapter, "commit_v2", None))
    ):
        raise RuntimeCompositionError("discovery_quota_adapter_required")
    try:
        contexts = quota_contexts_from_config(config)
    except (ReportOnlyError, TypeError, ValueError) as exc:
        raise RuntimeCompositionError(getattr(exc, "code", "config_invalid")) from exc
    if authorization_capability.plan_sha256 != typed_plan.plan_sha256:
        raise RuntimeCompositionError("discovery_v2_authorization_invalid")

    bound_month = contexts[0].utc_month if contexts else None

    runtime: BoundedSearchRuntime

    def check_before_transport() -> None:
        now = runtime.clock()
        if bound_month is None or now.strftime("%Y-%m") != bound_month:
            raise RuntimeCompositionError("discovery_quota_month_stale")
        expected = quota_contexts_from_config(
            config,
            created=datetime.strptime(f"{bound_month}-01", "%Y-%m-%d").replace(tzinfo=UTC),
        )
        if expected != contexts:
            raise RuntimeCompositionError("discovery_quota_context_stale")
        if now >= authorization_capability.expires_at_utc.astimezone(UTC):
            raise RuntimeCompositionError("discovery_v2_authorization_expired")

    runtime = BoundedSearchRuntime(
        plan=typed_plan,
        operation_id=authorization_capability.operation_id,
        authorization=authorization_capability,
        execution_budget=execution_budget,
        quota_adapter=quota_adapter,
        quota_contexts=cast(
            tuple[DiscoveryQuotaContextV2Protocol, ...],
            contexts,
        ),
        before_transport_check=check_before_transport,
    )
    return runtime


def run_discovery_v2(
    *,
    mode: Literal["report_only", "register"] = "report_only",
    config: object | None = None,
    verified_plan: DiscoveryQueryPlanV2 | None = None,
    authorization_capability: SearchAuthorizationCapability | None = None,
    execution_budget: DiscoveryBudgetV2 | None = None,
    quota_adapter: SearchQuotaAdapter | None = None,
) -> RuntimeResult:
    """Return the Gate A hard block before any live precondition or I/O."""

    del config, verified_plan, authorization_capability, execution_budget, quota_adapter
    if mode not in {"report_only", "register"}:
        return RuntimeResult(
            {
                "schema_version": RESULT_SCHEMA_VERSION,
                "result": "blocked",
                "code": "mode_invalid",
            },
            EXIT_BLOCKED,
        )
    return RuntimeResult(
        {
            "schema_version": RESULT_SCHEMA_VERSION,
            "result": "blocked",
            "code": DISCOVERY_V2_LIVE_GATE_BLOCKED,
        },
        EXIT_BLOCKED,
    )


async def execute_report_only_runtime(
    operation: ReportOnlyOperationV1,
    authorization: ReportOnlyAuthorizationEvidence,
    config: object,
    *,
    search_runtime: object,
    artifact_root: Path,
    official_verifier: ReportOnlyVerifier | None = None,
    clock: Callable[[], datetime] | datetime | None = None,
) -> ReportOnlyTerminalReportV1:
    """Explicit injected-capability execution seam for offline/fake tests."""

    if not hasattr(search_runtime, "search") or not hasattr(search_runtime, "last_responses"):
        raise RuntimeCompositionError("discovery_search_runtime_invalid")
    if isinstance(search_runtime, BoundedSearchRuntime) and clock is not None:
        search_runtime.clock = clock if callable(clock) else lambda: clock
        # An explicit clock identifies the injected offline/fake seam.  The
        # runtime's construction-time month is otherwise taken from wall clock
        # time, which would make deterministic historical test windows appear
        # stale before the fake delegate is reached.  Production composition
        # does not supply this seam clock and keeps the freshness guard.
        search_runtime.before_transport_check = None
    try:
        return await execute_report_only(
            operation,
            authorization,
            config,
            search_runtime=search_runtime,  # type: ignore[arg-type]
            artifact_root=artifact_root,
            official_verifier=official_verifier,
            clock=clock,
        )
    except ReportOnlyError as exc:
        raise RuntimeCompositionError(exc.code) from exc


def _command_name(args: object) -> str:
    value = getattr(args, "continuous_discovery_v2_command", None)
    if value is None:
        value = getattr(args, "v2_command", None)
    if value is None:
        value = getattr(args, "command", "")
    return str(value)


def run_continuous_discovery_v2(
    args: object,
    *,
    policy: DiscoveryPolicyV1 | LoadedDiscoveryPolicyV1 | Mapping[str, object] | None = None,
    profile: FrozenCandidateProfileV1 | CandidateProfileV1 | object | None = None,
    session: object | None = None,
    config: object | None = None,
    artifact_root: Path | None = None,
    clock: Callable[[], datetime] | datetime | None = None,
    nonce_source: Callable[[], bytes] | None = None,
) -> RuntimeResult:
    """Dispatch the dedicated command using only injected offline seams."""

    command = _command_name(args)
    if command == "run-report-only":
        if any(
            getattr(args, name, None) for name in ("acknowledgement", "manual_canary", "scheduled")
        ):
            return RuntimeResult(
                {
                    "schema_version": RESULT_SCHEMA_VERSION,
                    "result": "blocked",
                    "code": "discovery_v2_authorization_invalid",
                },
                EXIT_BLOCKED,
            )
        return run_discovery_v2(mode="report_only")
    if command == "run-register":
        if any(
            getattr(args, name, None) for name in ("acknowledgement", "manual_canary", "scheduled")
        ):
            return RuntimeResult(
                {
                    "schema_version": RESULT_SCHEMA_VERSION,
                    "result": "blocked",
                    "code": "discovery_v2_authorization_invalid",
                },
                EXIT_BLOCKED,
            )
        return run_discovery_v2(mode="register")
    if command not in {"plan", "prepare-report-only"}:
        return RuntimeResult(
            {
                "schema_version": RESULT_SCHEMA_VERSION,
                "result": "blocked",
                "code": "command_invalid",
            },
            EXIT_BLOCKED,
        )

    try:
        selected_policy: DiscoveryPolicyV1 | LoadedDiscoveryPolicyV1 | Mapping[str, object]
        selected_policy = load_discovery_policy() if policy is None else policy
        plan = build_discovery_plan(policy=selected_policy, session=session, profile=profile)
        root = artifact_root or DEFAULT_DISCOVERY_ARTIFACT_ROOT
        publish_plan(plan, root)
        if command == "plan":
            return RuntimeResult(plan_summary(plan), EXIT_OK)
        active_config = config
        if active_config is None:
            from role_radar.acquisition.configuration import (
                ProductionAcquisitionFilePolicy,
                load_acquisition_config,
            )

            active_config = load_acquisition_config(
                policy=ProductionAcquisitionFilePolicy(),
            )
        prepared = prepare_operation(
            plan,
            active_config,
            operation_id=getattr(args, "operation_id", None),
            clock=clock,
            nonce_source=nonce_source,
            artifact_root=root,
        )
        return RuntimeResult(prepared.sanitized_dict(), EXIT_OK)
    except RuntimeCompositionError:
        raise
    except Exception as exc:
        raise RuntimeCompositionError(
            getattr(exc, "code", "internal_error"), exit_code=EXIT_INTERNAL
        ) from exc


# Concise aliases are useful to callers that treat this file as the composition
# root, while the pure planner keeps ownership of query construction.
plan = build_discovery_plan
prepare_report_only = prepare_operation


__all__ = [
    "DEFAULT_DISCOVERY_POLICY_PATH",
    "DISCOVERY_V2_LIVE_GATE_BLOCKED",
    "EXIT_BLOCKED",
    "EXIT_INTERNAL",
    "EXIT_OK",
    "MAX_DISCOVERY_POLICY_BYTES",
    "RESULT_SCHEMA_VERSION",
    "LoadedDiscoveryPolicyV1",
    "RuntimeCompositionError",
    "RuntimeResult",
    "build_discovery_plan",
    "build_search_runtime",
    "execute_report_only_runtime",
    "freeze_selected_profile",
    "load_discovery_policy",
    "plan",
    "plan_summary",
    "prepare_operation",
    "prepare_report_only",
    "publish_plan",
    "run_continuous_discovery_v2",
    "run_discovery_v2",
    "verify_plan",
]
