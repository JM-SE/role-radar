from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from role_radar.collectors.outcomes import CollectionMetrics, CollectionSuccess
from role_radar.collectors.policy import CollectionRunBudget
from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot
from role_radar.domain.dto import RawJob
from role_radar.evaluation.controlled_acquisition.acquisition import (
    CollectorTask,
)
from role_radar.evaluation.controlled_acquisition.configuration import (
    ConfigurationError,
    ControlledAcquisitionConfig,
    freeze_window,
)
from role_radar.evaluation.controlled_acquisition.contracts import (
    HistoricalIdentity,
    Observation,
    SourceCheckpoint,
)
from role_radar.evaluation.controlled_acquisition.deduplication import (
    build_inventory_index,
    cluster_observations,
    normalize_identity_url,
)
from role_radar.evaluation.controlled_acquisition.journal import (
    Journal,
    JournalEvent,
    validate_transition,
)
from role_radar.evaluation.controlled_acquisition.live import (
    LiveAcquisition,
    LiveAdapters,
    acknowledgement_challenge,
)
from role_radar.evaluation.controlled_acquisition.protocols import ALLOWED_ORIGINS
from role_radar.evaluation.controlled_acquisition.recency import eligibility
from role_radar.evaluation.controlled_acquisition.runtime import (
    SystemdServiceGuard,
    verify_deployment_provenance,
)
from role_radar.evaluation.controlled_acquisition.selection import (
    blind_order,
    select_clusters,
)
from role_radar.evaluation.controlled_acquisition.snapshot import (
    SnapshotStore,
    label_view_item,
)
from role_radar.evaluation.controlled_acquisition.source_plan import (
    PlanError,
    SourcePlan,
    load_plan,
)

AS_OF = datetime(2026, 8, 11, 12, tzinfo=UTC)
TEST_COMMIT = "f" * 40
EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def observation(
    number: int,
    family: str = "jobicy",
    *,
    recency: datetime | None = AS_OF - timedelta(days=1),
    source_url: str | None = None,
    application_url: str | None = None,
) -> Observation:
    return Observation(
        source_family=family,
        source_id=f"{family}-{number}",
        source_key=f"board-{number}",
        source_revision=1,
        configuration_version=1,
        external_id=f"external-{number}",
        title=f"Engineer {number}",
        company=f"Company {number}",
        location="Remote",
        description=f"Description {number}",
        source_url=source_url or f"https://jobs.example.com/{number}",
        application_url=application_url or f"https://apply.example.com/{number}",
        provider_recency_at=recency,
        recency_semantic="published_at",
        provider_status=None,
        expires_at=None,
        collected_at=AS_OF,
    )


def test_lookback_is_required_strict_and_window_is_immutable() -> None:
    with pytest.raises(ConfigurationError, match="lookback_missing"):
        ControlledAcquisitionConfig.from_env({})
    with pytest.raises(ConfigurationError, match="lookback_not_strict_integer"):
        ControlledAcquisitionConfig.from_env({"ROLE_RADAR_F10_1_LOOKBACK_DAYS": " 14"})
    config = ControlledAcquisitionConfig.from_env({"ROLE_RADAR_F10_1_LOOKBACK_DAYS": "14"})
    window = freeze_window(selection_as_of_utc=AS_OF, lookback_days=config.lookback_days)
    assert window.cutoff_utc == AS_OF - timedelta(days=14)
    with pytest.raises(ConfigurationError, match="lookback_requires_new_approved_plan"):
        ControlledAcquisitionConfig.from_env(
            {"ROLE_RADAR_F10_1_LOOKBACK_DAYS": "13"}
        ).require_approved_run()


def test_recency_is_inclusive_and_rejects_future_missing_and_closed() -> None:
    window_start = AS_OF - timedelta(days=14)
    assert eligibility(
        observation(1, recency=window_start), cutoff_utc=window_start, as_of_utc=AS_OF
    ) is None
    assert eligibility(
        observation(2, recency=None), cutoff_utc=window_start, as_of_utc=AS_OF
    ) == "freshness_timestamp_missing"
    assert eligibility(
        observation(3, recency=AS_OF + timedelta(minutes=6)),
        cutoff_utc=window_start,
        as_of_utc=AS_OF,
    ) == "freshness_future"
    closed = observation(4)
    object.__setattr__(closed, "provider_status", "closed")
    assert eligibility(closed, cutoff_utc=window_start, as_of_utc=AS_OF) == "provider_closed"


def test_identity_url_removes_only_allowlisted_tracking() -> None:
    assert normalize_identity_url(
        "https://jobs.example.com/post/?utm_source=x&ref=abc&team=platform#read"
    ) == "https://jobs.example.com/post?team=platform"


def test_historical_strong_identity_excludes_candidate() -> None:
    item = observation(1)
    inventory = build_inventory_index(
        (
            HistoricalIdentity(
                "jobicy",
                item.source_key,
                item.external_id,
                normalize_identity_url(item.source_url),
                None,
            ),
        )
    )
    result = cluster_observations((item,), historical_keys=inventory)
    assert result.clusters == ()
    assert result.exclusions[0].reason == "historical_strong_identity"


def test_strong_cross_source_url_merges_and_weak_conflict_excludes_all() -> None:
    first = observation(1, "greenhouse", source_url="https://jobs.example.com/shared")
    second = observation(2, "lever", source_url="https://jobs.example.com/shared")
    merged = cluster_observations((first, second))
    assert len(merged.clusters) == 1
    weak_a = observation(3, "jobicy")
    weak_b = observation(4, "jobicy")
    object.__setattr__(weak_b, "company", weak_a.company)
    object.__setattr__(weak_b, "title", weak_a.title)
    object.__setattr__(weak_b, "location", weak_a.location)
    object.__setattr__(weak_b, "description", weak_a.description)
    conflicted = cluster_observations((weak_a, weak_b))
    assert conflicted.clusters == ()
    assert all(item.reason == "weak_identity_conflict" for item in conflicted.exclusions)


def test_selection_is_permutation_stable_and_fails_below_fifty() -> None:
    clusters = cluster_observations(tuple(observation(i, "jobicy") for i in range(50))).clusters
    first = select_clusters(clusters, seed="seed")
    second = select_clusters(tuple(reversed(clusters)), seed="seed")
    assert first.status == "selected"
    assert [item.cluster.cluster_id for item in first.selected] == [
        item.cluster.cluster_id for item in second.selected
    ]
    assert first.actual_counts == {"jobicy": 50}
    assert select_clusters(clusters[:49], seed="seed").status == "failed_insufficient"
    assert blind_order("seed", ["a", "b"]) == blind_order("seed", ["b", "a"])


def test_source_plan_is_canonical_and_rejects_secret_or_wrong_window() -> None:
    plan = SourcePlan(
        "f10.1-plan-v1",
        14,
        (
            {
                "family": "jobicy",
                "source_id": "source",
                "source_key": "jobicy:latam",
                "revision": 1,
                "configuration_version": 1,
                "configuration": {"region": "latam", "remote_only": True},
            },
        ),
    )
    assert len(plan.sha256) == 64
    assert load_plan(plan.as_dict()).sha256 == plan.sha256
    with pytest.raises(PlanError, match="source_plan_secret_field"):
        load_plan(
            {
                **plan.as_dict(),
                "source_configs": [
                    {"family": "jobicy", "source_id": "source", "revision": 1, "api_token": "x"}
                ],
            }
        )


def test_journal_transitions_are_atomic_and_invalid_transition_fails(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "operation.json")
    journal.append(JournalEvent("state", "planned", "planned", {}))
    assert journal.read()["events"][0]["code"] == "planned"
    validate_transition("planned", "plan_approved")
    with pytest.raises(ValueError, match="invalid_operation_transition"):
        validate_transition("planned", "completed")


def test_snapshot_is_exactly_fifty_create_once_and_tamper_evident(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "f10.1")
    lines = tuple(f'{{"id":{index}}}\n'.encode() for index in range(50))
    path = store.publish(
        dataset_id="a" * 64,
        dataset_lines=lines,
        provenance_lines=lines,
        label_lines=lines,
        internal={"schema_version": 1, "count": 50},
    )
    assert path.is_dir()
    assert store.verify("a" * 64)
    assert store.publish(
        dataset_id="a" * 64,
        dataset_lines=lines,
        provenance_lines=lines,
        label_lines=lines,
        internal={"schema_version": 1, "count": 50},
    ) == path
    with pytest.raises(FileExistsError, match="snapshot_id_conflict"):
        store.publish(
            dataset_id="a" * 64,
            dataset_lines=tuple(f'{{"id":{index + 1}}}\n'.encode() for index in range(50)),
            provenance_lines=lines,
            label_lines=lines,
            internal={"schema_version": 1, "count": 50},
        )
    (path / "dataset.jsonl").write_text("tampered\n", encoding="utf-8")
    assert not store.verify("a" * 64)


def test_label_view_has_no_source_or_selection_metadata() -> None:
    from role_radar.evaluation.controlled_acquisition.contracts import DatasetItem

    payload = label_view_item(
        DatasetItem(
            1,
            "opaque",
            "Engineer",
            "Company",
            "Remote",
            "Description",
            "https://jobs.example.com/1",
            "https://apply.example.com/1",
            AS_OF,
            "published_at",
            "jobicy",
            "quota",
        )
    )
    assert "source_url" not in payload
    assert "application_url" not in payload
    assert "selection_family" not in payload
    assert "selection_reason" not in payload
    assert "provider_recency_at" not in payload
    assert "recency_semantic" not in payload


def test_live_acknowledgement_is_bound_to_plan_and_window() -> None:
    challenge = acknowledgement_challenge(
        plan_sha256="a" * 64,
        lookback_days=14,
        selection_as_of_utc=AS_OF,
    )
    assert challenge == (
        "I ACKNOWLEDGE F10.1 LIVE ACQUISITION PLAN "
        + "a" * 64
        + " LOOKBACK 14 AS_OF 2026-08-11T12:00:00Z"
    )


def test_journal_detects_indeterminate_request(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "events.json")
    journal.record_request_intent(operation_id="op", request_id="req")
    assert journal.has_pending_request("op")
    journal.record_request_result(operation_id="op", request_id="req")
    assert not journal.has_pending_request("op")


def test_deployment_provenance_is_exact_and_rejects_dirty_state(tmp_path: Path) -> None:
    for name, value in (
        (".deployed-commit", TEST_COMMIT),
        (".deployed-diff-sha256", EMPTY_SHA),
        (".deployed-status-sha256", EMPTY_SHA),
        (".deployed-alembic-head", "e7a4c9f1b2d3"),
    ):
        (tmp_path / name).write_text(value + "\n", encoding="ascii")
    plan = SourcePlan(
        "f10.1-plan-v1",
        14,
        (),
        profile_sha256="a" * 64,
        profile_id="profile",
        profile_version=2,
        profile_schema_version=1,
        selection_as_of_utc=AS_OF.isoformat().replace("+00:00", "Z"),
        source_commit=TEST_COMMIT,
        source_diff_sha256=EMPTY_SHA,
        source_status_sha256=EMPTY_SHA,
        alembic_head="e7a4c9f1b2d3",
    )
    # The plan itself must still contain a source for a live run; provenance
    # verification is exercised directly against its immutable fields.
    verify_deployment_provenance(plan, app_root=tmp_path)
    (tmp_path / ".deployed-status-sha256").write_text("dirty\n", encoding="ascii")
    with pytest.raises(ValueError, match="deployment_provenance_mismatch"):
        verify_deployment_provenance(plan, app_root=tmp_path)


def test_systemd_guard_restores_only_previously_active_services() -> None:
    calls: list[tuple[str, ...]] = []

    class Result:
        def __init__(self, returncode: int) -> None:
            self.returncode = returncode

    def runner(command: tuple[str, ...], **_kwargs: object) -> Result:
        calls.append(command)
        if command[1] == "is-active":
            return Result(0 if command[-1].endswith("worker.service") else 3)
        return Result(0)

    guard = SystemdServiceGuard(runner=runner)  # type: ignore[arg-type]
    guard.prepare()
    guard.restore()
    assert calls == [
        ("systemctl", "is-active", "--quiet", "role-radar-worker.service"),
        ("systemctl", "is-active", "--quiet", "role-radar-scheduler.timer"),
        ("systemctl", "stop", "role-radar-worker.service"),
        ("systemctl", "start", "role-radar-worker.service"),
    ]


class FakeSourceState:
    def __init__(self) -> None:
        self.checkpoint_value = (
            SourceCheckpoint(
                "source", "greenhouse", "greenhouse:board", "Board", 1, 1, {}, False, False
            ),
        )

    def checkpoint(self, source_ids: tuple[str, ...]) -> tuple[SourceCheckpoint, ...]:
        assert source_ids == ("source",)
        return self.checkpoint_value

    def assert_unchanged(self, checkpoint: tuple[SourceCheckpoint, ...]) -> None:
        assert checkpoint == self.checkpoint_value

    def assert_all_disabled(self, checkpoint: tuple[SourceCheckpoint, ...]) -> None:
        assert not any(item.enabled for item in checkpoint)

    def assert_global_disabled(self) -> None:
        return None


class FakeInventory:
    def capture_before_requests(self) -> None:
        return None

    def strong_keys(self) -> frozenset[str]:
        return frozenset()


async def fake_collector(
    _snapshot: SourceSnapshot, _runtime: CollectorRuntime
) -> CollectionSuccess:
    jobs = tuple(
        RawJob(
            source="greenhouse",
            external_id=str(index),
            source_url=f"https://jobs.example.com/{index}",
            application_url=f"https://apply.example.com/{index}",
            title=f"Engineer {index}",
            company=f"Company {index}",
            location="Remote",
            description=f"Description {index}",
            published_at=AS_OF - timedelta(days=1),
            structured_data={"updated_at": (AS_OF - timedelta(days=1)).isoformat()},
            collected_at=AS_OF,
        )
        for index in range(50)
    )
    return CollectionSuccess(
        "ok",
        jobs,
        CollectionMetrics(provider_items=50, accepted_items=50),
    )


@pytest.mark.asyncio
async def test_live_workflow_with_fake_collectors_publishes_only_private_snapshot(
    tmp_path: Path,
) -> None:
    plan = SourcePlan(
        "f10.1-plan-v1",
        14,
        (
            {
                "family": "greenhouse",
                "source_id": "source",
                "source_key": "greenhouse:board",
                "revision": 1,
                "configuration_version": 1,
                "configuration": {"board_token": "board"},
            },
        ),
        profile_sha256="b" * 64,
        profile_id="profile",
        profile_version=2,
        profile_schema_version=1,
        selection_as_of_utc=AS_OF.isoformat().replace("+00:00", "Z"),
        allowed_origins=ALLOWED_ORIGINS,
        source_commit=TEST_COMMIT,
        source_diff_sha256=EMPTY_SHA,
        source_status_sha256=EMPTY_SHA,
        alembic_head="e7a4c9f1b2d3",
    )
    source_state = FakeSourceState()
    restored: list[bool] = []
    task = CollectorTask(
        SourceSnapshot("source", "greenhouse", "Board", {}, "greenhouse:board", 1),
        1,
        fake_collector,
    )
    adapters = LiveAdapters(
        source_state=source_state,
        inventory=FakeInventory(),
        tasks=lambda _plan: (task,),
        runtime=CollectorRuntime(budget=CollectionRunBudget(100)),
        snapshot_store=SnapshotStore(tmp_path / "snapshots"),
        journal=Journal(tmp_path / "journal" / "events.json"),
        prepare_services=lambda: None,
        restore_services=lambda: restored.append(True),
    )
    result = await LiveAcquisition(
        config=ControlledAcquisitionConfig.from_env(
            {"ROLE_RADAR_F10_1_LOOKBACK_DAYS": "14"},
            snapshot_root=str(tmp_path / "snapshots"),
        ),
        adapters=adapters,
    ).run(
        plan=plan,
        profile_sha256="b" * 64,
        acknowledgement=acknowledgement_challenge(
            plan_sha256=plan.sha256,
            lookback_days=14,
            selection_as_of_utc=AS_OF,
        ),
        source_ids=("source",),
        selection_as_of_utc=AS_OF,
    )
    assert result.state.value == "completed"
    assert result.dataset_result is not None
    assert len(result.dataset_result.selected) == 50
    assert restored == [True]


@pytest.mark.asyncio
async def test_live_workflow_rejects_bad_ack_without_collecting(tmp_path: Path) -> None:
    called = False

    async def forbidden_collector(
        _snapshot: SourceSnapshot, _runtime: CollectorRuntime
    ) -> CollectionSuccess:
        nonlocal called
        called = True
        raise AssertionError("collector must not run")

    plan = SourcePlan(
        "f10.1-plan-v1",
        14,
        (
            {
                "family": "greenhouse",
                "source_id": "source",
                "source_key": "greenhouse:board",
                "revision": 1,
                "configuration_version": 1,
                "configuration": {"board_token": "board"},
            },
        ),
        profile_sha256="c" * 64,
        profile_id="profile",
        profile_version=2,
        profile_schema_version=1,
        selection_as_of_utc=AS_OF.isoformat().replace("+00:00", "Z"),
        allowed_origins=ALLOWED_ORIGINS,
        source_commit=TEST_COMMIT,
        source_diff_sha256=EMPTY_SHA,
        source_status_sha256=EMPTY_SHA,
        alembic_head="e7a4c9f1b2d3",
    )
    adapters = LiveAdapters(
        source_state=FakeSourceState(),
        inventory=FakeInventory(),
        tasks=lambda _plan: (
            CollectorTask(
                SourceSnapshot("source", "greenhouse", "Board", {}, "greenhouse:board", 1),
                1,
                forbidden_collector,
            ),
        ),
        runtime=CollectorRuntime(budget=CollectionRunBudget(100)),
        snapshot_store=SnapshotStore(tmp_path / "snapshots"),
        journal=Journal(tmp_path / "journal" / "events.json"),
        prepare_services=lambda: None,
        restore_services=lambda: None,
    )
    result = await LiveAcquisition(
        config=ControlledAcquisitionConfig.from_env(
            {"ROLE_RADAR_F10_1_LOOKBACK_DAYS": "14"},
            snapshot_root=str(tmp_path / "snapshots"),
        ),
        adapters=adapters,
    ).run(
        plan=plan,
        profile_sha256="c" * 64,
        acknowledgement="wrong",
        source_ids=("source",),
        selection_as_of_utc=AS_OF,
    )
    assert result.error_code == "live_acknowledgement_mismatch"
    assert not called
