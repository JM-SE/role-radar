from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from role_radar.evaluation.controlled_acquisition.configuration import (
    ConfigurationError,
    ControlledAcquisitionConfig,
    freeze_window,
)
from role_radar.evaluation.controlled_acquisition.contracts import (
    HistoricalIdentity,
    Observation,
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
from role_radar.evaluation.controlled_acquisition.recency import eligibility
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
        ({"family": "jobicy", "source_id": "source", "revision": 1},),
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
