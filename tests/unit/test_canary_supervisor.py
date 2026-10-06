import pytest

from scripts.canary_supervisor import classify_observation


@pytest.mark.parametrize(
    ("run_status", "active_state", "main_pid", "expected"),
    [
        ("completed", "active", 11, "running"),
        ("deferred", "activating", 11, "running"),
        ("failed", "deactivating", 11, "running"),
        ("cancelled", "reloading", 11, "running"),
        ("pending", "activating", 0, "running"),
        ("deferred", "deactivating", 0, "running"),
        ("completed", "active", 0, "running"),
        ("failed", "reloading", 0, "running"),
        ("deferred", "inactive", 11, "running"),
        ("completed", "dead", 11, "running"),
        ("failed", "failed", 11, "running"),
        ("completed", "inactive", 0, "complete"),
        ("deferred", "inactive", 0, "incomplete"),
        ("failed", "inactive", 0, "incomplete"),
        ("cancelled", "dead", 0, "incomplete"),
        ("pending", "inactive", 0, "wait"),
        ("collecting", "inactive", 0, "incomplete"),
        ("normalizing", "dead", 0, "incomplete"),
        ("extracting", "inactive", 0, "incomplete"),
        ("scoring", "inactive", 0, "incomplete"),
        ("deep_evaluating", "inactive", 0, "incomplete"),
        ("notifying", "inactive", 0, "incomplete"),
        # Unit GC clears volatile result metadata; DB + observed inactive state suffice.
        ("deferred", "inactive", 0, "incomplete"),
        ("deferred", "failed", 0, "incomplete"),
        ("pending", "failed", 0, "incomplete"),
        ("completed", "failed", 0, "incomplete"),
    ],
)
def test_classify_observation(run_status, active_state, main_pid, expected):
    assert classify_observation(run_status, active_state, main_pid) == expected


@pytest.mark.parametrize(
    ("run_status", "active_state", "main_pid"),
    [
        ("unknown", "inactive", 0),
        ("pending", "unknown", 0),
        ("pending", "inactive", -1),
        ("pending", "inactive", True),
        ("pending", "inactive", None),
        (None, "inactive", 0),
        ("pending", None, 0),
        ("pending", "inactive", "0"),
    ],
)
def test_malformed_observation_fails_closed(run_status, active_state, main_pid):
    assert classify_observation(run_status, active_state, main_pid) == "error"
