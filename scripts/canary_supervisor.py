"""Pure canary observation decisions; callers own deadlines and process control."""


_RUN_STATUSES = {
    "pending",
    "collecting",
    "normalizing",
    "extracting",
    "scoring",
    "deep_evaluating",
    "notifying",
    "deferred",
    "completed",
    "failed",
    "cancelled",
}
_ACTIVE_STATES = {"active", "activating", "deactivating", "reloading"}
_QUIESCENT_STATES = {"inactive", "dead"}


def classify_observation(run_status: str, active_state: str, main_pid: int) -> str:
    """Return running, wait, complete, incomplete, or error from DB/systemd state.

    Any PID or active transition remains supervised, independent of DB status.
    Quiescent pending runs wait; completed runs complete; every other known
    quiescent status is incomplete. Invalid observations error.
    """
    if (
        not isinstance(run_status, str)
        or run_status not in _RUN_STATUSES
        or not isinstance(active_state, str)
        or not isinstance(main_pid, int)
        or isinstance(main_pid, bool)
        or main_pid < 0
    ):
        return "error"
    if active_state not in _ACTIVE_STATES | _QUIESCENT_STATES | {"failed"}:
        return "error"
    if main_pid > 0 or active_state in _ACTIVE_STATES:
        return "running"
    if active_state == "failed":
        return "incomplete"
    if run_status == "pending":
        return "wait"
    if run_status == "completed":
        return "complete"
    return "incomplete"
