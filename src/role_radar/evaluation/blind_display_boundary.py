"""Shared safe display boundary for evaluation materializers."""

from role_radar.evaluation.blind_labeling.display import DisplayError, render_evidence


def render_materialized_field(value: object) -> str:
    """Render one materialized user-visible field through display-v2."""

    if not isinstance(value, str):
        raise TypeError("materialized display field must be text")
    return render_evidence(value)


__all__ = ["DisplayError", "render_materialized_field"]
