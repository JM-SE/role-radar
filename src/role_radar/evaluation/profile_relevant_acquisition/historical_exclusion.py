"""Historical exclusion seam with no historical data access."""

from pathlib import Path

from role_radar.evaluation.filesystem import HISTORICAL_ROOTS
from role_radar.evaluation.profile_relevance.contracts import HistoricalIdentityExclusion


def validate_non_historical_root(root: Path) -> None:
    """Reject configured roots that alias a prior evaluation namespace."""

    text = str(root)
    if any(text == item or text.startswith(item + "/") for item in HISTORICAL_ROOTS):
        raise ValueError("historical_root_rejected")


__all__ = ["HISTORICAL_ROOTS", "HistoricalIdentityExclusion", "validate_non_historical_root"]
