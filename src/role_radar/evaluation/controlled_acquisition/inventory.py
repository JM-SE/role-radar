"""Read-only historical identity inventory; no write-capable repository calls."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from role_radar.evaluation.controlled_acquisition.contracts import HistoricalIdentity
from role_radar.evaluation.controlled_acquisition.deduplication import (
    build_inventory_index,
    normalize_identity_url,
)


class HistoricalInventory:
    def __init__(self, identities: Iterable[HistoricalIdentity]) -> None:
        self.identities = tuple(identities)
        self.keys = build_inventory_index(self.identities)

    def contains(self, *, source_family: str, source_key: str, external_id: str) -> bool:
        return f"source:{source_family}:{source_key}:{external_id}" in self.keys


def inventory_from_rows(rows: Iterable[Any]) -> HistoricalInventory:
    """Build an inventory from read-only row-like objects supplied by the caller.

    The function intentionally accepts a narrow row protocol rather than a
    SQLAlchemy Session, which makes accidental writes impossible at this seam.
    """
    identities: list[HistoricalIdentity] = []
    for row in rows:
        source = getattr(row, "source", None)
        identities.append(
            HistoricalIdentity(
                source_family=str(getattr(source, "type", "")),
                source_key=str(getattr(source, "source_key", "")),
                external_id=getattr(row, "external_id", None),
                official_url=normalize_identity_url(getattr(row, "source_url", None)),
                application_url=normalize_identity_url(
                    getattr(row, "application_url", None)
                ),
            )
        )
    return HistoricalInventory(identities)
