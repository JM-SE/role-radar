"""Fixed real ATS factory facade for Greenhouse and Lever only."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from .r2_greenhouse_lever_factory import R2GreenhouseLeverFactory
from .r2_real_ats_capability import ApprovedRealATSCapability
from .r2_real_ats_transport import (
    RealATSTestTransport,
    make_real_ats_transport,
)

if TYPE_CHECKING:
    from .profile_relevant_acquisition.source_plan import SourcePlan
    from .r2_operational_authorization import OperationPacket


RealATSCollectorFactory = R2GreenhouseLeverFactory


def create_real_ats_factory(
    capability: ApprovedRealATSCapability,
    packet: OperationPacket,
    plan: SourcePlan,
    *,
    current_time: datetime | None = None,
) -> R2GreenhouseLeverFactory:
    """Construct the fixed Greenhouse/Lever mapping and no other provider."""
    check = datetime.now(UTC) if current_time is None else current_time
    if type(capability) is not ApprovedRealATSCapability:
        raise ValueError("real_ats_capability_required")
    capability.verify_for(packet, plan, now=check)
    return R2GreenhouseLeverFactory(
        capability,
        packet,
        plan,
        make_real_ats_transport(capability),
        current_time,
    )


def create_test_real_ats_factory(
    capability: ApprovedRealATSCapability,
    packet: OperationPacket,
    plan: SourcePlan,
    transport: RealATSTestTransport,
    *,
    current_time: datetime | None = None,
) -> R2GreenhouseLeverFactory:
    """Offline-only named seam; accepts no arbitrary HTTP transport."""
    if type(transport) is not RealATSTestTransport:
        raise TypeError("real ATS test transport required")
    check = datetime.now(UTC) if current_time is None else current_time
    capability.verify_for(packet, plan, now=check)
    return R2GreenhouseLeverFactory(capability, packet, plan, transport, current_time)


__all__ = [
    "RealATSCollectorFactory",
    "create_real_ats_factory",
    "create_test_real_ats_factory",
]
