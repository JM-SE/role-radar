"""Typed preregistration binding; no defaults or live execution."""

import dataclasses


@dataclasses.dataclass(frozen=True, slots=True)
class AcquisitionPreregistration:
    """Minimal immutable binding consumed by acquisition runtime seams."""

    operation_id: str
    source_plan_sha256: str
    provenance_sha256: str
    preregistration_sha256: str

    def __post_init__(self) -> None:
        if not self.operation_id or not self.operation_id.strip():
            raise ValueError("preregistration_operation_invalid")
        if any(
            not isinstance(value, str)
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
            for value in (
                self.source_plan_sha256,
                self.provenance_sha256,
                self.preregistration_sha256,
            )
        ):
            raise ValueError("preregistration_binding_invalid")


__all__ = ["AcquisitionPreregistration"]
