"""One run-scoped, provider-neutral budget for discovery v2."""

from __future__ import annotations

from dataclasses import dataclass

from role_radar.discovery.authorization_v2 import DiscoveryBudgetsV2


class DiscoveryBudgetError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class DiscoveryBudgetSnapshotV2:
    brave_requests: int
    tavily_requests: int
    unique_candidates: int
    board_verifications: int
    verification_wire_attempts: int


class DiscoveryBudgetV2:
    """Mutable counters with fixed limits supplied by a verified plan."""

    def __init__(self, budgets: DiscoveryBudgetsV2 | None = None) -> None:
        self.budgets = budgets or DiscoveryBudgetsV2()
        self.brave_requests = 0
        self.tavily_requests = 0
        self.unique_candidates = 0
        self.board_verifications = 0
        self.verification_wire_attempts = 0

    def _reserve(self, current: int, limit: int, code: str) -> None:
        if current >= limit:
            raise DiscoveryBudgetError(code)

    def reserve_search(self, provider: str) -> None:
        if provider == "brave":
            self._reserve(
                self.brave_requests,
                self.budgets.max_brave_requests_per_run,
                "discovery_budget_exhausted",
            )
            self.brave_requests += 1
            return
        if provider == "tavily":
            self._reserve(
                self.tavily_requests,
                self.budgets.max_tavily_requests_per_run,
                "discovery_budget_exhausted",
            )
            self.tavily_requests += 1
            return
        raise DiscoveryBudgetError("discovery_provider_invalid")

    def reserve_candidate(self) -> None:
        self._reserve(
            self.unique_candidates,
            self.budgets.max_unique_board_candidates_per_run,
            "discovery_candidate_cap_exhausted",
        )
        self.unique_candidates += 1

    def reserve_verification(self) -> None:
        self._reserve(
            self.board_verifications,
            self.budgets.max_unique_board_verifications_per_run,
            "discovery_verification_cap_exhausted",
        )
        self.board_verifications += 1

    def reserve_wire_attempt(self) -> None:
        self._reserve(
            self.verification_wire_attempts,
            self.budgets.max_verification_wire_attempts_per_run,
            "discovery_wire_cap_exhausted",
        )
        self.verification_wire_attempts += 1

    @property
    def exhausted(self) -> bool:
        return (
            self.unique_candidates >= self.budgets.max_unique_board_candidates_per_run
            or self.board_verifications >= self.budgets.max_unique_board_verifications_per_run
            or self.verification_wire_attempts
            >= self.budgets.max_verification_wire_attempts_per_run
        )

    def snapshot(self) -> DiscoveryBudgetSnapshotV2:
        return DiscoveryBudgetSnapshotV2(
            self.brave_requests,
            self.tavily_requests,
            self.unique_candidates,
            self.board_verifications,
            self.verification_wire_attempts,
        )


RunDiscoveryBudgetV2 = DiscoveryBudgetV2

__all__ = [
    "DiscoveryBudgetError",
    "DiscoveryBudgetSnapshotV2",
    "DiscoveryBudgetV2",
    "RunDiscoveryBudgetV2",
]
