"""Pure discovery limits and policy versions."""

from dataclasses import dataclass

DISCOVERY_POLICY_VERSION = "discovery-policy-v1"
MAX_NEW_SOURCES_PER_RUN = 8
MAX_ACTIVE_DISCOVERY_SOURCES = 50
MAX_TRANSIENT_RESULTS_PER_QUERY = 100


@dataclass(frozen=True, slots=True)
class DiscoveryPolicy:
    version: str = DISCOVERY_POLICY_VERSION
    max_new_sources_per_run: int = MAX_NEW_SOURCES_PER_RUN
    max_active_sources: int = MAX_ACTIVE_DISCOVERY_SOURCES
    max_results_per_query: int = MAX_TRANSIENT_RESULTS_PER_QUERY

    def allows_new_source(self, created: int) -> bool:
        return created < self.max_new_sources_per_run
