"""Worker search orchestration: memo, reservation, provider call, settlement."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Literal, cast

from sqlalchemy.orm import Session

from role_radar.discovery.acquisition_config import AcquisitionConfig
from role_radar.discovery.contracts import (
    GreenhouseOfficialCandidate,
    LeverOfficialCandidate,
    ProviderIntent,
    ProviderTier,
    RejectedCandidate,
    SearchRequest,
    SearchResponse,
    TransientSearchHit,
    UnknownCandidate,
)
from role_radar.discovery.protocols import SearchProvider
from role_radar.discovery.routing import ProviderName
from role_radar.discovery.url_classifier import classify_url
from role_radar.repositories.acquisition import AcquisitionRepository
from role_radar.services.acquisition_budget_service import (
    AcquisitionBudgetService,
    AcquisitionOperation,
)
from role_radar.sources.identity import canonical_source_key

Clock = Callable[[], datetime]


class SearchRoutingService:
    """No ORM/session/secret crosses the provider await boundary."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        brave: SearchProvider | None,
        tavily: SearchProvider | None,
        budget: AcquisitionBudgetService,
        config: AcquisitionConfig,
        clock: Clock | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._brave = brave
        self._tavily = tavily
        self._budget = budget
        self._config = config
        self._clock = clock or (lambda: datetime.now(UTC))

    async def search_canary(self, request: SearchRequest) -> SearchResponse:
        """Run only the canary's Brave Free operation; never route to a fallback."""
        if self._brave is None or not self._config.brave_free.enabled:
            return SearchResponse(
                provider="brave",
                tier=ProviderTier.FREE,
                status="failed",
                error_code="provider_unavailable",
            )
        return await self._run_one(
            request,
            ProviderName.BRAVE,
            ProviderTier.FREE,
            "canary_brave_only",
            skip_memo=True,
        )

    async def search(self, request: SearchRequest) -> SearchResponse:
        if request.provider_intent is ProviderIntent.SEMANTIC:
            return await self._run_one(
                request, ProviderName.TAVILY, ProviderTier.FREE, "semantic_primary"
            )

        memo = self._find_memo(request, "brave", "free")
        if memo is not None:
            return memo
        if self._brave is not None and self._config.brave_free.enabled:
            response = await self._run_one(
                request, ProviderName.BRAVE, ProviderTier.FREE, "exact_primary"
            )
            if response.error_code == "quota_exhausted":
                if self._tavily is not None and self._config.tavily_free.enabled:
                    response = await self._run_one(
                        request, ProviderName.TAVILY, ProviderTier.FREE, "brave_overflow"
                    )
                elif self._brave is not None and self._paid_is_enabled():
                    response = await self._run_one(
                        request, ProviderName.BRAVE, ProviderTier.PAID, "paid_after_free_exhaustion"
                    )
                return response
            if response.status == "succeeded" and response.known_count < 3:
                tavily_memo = self._find_memo(request, "tavily", "free")
                if tavily_memo is not None:
                    return _merge(response, tavily_memo)
                if self._tavily is not None and self._config.tavily_free.enabled:
                    complement = await self._run_one(
                        request, ProviderName.TAVILY, ProviderTier.FREE, "low_yield_complement"
                    )
                    return _merge(response, complement)
            return response

        if self._tavily is not None and self._config.tavily_free.enabled:
            response = await self._run_one(
                request, ProviderName.TAVILY, ProviderTier.FREE, "brave_overflow"
            )
            if (
                response.error_code == "quota_exhausted"
                and self._brave is not None
                and self._paid_is_enabled()
            ):
                return await self._run_one(
                    request, ProviderName.BRAVE, ProviderTier.PAID, "paid_after_free_exhaustion"
                )
            return response

        if self._brave is not None and self._paid_is_enabled():
            return await self._run_one(
                request, ProviderName.BRAVE, ProviderTier.PAID, "paid_after_free_exhaustion"
            )
        return SearchResponse(
            provider="brave",
            tier=ProviderTier.FREE,
            status="failed",
            error_code="quota_unavailable",
        )

    async def _run_one(
        self,
        request: SearchRequest,
        provider: ProviderName,
        tier: ProviderTier,
        reason: str,
        *,
        skip_memo: bool = False,
    ) -> SearchResponse:
        del reason  # Routing reason is represented by the operation suffix, not persisted content.
        provider_value: Literal["brave", "tavily"] = (
            "brave" if provider is ProviderName.BRAVE else "tavily"
        )
        client = self._brave if provider is ProviderName.BRAVE else self._tavily
        if client is None:
            return SearchResponse(
                provider=provider_value,
                tier=tier,
                status="failed",
                error_code="provider_unavailable",
            )
        memo = None if skip_memo else self._find_memo(request, provider_value, tier.value)
        if memo is not None:
            return memo
        operation_key = f"{request.operation_key}:{provider.value}:{tier.value}"
        price = (
            self._config.brave_paid.unit_price_micro_usd or 0
            if provider is ProviderName.BRAVE and tier is ProviderTier.PAID
            else 0
        )
        operation = AcquisitionOperation(
            operation_key=operation_key,
            provider=provider.value,
            tier=tier.value,
            cycle_id=request.operation_key.split(":", 1)[0],
            query_key=request.query_key,
            query_ordinal=_query_ordinal(request.operation_key),
            unit_price_micro_usd=price,
        )
        handle = self._budget.reserve(operation)
        if handle is None:
            return SearchResponse(
                provider=provider_value, tier=tier, status="failed", error_code="quota_exhausted"
            )
        if not handle.created:
            return SearchResponse(
                provider=provider_value,
                tier=tier,
                status="indeterminate" if handle.status == "reserved" else "failed",
                error_code="operation_recovery_required",
            )
        try:
            response = await client.search(request)
        except BaseException:
            # A cancellation or process failure cannot prove no transmission.
            self._budget.finalize(
                operation,
                handle,
                status="indeterminate",
                candidate_count=0,
                known_count=0,
                unknown_count=0,
                rejected_count=0,
                duration_ms=0,
                error_code="indeterminate",
                transmission_status="indeterminate",
            )
            raise
        if response.tier is not tier:
            response = SearchResponse(
                provider=provider_value,
                tier=tier,
                status=response.status,
                hits=response.hits,
                result_count=response.result_count,
                duration_ms=response.duration_ms,
                error_code=response.error_code,
            )
        known, unknown, rejected = self._classification_counts(response.hits)
        response = response.model_copy(update={"known_count": known, "tier": tier})
        self._budget.finalize(
            operation,
            handle,
            status=response.status,
            candidate_count=response.result_count,
            known_count=known,
            unknown_count=unknown,
            rejected_count=rejected,
            duration_ms=response.duration_ms,
            error_code=response.error_code,
        )
        if response.status in {"succeeded", "empty"}:
            self._write_memo(request, response, provider, tier, known)
        return response

    def _find_memo(self, request: SearchRequest, provider: str, tier: str) -> SearchResponse | None:
        now = self._clock().astimezone(UTC)
        with self._session_factory() as session:
            row = AcquisitionRepository(session).find_memo(
                provider=provider,
                tier=ProviderTier(tier),
                query_key=request.query_key,
                planner_version=request.planner_version,
                query_version=request.query_version,
                config_version=self._config.config_version,
                now=now,
            )
            if row is None:
                return None
            return SearchResponse(
                provider=cast(Literal["brave", "tavily"], provider),
                tier=ProviderTier(tier),
                status=cast(
                    Literal["succeeded", "empty", "failed", "malformed", "indeterminate"],
                    row.status,
                ),
                result_count=row.candidate_count,
            )

    def _write_memo(
        self,
        request: SearchRequest,
        response: SearchResponse,
        provider: ProviderName,
        tier: ProviderTier,
        known: int,
    ) -> None:
        now = self._clock().astimezone(UTC)
        with self._session_factory() as session:
            AcquisitionRepository(session).upsert_memo(
                provider=provider.value,
                tier=tier.value,
                query_key=request.query_key,
                planner_version=request.planner_version,
                query_version=request.query_version,
                config_version=self._config.config_version,
                executed_at=now,
                expires_at=now + timedelta(hours=24),
                status=response.status,
                candidate_count=response.result_count,
                known_count=known,
            )
            session.commit()

    def _paid_is_enabled(self) -> bool:
        paid = self._config.brave_paid
        return (
            paid.enabled
            and paid.unit_price_micro_usd is not None
            and self._config.paid_is_current(self._clock())
            and self._config.effective_brave_paid_cap > 0
        )

    async def aclose(self) -> None:
        """Routing owns no transport; concrete clients are worker-owned."""
        return None

    @staticmethod
    def _allowlisted_count(hits: tuple[TransientSearchHit, ...]) -> int:
        return SearchRoutingService._classification_counts(hits)[0]

    @staticmethod
    def _classification_counts(
        hits: tuple[TransientSearchHit, ...],
    ) -> tuple[int, int, int]:
        seen: set[str] = set()
        unknown = rejected = 0
        for hit in hits:
            candidate = classify_url(hit.url)
            if isinstance(candidate, (GreenhouseOfficialCandidate, LeverOfficialCandidate)):
                seen.add(canonical_source_key(candidate.source_type, dict(candidate.configuration)))
            elif isinstance(candidate, UnknownCandidate):
                unknown += 1
            elif isinstance(candidate, RejectedCandidate):
                rejected += 1
        return len(seen), unknown, rejected


def _merge(first: SearchResponse, second: SearchResponse) -> SearchResponse:
    if second.status not in {"succeeded", "empty"}:
        return first
    seen = {item.url for item in first.hits}
    hits = list(first.hits)
    for item in second.hits:
        if item.url not in seen and len(hits) < 10:
            seen.add(item.url)
            hits.append(TransientSearchHit(url=item.url, rank=len(hits) + 1))
    return SearchResponse(
        provider=first.provider,
        tier=first.tier,
        status="succeeded" if hits else "empty",
        hits=tuple(hits),
        result_count=len(hits),
        known_count=min(10, first.known_count + second.known_count),
        duration_ms=first.duration_ms + second.duration_ms,
    )


def _query_ordinal(operation_key: str) -> int:
    try:
        return int(operation_key.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return 0
