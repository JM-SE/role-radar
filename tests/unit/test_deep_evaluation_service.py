import asyncio

from sqlalchemy.orm import Session

from role_radar.broker.fake import FakeLLMProvider
from role_radar.config import Settings
from role_radar.services.deep_evaluation_service import DeepEvaluationService


def test_service_has_stable_provider_contract(db_session: Session) -> None:
    provider = FakeLLMProvider(
        result={
            "fit_score": 50,
            "decision": "needs_review",
            "strengths": [],
            "gaps": [],
            "model_concerns": [],
            "uncertainties": [],
            "recommended_action": "review",
            "confidence": 0.5,
        }
    )
    service = DeepEvaluationService(lambda: db_session, provider=provider, settings=Settings())
    assert service is not None
    assert asyncio.iscoroutinefunction(service.execute)
