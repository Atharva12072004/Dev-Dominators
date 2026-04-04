from fastapi import APIRouter, Depends

from app.api.deps import get_ai_service
from app.models.schemas import ExplainResponse, ExplanationRequest
from app.services.ai_enhancement_service import AIEnhancementService

router = APIRouter(tags=["explain"])


@router.post("/explain", response_model=ExplainResponse)
async def explain_scan(
    payload: ExplanationRequest,
    ai_service: AIEnhancementService = Depends(get_ai_service),
) -> ExplainResponse:
    explanation = await ai_service.generate_explanation(payload)
    return ExplainResponse(**explanation)

