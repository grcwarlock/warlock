"""Warlock AI layer -- unified service for all AI capabilities.

Public API::

    from warlock.ai import AIService, get_ai_service, AITask, AIResult

    svc = get_ai_service()
    result = svc.reason(AITask.REMEDIATION_GUIDANCE, context, fallback=lambda: "N/A")
"""

from warlock.ai.service import AIService, get_ai_service
from warlock.ai.types import AIResult, AITask

__all__ = [
    "AIResult",
    "AIService",
    "AITask",
    "get_ai_service",
]
