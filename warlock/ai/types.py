"""AI layer data types.

Shared enums and dataclasses used across the AI service, providers,
and consumer code.  No external dependencies beyond the stdlib.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Generic, TypeVar

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Task taxonomy
# ---------------------------------------------------------------------------


class AITask(str, Enum):
    """Every distinct AI capability the platform can invoke."""

    COMPLIANCE_ASSESSMENT = "compliance_assessment"
    QUESTIONNAIRE_RESPONSE = "questionnaire_response"
    GOVERNANCE_ANALYSIS = "governance_analysis"
    REMEDIATION_GUIDANCE = "remediation_guidance"
    RISK_NARRATIVE = "risk_narrative"
    SSP_NARRATIVE = "ssp_narrative"
    CIS_NARRATIVE = "cis_narrative"
    POLICY_REVIEW = "policy_review"
    VENDOR_RISK_ANALYSIS = "vendor_risk_analysis"
    DRIFT_EXPLANATION = "drift_explanation"
    ISSUE_TRIAGE = "issue_triage"
    FOLLOW_UP = "follow_up"
    EVIDENCE_EVALUATION = "evidence_evaluation"
    EXECUTIVE_REPORT = "executive_report"
    AUDIT_READINESS = "audit_readiness"
    AGGREGATE_CONTROL_ASSESSMENT = "aggregate_control_assessment"
    COMPLIANCE_QUERY = "compliance_query"


# ---------------------------------------------------------------------------
# Token accounting
# ---------------------------------------------------------------------------


@dataclass
class TokenUsage:
    """Input/output token counts from a single AI call."""

    input_tokens: int
    output_tokens: int


# ---------------------------------------------------------------------------
# Unified result envelope
# ---------------------------------------------------------------------------


@dataclass
class AIResult(Generic[T]):
    """Uniform wrapper returned by every ``AIService`` method.

    Consumers inspect ``ai_used`` to know whether the value came from a
    model or from a deterministic fallback.
    """

    value: T
    ai_used: bool
    confidence: float
    model: str
    provider: str
    prompt_hash: str
    latency_ms: int
    fallback_reason: str
    token_usage: TokenUsage | None = None


# ---------------------------------------------------------------------------
# Model discovery
# ---------------------------------------------------------------------------


@dataclass
class ModelInfo:
    """Metadata for a single model exposed by a provider."""

    id: str
    display_name: str
    verified: bool


@dataclass
class DiscoveryResult:
    """Outcome of a provider model-discovery call."""

    connected: bool
    models: list[ModelInfo] = field(default_factory=list)
    error: str | None = None


# ---------------------------------------------------------------------------
# Conversation state (interactive follow-up)
# ---------------------------------------------------------------------------


@dataclass
class ConversationContext:
    """Holds the full context window for an interactive AI session."""

    entity_type: str
    entity_id: str
    entity_data: dict
    related_controls: list[dict] = field(default_factory=list)
    related_findings: list[dict] = field(default_factory=list)
    compliance_context: dict = field(default_factory=dict)
    messages: list[dict] = field(default_factory=list)
    session_id: str = ""
    created_at: datetime | None = None
    last_activity: datetime | None = None
