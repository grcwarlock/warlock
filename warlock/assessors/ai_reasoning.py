"""Tier 2 — AI Reasoning.

Uses an LLM to evaluate a finding against a compliance control when
Tier 1 deterministic assertions are unavailable or inconclusive.

Supports: anthropic, openai, gemini, ollama.
All calls go through httpx — no vendor SDKs required.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

import httpx

from warlock.mappers.control_mapper import ControlMappingData
from warlock.normalizers.base import FindingData

log = logging.getLogger(__name__)

TIMEOUT = 60.0

# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class AIReasoningResult:
    status: str                # compliant, non_compliant, partial, not_assessed
    assessment: str            # narrative explanation
    confidence: float          # 0.0 – 1.0
    model: str
    context_factors: list[str] = None  # what context influenced the assessment

    def __post_init__(self):
        if self.context_factors is None:
            self.context_factors = []


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a cloud security compliance assessor with deep GRC expertise. Given a \
security finding, a compliance control, and the broader compliance context \
(including compensating controls, risk acceptances, control inheritance, \
posture trends, and monitoring cadence), evaluate whether the finding \
indicates compliance, non-compliance, or partial compliance with the control.

Important context rules:
- If an active COMPENSATING CONTROL exists, the control may be "partial" even \
if the primary finding is non-compliant. Factor the compensating control's \
effectiveness score into your confidence.
- If an active RISK ACCEPTANCE exists, note it but still assess the technical \
compliance status — risk acceptance is a business decision, not a technical one.
- If the control is INHERITED from a provider system, assess based on the \
provider's compliance status and the evidence requirement (provider_only, \
consumer_only, both).
- Consider POSTURE TRENDS: a control that was recently compliant but just \
drifted is different from one that has been non-compliant for months.
- Consider MONITORING CADENCE: stale evidence reduces confidence.

Respond ONLY with a JSON object (no markdown fences, no commentary):
{
  "status": "compliant" | "non_compliant" | "partial",
  "assessment": "<1-3 sentence narrative referencing the relevant context>",
  "confidence": <float 0.0-1.0>,
  "recommended_action": "<short remediation suggestion or empty string>",
  "context_factors": ["<list of context factors that influenced the assessment>"]
}\
"""


@dataclass
class ComplianceContext:
    """Broader compliance context for AI reasoning — Phase 2-5 data."""
    compensating_control: dict | None = None   # active CC if any
    risk_acceptance: dict | None = None        # active RA if any
    inheritance: dict | None = None            # inheritance info if any
    posture_trend: dict | None = None          # recent trend data
    cadence_status: dict | None = None         # monitoring freshness
    drift_history: list | None = None          # recent drift events
    system_context: dict | None = None         # system profile info


def _build_user_prompt(
    finding: FindingData,
    mapping: ControlMappingData,
    raw_data: dict,
    context: ComplianceContext | None = None,
) -> str:
    prompt_data = {
        "finding": {
            "title": finding.title,
            "observation_type": finding.observation_type,
            "severity": finding.severity,
            "resource_type": finding.resource_type,
            "resource_id": finding.resource_id,
            "detail": finding.detail,
        },
        "control": {
            "framework": mapping.framework,
            "control_id": mapping.control_id,
            "control_family": mapping.control_family,
            "mapping_method": mapping.mapping_method,
            "monitoring_frequency": mapping.monitoring_frequency,
        },
        "raw_data_sample": {k: v for k, v in list(raw_data.items())[:20]} if raw_data else {},
    }

    # Add Phase 2-5 context if available
    if context:
        compliance_context = {}
        if context.compensating_control:
            compliance_context["compensating_control"] = context.compensating_control
        if context.risk_acceptance:
            compliance_context["risk_acceptance"] = context.risk_acceptance
        if context.inheritance:
            compliance_context["inheritance"] = context.inheritance
        if context.posture_trend:
            compliance_context["posture_trend"] = context.posture_trend
        if context.cadence_status:
            compliance_context["cadence_status"] = context.cadence_status
        if context.drift_history:
            compliance_context["recent_drift"] = context.drift_history[:5]
        if context.system_context:
            compliance_context["system"] = context.system_context
        if compliance_context:
            prompt_data["compliance_context"] = compliance_context

    return json.dumps(prompt_data, indent=2, default=str)


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

_VALID_STATUSES = {"compliant", "non_compliant", "partial", "not_assessed"}


def _parse_response(text: str, model: str) -> AIReasoningResult:
    """Extract JSON from the LLM response text."""
    text = text.strip()
    # Strip markdown code fences if present
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3].strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        log.warning("AI response was not valid JSON: %.200s", text)
        return AIReasoningResult(
            status="not_assessed",
            assessment=f"AI returned unparseable response: {text[:200]}",
            confidence=0.0,
            model=model,
        )

    status = data.get("status", "not_assessed")
    if status not in _VALID_STATUSES:
        status = "not_assessed"

    confidence = float(data.get("confidence", 0.0))
    confidence = max(0.0, min(1.0, confidence))

    assessment = data.get("assessment", "")
    action = data.get("recommended_action", "")
    if action:
        assessment = f"{assessment} Recommended: {action}"

    context_factors = data.get("context_factors", [])
    if not isinstance(context_factors, list):
        context_factors = []

    return AIReasoningResult(
        status=status,
        assessment=assessment,
        confidence=confidence,
        model=model,
        context_factors=context_factors,
    )


# ---------------------------------------------------------------------------
# Provider implementations
# ---------------------------------------------------------------------------

class AIReasoner:
    """Base class for AI reasoning providers."""

    def __init__(self, api_key: str, model: str, base_url: str = "") -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url

    def evaluate(
        self,
        finding: FindingData,
        mapping: ControlMappingData,
        raw_data: dict[str, Any],
        context: ComplianceContext | None = None,
    ) -> AIReasoningResult:
        raise NotImplementedError


class AnthropicReasoner(AIReasoner):

    def evaluate(self, finding: FindingData, mapping: ControlMappingData, raw_data: dict[str, Any], context: ComplianceContext | None = None) -> AIReasoningResult:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": self.model,
            "max_tokens": 1024,
            "system": _SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": _build_user_prompt(finding, mapping, raw_data, context)}],
        }
        try:
            resp = httpx.post(url, headers=headers, json=payload, timeout=TIMEOUT)
            resp.raise_for_status()
            body = resp.json()
            text = body["content"][0]["text"]
            return _parse_response(text, self.model)
        except Exception as e:
            log.exception("Anthropic API call failed")
            return AIReasoningResult(status="not_assessed", assessment=f"AI error: {e}", confidence=0.0, model=self.model)


class OpenAIReasoner(AIReasoner):

    def evaluate(self, finding: FindingData, mapping: ControlMappingData, raw_data: dict[str, Any], context: ComplianceContext | None = None) -> AIReasoningResult:
        url = f"{self.base_url or 'https://api.openai.com'}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "max_tokens": 1024,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_prompt(finding, mapping, raw_data, context)},
            ],
        }
        try:
            resp = httpx.post(url, headers=headers, json=payload, timeout=TIMEOUT)
            resp.raise_for_status()
            body = resp.json()
            text = body["choices"][0]["message"]["content"]
            return _parse_response(text, self.model)
        except Exception as e:
            log.exception("OpenAI API call failed")
            return AIReasoningResult(status="not_assessed", assessment=f"AI error: {e}", confidence=0.0, model=self.model)


class GeminiReasoner(AIReasoner):

    def evaluate(self, finding: FindingData, mapping: ControlMappingData, raw_data: dict[str, Any], context: ComplianceContext | None = None) -> AIReasoningResult:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "system_instruction": {"parts": [{"text": _SYSTEM_PROMPT}]},
            "contents": [{"parts": [{"text": _build_user_prompt(finding, mapping, raw_data, context)}]}],
            "generationConfig": {"maxOutputTokens": 1024},
        }
        try:
            resp = httpx.post(url, json=payload, timeout=TIMEOUT)
            resp.raise_for_status()
            body = resp.json()
            text = body["candidates"][0]["content"]["parts"][0]["text"]
            return _parse_response(text, self.model)
        except Exception as e:
            log.exception("Gemini API call failed")
            return AIReasoningResult(status="not_assessed", assessment=f"AI error: {e}", confidence=0.0, model=self.model)


class OllamaReasoner(AIReasoner):
    """Ollama exposes an OpenAI-compatible endpoint."""

    def evaluate(self, finding: FindingData, mapping: ControlMappingData, raw_data: dict[str, Any], context: ComplianceContext | None = None) -> AIReasoningResult:
        url = f"{self.base_url or 'http://localhost:11434'}/v1/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_prompt(finding, mapping, raw_data, context)},
            ],
        }
        try:
            resp = httpx.post(url, headers=headers, json=payload, timeout=TIMEOUT)
            resp.raise_for_status()
            body = resp.json()
            text = body["choices"][0]["message"]["content"]
            return _parse_response(text, self.model)
        except Exception as e:
            log.exception("Ollama API call failed")
            return AIReasoningResult(status="not_assessed", assessment=f"AI error: {e}", confidence=0.0, model=self.model)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_PROVIDERS: dict[str, type[AIReasoner]] = {
    "anthropic": AnthropicReasoner,
    "openai": OpenAIReasoner,
    "gemini": GeminiReasoner,
    "ollama": OllamaReasoner,
}


def create_reasoner(provider: str, api_key: str, model: str, base_url: str = "") -> AIReasoner:
    """Create an AIReasoner for the given provider."""
    cls = _PROVIDERS.get(provider)
    if cls is None:
        raise ValueError(f"Unknown AI provider: {provider!r}. Supported: {', '.join(_PROVIDERS)}")
    return cls(api_key=api_key, model=model, base_url=base_url)


# ---------------------------------------------------------------------------
# Context builder — gathers Phase 2-5 data for AI reasoning
# ---------------------------------------------------------------------------


def build_compliance_context(
    session: Any,
    framework: str,
    control_id: str,
    system_profile_id: str | None = None,
) -> ComplianceContext:
    """Gather compensating controls, risk acceptances, inheritance, trends,
    cadence, and drift for a control to provide to the AI reasoner.

    This is optional — if called, it enriches the AI prompt with the full
    compliance picture. If not called, the AI falls back to finding-only reasoning.
    """
    from warlock.db.models import (
        CompensatingControl, RiskAcceptance, ControlInheritance,
        ComplianceDrift, PostureSnapshot, SystemProfile,
    )
    from datetime import timedelta, timezone
    from datetime import datetime

    ctx = ComplianceContext()
    now = datetime.now(timezone.utc)

    # Compensating controls
    cc = (
        session.query(CompensatingControl)
        .filter(
            CompensatingControl.original_framework == framework,
            CompensatingControl.original_control_id == control_id,
            CompensatingControl.status == "active",
        )
        .first()
    )
    if cc:
        ctx.compensating_control = {
            "title": cc.title,
            "description": cc.description,
            "effectiveness_score": cc.effectiveness_score,
            "expiry_date": cc.expiry_date.isoformat() if cc.expiry_date else None,
            "review_frequency": cc.review_frequency,
        }

    # Risk acceptance
    ra = (
        session.query(RiskAcceptance)
        .filter(
            RiskAcceptance.framework == framework,
            RiskAcceptance.control_id == control_id,
            RiskAcceptance.status == "active",
            RiskAcceptance.expiry_date > now,
        )
        .first()
    )
    if ra:
        ctx.risk_acceptance = {
            "risk_level": ra.risk_level,
            "residual_risk_level": ra.residual_risk_level,
            "conditions": ra.conditions,
            "expiry_date": ra.expiry_date.isoformat() if ra.expiry_date else None,
            "approved_by": ra.approved_by,
        }

    # Inheritance (if system scoped)
    if system_profile_id:
        ci = (
            session.query(ControlInheritance)
            .filter(
                ControlInheritance.system_profile_id == system_profile_id,
                ControlInheritance.framework == framework,
                ControlInheritance.control_id == control_id,
            )
            .first()
        )
        if ci:
            ctx.inheritance = {
                "type": ci.inheritance_type,
                "provider_system_id": ci.provider_system_id,
                "provider_description": ci.provider_description,
                "responsibility_description": ci.responsibility_description,
                "evidence_requirement": ci.evidence_requirement,
            }

        # System context
        sp = session.query(SystemProfile).filter_by(id=system_profile_id).first()
        if sp:
            ctx.system_context = {
                "name": sp.name,
                "acronym": sp.acronym,
                "impact_level": sp.overall_impact,
                "deployment_model": sp.deployment_model,
                "authorization_status": sp.authorization_status,
            }

    # Posture trend (last 5 snapshots)
    snapshots = (
        session.query(PostureSnapshot)
        .filter(
            PostureSnapshot.framework == framework,
            PostureSnapshot.control_id == control_id,
        )
        .order_by(PostureSnapshot.snapshot_date.desc())
        .limit(5)
        .all()
    )
    if snapshots:
        ctx.posture_trend = {
            "latest_score": snapshots[0].posture_score,
            "latest_status": snapshots[0].status,
            "history": [
                {"date": s.snapshot_date.isoformat(), "score": s.posture_score, "status": s.status}
                for s in snapshots
            ],
        }

    # Cadence status
    from warlock.db.models import ControlMapping
    from sqlalchemy import func, distinct
    from warlock.db.models import ControlResult
    freq_row = (
        session.query(ControlMapping.monitoring_frequency)
        .filter(
            ControlMapping.framework == framework,
            ControlMapping.control_id == control_id,
            ControlMapping.monitoring_frequency.isnot(None),
        )
        .first()
    )
    latest_evidence = (
        session.query(func.max(ControlResult.assessed_at))
        .filter(
            ControlResult.framework == framework,
            ControlResult.control_id == control_id,
        )
        .scalar()
    )
    if freq_row and latest_evidence:
        frequency = freq_row[0]
        freq_hours = {"daily": 24, "weekly": 168, "monthly": 720, "quarterly": 2160, "annual": 8760}.get(frequency, 720)
        if latest_evidence.tzinfo is None:
            latest_evidence = latest_evidence.replace(tzinfo=timezone.utc)
        hours_since = (now - latest_evidence).total_seconds() / 3600
        ctx.cadence_status = {
            "required_frequency": frequency,
            "hours_since_last_evidence": round(hours_since, 1),
            "is_stale": hours_since > freq_hours,
            "staleness_ratio": round(hours_since / freq_hours, 2) if freq_hours > 0 else 0,
        }

    # Recent drift events
    drifts = (
        session.query(ComplianceDrift)
        .filter(
            ComplianceDrift.framework == framework,
            ComplianceDrift.control_id == control_id,
            ComplianceDrift.detected_at >= now - timedelta(days=30),
        )
        .order_by(ComplianceDrift.detected_at.desc())
        .limit(5)
        .all()
    )
    if drifts:
        ctx.drift_history = [
            {
                "direction": d.drift_direction,
                "from": d.previous_status,
                "to": d.new_status,
                "detected_at": d.detected_at.isoformat() if d.detected_at else None,
                "correlated_changes": len(d.correlated_change_event_ids or []),
            }
            for d in drifts
        ]

    return ctx
