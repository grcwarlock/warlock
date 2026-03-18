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


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a cloud security compliance assessor. Given a security finding and a \
compliance control, evaluate whether the finding indicates compliance, \
non-compliance, or partial compliance with the control.

Respond ONLY with a JSON object (no markdown fences, no commentary):
{
  "status": "compliant" | "non_compliant" | "partial",
  "assessment": "<1-3 sentence narrative>",
  "confidence": <float 0.0-1.0>,
  "recommended_action": "<short remediation suggestion or empty string>"
}\
"""


def _build_user_prompt(finding: FindingData, mapping: ControlMappingData, raw_data: dict) -> str:
    return json.dumps({
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
        },
        "raw_data_sample": {k: v for k, v in list(raw_data.items())[:20]} if raw_data else {},
    }, indent=2, default=str)


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

    return AIReasoningResult(
        status=status,
        assessment=assessment,
        confidence=confidence,
        model=model,
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
    ) -> AIReasoningResult:
        raise NotImplementedError


class AnthropicReasoner(AIReasoner):

    def evaluate(self, finding: FindingData, mapping: ControlMappingData, raw_data: dict[str, Any]) -> AIReasoningResult:
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
            "messages": [{"role": "user", "content": _build_user_prompt(finding, mapping, raw_data)}],
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

    def evaluate(self, finding: FindingData, mapping: ControlMappingData, raw_data: dict[str, Any]) -> AIReasoningResult:
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
                {"role": "user", "content": _build_user_prompt(finding, mapping, raw_data)},
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

    def evaluate(self, finding: FindingData, mapping: ControlMappingData, raw_data: dict[str, Any]) -> AIReasoningResult:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "system_instruction": {"parts": [{"text": _SYSTEM_PROMPT}]},
            "contents": [{"parts": [{"text": _build_user_prompt(finding, mapping, raw_data)}]}],
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

    def evaluate(self, finding: FindingData, mapping: ControlMappingData, raw_data: dict[str, Any]) -> AIReasoningResult:
        url = f"{self.base_url or 'http://localhost:11434'}/v1/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_prompt(finding, mapping, raw_data)},
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
