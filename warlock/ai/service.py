"""Unified AI service.

Single entry-point for every AI capability in the platform.  Wraps the
existing ``ai_reasoning.create_reasoner()`` for compliance assessment
and talks directly to providers via ``httpx`` for all other task types.

No new external dependencies.  No changes to existing files.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Callable, TypeVar

import httpx

from warlock.ai.sanitize import hash_prompt, strip_secrets, wrap_evidence
from warlock.ai.types import (
    AIResult,
    AITask,
    ConversationContext,
    DiscoveryResult,
    ModelInfo,
    TokenUsage,
)

log = logging.getLogger(__name__)

T = TypeVar("T")

TIMEOUT = 60.0

# ---------------------------------------------------------------------------
# Task prompt registry
# ---------------------------------------------------------------------------
# Each non-COMPLIANCE_ASSESSMENT task has a system prompt.  These are
# intentionally short placeholders for Phase 0 -- the full prompt
# engineering work happens in Phase 1 when each feature is wired up.

_TASK_PROMPTS: dict[AITask, str] = {
    AITask.QUESTIONNAIRE_RESPONSE: (
        "You are a GRC compliance expert.  Given a security questionnaire "
        "question and the organization's compliance data, draft a professional "
        "response.  Respond with JSON: {\"response\": \"<answer>\"}."
    ),
    AITask.GOVERNANCE_ANALYSIS: (
        "You are a governance analyst.  Given organizational governance data, "
        "identify gaps and provide actionable recommendations.  "
        "Respond with JSON: {\"analysis\": \"<text>\", \"recommendations\": [\"...\"]}"
    ),
    AITask.REMEDIATION_GUIDANCE: (
        "You are a cloud security remediation expert.  Given a non-compliant "
        "finding and its environment context, provide specific, actionable "
        "remediation steps.  Respond with JSON: {\"guidance\": \"<text>\", \"steps\": [\"...\"]}"
    ),
    AITask.RISK_NARRATIVE: (
        "You are a risk analyst.  Given quantitative risk data (Monte Carlo "
        "outputs, ALE, VaR), write a concise executive-level narrative that "
        "explains what the numbers mean in business terms.  "
        "Respond with JSON: {\"narrative\": \"<text>\"}"
    ),
    AITask.SSP_NARRATIVE: (
        "You are a FedRAMP documentation specialist.  Given control "
        "implementation data, write a System Security Plan narrative suitable "
        "for an SSP appendix.  Respond with JSON: {\"narrative\": \"<text>\"}"
    ),
    AITask.CIS_NARRATIVE: (
        "You are a CIS Benchmarks expert.  Given a CIS control and its "
        "assessment results, write a concise compliance narrative.  "
        "Respond with JSON: {\"narrative\": \"<text>\"}"
    ),
    AITask.POLICY_REVIEW: (
        "You are a security policy analyst.  Given an organizational policy "
        "document and a set of compliance controls, assess whether the policy "
        "adequately addresses each control requirement.  "
        "Respond with JSON: {\"review\": \"<text>\", \"gaps\": [\"...\"]}"
    ),
    AITask.VENDOR_RISK_ANALYSIS: (
        "You are a third-party risk analyst.  Given a vendor's risk profile "
        "and compliance posture, assess the risk and recommend mitigations.  "
        "Respond with JSON: {\"analysis\": \"<text>\", \"risk_level\": \"<low|medium|high|critical>\"}"
    ),
    AITask.DRIFT_EXPLANATION: (
        "You are a compliance drift analyst.  Given a compliance drift event "
        "and correlated change events, explain the root cause and impact.  "
        "Respond with JSON: {\"explanation\": \"<text>\", \"root_cause\": \"<text>\"}"
    ),
    AITask.ISSUE_TRIAGE: (
        "You are a GRC issue triage specialist.  Given a set of compliance "
        "issues, prioritize them and explain your reasoning.  "
        "Respond with JSON: {\"triage\": [{\"issue_id\": \"...\", \"priority\": \"...\", \"reason\": \"...\"}]}"
    ),
    AITask.FOLLOW_UP: (
        "You are a GRC compliance assistant.  Continue the conversation, "
        "answering the user's follow-up question using the provided compliance "
        "context.  Respond with JSON: {\"response\": \"<text>\"}"
    ),
    AITask.EVIDENCE_EVALUATION: (
        "You are a compliance evidence evaluator.  Given evidence artifacts "
        "and their associated control requirements, assess whether the evidence "
        "is sufficient, current, and relevant.  "
        "Respond with JSON: {\"evaluation\": \"<text>\", \"sufficient\": true|false}"
    ),
    AITask.EXECUTIVE_REPORT: (
        "You are a GRC reporting specialist.  Given compliance posture data "
        "across multiple frameworks, write a concise executive summary suitable "
        "for board-level reporting.  "
        "Respond with JSON: {\"report\": \"<text>\"}"
    ),
    AITask.AUDIT_READINESS: (
        "You are an audit readiness advisor.  Given the current compliance "
        "posture, open issues, and evidence gaps, assess audit readiness and "
        "recommend preparation steps.  "
        "Respond with JSON: {\"readiness_score\": 0.0, \"assessment\": \"<text>\", \"actions\": [\"...\"]}"
    ),
}


# ---------------------------------------------------------------------------
# Provider HTTP helpers  (mirrors ai_reasoning.py patterns)
# ---------------------------------------------------------------------------


def _call_anthropic(
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    temperature: float,
    max_tokens: int,
    base_url: str,
) -> tuple[str, TokenUsage | None]:
    """Send a completion request to the Anthropic Messages API."""
    url = f"{base_url}/v1/messages" if base_url else "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_prompt}],
    }
    resp = httpx.post(url, headers=headers, json=payload, timeout=TIMEOUT)
    resp.raise_for_status()
    body = resp.json()
    text = body["content"][0]["text"]
    usage = body.get("usage")
    token_usage = None
    if usage:
        token_usage = TokenUsage(
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
        )
    return text, token_usage


def _call_openai_compat(
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    temperature: float,
    max_tokens: int,
    base_url: str,
) -> tuple[str, TokenUsage | None]:
    """Send a completion request to an OpenAI-compatible API (OpenAI, Ollama, vLLM)."""
    url = f"{base_url}/v1/chat/completions" if base_url else "https://api.openai.com/v1/chat/completions"
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    payload: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    resp = httpx.post(url, headers=headers, json=payload, timeout=TIMEOUT)
    resp.raise_for_status()
    body = resp.json()
    text = body["choices"][0]["message"]["content"]
    usage = body.get("usage")
    token_usage = None
    if usage:
        token_usage = TokenUsage(
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
        )
    return text, token_usage


def _call_gemini(
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    temperature: float,
    max_tokens: int,
    base_url: str,
) -> tuple[str, TokenUsage | None]:
    """Send a completion request to the Gemini API."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    headers = {"x-goog-api-key": api_key}
    payload = {
        "system_instruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"parts": [{"text": user_prompt}]}],
        "generationConfig": {"maxOutputTokens": max_tokens, "temperature": temperature},
    }
    resp = httpx.post(url, headers=headers, json=payload, timeout=TIMEOUT)
    resp.raise_for_status()
    body = resp.json()
    text = body["candidates"][0]["content"]["parts"][0]["text"]
    usage_meta = body.get("usageMetadata")
    token_usage = None
    if usage_meta:
        token_usage = TokenUsage(
            input_tokens=usage_meta.get("promptTokenCount", 0),
            output_tokens=usage_meta.get("candidatesTokenCount", 0),
        )
    return text, token_usage


# Provider dispatcher
_PROVIDER_CALLERS = {
    "anthropic": _call_anthropic,
    "openai": _call_openai_compat,
    "ollama": _call_openai_compat,
}


# ---------------------------------------------------------------------------
# Conversation store (in-memory, per-process)
# ---------------------------------------------------------------------------

_conversations: dict[str, list[dict[str, str]]] = {}


# ---------------------------------------------------------------------------
# Model discovery helpers
# ---------------------------------------------------------------------------


def _discover_models_openai_compat(
    api_key: str, base_url: str
) -> DiscoveryResult:
    """List models from an OpenAI-compatible ``/v1/models`` endpoint."""
    url = f"{base_url}/v1/models" if base_url else "https://api.openai.com/v1/models"
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        resp = httpx.get(url, headers=headers, timeout=15.0)
        resp.raise_for_status()
        body = resp.json()
        models = [
            ModelInfo(
                id=m["id"],
                display_name=m.get("id", ""),
                verified=True,
            )
            for m in body.get("data", [])
        ]
        return DiscoveryResult(connected=True, models=models)
    except Exception as exc:
        log.warning("Model discovery failed: %s", exc)
        return DiscoveryResult(connected=False, error=str(exc))


def _discover_models_anthropic(api_key: str) -> DiscoveryResult:
    """Return a static list of known Anthropic models (no discovery endpoint)."""
    known = [
        ModelInfo(id="claude-sonnet-4-20250514", display_name="Claude Sonnet 4", verified=True),
        ModelInfo(id="claude-opus-4-20250514", display_name="Claude Opus 4", verified=True),
        ModelInfo(id="claude-3-5-haiku-20241022", display_name="Claude 3.5 Haiku", verified=True),
    ]
    return DiscoveryResult(connected=bool(api_key), models=known)


def _discover_models_gemini(api_key: str) -> DiscoveryResult:
    """List models from the Gemini API."""
    url = "https://generativelanguage.googleapis.com/v1beta/models"
    headers = {"x-goog-api-key": api_key}
    try:
        resp = httpx.get(url, headers=headers, timeout=15.0)
        resp.raise_for_status()
        body = resp.json()
        models = [
            ModelInfo(
                id=m.get("name", "").removeprefix("models/"),
                display_name=m.get("displayName", ""),
                verified=True,
            )
            for m in body.get("models", [])
            if "generateContent" in m.get("supportedGenerationMethods", [])
        ]
        return DiscoveryResult(connected=True, models=models)
    except Exception as exc:
        log.warning("Gemini model discovery failed: %s", exc)
        return DiscoveryResult(connected=False, error=str(exc))


# ---------------------------------------------------------------------------
# AIService
# ---------------------------------------------------------------------------


class AIService:
    """Unified AI service for the Warlock GRC platform.

    Provides a single ``reason()`` entry-point that handles provider
    selection, prompt construction, fallback logic, and result
    normalization.  For compliance assessment it delegates to the
    existing ``create_reasoner()`` factory so that current behavior is
    preserved exactly.

    Parameters
    ----------
    settings:
        A ``warlock.config.Settings`` instance (or compatible object).
    """

    def __init__(self, settings: Any) -> None:
        self._settings = settings
        self._provider: str = getattr(settings, "ai_provider", "")
        self._api_key: str = getattr(settings, "ai_api_key", "")
        self._model: str = getattr(settings, "ai_model", "")
        self._base_url: str = getattr(settings, "ai_base_url", "")
        self._temperature: float = getattr(settings, "ai_temperature", 0.0)
        self._max_tokens: int = getattr(settings, "ai_max_tokens", 1024)
        self._confidence_floor: float = getattr(settings, "ai_confidence_floor", 0.7)
        self._configured: bool = bool(self._provider and self._api_key)

    # -- availability -------------------------------------------------------

    def is_available(self) -> bool:
        """Return ``True`` if AI is configured and the master toggle is on."""
        enabled = getattr(self._settings, "ai_enabled", True)
        return bool(enabled and self._configured)

    def is_task_enabled(self, task: AITask) -> bool:
        """Check whether a specific AI task type is enabled.

        If ``ai_enhanced_features`` is empty, all tasks are enabled when
        AI is on.  If it contains specific task names, only those are
        enabled.
        """
        if not self.is_available():
            return False
        features: list[str] = getattr(self._settings, "ai_enhanced_features", [])
        if not features:
            return True
        return task.value in features

    # -- core reasoning -----------------------------------------------------

    def reason(
        self,
        task: AITask,
        context: dict[str, Any],
        fallback: Callable[[], T] | None = None,
    ) -> AIResult:
        """Execute an AI reasoning task with automatic fallback.

        For ``COMPLIANCE_ASSESSMENT``, delegates to the existing
        ``create_reasoner()`` in ``warlock.assessors.ai_reasoning`` so
        that current behavior is preserved.

        For all other tasks, uses the task prompt registry and calls the
        configured provider directly.

        Parameters
        ----------
        task:
            Which AI capability to invoke.
        context:
            Task-specific data dict.  For ``COMPLIANCE_ASSESSMENT`` this
            must include ``finding``, ``mapping``, ``raw_data``, and
            optionally ``compliance_context``.  For other tasks it is
            serialized as evidence.
        fallback:
            Zero-argument callable returning a default value when AI is
            unavailable or fails.
        """
        if not self.is_task_enabled(task):
            return AIResult(
                value=fallback() if fallback else None,
                ai_used=False,
                confidence=0.0,
                model="none",
                provider="fallback",
                prompt_hash="",
                latency_ms=0,
                fallback_reason="task_disabled",
            )

        try:
            if task == AITask.COMPLIANCE_ASSESSMENT:
                return self._reason_compliance(context)
            return self._reason_generic(task, context)
        except Exception as exc:
            log.exception("AI call failed for task %s", task.value)
            if fallback is not None:
                return AIResult(
                    value=fallback(),
                    ai_used=False,
                    confidence=0.0,
                    model=self._model,
                    provider=self._provider,
                    prompt_hash="",
                    latency_ms=0,
                    fallback_reason=f"AI call failed: {exc}",
                )
            raise

    # -- batch --------------------------------------------------------------

    async def reason_batch(
        self,
        tasks: list[tuple[AITask, dict[str, Any], Callable[[], Any] | None]],
        concurrency: int = 10,
    ) -> list[AIResult]:
        """Execute multiple reasoning tasks concurrently.

        Each element in *tasks* is a ``(task, context, fallback)`` tuple
        matching the ``reason()`` signature.

        Parameters
        ----------
        tasks:
            List of (AITask, context_dict, fallback_callable) tuples.
        concurrency:
            Maximum number of concurrent AI calls.
        """
        sem = asyncio.Semaphore(concurrency)

        async def _run(
            task: AITask,
            ctx: dict[str, Any],
            fb: Callable[[], Any] | None,
        ) -> AIResult:
            async with sem:
                loop = asyncio.get_running_loop()
                return await loop.run_in_executor(None, self.reason, task, ctx, fb)

        coros = [_run(t, c, f) for t, c, f in tasks]
        return list(await asyncio.gather(*coros))

    # -- conversation -------------------------------------------------------

    def converse(
        self,
        session_id: str,
        message: str,
        context: ConversationContext | None = None,
    ) -> AIResult:
        """Interactive follow-up conversation.

        Maintains an in-memory message history keyed by *session_id*.

        Parameters
        ----------
        session_id:
            Unique conversation identifier.
        message:
            The user's follow-up message.
        context:
            Optional structured context for the conversation.
        """
        if not self.is_task_enabled(AITask.FOLLOW_UP):
            return AIResult(
                value=None,
                ai_used=False,
                confidence=0.0,
                model="none",
                provider="fallback",
                prompt_hash="",
                latency_ms=0,
                fallback_reason="follow_up_disabled",
            )

        history = _conversations.setdefault(session_id, [])
        history.append({"role": "user", "content": message})

        system_prompt = _TASK_PROMPTS[AITask.FOLLOW_UP]

        # Build user prompt with context
        ctx_data: dict[str, Any] = {}
        if context is not None:
            ctx_data = strip_secrets({
                "entity_type": context.entity_type,
                "entity_id": context.entity_id,
                "entity_data": context.entity_data,
                "related_controls": context.related_controls,
                "related_findings": context.related_findings,
                "compliance_context": context.compliance_context,
            })
        user_prompt = wrap_evidence(ctx_data) if ctx_data else ""
        user_prompt += f"\n\nConversation so far:\n{json.dumps(history, default=str)}"

        prompt_h = hash_prompt(system_prompt, user_prompt)

        try:
            start = time.monotonic()
            text, token_usage = self._call_provider(system_prompt, user_prompt)
            elapsed_ms = int((time.monotonic() - start) * 1000)

            history.append({"role": "assistant", "content": text})

            return AIResult(
                value=text,
                ai_used=True,
                confidence=1.0,
                model=self._model,
                provider=self._provider,
                prompt_hash=prompt_h,
                latency_ms=elapsed_ms,
                fallback_reason="",
                token_usage=token_usage,
            )
        except Exception as exc:
            log.exception("Converse call failed for session %s", session_id)
            return AIResult(
                value=None,
                ai_used=False,
                confidence=0.0,
                model=self._model,
                provider=self._provider,
                prompt_hash=prompt_h,
                latency_ms=0,
                fallback_reason=f"AI call failed: {exc}",
            )

    # -- model discovery ----------------------------------------------------

    def list_models(self) -> list[ModelInfo]:
        """Discover available models for the configured provider.

        Returns an empty list if the provider is unknown or unreachable.
        """
        if self._provider in ("openai", "ollama"):
            result = _discover_models_openai_compat(self._api_key, self._base_url)
        elif self._provider == "anthropic":
            result = _discover_models_anthropic(self._api_key)
        elif self._provider == "gemini":
            result = _discover_models_gemini(self._api_key)
        else:
            log.warning("Unknown provider for model discovery: %s", self._provider)
            return []
        if not result.connected:
            log.warning("Model discovery failed: %s", result.error)
        return result.models

    # -- internals ----------------------------------------------------------

    def _reason_compliance(self, context: dict[str, Any]) -> AIResult:
        """Delegate to the existing ``create_reasoner()`` for compliance assessment."""
        from warlock.assessors.ai_reasoning import create_reasoner, ComplianceContext

        reasoner = create_reasoner(
            provider=self._provider,
            api_key=self._api_key,
            model=self._model,
            base_url=self._base_url,
        )

        finding = context["finding"]
        mapping = context["mapping"]
        raw_data = context.get("raw_data", {})
        compliance_ctx = context.get("compliance_context")

        # Convert dict to ComplianceContext if needed
        if isinstance(compliance_ctx, dict):
            compliance_ctx = ComplianceContext(**compliance_ctx)

        start = time.monotonic()
        result = reasoner.evaluate(finding, mapping, raw_data, compliance_ctx)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        return AIResult(
            value=result,
            ai_used=True,
            confidence=result.confidence,
            model=result.model,
            provider=self._provider,
            prompt_hash=result.prompt_hash,
            latency_ms=elapsed_ms,
            fallback_reason="",
        )

    def _reason_generic(self, task: AITask, context: dict[str, Any]) -> AIResult:
        """Call the configured provider with the task's registered prompt."""
        system_prompt = _TASK_PROMPTS.get(task)
        if system_prompt is None:
            raise ValueError(f"No prompt registered for task: {task.value}")

        user_prompt = wrap_evidence(strip_secrets(context))
        prompt_h = hash_prompt(system_prompt, user_prompt)

        start = time.monotonic()
        text, token_usage = self._call_provider(system_prompt, user_prompt)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        # Try to parse JSON response; fall back to raw text
        value: Any = text
        try:
            value = json.loads(text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip())
        except (json.JSONDecodeError, ValueError):
            pass

        return AIResult(
            value=value,
            ai_used=True,
            confidence=1.0,
            model=self._model,
            provider=self._provider,
            prompt_hash=prompt_h,
            latency_ms=elapsed_ms,
            fallback_reason="",
            token_usage=token_usage,
        )

    def _call_provider(
        self, system_prompt: str, user_prompt: str
    ) -> tuple[str, TokenUsage | None]:
        """Dispatch to the correct provider HTTP helper."""
        caller = _PROVIDER_CALLERS.get(self._provider)
        if caller is None:
            if self._provider == "gemini":
                return _call_gemini(
                    api_key=self._api_key,
                    model=self._model,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    temperature=self._temperature,
                    max_tokens=self._max_tokens,
                    base_url=self._base_url,
                )
            raise ValueError(
                f"Unknown AI provider: {self._provider!r}. "
                f"Supported: anthropic, openai, ollama, gemini"
            )
        return caller(
            api_key=self._api_key,
            model=self._model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
            base_url=self._base_url,
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_instance: AIService | None = None


def get_ai_service() -> AIService:
    """Return the module-level ``AIService`` singleton.

    Lazily creates the instance on first call using the global
    ``Settings`` from ``warlock.config``.
    """
    global _instance
    if _instance is None:
        from warlock.config import get_settings

        _instance = AIService(get_settings())
    return _instance
