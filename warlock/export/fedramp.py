"""FedRAMP package generation: SSP template, CRM, CIS, and ConMon plan.

Produces structured dicts suitable for JSON serialisation or further
rendering into FedRAMP Appendix documents.

Async parallel AI assessment
-----------------------------
Use :meth:`FedRAMPPackageGenerator.generate_ssp_template_parallel` (or
:meth:`generate_cis_parallel`) to fan-out AI assessment calls across all
controls that lack an existing ``ai_assessment``.  Concurrency is bounded by
``asyncio.Semaphore(10)`` to stay within typical provider rate limits.  Each
provider call is attempted up to **2 times** with a **30-second** per-attempt
timeout.  A failed call degrades gracefully — the control keeps whatever
evidence text already existed rather than blocking the whole export.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml
from sqlalchemy.orm import Session

from warlock.db.models import (
    ControlInheritance,
    ControlMapping,
    ControlResult,
    SystemProfile,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Async AI assessment constants
# ---------------------------------------------------------------------------

_AI_TIMEOUT = 30.0       # seconds per attempt
_AI_RETRIES = 2          # total attempts (1 initial + 1 retry)
_AI_CONCURRENCY = 10     # semaphore width

_AI_SYSTEM_PROMPT = """\
You are a FedRAMP compliance assessor. Given a control ID, control title, and \
evidence snippets from the pipeline, write a concise 2-3 sentence implementation \
statement describing how the system addresses the control. \
Be specific, reference the evidence, and avoid generic boilerplate. \
Respond with plain text only — no JSON, no markdown.\
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FRAMEWORKS_DIR = Path(__file__).resolve().parent.parent / "frameworks"


def _load_framework_yaml(framework_id: str) -> dict[str, Any]:
    """Load a framework YAML from the frameworks directory."""
    path = _FRAMEWORKS_DIR / f"{framework_id}.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"Framework YAML not found: {path}")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _iter_controls(config: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    """Yield (family_id, control_id, control_dict) from framework YAML."""
    results: list[tuple[str, str, dict[str, Any]]] = []
    for family_id, family in config.get("control_families", {}).items():
        for control_id, control in family.get("controls", {}).items():
            results.append((family_id, control_id, control))
    return results


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Status aggregation
# ---------------------------------------------------------------------------

_STATUS_PRIORITY = {
    "non_compliant": 0,
    "partial": 1,
    "not_assessed": 2,
    "compliant": 3,
    "not_applicable": 4,
}


def _aggregate_status(statuses: list[str]) -> str:
    """Pick the worst-case status from a list."""
    if not statuses:
        return "not_assessed"
    return min(statuses, key=lambda s: _STATUS_PRIORITY.get(s, 2))


def _impl_label(status: str) -> str:
    return {
        "compliant": "Implemented",
        "partial": "Partially Implemented",
        "non_compliant": "Planned",
        "not_assessed": "Not Assessed",
        "not_applicable": "Not Applicable",
    }.get(status, "Not Assessed")


# ---------------------------------------------------------------------------
# Async AI assessment helper
# ---------------------------------------------------------------------------


def _build_ai_payload(
    provider: str,
    model: str,
    control_id: str,
    control_title: str,
    evidence_snippets: list[str],
) -> tuple[str, dict[str, str], dict[str, Any]]:
    """Return ``(url, headers, payload)`` for a one-shot assessment call.

    Mirrors the provider patterns from ``warlock.assessors.ai_reasoning``:
    Anthropic, OpenAI-compatible (OpenAI / Ollama), and Gemini.

    Args:
        provider: One of ``"anthropic"``, ``"openai"``, ``"gemini"``, ``"ollama"``.
        model: The model identifier string.
        control_id: FedRAMP control identifier, e.g. ``"AC-2"``.
        control_title: Human-readable control title.
        evidence_snippets: Short evidence strings already stored in the DB.

    Returns:
        A 3-tuple of ``(url, headers, payload)`` ready for ``httpx.AsyncClient.post``.

    Raises:
        ValueError: If *provider* is not one of the four supported values.
    """
    evidence_text = "\n".join(f"- {s}" for s in evidence_snippets[:10]) or "(no evidence)"
    user_msg = (
        f"Control: {control_id} — {control_title}\n\n"
        "Evidence from pipeline:\n"
        f"{evidence_text}\n\n"
        "Write the implementation statement."
    )

    if provider == "anthropic":
        url = "https://api.anthropic.com/v1/messages"
        headers: dict[str, str] = {
            "x-api-key": "",       # caller injects key
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": 512,
            "temperature": 0,
            "system": _AI_SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_msg}],
        }
    elif provider in ("openai", "ollama"):
        base = "https://api.openai.com" if provider == "openai" else "http://localhost:11434"
        url = f"{base}/v1/chat/completions"
        headers = {
            "Authorization": "",  # caller injects key
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "max_tokens": 512,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": _AI_SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
        }
    elif provider == "gemini":
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        headers = {"x-goog-api-key": ""}   # caller injects key
        payload = {
            "system_instruction": {"parts": [{"text": _AI_SYSTEM_PROMPT}]},
            "contents": [{"parts": [{"text": user_msg}]}],
            "generationConfig": {"maxOutputTokens": 512, "temperature": 0},
        }
    else:
        raise ValueError(
            f"Unsupported AI provider for parallel SSP export: {provider!r}. "
            "Expected one of: anthropic, openai, gemini, ollama."
        )

    return url, headers, payload


def _inject_api_key(
    provider: str,
    headers: dict[str, str],
    api_key: str,
    base_url: str,
) -> tuple[str, dict[str, str]]:
    """Mutate *headers* in-place with the real API key and return a possibly
    overridden URL for ollama/openai base_url customisation.

    Args:
        provider: Provider string.
        headers: Headers dict built by :func:`_build_ai_payload`.
        api_key: Secret key from config.
        base_url: Optional override URL (for Ollama / vLLM).

    Returns:
        The (possibly modified) URL as a string.  The *headers* dict is
        mutated in-place.
    """
    if provider == "anthropic":
        headers["x-api-key"] = api_key
    elif provider in ("openai", "ollama"):
        headers["Authorization"] = f"Bearer {api_key}" if api_key else ""
    elif provider == "gemini":
        headers["x-goog-api-key"] = api_key
    return base_url  # returned for completeness; callers may use it


async def _assess_control_async(
    client: httpx.AsyncClient,
    provider: str,
    model: str,
    api_key: str,
    base_url: str,
    control_id: str,
    control_title: str,
    evidence_snippets: list[str],
    semaphore: asyncio.Semaphore,
) -> tuple[str, str]:
    """Fetch an AI assessment for a single control, bounded by *semaphore*.

    Attempts up to :data:`_AI_RETRIES` times with a :data:`_AI_TIMEOUT`-second
    timeout per attempt.  On any unrecoverable failure the function returns an
    empty string so the caller can fall back to existing DB evidence.

    Args:
        client: Shared ``httpx.AsyncClient`` for connection re-use.
        provider: AI provider identifier.
        model: Model name string.
        api_key: API key for the provider.
        base_url: Optional base URL override (Ollama / vLLM).
        control_id: FedRAMP control identifier.
        control_title: Human-readable title for prompt construction.
        evidence_snippets: Existing evidence strings to include in the prompt.
        semaphore: Concurrency limiter shared across all tasks.

    Returns:
        A ``(control_id, assessment_text)`` tuple.  *assessment_text* is the
        empty string if every attempt failed.
    """
    try:
        url, headers, payload = _build_ai_payload(
            provider, model, control_id, control_title, evidence_snippets
        )
    except ValueError as exc:
        log.warning("_assess_control_async: %s — skipping %s", exc, control_id)
        return control_id, ""

    _inject_api_key(provider, headers, api_key, base_url)

    # Apply base_url override for ollama / custom openai deployments
    if base_url and provider in ("openai", "ollama"):
        url = f"{base_url.rstrip('/')}/v1/chat/completions"

    async with semaphore:
        for attempt in range(1, _AI_RETRIES + 1):
            try:
                resp = await client.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=_AI_TIMEOUT,
                    follow_redirects=True,
                )
                resp.raise_for_status()
                body = resp.json()

                # Extract text depending on provider response shape
                if provider == "anthropic":
                    text = body["content"][0]["text"].strip()
                elif provider in ("openai", "ollama"):
                    text = body["choices"][0]["message"]["content"].strip()
                elif provider == "gemini":
                    text = body["candidates"][0]["content"]["parts"][0]["text"].strip()
                else:
                    text = ""

                return control_id, text

            except (httpx.TimeoutException, httpx.HTTPStatusError, KeyError) as exc:
                if attempt < _AI_RETRIES:
                    log.debug(
                        "_assess_control_async: attempt %d/%d failed for %s: %s",
                        attempt, _AI_RETRIES, control_id, exc,
                    )
                else:
                    log.warning(
                        "_assess_control_async: all %d attempts failed for %s: %s",
                        _AI_RETRIES, control_id, exc,
                    )
            except Exception as exc:  # unexpected — don't retry
                log.warning(
                    "_assess_control_async: unexpected error for %s: %s",
                    control_id, exc,
                )
                return control_id, ""

    return control_id, ""


# ---------------------------------------------------------------------------
# FedRAMPPackageGenerator
# ---------------------------------------------------------------------------


class FedRAMPPackageGenerator:
    """Generates FedRAMP package artefacts from Warlock pipeline data."""

    # ------------------------------------------------------------------
    # SSP Template
    # ------------------------------------------------------------------

    def generate_ssp_template(
        self,
        session: Session,
        system_profile_id: str,
    ) -> dict[str, Any]:
        """Return a structured dict with FedRAMP SSP sections.

        Populated from SystemProfile metadata and ControlResult data.
        """
        profile = (
            session.query(SystemProfile)
            .filter(SystemProfile.id == system_profile_id)
            .first()
        )
        if profile is None:
            raise ValueError(f"SystemProfile {system_profile_id} not found")

        # Gather latest control results for fedramp
        results = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == "fedramp",
                ControlResult.system_profile_id == system_profile_id,
            )
            .all()
        )

        # Build per-control status map
        ctrl_statuses: dict[str, list[str]] = {}
        ctrl_details: dict[str, list[str]] = {}
        for cr in results:
            ctrl_statuses.setdefault(cr.control_id, []).append(cr.status)
            desc = cr.ai_assessment or cr.remediation_summary or ""
            if desc:
                ctrl_details.setdefault(cr.control_id, []).append(desc)

        # Load FedRAMP YAML for control catalogue
        fedramp_config = _load_framework_yaml("fedramp")
        control_entries = []
        for family_id, control_id, control in _iter_controls(fedramp_config):
            statuses = ctrl_statuses.get(control_id, [])
            agg = _aggregate_status(statuses)
            control_entries.append({
                "control_id": control_id,
                "family": family_id,
                "title": control.get("title", ""),
                "description": control.get("description", ""),
                "implementation_status": _impl_label(agg),
                "implementation_details": ctrl_details.get(control_id, []),
            })

        # Counts
        total = len(control_entries)
        implemented = sum(1 for c in control_entries if c["implementation_status"] == "Implemented")

        return {
            "document_type": "FedRAMP SSP",
            "generated_at": _now_iso(),
            "system_description": {
                "system_name": profile.name,
                "system_acronym": profile.acronym or "",
                "description": profile.description or "",
                "deployment_model": profile.deployment_model or "cloud",
                "service_model": profile.service_model or "SaaS",
                "authorization_status": profile.authorization_status,
                "authorization_date": (
                    profile.authorization_date.isoformat()
                    if profile.authorization_date
                    else None
                ),
            },
            "security_objectives": {
                "confidentiality": profile.confidentiality_impact or "moderate",
                "integrity": profile.integrity_impact or "moderate",
                "availability": profile.availability_impact or "moderate",
                "overall_impact": profile.overall_impact or "moderate",
            },
            "system_environment": {
                "cloud_accounts": profile.cloud_accounts or [],
                "network_boundaries": profile.network_boundaries or [],
                "connector_scope": profile.connector_scope or [],
            },
            "system_interconnections": profile.interconnections or [],
            "responsible_parties": {
                "system_owner": profile.system_owner,
                "system_owner_email": profile.system_owner_email,
                "isso": profile.isso,
                "isso_email": profile.isso_email,
                "issm": profile.issm,
                "issm_email": profile.issm_email,
                "authorizing_official": profile.authorizing_official,
                "ao_email": profile.ao_email,
            },
            "control_summary": {
                "total_controls": total,
                "implemented": implemented,
                "not_implemented": total - implemented,
            },
            "controls": control_entries,
        }

    # ------------------------------------------------------------------
    # SSP Template — async parallel AI path
    # ------------------------------------------------------------------

    async def generate_ssp_template_async(
        self,
        session: Session,
        system_profile_id: str,
        ai_provider: str = "",
        ai_api_key: str = "",
        ai_model: str = "",
        ai_base_url: str = "",
    ) -> dict[str, Any]:
        """Async variant of :meth:`generate_ssp_template` that fills missing
        ``ai_assessment`` fields by calling the AI provider in parallel.

        Controls that already have an ``ai_assessment`` stored in the database
        are **not** re-assessed — this keeps the function cheap to call
        incrementally.  Controls with no evidence and no existing assessment
        are also skipped (nothing useful to send to the model).

        If *ai_provider* is empty or any configuration is missing the method
        falls back silently to the synchronous output — parallel execution
        only fires when a fully configured provider is available.

        Args:
            session: SQLAlchemy session (read-only inside this call).
            system_profile_id: PK of the ``SystemProfile`` row.
            ai_provider: ``"anthropic"``, ``"openai"``, ``"gemini"``, or
                ``"ollama"``.  Empty string disables parallel AI calls.
            ai_api_key: API key for the provider.
            ai_model: Model identifier string.
            ai_base_url: Optional base URL override for Ollama / vLLM.

        Returns:
            The same document structure as :meth:`generate_ssp_template` but
            with ``implementation_details`` populated by fresh AI assessments
            for any controls that were missing them.
        """
        # ------------------------------------------------------------------
        # 1. Load profile and existing DB results (same as sync path)
        # ------------------------------------------------------------------
        profile = (
            session.query(SystemProfile)
            .filter(SystemProfile.id == system_profile_id)
            .first()
        )
        if profile is None:
            raise ValueError(f"SystemProfile {system_profile_id} not found")

        results = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == "fedramp",
                ControlResult.system_profile_id == system_profile_id,
            )
            .all()
        )

        ctrl_statuses: dict[str, list[str]] = {}
        ctrl_details: dict[str, list[str]] = {}
        ctrl_has_ai: set[str] = set()
        for cr in results:
            ctrl_statuses.setdefault(cr.control_id, []).append(cr.status)
            if cr.ai_assessment:
                ctrl_details.setdefault(cr.control_id, []).append(cr.ai_assessment)
                ctrl_has_ai.add(cr.control_id)
            elif cr.remediation_summary:
                ctrl_details.setdefault(cr.control_id, []).append(cr.remediation_summary)

        # ------------------------------------------------------------------
        # 2. Build initial control entries from framework YAML
        # ------------------------------------------------------------------
        fedramp_config = _load_framework_yaml("fedramp")
        control_meta: dict[str, dict[str, Any]] = {}   # control_id → YAML dict
        family_map: dict[str, str] = {}                  # control_id → family_id
        for family_id, control_id, control in _iter_controls(fedramp_config):
            control_meta[control_id] = control
            family_map[control_id] = family_id

        # ------------------------------------------------------------------
        # 3. Parallel AI assessment for controls missing ai_assessment
        # ------------------------------------------------------------------
        needs_assessment: list[tuple[str, str, list[str]]] = []
        for cid, meta in control_meta.items():
            if cid in ctrl_has_ai:
                continue
            existing_evidence = ctrl_details.get(cid, [])
            # Only call the model if there is at least some evidence to
            # reason over; controls with zero data produce nothing useful.
            if existing_evidence:
                needs_assessment.append((cid, meta.get("title", ""), existing_evidence))

        ai_results: dict[str, str] = {}
        if needs_assessment:
            t0 = time.monotonic()

            # -- preferred path: AIService.reason_batch() ------------------
            from warlock.ai import get_ai_service, AITask

            _ai_svc = get_ai_service()
            if _ai_svc.is_available():
                batch_tasks = [
                    (
                        AITask.SSP_NARRATIVE,
                        {
                            "control_id": cid,
                            "control_title": title,
                            "evidence": evidence,
                        },
                        None,
                    )
                    for cid, title, evidence in needs_assessment
                ]
                concurrency = getattr(
                    _ai_svc._settings, "ai_batch_concurrency", _AI_CONCURRENCY
                )
                batch_results = await _ai_svc.reason_batch(batch_tasks, concurrency=concurrency)
                for (cid, _title, _ev), result in zip(needs_assessment, batch_results):
                    if result.ai_used and result.value:
                        # SSP_NARRATIVE responds with {"narrative": "..."} or plain text
                        if isinstance(result.value, dict):
                            text = result.value.get("narrative", "")
                        else:
                            text = str(result.value)
                        if text:
                            ai_results[cid] = text
                elapsed = time.monotonic() - t0
                log.info(
                    "SSP export: %d controls assessed via AIService in %.1fs",
                    len(ai_results),
                    elapsed,
                )

            # -- fallback path: inline httpx (existing logic) --------------
            elif ai_provider and ai_api_key and ai_model:
                semaphore = asyncio.Semaphore(_AI_CONCURRENCY)
                async with httpx.AsyncClient() as client:
                    inline_tasks = [
                        _assess_control_async(
                            client=client,
                            provider=ai_provider,
                            model=ai_model,
                            api_key=ai_api_key,
                            base_url=ai_base_url,
                            control_id=cid,
                            control_title=title,
                            evidence_snippets=evidence,
                            semaphore=semaphore,
                        )
                        for cid, title, evidence in needs_assessment
                    ]
                    gathered: list[tuple[str, str]] = await asyncio.gather(
                        *inline_tasks, return_exceptions=False
                    )
                elapsed = time.monotonic() - t0
                ai_results = {cid: text for cid, text in gathered if text}
                log.info(
                    "SSP export: %d controls assessed in %.1fs (parallel)",
                    len(ai_results),
                    elapsed,
                )
            else:
                log.debug(
                    "SSP export: AI provider not configured — "
                    "%d controls skipped (sequential fallback)",
                    len(needs_assessment),
                )

        # Merge fresh AI results into ctrl_details
        for cid, text in ai_results.items():
            ctrl_details.setdefault(cid, []).insert(0, text)

        # ------------------------------------------------------------------
        # 4. Assemble document (identical logic to sync path)
        # ------------------------------------------------------------------
        control_entries = []
        for control_id, meta in control_meta.items():
            statuses = ctrl_statuses.get(control_id, [])
            agg = _aggregate_status(statuses)
            control_entries.append({
                "control_id": control_id,
                "family": family_map[control_id],
                "title": meta.get("title", ""),
                "description": meta.get("description", ""),
                "implementation_status": _impl_label(agg),
                "implementation_details": ctrl_details.get(control_id, []),
            })

        total = len(control_entries)
        implemented = sum(
            1 for c in control_entries if c["implementation_status"] == "Implemented"
        )

        return {
            "document_type": "FedRAMP SSP",
            "generated_at": _now_iso(),
            "system_description": {
                "system_name": profile.name,
                "system_acronym": profile.acronym or "",
                "description": profile.description or "",
                "deployment_model": profile.deployment_model or "cloud",
                "service_model": profile.service_model or "SaaS",
                "authorization_status": profile.authorization_status,
                "authorization_date": (
                    profile.authorization_date.isoformat()
                    if profile.authorization_date
                    else None
                ),
            },
            "security_objectives": {
                "confidentiality": profile.confidentiality_impact or "moderate",
                "integrity": profile.integrity_impact or "moderate",
                "availability": profile.availability_impact or "moderate",
                "overall_impact": profile.overall_impact or "moderate",
            },
            "system_environment": {
                "cloud_accounts": profile.cloud_accounts or [],
                "network_boundaries": profile.network_boundaries or [],
                "connector_scope": profile.connector_scope or [],
            },
            "system_interconnections": profile.interconnections or [],
            "responsible_parties": {
                "system_owner": profile.system_owner,
                "system_owner_email": profile.system_owner_email,
                "isso": profile.isso,
                "isso_email": profile.isso_email,
                "issm": profile.issm,
                "issm_email": profile.issm_email,
                "authorizing_official": profile.authorizing_official,
                "ao_email": profile.ao_email,
            },
            "control_summary": {
                "total_controls": total,
                "implemented": implemented,
                "not_implemented": total - implemented,
            },
            "controls": control_entries,
        }

    def generate_ssp_template_parallel(
        self,
        session: Session,
        system_profile_id: str,
        ai_provider: str = "",
        ai_api_key: str = "",
        ai_model: str = "",
        ai_base_url: str = "",
    ) -> dict[str, Any]:
        """Synchronous wrapper around :meth:`generate_ssp_template_async`.

        This is the **recommended entrypoint** for callers that want parallel
        AI assessment but cannot use ``await``.  It delegates to
        :func:`asyncio.run` which creates a fresh event loop, runs the async
        method to completion, and returns the result.

        If *ai_provider* / *ai_api_key* / *ai_model* are empty the call is
        functionally equivalent to :meth:`generate_ssp_template` (sequential,
        no AI calls) but still exercises the full async code path.

        Args:
            session: SQLAlchemy session.
            system_profile_id: PK of the ``SystemProfile`` row.
            ai_provider: Provider string — ``"anthropic"``, ``"openai"``,
                ``"gemini"``, or ``"ollama"``.
            ai_api_key: API key for the provider.
            ai_model: Model identifier.
            ai_base_url: Optional base URL override.

        Returns:
            FedRAMP SSP document dict, same shape as
            :meth:`generate_ssp_template`.
        """
        return asyncio.run(
            self.generate_ssp_template_async(
                session=session,
                system_profile_id=system_profile_id,
                ai_provider=ai_provider,
                ai_api_key=ai_api_key,
                ai_model=ai_model,
                ai_base_url=ai_base_url,
            )
        )

    # ------------------------------------------------------------------
    # Customer Responsibility Matrix (CRM)
    # ------------------------------------------------------------------

    def generate_crm(
        self,
        session: Session,
        system_profile_id: str,
    ) -> dict[str, Any]:
        """Customer Responsibility Matrix from ControlInheritance data."""
        rows = (
            session.query(ControlInheritance)
            .filter(ControlInheritance.system_profile_id == system_profile_id)
            .all()
        )

        entries: list[dict[str, Any]] = []
        for ci in rows:
            entries.append({
                "framework": ci.framework,
                "control_id": ci.control_id,
                "inheritance_type": ci.inheritance_type,
                "provider_description": ci.provider_description or "",
                "responsibility_description": ci.responsibility_description or "",
                "evidence_requirement": ci.evidence_requirement or "both",
                "status": ci.status,
            })

        # Summarise by type
        type_counts: dict[str, int] = {}
        for e in entries:
            t = e["inheritance_type"]
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "document_type": "FedRAMP CRM",
            "generated_at": _now_iso(),
            "system_profile_id": system_profile_id,
            "summary": type_counts,
            "total_controls": len(entries),
            "entries": entries,
        }

    # ------------------------------------------------------------------
    # Control Implementation Summary (CIS)
    # ------------------------------------------------------------------

    def generate_cis(
        self,
        session: Session,
        framework: str,
        system_profile_id: str,
    ) -> dict[str, Any]:
        """Control Implementation Summary: one entry per control.

        Includes status, implementation description from assertion results,
        and responsible role.
        """
        config = _load_framework_yaml(framework)
        all_controls = _iter_controls(config)

        # Latest results per control
        results = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.system_profile_id == system_profile_id,
            )
            .all()
        )

        ctrl_map: dict[str, list[ControlResult]] = {}
        for cr in results:
            ctrl_map.setdefault(cr.control_id, []).append(cr)

        # Inheritance info
        inheritances = (
            session.query(ControlInheritance)
            .filter(
                ControlInheritance.system_profile_id == system_profile_id,
                ControlInheritance.framework == framework,
            )
            .all()
        )
        inh_map: dict[str, ControlInheritance] = {ci.control_id: ci for ci in inheritances}

        entries: list[dict[str, Any]] = []
        for family_id, control_id, control in all_controls:
            crs = ctrl_map.get(control_id, [])
            statuses = [cr.status for cr in crs]
            agg = _aggregate_status(statuses)

            # Build description from assertion findings
            descriptions: list[str] = []
            for cr in crs:
                if cr.ai_assessment:
                    descriptions.append(cr.ai_assessment)
                elif cr.assertion_findings:
                    if isinstance(cr.assertion_findings, list):
                        descriptions.extend(str(f) for f in cr.assertion_findings)
                    else:
                        descriptions.append(str(cr.assertion_findings))

            ci = inh_map.get(control_id)
            responsible_role = "Customer"
            if ci:
                if ci.inheritance_type == "inherited":
                    responsible_role = "Provider"
                elif ci.inheritance_type == "shared":
                    responsible_role = "Shared"
                elif ci.inheritance_type == "common":
                    responsible_role = "Common"

            entries.append({
                "control_id": control_id,
                "family": family_id,
                "title": control.get("title", ""),
                "implementation_status": _impl_label(agg),
                "implementation_description": " | ".join(descriptions[:5]) if descriptions else "",
                "responsible_role": responsible_role,
                "inheritance_type": ci.inheritance_type if ci else "system_specific",
            })

        return {
            "document_type": "FedRAMP CIS",
            "generated_at": _now_iso(),
            "framework": framework,
            "system_profile_id": system_profile_id,
            "total_controls": len(entries),
            "entries": entries,
        }

    # ------------------------------------------------------------------
    # CIS — async parallel AI path
    # ------------------------------------------------------------------

    async def generate_cis_async(
        self,
        session: Session,
        framework: str,
        system_profile_id: str,
        ai_provider: str = "",
        ai_api_key: str = "",
        ai_model: str = "",
        ai_base_url: str = "",
    ) -> dict[str, Any]:
        """Async variant of :meth:`generate_cis` with parallel AI assessment.

        Controls whose ``implementation_description`` would otherwise be empty
        (no ``ai_assessment`` or ``assertion_findings`` in the DB) are sent to
        the AI provider in parallel to generate concise implementation
        statements.  Controls that already have descriptions are untouched.

        Args:
            session: SQLAlchemy session (read-only inside this call).
            framework: Framework identifier, e.g. ``"fedramp"``.
            system_profile_id: PK of the ``SystemProfile`` row.
            ai_provider: Provider string.  Empty string disables AI calls.
            ai_api_key: API key for the provider.
            ai_model: Model identifier.
            ai_base_url: Optional base URL override.

        Returns:
            CIS document dict, same shape as :meth:`generate_cis` but with
            ``implementation_description`` populated by AI for empty controls.
        """
        config = _load_framework_yaml(framework)
        all_controls = _iter_controls(config)

        results = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.system_profile_id == system_profile_id,
            )
            .all()
        )

        ctrl_map: dict[str, list[ControlResult]] = {}
        for cr in results:
            ctrl_map.setdefault(cr.control_id, []).append(cr)

        inheritances = (
            session.query(ControlInheritance)
            .filter(
                ControlInheritance.system_profile_id == system_profile_id,
                ControlInheritance.framework == framework,
            )
            .all()
        )
        inh_map: dict[str, ControlInheritance] = {ci.control_id: ci for ci in inheritances}

        # Build entries the same way as the sync path
        entries: list[dict[str, Any]] = []
        needs_assessment: list[tuple[str, str, list[str]]] = []

        for family_id, control_id, control in all_controls:
            crs = ctrl_map.get(control_id, [])
            statuses = [cr.status for cr in crs]
            agg = _aggregate_status(statuses)

            descriptions: list[str] = []
            for cr in crs:
                if cr.ai_assessment:
                    descriptions.append(cr.ai_assessment)
                elif cr.assertion_findings:
                    if isinstance(cr.assertion_findings, list):
                        descriptions.extend(str(f) for f in cr.assertion_findings)
                    else:
                        descriptions.append(str(cr.assertion_findings))

            ci = inh_map.get(control_id)
            responsible_role = "Customer"
            if ci:
                if ci.inheritance_type == "inherited":
                    responsible_role = "Provider"
                elif ci.inheritance_type == "shared":
                    responsible_role = "Shared"
                elif ci.inheritance_type == "common":
                    responsible_role = "Common"

            # Queue for AI if no description and provider is configured
            if not descriptions and ai_provider and ai_api_key and ai_model:
                needs_assessment.append((control_id, control.get("title", ""), []))

            entries.append({
                "control_id": control_id,
                "family": family_id,
                "title": control.get("title", ""),
                "implementation_status": _impl_label(agg),
                "implementation_description": " | ".join(descriptions[:5]),
                "responsible_role": responsible_role,
                "inheritance_type": ci.inheritance_type if ci else "system_specific",
                "_needs_ai": not descriptions,  # internal flag, stripped below
            })

        # Parallel AI calls for empty entries
        ai_results: dict[str, str] = {}
        if needs_assessment:
            t0 = time.monotonic()

            # -- preferred path: AIService.reason_batch() ------------------
            from warlock.ai import get_ai_service, AITask

            _ai_svc = get_ai_service()
            if _ai_svc.is_available():
                batch_tasks = [
                    (
                        AITask.CIS_NARRATIVE,
                        {
                            "control_id": cid,
                            "control_title": title,
                            "evidence": evidence,
                        },
                        None,
                    )
                    for cid, title, evidence in needs_assessment
                ]
                concurrency = getattr(
                    _ai_svc._settings, "ai_batch_concurrency", _AI_CONCURRENCY
                )
                batch_results = await _ai_svc.reason_batch(batch_tasks, concurrency=concurrency)
                for (cid, _title, _ev), result in zip(needs_assessment, batch_results):
                    if result.ai_used and result.value:
                        # CIS_NARRATIVE responds with {"narrative": "..."} or plain text
                        if isinstance(result.value, dict):
                            text = result.value.get("narrative", "")
                        else:
                            text = str(result.value)
                        if text:
                            ai_results[cid] = text
                elapsed = time.monotonic() - t0
                log.info(
                    "CIS export: %d controls assessed via AIService in %.1fs",
                    len(ai_results),
                    elapsed,
                )

            # -- fallback path: inline httpx (existing logic) --------------
            elif ai_provider and ai_api_key and ai_model:
                semaphore = asyncio.Semaphore(_AI_CONCURRENCY)
                async with httpx.AsyncClient() as client:
                    inline_tasks = [
                        _assess_control_async(
                            client=client,
                            provider=ai_provider,
                            model=ai_model,
                            api_key=ai_api_key,
                            base_url=ai_base_url,
                            control_id=cid,
                            control_title=title,
                            evidence_snippets=evidence,
                            semaphore=semaphore,
                        )
                        for cid, title, evidence in needs_assessment
                    ]
                    gathered: list[tuple[str, str]] = await asyncio.gather(
                        *inline_tasks, return_exceptions=False
                    )
                elapsed = time.monotonic() - t0
                ai_results = {cid: text for cid, text in gathered if text}
                log.info(
                    "CIS export: %d controls assessed in %.1fs (parallel)",
                    len(ai_results),
                    elapsed,
                )

        # Merge AI results and strip internal flag
        for entry in entries:
            entry.pop("_needs_ai")
            cid = entry["control_id"]
            if not entry["implementation_description"] and cid in ai_results:
                entry["implementation_description"] = ai_results[cid]

        return {
            "document_type": "FedRAMP CIS",
            "generated_at": _now_iso(),
            "framework": framework,
            "system_profile_id": system_profile_id,
            "total_controls": len(entries),
            "entries": entries,
        }

    def generate_cis_parallel(
        self,
        session: Session,
        framework: str,
        system_profile_id: str,
        ai_provider: str = "",
        ai_api_key: str = "",
        ai_model: str = "",
        ai_base_url: str = "",
    ) -> dict[str, Any]:
        """Synchronous wrapper around :meth:`generate_cis_async`.

        Equivalent to calling :meth:`generate_cis` when no AI provider is
        configured.  When a provider is supplied it fans out AI calls across
        all controls with empty ``implementation_description`` fields.

        Args:
            session: SQLAlchemy session.
            framework: Framework identifier.
            system_profile_id: PK of the ``SystemProfile`` row.
            ai_provider: Provider string.
            ai_api_key: API key for the provider.
            ai_model: Model identifier.
            ai_base_url: Optional base URL override.

        Returns:
            CIS document dict.
        """
        return asyncio.run(
            self.generate_cis_async(
                session=session,
                framework=framework,
                system_profile_id=system_profile_id,
                ai_provider=ai_provider,
                ai_api_key=ai_api_key,
                ai_model=ai_model,
                ai_base_url=ai_base_url,
            )
        )

    # ------------------------------------------------------------------
    # Continuous Monitoring (ConMon) Plan
    # ------------------------------------------------------------------

    def generate_conmon_plan(
        self,
        session: Session,
    ) -> dict[str, Any]:
        """ConMon plan template with scan schedules and assessment frequencies.

        Derives frequencies from the monitoring_frequency fields in all
        loaded framework YAMLs.
        """
        frequency_map: dict[str, list[dict[str, str]]] = {}

        # Scan all framework YAMLs for monitoring_frequency
        for yaml_path in sorted(_FRAMEWORKS_DIR.glob("*.yaml")):
            if yaml_path.name.startswith("crosswalk"):
                continue
            try:
                config = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
            except Exception:
                log.debug("Skipping %s", yaml_path.name, exc_info=True)
                continue

            fw_id = config.get("framework_id", yaml_path.stem)
            for _family_id, control_id, control in _iter_controls(config):
                freq = control.get("monitoring_frequency")
                if not freq:
                    # Check if any check has a monitoring_frequency
                    for check in control.get("checks", []):
                        freq = check.get("monitoring_frequency")
                        if freq:
                            break
                if freq:
                    frequency_map.setdefault(freq, []).append({
                        "framework": fw_id,
                        "control_id": control_id,
                    })

        # Distinct active frameworks from ControlMapping
        active_frameworks = [
            row[0]
            for row in session.query(ControlMapping.framework).distinct().all()
        ]

        return {
            "document_type": "FedRAMP ConMon Plan",
            "generated_at": _now_iso(),
            "active_frameworks": sorted(active_frameworks),
            "scan_schedules": {
                "vulnerability_scanning": {
                    "frequency": "monthly",
                    "description": "OS, infrastructure, and web application vulnerability scans",
                },
                "configuration_scanning": {
                    "frequency": "monthly",
                    "description": "CIS benchmark and STIG compliance scans",
                },
                "penetration_testing": {
                    "frequency": "annual",
                    "description": "Third-party penetration test (3PAO)",
                },
            },
            "assessment_frequencies": {
                freq: {
                    "control_count": len(controls),
                    "controls": controls,
                }
                for freq, controls in sorted(frequency_map.items())
            },
            "reporting_cadence": {
                "monthly": "ConMon deliverables: scan results, POA&M updates, significant change reports",
                "quarterly": "Quarterly posture review with AO",
                "annual": "Full 3PAO assessment, ATO renewal",
            },
        }
