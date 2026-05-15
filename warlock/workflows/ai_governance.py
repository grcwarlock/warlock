"""AI governance workflow -- model inventory and EU AI Act risk classification.

Provides:
- ``AIModelInventory`` -- registry of AI/ML models with metadata
- ``AIRiskClassifier`` -- EU AI Act risk tier classification engine
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# EU AI Act risk tiers
# ---------------------------------------------------------------------------

RISK_TIERS = {
    "unacceptable": {
        "level": 4,
        "label": "Unacceptable Risk",
        "description": "Prohibited AI practices (Art. 5)",
        "action": "Must not be deployed in the EU",
    },
    "high": {
        "level": 3,
        "label": "High Risk",
        "description": "AI systems in Annex III areas (Art. 6)",
        "action": "Full conformity assessment, registration, CE marking required",
    },
    "limited": {
        "level": 2,
        "label": "Limited Risk",
        "description": "Transparency obligations (Art. 52)",
        "action": "Disclosure and transparency requirements apply",
    },
    "minimal": {
        "level": 1,
        "label": "Minimal Risk",
        "description": "No specific obligations beyond existing law",
        "action": "Voluntary codes of conduct encouraged",
    },
}

# Keywords that signal risk tier (simplified heuristic classifier)
_HIGH_RISK_DOMAINS = [
    "biometric",
    "critical infrastructure",
    "education",
    "employment",
    "credit scoring",
    "law enforcement",
    "migration",
    "justice",
    "democratic process",
    "safety component",
    "medical device",
    "recruitment",
    "worker management",
    "essential services",
]

_UNACCEPTABLE_PATTERNS = [
    "social scoring",
    "subliminal manipulation",
    "exploitation of vulnerabilities",
    "real-time biometric identification",
    "emotion recognition workplace",
    "emotion recognition education",
]

_LIMITED_RISK_PATTERNS = [
    "chatbot",
    "deepfake",
    "synthetic content",
    "emotion recognition",
    "biometric categorisation",
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class AIModelRecord:
    """An AI/ML model in the inventory."""

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    version: str = ""
    provider: str = ""
    model_type: str = ""  # classification, generation, recommendation, etc.
    domain: str = ""  # healthcare, finance, hr, etc.
    purpose: str = ""
    data_sources: list[str] = field(default_factory=list)
    risk_tier: str = "minimal"
    risk_rationale: str = ""
    deployed: bool = False
    deployment_region: str = ""
    owner: str = ""
    last_assessment: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskClassificationResult:
    """Result of EU AI Act risk classification."""

    model_id: str = ""
    model_name: str = ""
    risk_tier: str = "minimal"
    confidence: float = 0.0
    rationale: str = ""
    obligations: list[str] = field(default_factory=list)
    matched_patterns: list[str] = field(default_factory=list)
    tier_info: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


class AIRiskClassifier:
    """Classify AI models according to EU AI Act risk tiers."""

    def classify(self, model: AIModelRecord) -> RiskClassificationResult:
        """Classify a model's risk tier based on domain and purpose."""
        text = f"{model.domain} {model.purpose} {model.model_type} {model.name}".lower()
        matched: list[str] = []

        # Check unacceptable first (highest priority)
        for pattern in _UNACCEPTABLE_PATTERNS:
            if pattern in text:
                matched.append(pattern)
        if matched:
            return self._build_result(model, "unacceptable", matched, 0.9)

        # Check high risk
        matched = []
        for domain_kw in _HIGH_RISK_DOMAINS:
            if domain_kw in text:
                matched.append(domain_kw)
        if matched:
            return self._build_result(model, "high", matched, 0.8)

        # Check limited risk
        matched = []
        for pattern in _LIMITED_RISK_PATTERNS:
            if pattern in text:
                matched.append(pattern)
        if matched:
            return self._build_result(model, "limited", matched, 0.7)

        # Default: minimal
        return self._build_result(model, "minimal", [], 0.6)

    def _build_result(
        self,
        model: AIModelRecord,
        tier: str,
        patterns: list[str],
        confidence: float,
    ) -> RiskClassificationResult:
        tier_info = RISK_TIERS.get(tier, RISK_TIERS["minimal"])
        obligations = self._get_obligations(tier)
        return RiskClassificationResult(
            model_id=model.id,
            model_name=model.name,
            risk_tier=tier,
            confidence=confidence,
            rationale=f"{tier_info['description']}. Matched: {', '.join(patterns) or 'none'}",
            obligations=obligations,
            matched_patterns=patterns,
            tier_info=tier_info,
        )

    @staticmethod
    def _get_obligations(tier: str) -> list[str]:
        if tier == "unacceptable":
            return ["Deployment prohibited under Art. 5 EU AI Act"]
        if tier == "high":
            return [
                "Risk management system (Art. 9)",
                "Data governance (Art. 10)",
                "Technical documentation (Art. 11)",
                "Record-keeping / logging (Art. 12)",
                "Transparency to users (Art. 13)",
                "Human oversight (Art. 14)",
                "Accuracy, robustness, cybersecurity (Art. 15)",
                "Conformity assessment (Art. 43)",
                "EU database registration (Art. 49)",
                "CE marking (Art. 49)",
            ]
        if tier == "limited":
            return [
                "Disclosure that user is interacting with AI (Art. 52)",
                "Label AI-generated / manipulated content",
            ]
        return ["Voluntary codes of conduct (Art. 69)"]


# ---------------------------------------------------------------------------
# Inventory manager
# ---------------------------------------------------------------------------


class AIModelInventory:
    """Manage AI/ML model inventory records in the database.

    Uses AuditEntry with entity_type='ai_model' for storage,
    avoiding schema migrations.
    """

    def list_models(self, session) -> list[AIModelRecord]:
        """List all AI models in the inventory."""
        from warlock.db.models import AuditEntry

        entries = (
            session.query(AuditEntry)
            .filter(AuditEntry.entity_type == "ai_model")
            .filter(AuditEntry.action == "registered")
            .order_by(AuditEntry.timestamp.desc())
            .all()
        )
        models: list[AIModelRecord] = []
        for entry in entries:
            extra = entry.extra or {}
            models.append(
                AIModelRecord(
                    id=entry.entity_id,
                    name=extra.get("name", ""),
                    version=extra.get("version", ""),
                    provider=extra.get("provider", ""),
                    model_type=extra.get("model_type", ""),
                    domain=extra.get("domain", ""),
                    purpose=extra.get("purpose", ""),
                    risk_tier=extra.get("risk_tier", "minimal"),
                    owner=extra.get("owner", ""),
                    deployed=extra.get("deployed", False),
                    deployment_region=extra.get("deployment_region", ""),
                    created_at=entry.timestamp.isoformat() if entry.timestamp else "",
                )
            )
        return models

    def register_model(self, session, model: AIModelRecord, actor: str = "system") -> AIModelRecord:
        """Register a new AI model in the inventory.

        SEC-C4: previously instantiated AuditEntry directly with the
        non-existent ``timestamp=`` kwarg (column is ``created_at``) and
        without ``sequence`` / ``previous_hash`` / ``entry_hash`` — the
        constructor raised TypeError on every call. Routed through
        ``AuditTrail.record()`` for canonical hash-chained writes.
        """
        from warlock.db.audit import AuditTrail

        AuditTrail(session).record(
            action="registered",
            entity_type="ai_model",
            entity_id=model.id,
            actor=actor,
            metadata={
                "name": model.name,
                "version": model.version,
                "provider": model.provider,
                "model_type": model.model_type,
                "domain": model.domain,
                "purpose": model.purpose,
                "risk_tier": model.risk_tier,
                "owner": model.owner,
                "deployed": model.deployed,
                "deployment_region": model.deployment_region,
                "data_sources": model.data_sources,
            },
        )
        return model
