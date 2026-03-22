"""Unified policy engine — stores and resolves operational rules."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from warlock.db.models import Policy, PolicyHistory

log = logging.getLogger(__name__)


class ResolvedPolicy:
    """A policy resolved for a specific context."""

    def __init__(self, policy: Policy):
        self.id = policy.id
        self.policy_type = policy.policy_type
        self.scope = policy.scope or {}
        self.rules = policy.rules
        self.priority = policy.priority
        self.description = policy.description
        self.created_by = policy.created_by


class PolicyEngine:
    """Central policy store. Domains read policies at decision time."""

    def __init__(self, session: Session):
        self._session = session

    def set_policy(
        self,
        policy_type: str,
        scope: dict,
        rules: dict,
        actor: str,
        priority: int = 0,
        description: str = "",
        effective_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> Policy:
        now = datetime.now(timezone.utc)
        policy = Policy(
            policy_type=policy_type,
            scope=scope,
            rules=rules,
            priority=priority,
            created_by=actor,
            created_at=now,
            effective_at=effective_at or now,
            expires_at=expires_at,
            description=description,
        )
        self._session.add(policy)
        self._session.flush()  # populate policy.id before referencing it in history

        history = PolicyHistory(
            policy_id=policy.id,
            action="created",
            new_rules=rules,
            actor=actor,
            timestamp=now,
        )
        self._session.add(history)
        self._session.commit()
        return policy

    def get(self, policy_type: str, **context) -> ResolvedPolicy | None:
        """Get effective policy for context. Resolution: specificity > priority > recency."""
        now = datetime.now(timezone.utc)
        candidates = (
            self._session.query(Policy)
            .filter(Policy.policy_type == policy_type, Policy.enabled.is_(True), Policy.effective_at <= now)
            .all()
        )
        candidates = [p for p in candidates if p.expires_at is None or p.expires_at > now]
        if not candidates:
            return None

        scored: list[tuple[int, int, datetime, Policy]] = []
        for p in candidates:
            specificity = self._scope_match(p.scope or {}, context)
            if specificity >= 0:
                scored.append((specificity, p.priority, p.created_at, p))

        if not scored:
            return None

        scored.sort(key=lambda x: (x[0], x[1], x[2]), reverse=True)
        return ResolvedPolicy(scored[0][3])

    def _scope_match(self, scope: dict, context: dict) -> int:
        """Score scope vs context. -1 = no match. 0+ = match (higher = more specific)."""
        if not scope:
            return 0
        specificity = 0
        for key, scope_values in scope.items():
            if not scope_values:
                continue
            context_key = key.rstrip("s") if key.endswith("s") else key
            context_value = context.get(context_key) or context.get(key)
            if context_value is None:
                continue
            if isinstance(scope_values, list):
                if context_value in scope_values:
                    specificity += 1
                else:
                    return -1
            elif scope_values == context_value:
                specificity += 1
            else:
                return -1
        return specificity

    def list_policies(self, policy_type: str | None = None, framework: str | None = None) -> list[Policy]:
        q = self._session.query(Policy).filter(Policy.enabled.is_(True))
        if policy_type:
            q = q.filter(Policy.policy_type == policy_type)
        policies = q.order_by(Policy.policy_type, Policy.priority.desc()).all()
        if framework:
            policies = [
                p for p in policies
                if not p.scope or not p.scope.get("frameworks")
                or framework in p.scope["frameworks"]
            ]
        return policies
