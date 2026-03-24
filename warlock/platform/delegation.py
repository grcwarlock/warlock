"""PLT-3 / PLT-4: Role hierarchy and delegated admin.

Supports granting scoped admin privileges from one user to another, tracking
delegation chains, and computing effective permissions by merging a user's
direct role with any inherited parent role and active delegations.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from warlock.db.models import User

log = logging.getLogger(__name__)

# Canonical role hierarchy (highest privilege first).
ROLE_HIERARCHY: list[str] = ["admin", "auditor", "owner", "viewer"]

# Default permission sets per role.
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {
        "read",
        "write",
        "delete",
        "manage_users",
        "manage_tenants",
        "manage_delegations",
        "manage_config",
        "export",
        "audit",
    },
    "auditor": {"read", "export", "audit"},
    "owner": {"read", "write", "delete", "export"},
    "viewer": {"read"},
}


class DelegationRecord:
    """In-memory representation of a single delegation grant."""

    __slots__ = (
        "id",
        "from_user_id",
        "to_user_id",
        "scope",
        "granted_at",
        "granted_by",
        "revoked_at",
        "revoked_by",
    )

    def __init__(
        self,
        *,
        delegation_id: str,
        from_user_id: str,
        to_user_id: str,
        scope: dict[str, Any],
        granted_by: str,
    ) -> None:
        self.id = delegation_id
        self.from_user_id = from_user_id
        self.to_user_id = to_user_id
        self.scope = scope
        self.granted_at = datetime.now(timezone.utc)
        self.granted_by = granted_by
        self.revoked_at: datetime | None = None
        self.revoked_by: str | None = None

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "from_user_id": self.from_user_id,
            "to_user_id": self.to_user_id,
            "scope": self.scope,
            "granted_at": self.granted_at.isoformat(),
            "granted_by": self.granted_by,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoked_by": self.revoked_by,
            "is_active": self.is_active,
        }


class DelegationManager:
    """Manage delegated admin grants and effective permission resolution."""

    def __init__(self) -> None:
        # delegation_id -> DelegationRecord
        self._delegations: dict[str, DelegationRecord] = {}

    # ------------------------------------------------------------------
    # Delegation lifecycle
    # ------------------------------------------------------------------

    def delegate_admin(
        self,
        session: Session,
        from_user_id: str,
        to_user_id: str,
        scope: dict[str, Any],
        actor: str,
    ) -> dict[str, Any]:
        """Grant delegated admin from *from_user_id* to *to_user_id*.

        Parameters
        ----------
        session:
            Active SQLAlchemy session for user lookups.
        from_user_id:
            The user granting delegation.  Must have ``admin`` or ``owner`` role.
        to_user_id:
            The user receiving delegated permissions.
        scope:
            A dict describing the scope of delegation.  Example::

                {"frameworks": ["nist_800_53"], "actions": ["read", "write"]}

        actor:
            Identifier of the person/system performing this action (for audit).

        Returns the delegation record as a dict.

        Raises ``PermissionError`` if the granting user lacks sufficient role.
        Raises ``ValueError`` for self-delegation or missing users.
        """
        if from_user_id == to_user_id:
            raise ValueError("Cannot delegate to yourself")

        from_user = self._load_user(session, from_user_id)
        self._load_user(session, to_user_id)  # validate exists

        if from_user.role not in ("admin", "owner"):
            raise PermissionError(
                f"User {from_user_id} with role '{from_user.role}' cannot delegate admin"
            )

        # Prevent delegating permissions the granting user does not have.
        granting_perms = self._permissions_for_role(from_user.role)
        requested_actions = set(scope.get("actions", []))
        if requested_actions and not requested_actions.issubset(granting_perms):
            excess = requested_actions - granting_perms
            raise PermissionError(f"Cannot delegate actions not held by granting user: {excess}")

        delegation_id = str(uuid4())
        record = DelegationRecord(
            delegation_id=delegation_id,
            from_user_id=from_user_id,
            to_user_id=to_user_id,
            scope=scope,
            granted_by=actor,
        )
        self._delegations[delegation_id] = record

        # Stamp the delegated_by field on the target user.
        to_user = self._load_user(session, to_user_id)
        to_user.delegated_by = from_user_id
        session.flush()

        log.info(
            "Delegation %s: %s -> %s (scope=%s, actor=%s)",
            delegation_id,
            from_user_id,
            to_user_id,
            scope,
            actor,
        )
        return record.to_dict()

    def revoke_delegation(
        self,
        session: Session,
        delegation_id: str,
        actor: str,
    ) -> dict[str, Any]:
        """Revoke an active delegation.

        Raises ``KeyError`` if the delegation does not exist.
        Raises ``ValueError`` if already revoked.
        """
        record = self._get_delegation(delegation_id)
        if not record.is_active:
            raise ValueError(f"Delegation {delegation_id} is already revoked")

        record.revoked_at = datetime.now(timezone.utc)
        record.revoked_by = actor

        # Clear delegated_by on the target user if no other active delegations remain.
        active_for_user = [
            d
            for d in self._delegations.values()
            if d.to_user_id == record.to_user_id and d.is_active
        ]
        if not active_for_user:
            to_user = self._load_user(session, record.to_user_id)
            to_user.delegated_by = None
            session.flush()

        log.info("Revoked delegation %s (actor=%s)", delegation_id, actor)
        return record.to_dict()

    def get_effective_permissions(
        self,
        session: Session,
        user_id: str,
    ) -> dict[str, Any]:
        """Compute effective permissions for a user.

        Merges:
        1. The user's direct role permissions.
        2. The parent_role permissions (if set).
        3. Scoped permissions from active delegations.
        4. Explicit ``allowed_actions`` overrides on the User model.

        Returns a dict with ``role``, ``permissions`` (set as list),
        ``delegations`` (active delegation summaries), and scope filters.
        """
        user = self._load_user(session, user_id)

        # Base permissions from direct role.
        perms = set(self._permissions_for_role(user.role))

        # Merge parent_role if present.
        if user.parent_role:
            parent_perms = self._permissions_for_role(user.parent_role)
            perms |= parent_perms

        # Merge explicit allowed_actions overrides.
        if user.allowed_actions:
            perms |= set(user.allowed_actions)

        # Merge delegated permissions.
        active_delegations: list[dict[str, Any]] = []
        for d in self._delegations.values():
            if d.to_user_id == user_id and d.is_active:
                delegated_actions = set(d.scope.get("actions", []))
                perms |= delegated_actions
                active_delegations.append(d.to_dict())

        return {
            "user_id": user_id,
            "role": user.role,
            "parent_role": user.parent_role,
            "permissions": sorted(perms),
            "delegations": active_delegations,
            "allowed_frameworks": user.allowed_frameworks or [],
            "allowed_sources": user.allowed_sources or [],
            "allowed_control_families": user.allowed_control_families or [],
        }

    def list_delegations(
        self,
        session: Session,
        user_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """List delegations, optionally filtered to a specific user.

        When *user_id* is given, returns delegations where the user is either
        the grantor or the grantee.
        """
        results: list[dict[str, Any]] = []
        for d in self._delegations.values():
            if user_id is not None:
                if d.from_user_id != user_id and d.to_user_id != user_id:
                    continue
            results.append(d.to_dict())
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_user(session: Session, user_id: str) -> User:
        user = session.get(User, user_id)
        if user is None:
            raise ValueError(f"User '{user_id}' not found")
        return user

    @staticmethod
    def _permissions_for_role(role: str) -> set[str]:
        return set(ROLE_PERMISSIONS.get(role, set()))

    def _get_delegation(self, delegation_id: str) -> DelegationRecord:
        try:
            return self._delegations[delegation_id]
        except KeyError:
            raise KeyError(f"Delegation '{delegation_id}' not found") from None
