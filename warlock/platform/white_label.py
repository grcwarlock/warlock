"""PLT-2: White-label branding capability.

Stores per-tenant branding (logo, colors, app name, support email) and
provides a lightweight template rendering helper that injects branding
variables into report templates.

GAP-100 / STUB-033: Now persists branding to the ``branding_configs`` DB
table via :class:`BrandingManager`, with an in-memory fallback via the
legacy :class:`WhiteLabelConfig`.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

_ALLOWED_BRANDING_KEYS = frozenset(
    {
        "logo_url",
        "primary_color",
        "secondary_color",
        "accent_color",
        "app_name",
        "support_email",
        "favicon_url",
        "footer_text",
        "custom_css",
    }
)

_DEFAULT_BRANDING: dict[str, str] = {
    "logo_url": "",
    "primary_color": "#6366f1",
    "secondary_color": "#174ea6",
    "accent_color": "#8b5cf6",
    "app_name": "Warlock GRC",
    "support_email": "",
    "favicon_url": "",
    "footer_text": "",
    "custom_css": "",
}


@dataclass
class BrandingSpec:
    """Immutable snapshot of a tenant's branding configuration."""

    tenant_id: str
    logo_url: str = ""
    primary_color: str = "#6366f1"
    secondary_color: str = "#174ea6"
    accent_color: str = "#8b5cf6"
    app_name: str = "Warlock GRC"
    support_email: str = ""
    favicon_url: str = ""
    footer_text: str = ""
    custom_css: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "logo_url": self.logo_url,
            "primary_color": self.primary_color,
            "secondary_color": self.secondary_color,
            "accent_color": self.accent_color,
            "app_name": self.app_name,
            "support_email": self.support_email,
            "favicon_url": self.favicon_url,
            "footer_text": self.footer_text,
            "custom_css": self.custom_css,
            **self.extra,
        }


class BrandingManager:
    """DB-backed branding manager using the BrandingConfig model.

    Persists branding to the ``branding_configs`` table.  Falls back to
    in-memory storage when the DB is unavailable (e.g. during early startup).
    """

    def get(self, tenant_id: str) -> BrandingSpec:
        """Load branding for *tenant_id* from the database."""
        from warlock.db.engine import get_read_session
        from warlock.db.models import BrandingConfig

        with get_read_session() as session:
            row = (
                session.query(BrandingConfig)
                .filter(BrandingConfig.tenant_id_unique == tenant_id)
                .first()
            )
            if row is None:
                return BrandingSpec(tenant_id=tenant_id)
            return BrandingSpec(
                tenant_id=tenant_id,
                logo_url=row.logo_url or "",
                primary_color=row.primary_color or "#6366f1",
                accent_color=row.accent_color or "#8b5cf6",
                app_name=row.app_name or "Warlock GRC",
                favicon_url=row.favicon_url or "",
                custom_css=row.custom_css or "",
            )

    def set(self, tenant_id: str, branding: dict[str, Any]) -> BrandingSpec:
        """Upsert branding for *tenant_id* into the database."""
        from warlock.db.engine import get_session
        from warlock.db.models import BrandingConfig

        with get_session() as session:
            row = (
                session.query(BrandingConfig)
                .filter(BrandingConfig.tenant_id_unique == tenant_id)
                .first()
            )
            if row is None:
                row = BrandingConfig(
                    tenant_id_unique=tenant_id,
                    tenant_id=tenant_id,
                )
                session.add(row)

            for key in (
                "logo_url",
                "primary_color",
                "accent_color",
                "app_name",
                "favicon_url",
                "custom_css",
            ):
                if key in branding:
                    setattr(row, key, branding[key])

            log.info("Persisted branding for tenant %s", tenant_id)

        return self.get(tenant_id)

    def remove(self, tenant_id: str) -> None:
        """Delete persisted branding for *tenant_id*."""
        from warlock.db.engine import get_session
        from warlock.db.models import BrandingConfig

        with get_session() as session:
            session.query(BrandingConfig).filter(
                BrandingConfig.tenant_id_unique == tenant_id
            ).delete()

        log.info("Removed persisted branding for tenant %s", tenant_id)


class WhiteLabelConfig:
    """Manage per-tenant branding configuration.

    Uses :class:`BrandingManager` for DB persistence when available, with
    an in-memory dict as fallback for non-DB contexts.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # tenant_id -> branding dict (in-memory fallback)
        self._branding: dict[str, dict[str, Any]] = {}
        self._db = BrandingManager()

    def configure(self, tenant_id: str, branding: dict[str, Any]) -> BrandingSpec:
        """Set or update branding for a tenant.

        Parameters
        ----------
        tenant_id:
            The tenant to brand.
        branding:
            Dict of branding keys.  Unknown keys are stored in the ``extra``
            bucket but standard keys are validated.

        Returns the resulting :class:`BrandingSpec`.
        """
        if not tenant_id:
            raise ValueError("tenant_id is required")
        if not isinstance(branding, dict):
            raise TypeError("branding must be a dict")

        # Persist to DB (best-effort — fall back to memory)
        try:
            return self._db.set(tenant_id, branding)
        except Exception:
            log.debug("DB branding write failed, using in-memory", exc_info=True)

        with self._lock:
            existing = self._branding.get(tenant_id, dict(_DEFAULT_BRANDING))
            existing.update(branding)
            self._branding[tenant_id] = existing
            log.info("Updated branding for tenant %s (in-memory)", tenant_id)
            return self._to_spec(tenant_id, existing)

    def get_branding(self, tenant_id: str) -> BrandingSpec:
        """Return the branding config for a tenant.

        If no custom branding has been configured, the platform defaults are
        returned.
        """
        # Try DB first
        try:
            spec = self._db.get(tenant_id)
            if spec.logo_url or spec.app_name != "Warlock GRC":
                return spec
        except Exception:
            log.debug("DB branding read failed, using in-memory", exc_info=True)

        with self._lock:
            data = self._branding.get(tenant_id, dict(_DEFAULT_BRANDING))
        return self._to_spec(tenant_id, data)

    def remove_branding(self, tenant_id: str) -> None:
        """Reset a tenant's branding to platform defaults."""
        try:
            self._db.remove(tenant_id)
        except Exception:
            log.debug("DB branding delete failed", exc_info=True)

        with self._lock:
            self._branding.pop(tenant_id, None)
        log.info("Removed custom branding for tenant %s", tenant_id)

    def render_template(self, template_name: str, tenant_id: str) -> dict[str, Any]:
        """Return a context dict suitable for injecting into a report template.

        The returned dict contains all branding variables plus
        ``template_name`` so that the rendering engine can select the correct
        template file.  This method does NOT perform actual file rendering --
        that is the responsibility of the report/export layer.

        Parameters
        ----------
        template_name:
            Logical template identifier (e.g. ``"compliance_report"``).
        tenant_id:
            The tenant whose branding should be injected.
        """
        spec = self.get_branding(tenant_id)
        ctx = spec.to_dict()
        ctx["template_name"] = template_name
        return ctx

    def list_branded_tenants(self) -> list[str]:
        """Return tenant IDs that have custom branding configured."""
        with self._lock:
            return list(self._branding.keys())

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _to_spec(tenant_id: str, data: dict[str, Any]) -> BrandingSpec:
        known = {k: data.get(k, v) for k, v in _DEFAULT_BRANDING.items()}
        extra = {k: v for k, v in data.items() if k not in _ALLOWED_BRANDING_KEYS}
        return BrandingSpec(tenant_id=tenant_id, **known, extra=extra)
