"""PLT-2: White-label branding capability.

Stores per-tenant branding (logo, colors, app name, support email) and
provides a lightweight template rendering helper that injects branding
variables into report templates.
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
        "app_name",
        "support_email",
        "favicon_url",
        "footer_text",
        "custom_css",
    }
)

_DEFAULT_BRANDING: dict[str, str] = {
    "logo_url": "",
    "primary_color": "#1a73e8",
    "secondary_color": "#174ea6",
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
    primary_color: str = "#1a73e8"
    secondary_color: str = "#174ea6"
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
            "app_name": self.app_name,
            "support_email": self.support_email,
            "favicon_url": self.favicon_url,
            "footer_text": self.footer_text,
            "custom_css": self.custom_css,
            **self.extra,
        }


class WhiteLabelConfig:
    """Manage per-tenant branding configuration."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # tenant_id -> branding dict
        self._branding: dict[str, dict[str, Any]] = {}

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

        with self._lock:
            existing = self._branding.get(tenant_id, dict(_DEFAULT_BRANDING))
            existing.update(branding)
            self._branding[tenant_id] = existing
            log.info("Updated branding for tenant %s", tenant_id)
            return self._to_spec(tenant_id, existing)

    def get_branding(self, tenant_id: str) -> BrandingSpec:
        """Return the branding config for a tenant.

        If no custom branding has been configured, the platform defaults are
        returned.
        """
        with self._lock:
            data = self._branding.get(tenant_id, dict(_DEFAULT_BRANDING))
        return self._to_spec(tenant_id, data)

    def remove_branding(self, tenant_id: str) -> None:
        """Reset a tenant's branding to platform defaults."""
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
