"""Platform infrastructure modules for multi-tenancy, white-label, delegation, sandboxing, and import."""

from __future__ import annotations

from warlock.platform.bulk_import import BulkImporter
from warlock.platform.delegation import DelegationManager
from warlock.platform.legacy_import import LegacyImporter
from warlock.platform.sandbox import SandboxManager
from warlock.platform.tenancy import TenantManager
from warlock.platform.white_label import WhiteLabelConfig

__all__ = [
    "TenantManager",
    "WhiteLabelConfig",
    "DelegationManager",
    "SandboxManager",
    "LegacyImporter",
    "BulkImporter",
]


def list_platform_features() -> list[dict[str, object]]:
    """Return a list of platform features with enabled/disabled status.

    Each feature is considered enabled if its manager class can be instantiated
    without error.  This is a lightweight check -- it does not verify external
    dependencies like database connectivity.
    """
    features: list[dict[str, object]] = []
    registry: list[tuple[str, str, type]] = [
        ("multi_tenancy", "Tenant isolation and scoped queries", TenantManager),
        ("white_label", "Custom branding per tenant", WhiteLabelConfig),
        ("delegation", "Role hierarchy and delegated admin", DelegationManager),
        ("sandbox", "Staging/sandbox environments", SandboxManager),
        ("legacy_import", "Import from Archer, ServiceNow GRC, spreadsheets", LegacyImporter),
        (
            "bulk_import",
            "Bulk CSV/JSON/Excel import for findings, vendors, personnel",
            BulkImporter,
        ),
    ]
    for name, description, cls in registry:
        try:
            cls()
            enabled = True
        except Exception:
            enabled = False
        features.append({"name": name, "description": description, "enabled": enabled})
    return features
