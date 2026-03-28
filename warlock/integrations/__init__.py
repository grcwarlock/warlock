"""Integration registry for Warlock GRC platform.

Provides a central registry of all available integrations (Jira, ServiceNow,
Teams, Slack, PagerDuty, STIX/TAXII, Terraform) with configuration status
checking and lazy-loaded client classes.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

# Registry mapping integration name -> (module_path, class_name)
# Uses lazy imports to avoid pulling in all dependencies at startup.
_INTEGRATION_REGISTRY: dict[str, tuple[str, str]] = {
    "jira_sync": (
        "warlock.integrations.jira_sync",
        "JiraClient",
    ),
    "jira_notifier": (
        "warlock.integrations.jira_integration",
        "JiraNotifier",
    ),
    "servicenow_push": (
        "warlock.integrations.servicenow_push",
        "ServiceNowClient",
    ),
    "servicenow_notifier": (
        "warlock.integrations.servicenow_integration",
        "ServiceNowNotifier",
    ),
    "teams": (
        "warlock.integrations.teams",
        "TeamsNotifier",
    ),
    "slack": (
        "warlock.integrations.slack",
        "SlackNotifier",
    ),
    "pagerduty": (
        "warlock.integrations.pagerduty",
        "PagerDutyNotifier",
    ),
    "stix_taxii": (
        "warlock.integrations.stix_taxii",
        "TAXIIClient",
    ),
    "terraform_provider": (
        "warlock.integrations.terraform_provider",
        "TerraformProvider",
    ),
    "email_notifications": (
        "warlock.integrations.email_notifications",
        "EmailNotifier",
    ),
}


def get_integration(name: str) -> type[Any]:
    """Return the integration class for the given name.

    Args:
        name: Integration name (e.g. ``"jira_sync"``, ``"teams"``).

    Returns:
        The integration class (not an instance).

    Raises:
        KeyError: If the integration name is not registered.
        ImportError: If the integration module cannot be imported.
    """
    if name not in _INTEGRATION_REGISTRY:
        available = ", ".join(sorted(_INTEGRATION_REGISTRY.keys()))
        raise KeyError(f"Unknown integration: {name!r}. Available: {available}")

    module_path, class_name = _INTEGRATION_REGISTRY[name]

    import importlib

    module = importlib.import_module(module_path)
    cls = getattr(module, class_name)
    return cls


def list_available() -> list[dict[str, Any]]:
    """List all registered integrations with their configuration status.

    Returns:
        List of dicts with ``name``, ``class_name``, ``module``,
        ``configured`` (bool), and ``available`` (bool, import check).
    """
    results: list[dict[str, Any]] = []

    for name, (module_path, class_name) in sorted(_INTEGRATION_REGISTRY.items()):
        entry: dict[str, Any] = {
            "name": name,
            "class_name": class_name,
            "module": module_path,
            "available": False,
            "configured": False,
        }

        try:
            import importlib

            module = importlib.import_module(module_path)
            cls = getattr(module, class_name)
            entry["available"] = True

            # Check if the integration has an is_configured() method
            if hasattr(cls, "is_configured"):
                entry["configured"] = cls.is_configured()
        except ImportError as exc:
            log.debug("Integration %s not available (import failed): %s", name, exc)
        except Exception as exc:
            log.debug("Integration %s configuration check failed: %s", name, exc)

        results.append(entry)

    return results


# Convenience re-exports for direct imports
INTEGRATIONS = _INTEGRATION_REGISTRY

__all__ = [
    "INTEGRATIONS",
    "get_integration",
    "list_available",
]
