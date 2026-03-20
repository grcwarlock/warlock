"""Connector configuration management with credential testing."""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from warlock.db.models import ConnectorRun

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Known connector environment variable requirements
# ---------------------------------------------------------------------------

_CONNECTOR_ENV_VARS: dict[str, list[dict[str, Any]]] = {
    "aws": [
        {
            "name": "AWS_ACCESS_KEY_ID",
            "required": False,
            "description": "AWS access key (or use IAM role)",
        },
        {"name": "AWS_SECRET_ACCESS_KEY", "required": False, "description": "AWS secret key"},
        {"name": "AWS_DEFAULT_REGION", "required": False, "description": "Default AWS region"},
        {
            "name": "WLK_AWS_ASSUME_ROLE_ARN",
            "required": False,
            "description": "IAM role ARN to assume",
        },
    ],
    "azure": [
        {"name": "AZURE_SUBSCRIPTION_ID", "required": True, "description": "Azure subscription ID"},
        {"name": "AZURE_TENANT_ID", "required": True, "description": "Azure AD tenant ID"},
        {
            "name": "AZURE_CLIENT_ID",
            "required": False,
            "description": "Service principal client ID",
        },
        {
            "name": "AZURE_CLIENT_SECRET",
            "required": False,
            "description": "Service principal secret",
        },
    ],
    "gcp": [
        {
            "name": "GOOGLE_APPLICATION_CREDENTIALS",
            "required": False,
            "description": "Path to service account JSON",
        },
        {"name": "WLK_GCP_PROJECT_ID", "required": True, "description": "GCP project ID"},
    ],
    "crowdstrike": [
        {
            "name": "CROWDSTRIKE_CLIENT_ID",
            "required": True,
            "description": "CrowdStrike API client ID",
        },
        {
            "name": "CROWDSTRIKE_CLIENT_SECRET",
            "required": True,
            "description": "CrowdStrike API client secret",
        },
    ],
    "okta": [
        {
            "name": "WLK_OKTA_DOMAIN",
            "required": True,
            "description": "Okta domain (e.g. dev-12345.okta.com)",
        },
        {"name": "WLK_OKTA_API_TOKEN", "required": True, "description": "Okta API token"},
    ],
    "tenable": [
        {"name": "TENABLE_ACCESS_KEY", "required": True, "description": "Tenable.io access key"},
        {"name": "TENABLE_SECRET_KEY", "required": True, "description": "Tenable.io secret key"},
    ],
    "defender": [
        {"name": "WLK_DEFENDER_TENANT_ID", "required": True, "description": "Azure AD tenant ID"},
        {
            "name": "WLK_DEFENDER_CLIENT_ID",
            "required": True,
            "description": "App registration client ID",
        },
        {
            "name": "WLK_DEFENDER_CLIENT_SECRET",
            "required": True,
            "description": "App registration secret",
        },
    ],
    "sentinelone": [
        {
            "name": "WLK_SENTINELONE_BASE_URL",
            "required": True,
            "description": "SentinelOne console URL",
        },
        {
            "name": "WLK_SENTINELONE_API_TOKEN",
            "required": True,
            "description": "SentinelOne API token",
        },
    ],
    "snyk": [
        {"name": "SNYK_TOKEN", "required": True, "description": "Snyk API token"},
        {"name": "WLK_SNYK_ORG_ID", "required": True, "description": "Snyk organization ID"},
    ],
    "securityscorecard": [
        {
            "name": "SECURITYSCORECARD_API_KEY",
            "required": True,
            "description": "SecurityScorecard API key",
        },
    ],
}


class ToolConfigManager:
    """Manage connector configurations and test connectivity."""

    def list_connectors(self) -> list[dict[str, Any]]:
        """Return all registered connectors with their config status.

        Shows: provider, source_type, enabled, configured (has required env vars), last_test.
        """
        try:
            from warlock.connectors.base import registry
            from warlock.pipeline.loader import load_all_connectors

            load_all_connectors()
            providers = registry.list_types()
        except Exception:
            providers = []

        results = []
        for provider in sorted(providers):
            env_vars = self.get_required_env_vars(provider)
            required_vars = [v for v in env_vars if v["required"]]
            all_required_set = all(v["is_set"] for v in required_vars) if required_vars else True

            results.append(
                {
                    "provider": provider,
                    "source_type": self._get_source_type(provider),
                    "enabled": self._is_enabled(provider),
                    "configured": all_required_set,
                    "required_env_vars": len(required_vars),
                    "env_vars_set": sum(1 for v in required_vars if v["is_set"]),
                }
            )

        return results

    def test_connector(self, session: Session, provider: str) -> dict[str, Any]:
        """Test a connector's health_check and return result.

        Returns: {provider, success, latency_ms, error, tested_at}.
        """
        try:
            from warlock.connectors.base import registry
            from warlock.pipeline.loader import load_all_connectors

            load_all_connectors()
        except Exception as exc:
            return {
                "provider": provider,
                "success": False,
                "latency_ms": 0,
                "error": f"Failed to load connectors: {exc}",
                "tested_at": datetime.now(timezone.utc).isoformat(),
            }

        # Find the active connector or try to get the registered type
        connector = None
        for name in registry.list_active():
            c = registry.get(name)
            if c and c.provider == provider:
                connector = c
                break

        if connector is None:
            # Try to instantiate from the registered type
            try:
                from warlock.connectors.base import ConnectorConfig, SourceType

                types = registry._types
                if provider not in types:
                    return {
                        "provider": provider,
                        "success": False,
                        "latency_ms": 0,
                        "error": f"Connector not registered: {provider}",
                        "tested_at": datetime.now(timezone.utc).isoformat(),
                    }
                cls = types[provider]
                config = ConnectorConfig(
                    name=f"{provider}_test",
                    source_type=SourceType.CUSTOM,
                    provider=provider,
                )
                connector = cls(config)
            except Exception as exc:
                return {
                    "provider": provider,
                    "success": False,
                    "latency_ms": 0,
                    "error": f"Failed to instantiate: {exc}",
                    "tested_at": datetime.now(timezone.utc).isoformat(),
                }

        # Run health check
        start = time.monotonic()
        try:
            success = connector.health_check()
            latency_ms = round((time.monotonic() - start) * 1000, 1)
            error = None if success else "Health check returned False"
        except Exception as exc:
            latency_ms = round((time.monotonic() - start) * 1000, 1)
            success = False
            error = str(exc)

        return {
            "provider": provider,
            "success": success,
            "latency_ms": latency_ms,
            "error": error,
            "tested_at": datetime.now(timezone.utc).isoformat(),
        }

    def test_all(self, session: Session) -> list[dict[str, Any]]:
        """Test all enabled connectors."""
        connectors = self.list_connectors()
        results = []
        for conn in connectors:
            if conn.get("enabled"):
                result = self.test_connector(session, conn["provider"])
                results.append(result)
        return results

    def get_required_env_vars(self, provider: str) -> list[dict[str, Any]]:
        """Return required env vars for a connector with set/unset status.

        ``[{name, required, is_set, description}]``
        """
        known = _CONNECTOR_ENV_VARS.get(provider, [])
        if not known:
            # Return generic WLK_<PROVIDER>_ENABLED check
            env_name = f"WLK_{provider.upper()}_ENABLED"
            return [
                {
                    "name": env_name,
                    "required": False,
                    "is_set": bool(os.environ.get(env_name, "")),
                    "description": f"Enable {provider} connector",
                }
            ]

        return [
            {
                "name": v["name"],
                "required": v.get("required", False),
                "is_set": bool(os.environ.get(v["name"], "")),
                "description": v.get("description", ""),
            }
            for v in known
        ]

    def connection_history(
        self,
        session: Session,
        provider: str,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Return recent ConnectorRun results for a provider."""
        runs = (
            session.query(ConnectorRun)
            .filter(ConnectorRun.provider == provider)
            .order_by(ConnectorRun.started_at.desc())
            .limit(limit)
            .all()
        )

        return [
            {
                "id": r.id,
                "connector_name": r.connector_name,
                "status": r.status,
                "event_count": r.event_count,
                "error_count": r.error_count,
                "errors": r.errors,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                "duration_seconds": r.duration_seconds,
            }
            for r in runs
        ]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_source_type(self, provider: str) -> str:
        """Best-effort source type lookup."""
        _map = {
            "aws": "cloud",
            "azure": "cloud",
            "gcp": "cloud",
            "crowdstrike": "edr",
            "defender": "edr",
            "sentinelone": "edr",
            "okta": "iam",
            "entra_id": "iam",
            "cyberark": "iam",
            "sailpoint": "iam",
            "tenable": "scanner",
            "qualys": "scanner",
            "wiz": "scanner",
            "sentinel": "siem",
            "splunk": "siem",
            "elastic": "siem",
            "snyk": "code",
            "github": "code",
            "securityscorecard": "grc",
            "servicenow": "itsm",
            "knowbe4": "training",
            "confluence": "grc",
        }
        return _map.get(provider, "custom")

    def _is_enabled(self, provider: str) -> bool:
        """Check if a connector is enabled via env var."""
        env_name = f"WLK_{provider.upper()}_ENABLED"
        val = os.environ.get(env_name, "").lower()
        return val in ("true", "1", "yes")
