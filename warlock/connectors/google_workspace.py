"""Google Workspace connector — Layer 1 implementation for collaboration security.

Collects users (MFA, suspended), org units, admin activity logs, and login
audit events via the Google Admin SDK Directory API and Reports API
with service account authentication.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

try:
    from google.auth.transport.requests import Request
    from google.oauth2 import service_account

    _google_auth_available = True
except ImportError:
    _google_auth_available = False


class GoogleWorkspaceConnector(BaseConnector):
    """Collects compliance telemetry from Google Admin SDK."""

    SCOPES = [
        "https://www.googleapis.com/auth/admin.directory.user.readonly",
        "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    ]

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[google]")
        if not _google_auth_available:
            errors.append("google-auth not installed. Install with: pip install google-auth")
        if not self.get_secret("WLK_GOOGLE_SERVICE_ACCOUNT_JSON"):
            errors.append("WLK_GOOGLE_SERVICE_ACCOUNT_JSON not set")
        if not self.get_secret("WLK_GOOGLE_ADMIN_EMAIL"):
            errors.append("WLK_GOOGLE_ADMIN_EMAIL not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            admin_email = self.get_secret("WLK_GOOGLE_ADMIN_EMAIL")
            resp = client.get(
                f"https://admin.googleapis.com/admin/directory/v1/users/{admin_email}",
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="google_workspace",
            source_type=SourceType.COLLABORATION,
            provider="google",
        )

        self._collect_users(result)
        self._collect_org_units(result)
        self._collect_admin_activity(result)
        self._collect_login_audit(result)

        result.complete()
        return result

    # -- Helpers --

    def _get_credentials(self) -> service_account.Credentials:
        """Build delegated service account credentials."""
        sa_json_path = self.get_secret("WLK_GOOGLE_SERVICE_ACCOUNT_JSON")
        admin_email = self.get_secret("WLK_GOOGLE_ADMIN_EMAIL")

        # Support both file path and inline JSON
        try:
            with open(sa_json_path) as f:
                sa_info = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            sa_info = json.loads(sa_json_path)

        creds = service_account.Credentials.from_service_account_info(
            sa_info,
            scopes=self.SCOPES,
            subject=admin_email,
        )
        creds.refresh(Request())
        return creds

    def _client(self) -> httpx.Client:
        creds = self._get_credentials()
        return httpx.Client(
            timeout=self.config.timeout_seconds,
            headers={
                "Authorization": f"Bearer {creds.token}",
                "Content-Type": "application/json",
            },
        )

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="google_workspace",
            source_type=SourceType.COLLABORATION,
            provider="google",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_users(self, result: ConnectorResult) -> None:
        """Collect Google Workspace users with MFA and suspension status."""
        try:
            client = self._client()
            resp = client.get(
                "https://admin.googleapis.com/admin/directory/v1/users",
                params={
                    "customer": "my_customer",
                    "maxResults": "500",
                    "projection": "full",
                    "orderBy": "email",
                },
            )
            resp.raise_for_status()
            data = resp.json()
            users = data.get("users", [])
            result.events.append(self._raw_event("gws_users", {"users": users}))
        except Exception as e:
            log.debug("Google Workspace users collection failed: %s", e)
            result.errors.append(f"gws_users: {e}")

    def _collect_org_units(self, result: ConnectorResult) -> None:
        """Collect organizational units."""
        try:
            client = self._client()
            resp = client.get(
                "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/orgunits",
                params={"type": "all"},
            )
            resp.raise_for_status()
            data = resp.json()
            org_units = data.get("organizationUnits", [])
            result.events.append(self._raw_event("gws_org_units", {"org_units": org_units}))
        except Exception as e:
            log.debug("Google Workspace org units collection failed: %s", e)
            result.errors.append(f"gws_org_units: {e}")

    def _collect_admin_activity(self, result: ConnectorResult) -> None:
        """Collect admin activity audit logs."""
        try:
            client = self._client()
            resp = client.get(
                "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin",
                params={"maxResults": "100"},
            )
            resp.raise_for_status()
            data = resp.json()
            activities = data.get("items", [])
            result.events.append(self._raw_event("gws_admin_activity", {"activities": activities}))
        except Exception as e:
            log.debug("Google Workspace admin activity collection failed: %s", e)
            result.errors.append(f"gws_admin_activity: {e}")

    def _collect_login_audit(self, result: ConnectorResult) -> None:
        """Collect login audit events for suspicious activity detection."""
        try:
            client = self._client()
            resp = client.get(
                "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login",
                params={"maxResults": "100"},
            )
            resp.raise_for_status()
            data = resp.json()
            activities = data.get("items", [])
            result.events.append(self._raw_event("gws_login_audit", {"activities": activities}))
        except Exception as e:
            log.debug("Google Workspace login audit collection failed: %s", e)
            result.errors.append(f"gws_login_audit: {e}")


# Register
registry.register("google_workspace", GoogleWorkspaceConnector)
