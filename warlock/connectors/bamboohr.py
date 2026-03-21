"""BambooHR connector — Layer 1 implementation for HRIS data.

Collects employee directory, employee details (status, department,
hire/termination dates), and recent changes via BambooHR REST API.
"""

from __future__ import annotations

import base64
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


class BambooHRConnector(BaseConnector):
    """Collects compliance telemetry from BambooHR REST API."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[bamboohr]")
        if not self.get_secret("WLK_BAMBOOHR_API_KEY"):
            errors.append("WLK_BAMBOOHR_API_KEY not set")
        if not self.get_secret("WLK_BAMBOOHR_SUBDOMAIN"):
            errors.append("WLK_BAMBOOHR_SUBDOMAIN not set (e.g. 'mycompany')")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{self._base_url()}/v1/meta/fields")
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="bamboohr",
            source_type=SourceType.HRIS,
            provider="bamboohr",
        )

        client = self._client()

        self._collect_employees(client, result)
        self._collect_directory(client, result)
        self._collect_changes(client, result)

        result.complete()
        return result

    # -- Auth & Client --

    def _base_url(self) -> str:
        subdomain = self.get_secret("WLK_BAMBOOHR_SUBDOMAIN")
        return f"https://api.bamboohr.com/api/gateway.php/{subdomain}"

    def _client(self) -> httpx.Client:
        api_key = self.get_secret("WLK_BAMBOOHR_API_KEY")
        # BambooHR uses basic auth: API key as username, "x" as password
        credentials = base64.b64encode(f"{api_key}:x".encode()).decode()
        headers = {
            "Accept": "application/json",
            "Authorization": f"Basic {credentials}",
        }
        return httpx.Client(headers=headers, timeout=self.config.timeout_seconds)

    # -- Event helpers --

    def _raw_event(self, event_type: str, data: dict) -> RawEventData:
        return RawEventData(
            source="bamboohr",
            source_type=SourceType.HRIS,
            provider="bamboohr",
            event_type=event_type,
            raw_data=data,
            observed_at=datetime.now(timezone.utc),
        )

    # -- Collectors --

    def _collect_employees(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect employee report with key fields for GRC assessment."""
        try:
            # Use the custom report endpoint to get specific fields
            report_fields = [
                "id",
                "displayName",
                "firstName",
                "lastName",
                "jobTitle",
                "department",
                "division",
                "status",
                "employeeNumber",
                "hireDate",
                "terminationDate",
                "supervisorId",
                "supervisor",
                "workEmail",
                "location",
                "employmentHistoryStatus",
            ]
            fields_xml = "".join(f'<field id="{f}" />' for f in report_fields)
            body = f"<report><fields>{fields_xml}</fields></report>"

            resp = client.post(
                f"{self._base_url()}/v1/reports/custom",
                content=body,
                params={"format": "JSON"},
                headers={"Content-Type": "application/xml"},
            )
            resp.raise_for_status()
            data = resp.json()
            employees = data.get("employees", [])

            result.events.append(self._raw_event("bamboohr_employees", {"employees": employees}))
        except Exception as e:
            log.debug("BambooHR employees collection failed: %s", e)
            result.errors.append(f"bamboohr_employees: {e}")

    def _collect_directory(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect the employee directory."""
        try:
            resp = client.get(f"{self._base_url()}/v1/employees/directory")
            resp.raise_for_status()
            data = resp.json()
            employees = data.get("employees", [])

            result.events.append(self._raw_event("bamboohr_directory", {"employees": employees}))
        except Exception as e:
            log.debug("BambooHR directory collection failed: %s", e)
            result.errors.append(f"bamboohr_directory: {e}")

    def _collect_changes(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect recent employee changes (last changed since)."""
        try:
            # Get changes from the last 30 days
            resp = client.get(
                f"{self._base_url()}/v1/employees/changed",
                params={"type": "all"},
            )
            resp.raise_for_status()
            data = resp.json()
            # The response is a dict of employee_id -> {changes}
            changes = data.get("employees", data) if isinstance(data, dict) else data

            result.events.append(self._raw_event("bamboohr_changes", {"changes": changes}))
        except Exception as e:
            log.debug("BambooHR changes collection failed: %s", e)
            result.errors.append(f"bamboohr_changes: {e}")


# Register
registry.register("bamboohr", BambooHRConnector)
