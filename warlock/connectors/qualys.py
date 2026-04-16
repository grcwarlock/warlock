"""Qualys VMDR connector — Layer 1 implementation for vulnerability scanning.

Collects host detections (severity 4+5), knowledge base entries,
compliance posture, and asset inventory via Qualys REST API.
"""

from __future__ import annotations

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
    from defusedxml import ElementTree as ET  # N13: XXE/billion-laughs safe
except ImportError:
    ET = None  # type: ignore[assignment,misc]


def _xml_to_dict(element) -> dict:
    """Recursively convert an XML element to a dict."""
    result: dict = {}
    for child in element:
        tag = child.tag
        if len(child):
            value = _xml_to_dict(child)
        else:
            value = child.text or ""  # type: ignore[assignment]
        if tag in result:
            if not isinstance(result[tag], list):
                result[tag] = [result[tag]]
            result[tag].append(value)
        else:
            result[tag] = value
    return result


class QualysConnector(BaseConnector):
    """Collects compliance telemetry from Qualys VMDR APIs."""

    def validate(self) -> list[str]:
        errors = []
        if httpx is None:
            errors.append("httpx not installed. Install with: pip install warlock[qualys]")
        if not self.get_secret("QUALYS_USERNAME"):
            errors.append("QUALYS_USERNAME env var not set")
        if not self.get_secret("QUALYS_PASSWORD"):
            errors.append("QUALYS_PASSWORD env var not set")
        if not self.config.settings.get("api_url"):
            errors.append("settings.api_url not set (e.g. https://qualysapi.qualys.com)")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._client()
            resp = client.get(f"{self._api_url}/msp/about.php")
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        if httpx is None:
            raise RuntimeError("QualysConnector requires httpx. Install with: pip install httpx")
        result = ConnectorResult(
            connector_name=self.name,
            source="qualys",
            source_type=SourceType.SCANNER,
            provider="qualys",
        )

        client = self._client()

        self._collect_host_detections(client, result)
        self._collect_knowledgebase(client, result)
        self._collect_compliance(client, result)
        self._collect_assets(client, result)

        result.complete()
        return result

    @property
    def _api_url(self) -> str:
        return self.config.settings.get("api_url", "https://qualysapi.qualys.com").rstrip("/")

    def _client(self) -> httpx.Client:
        return httpx.Client(
            auth=(
                self.get_secret("QUALYS_USERNAME"),
                self.get_secret("QUALYS_PASSWORD"),
            ),
            headers={
                "X-Requested-With": "warlock",
            },
            timeout=self.config.timeout_seconds,
        )

    def _parse_xml(self, text: str) -> dict:
        """Parse XML response into dict."""
        root = ET.fromstring(text)
        return _xml_to_dict(root)

    def _collect_host_detections(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect host detections with severity 4 (Potential) and 5 (Confirmed)."""
        try:
            resp = client.post(
                f"{self._api_url}/api/2.0/fo/asset/host/vm/detection/",
                data={
                    "action": "list",
                    "severities": "4,5",
                    "status": "New,Active,Re-Opened",
                    "truncation_limit": self.config.settings.get("detection_limit", 1000),
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            data = self._parse_xml(resp.text)

            result.events.append(
                RawEventData(
                    source="qualys",
                    source_type=SourceType.SCANNER,
                    provider="qualys",
                    event_type="host_detections",
                    raw_data={"detections": data},
                    observed_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            log.debug("Qualys host detections failed: %s", e)
            result.errors.append(f"host_detections: {e}")

    def _collect_knowledgebase(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect knowledge base entries for detected QIDs."""
        try:
            resp = client.post(
                f"{self._api_url}/api/2.0/fo/knowledge_base/vuln/",
                data={
                    "action": "list",
                    "details": "All",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            data = self._parse_xml(resp.text)

            result.events.append(
                RawEventData(
                    source="qualys",
                    source_type=SourceType.SCANNER,
                    provider="qualys",
                    event_type="knowledge_base",
                    raw_data={"knowledge_base": data},
                    observed_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            log.debug("Qualys knowledge base failed: %s", e)
            result.errors.append(f"knowledge_base: {e}")

    def _collect_compliance(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect compliance posture data."""
        try:
            resp = client.post(
                f"{self._api_url}/api/2.0/fo/compliance/posture/info/",
                data={
                    "action": "list",
                    "truncation_limit": self.config.settings.get("compliance_limit", 1000),
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            data = self._parse_xml(resp.text)

            result.events.append(
                RawEventData(
                    source="qualys",
                    source_type=SourceType.SCANNER,
                    provider="qualys",
                    event_type="compliance_posture",
                    raw_data={"posture": data},
                    observed_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            log.debug("Qualys compliance posture failed: %s", e)
            result.errors.append(f"compliance_posture: {e}")

    def _collect_assets(self, client: httpx.Client, result: ConnectorResult) -> None:
        """Collect asset inventory."""
        try:
            resp = client.post(
                f"{self._api_url}/api/2.0/fo/asset/host/",
                data={
                    "action": "list",
                    "truncation_limit": self.config.settings.get("asset_limit", 1000),
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            data = self._parse_xml(resp.text)

            result.events.append(
                RawEventData(
                    source="qualys",
                    source_type=SourceType.SCANNER,
                    provider="qualys",
                    event_type="asset_inventory",
                    raw_data={"hosts": data},
                    observed_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            log.debug("Qualys asset inventory failed: %s", e)
            result.errors.append(f"asset_inventory: {e}")


# Register
registry.register("qualys", QualysConnector)
