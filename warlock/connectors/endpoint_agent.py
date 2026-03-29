"""Endpoint compliance agent connector.

Collects endpoint compliance telemetry (OS patch level, encryption status,
AV status, firewall state) from agent reports. Designed to ingest reports
from MDM/EDR agents (Intune, Jamf, CrowdStrike, SentinelOne) or a custom
Warlock endpoint agent.

Schema
------
Each agent report is a JSON object with:

- ``hostname``        -- device hostname
- ``os``              -- operating system name
- ``os_version``      -- OS version string
- ``encrypted``       -- disk encryption enabled (bool)
- ``av_enabled``      -- antivirus active (bool)
- ``firewall_enabled``-- host firewall active (bool)
- ``patch_level``     -- days since last OS patch (int)
- ``agent_version``   -- reporting agent version
- ``last_seen``       -- ISO timestamp of last check-in
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
)

log = logging.getLogger(__name__)


@dataclass
class EndpointComplianceReport:
    """Parsed endpoint compliance report."""

    hostname: str = ""
    os: str = ""
    os_version: str = ""
    encrypted: bool = False
    av_enabled: bool = False
    firewall_enabled: bool = False
    patch_level: int = 0
    agent_version: str = ""
    last_seen: str = ""
    compliant: bool = False
    issues: list[str] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EndpointComplianceReport":
        issues: list[str] = []
        encrypted = bool(data.get("encrypted", False))
        av_enabled = bool(data.get("av_enabled", False))
        firewall_enabled = bool(data.get("firewall_enabled", False))
        patch_level = int(data.get("patch_level", 0))

        if not encrypted:
            issues.append("disk_encryption_disabled")
        if not av_enabled:
            issues.append("antivirus_disabled")
        if not firewall_enabled:
            issues.append("firewall_disabled")
        if patch_level > 30:
            issues.append(f"patch_overdue_{patch_level}d")

        return cls(
            hostname=str(data.get("hostname", "")),
            os=str(data.get("os", "")),
            os_version=str(data.get("os_version", "")),
            encrypted=encrypted,
            av_enabled=av_enabled,
            firewall_enabled=firewall_enabled,
            patch_level=patch_level,
            agent_version=str(data.get("agent_version", "")),
            last_seen=str(data.get("last_seen", "")),
            compliant=len(issues) == 0,
            issues=issues,
        )


class EndpointAgentConnector(BaseConnector):
    """Connector for endpoint compliance agent reports."""

    name = "endpoint_agent"
    source_type = SourceType.MDM
    description = "Endpoint compliance agent telemetry"

    def validate(self) -> list[str]:
        """Validate connector configuration."""
        return []

    def health_check(self) -> bool:
        """Check if the endpoint agent source is reachable."""
        return True

    def collect(self) -> ConnectorResult:
        """Collect endpoint reports.

        In production this would poll an MDM/EDR API. For demo purposes,
        returns synthetic endpoint data.
        """
        result = ConnectorResult(
            connector_name=self.name,
            source=self.name,
            source_type=self.source_type,
            provider="endpoint_agent",
        )

        # Demo: generate sample endpoint reports
        endpoints = self._generate_demo_endpoints()

        for ep in endpoints:
            EndpointComplianceReport.from_dict(ep)  # validate schema
            raw = RawEventData(
                source=self.name,
                source_type=self.source_type,
                provider="endpoint_agent",
                event_type="endpoint_compliance",
                raw_data=ep,
            )
            result.events.append(raw)

        result.complete()
        return result

    def _generate_demo_endpoints(self) -> list[dict[str, Any]]:
        """Generate synthetic endpoint compliance data for demo."""
        now = datetime.now(timezone.utc).isoformat()
        return [
            {
                "hostname": "laptop-001",
                "os": "macOS",
                "os_version": "15.3",
                "encrypted": True,
                "av_enabled": True,
                "firewall_enabled": True,
                "patch_level": 5,
                "agent_version": "1.0.0",
                "last_seen": now,
            },
            {
                "hostname": "desktop-042",
                "os": "Windows",
                "os_version": "11 23H2",
                "encrypted": False,
                "av_enabled": True,
                "firewall_enabled": True,
                "patch_level": 45,
                "agent_version": "1.0.0",
                "last_seen": now,
            },
            {
                "hostname": "server-prod-03",
                "os": "Ubuntu",
                "os_version": "24.04",
                "encrypted": True,
                "av_enabled": False,
                "firewall_enabled": True,
                "patch_level": 12,
                "agent_version": "1.0.0",
                "last_seen": now,
            },
        ]
