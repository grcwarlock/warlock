"""Physical security connector — multi-vendor access control systems (GAP-087).

Collects access events and door status from physical security platforms:
Lenel/S2, Genetec, HID Global. Vendor is selected via WLK_PHYSICAL_VENDOR.
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

    _HAS_HTTPX = True
except ImportError:
    httpx = None  # type: ignore[assignment]
    _HAS_HTTPX = False

# Vendor-specific API paths
_VENDOR_CONFIGS: dict[str, dict[str, list[tuple[str, str]]]] = {
    "lenel": {
        "base_path": "/api/v1",
        "endpoints": [
            ("/access/events", "physical_access_events"),
            ("/doors/status", "physical_door_status"),
            ("/badges/active", "physical_badge_inventory"),
        ],
    },
    "genetec": {
        "base_path": "/api/v2",
        "endpoints": [
            ("/AccessEvents", "physical_access_events"),
            ("/DoorStatus", "physical_door_status"),
            ("/Cardholders", "physical_badge_inventory"),
        ],
    },
    "hid_global": {
        "base_path": "/aam/api/v1",
        "endpoints": [
            ("/events/access", "physical_access_events"),
            ("/doors", "physical_door_status"),
            ("/credentials", "physical_badge_inventory"),
        ],
    },
}


class PhysicalSecurityConnector(BaseConnector):
    """Collects access events from physical security systems."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not _HAS_HTTPX:
            errors.append("httpx not installed. Install with: pip install httpx")
        if not self.get_secret("WLK_PHYSICAL_API_URL"):
            errors.append("WLK_PHYSICAL_API_URL not set")
        if not self.get_secret("WLK_PHYSICAL_API_KEY"):
            errors.append("WLK_PHYSICAL_API_KEY not set")
        vendor = self.get_secret("WLK_PHYSICAL_VENDOR") or "lenel"
        if vendor not in _VENDOR_CONFIGS:
            errors.append(
                f"WLK_PHYSICAL_VENDOR={vendor} not supported. Options: {', '.join(_VENDOR_CONFIGS)}"
            )
        return errors

    def health_check(self) -> bool:
        try:
            base_url = self.get_secret("WLK_PHYSICAL_API_URL")
            api_key = self.get_secret("WLK_PHYSICAL_API_KEY")
            resp = httpx.get(
                f"{base_url}/health",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="physical_security",
            source_type=SourceType.PHYSICAL,
            provider="physical_security",
        )

        base_url = self.get_secret("WLK_PHYSICAL_API_URL").rstrip("/")
        api_key = self.get_secret("WLK_PHYSICAL_API_KEY")
        vendor = self.get_secret("WLK_PHYSICAL_VENDOR") or "lenel"
        vendor_cfg = _VENDOR_CONFIGS.get(vendor, _VENDOR_CONFIGS["lenel"])

        client = httpx.Client(
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout=self.config.timeout_seconds,
        )

        base_path = vendor_cfg.get("base_path", "")
        try:
            for endpoint, event_type in vendor_cfg.get("endpoints", []):
                try:
                    url = f"{base_url}{base_path}{endpoint}"
                    resp = client.get(url)
                    resp.raise_for_status()
                    data = resp.json()
                    result.events.append(
                        RawEventData(
                            source="physical_security",
                            source_type=SourceType.PHYSICAL,
                            provider=f"physical_security:{vendor}",
                            event_type=event_type,
                            raw_data={
                                "vendor": vendor,
                                "endpoint": endpoint,
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("Physical security %s failed: %s", endpoint, e)
                    result.errors.append(f"{event_type}: {e}")
        finally:
            client.close()

        result.complete()
        return result


registry.register("physical_security", PhysicalSecurityConnector)
