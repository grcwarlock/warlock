"""runZero normalizer — transforms raw runZero API responses into Findings.

Normalizes network assets, services, and wireless endpoints as inventory findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class RunZeroNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "runzero_assets": "_normalize_assets",
        "runzero_services": "_normalize_services",
        "runzero_wireless": "_normalize_wireless",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "runzero" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all runZero findings."""
        return {
            "raw_event_id": raw.id,
            "source": "runzero",
            "source_type": SourceType.CUSTOM,
            "provider": "runzero",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _extract_items(self, raw: RawEventData) -> list:
        """Extract items list from response."""
        items = raw.raw_data.get("response", [])
        if isinstance(items, dict):
            items = items.get("data", items.get("results", [items]))
        return items if isinstance(items, list) else [items]

    # -- Assets --

    def _normalize_assets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = self._extract_items(raw)

        for asset in items:
            asset_id = str(asset.get("id", ""))
            names = asset.get("names", [])
            hostname = names[0] if names else asset.get("address", "unknown")
            os_str = asset.get("os", "")
            alive = asset.get("alive", True)

            # Flag assets that haven't been seen alive as low severity
            severity = "info" if alive else "low"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"runZero asset: {hostname}",
                    detail={
                        "asset_id": asset_id,
                        "hostname": hostname,
                        "address": asset.get("address", ""),
                        "os": os_str,
                        "alive": alive,
                        "type": asset.get("type", ""),
                        "hw": asset.get("hw", ""),
                        "first_seen": asset.get("first_seen", 0),
                        "last_seen": asset.get("last_seen", 0),
                        "tags": asset.get("tags", {}),
                    },
                    resource_id=asset_id,
                    resource_type="runzero_asset",
                    resource_name=str(hostname),
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    # -- Services --

    def _normalize_services(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = self._extract_items(raw)

        for service in items:
            service_id = str(service.get("id", ""))
            asset_id = str(service.get("asset_id", ""))
            port = service.get("port", 0)
            proto = service.get("protocol", "")
            transport = service.get("transport", "")
            service_name = f"{proto}/{transport}:{port}" if port else service_id

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"runZero service: {service_name}",
                    detail={
                        "service_id": service_id,
                        "asset_id": asset_id,
                        "port": port,
                        "protocol": proto,
                        "transport": transport,
                        "summary": service.get("summary", ""),
                        "first_seen": service.get("first_seen", 0),
                        "last_seen": service.get("last_seen", 0),
                    },
                    resource_id=service_id,
                    resource_type="runzero_service",
                    resource_name=service_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    # -- Wireless --

    def _normalize_wireless(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = self._extract_items(raw)

        for wireless in items:
            wireless_id = str(wireless.get("id", ""))
            ssid = wireless.get("ssid", "unknown")
            bssid = wireless.get("bssid", "")
            band = wireless.get("band", "")
            security = wireless.get("security", "")

            # Flag open/no-security wireless networks
            severity = "info"
            obs_type = "inventory"
            if security in ("", "open", "none"):
                severity = "high"
                obs_type = "misconfiguration"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"runZero wireless: {ssid}" + (" (open)" if severity == "high" else ""),
                    detail={
                        "wireless_id": wireless_id,
                        "ssid": ssid,
                        "bssid": bssid,
                        "band": band,
                        "security": security,
                        "first_seen": wireless.get("first_seen", 0),
                        "last_seen": wireless.get("last_seen", 0),
                    },
                    resource_id=wireless_id,
                    resource_type="runzero_wireless",
                    resource_name=ssid,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(RunZeroNormalizer())
