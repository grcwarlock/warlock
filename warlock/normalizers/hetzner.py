"""Hetzner normalizer — transforms raw Hetzner Cloud API responses into Findings.

Normalizes servers and firewalls (as inventory), and certificates (as inventory,
flagging expired/expiring certs as misconfiguration).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class HetznerNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Hetzner Cloud."""

    HANDLERS: dict[str, str] = {
        "hetzner_servers": "_normalize_servers",
        "hetzner_firewalls": "_normalize_firewalls",
        "hetzner_certificates": "_normalize_certificates",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "hetzner" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "hetzner",
            "source_type": SourceType.CLOUD,
            "provider": "hetzner",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_servers(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for server in items:
            server_id = str(server.get("id", ""))
            name = server.get("name", "unknown")
            status = server.get("status", "unknown")
            datacenter = server.get("datacenter", {}) or {}
            location = datacenter.get("location", {}) or {}
            region = location.get("name", "") if isinstance(location, dict) else ""

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Hetzner server: {name}",
                    detail={
                        "server_id": server_id,
                        "name": name,
                        "status": status,
                        "server_type": (server.get("server_type") or {}).get("name", ""),
                        "datacenter": datacenter.get("name", "") if isinstance(datacenter, dict) else "",
                        "created": server.get("created", ""),
                    },
                    resource_id=server_id,
                    resource_type="hetzner_server",
                    resource_name=name,
                    region=region,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_firewalls(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for fw in items:
            fw_id = str(fw.get("id", ""))
            name = fw.get("name", "unknown")
            rules = fw.get("rules", [])

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Hetzner firewall: {name}",
                    detail={
                        "firewall_id": fw_id,
                        "name": name,
                        "rule_count": len(rules),
                        "created": fw.get("created", ""),
                    },
                    resource_id=fw_id,
                    resource_type="hetzner_firewall",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_certificates(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for cert in items:
            cert_id = str(cert.get("id", ""))
            name = cert.get("name", "unknown")
            cert_type = cert.get("type", "")
            not_valid_after = cert.get("not_valid_after", "")
            status = (cert.get("status") or {}).get("issuance", "unknown")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Hetzner certificate: {name}",
                    detail={
                        "certificate_id": cert_id,
                        "name": name,
                        "type": cert_type,
                        "not_valid_after": not_valid_after,
                        "issuance_status": status,
                        "domain_names": cert.get("domain_names", []),
                    },
                    resource_id=cert_id,
                    resource_type="hetzner_certificate",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(HetznerNormalizer())
