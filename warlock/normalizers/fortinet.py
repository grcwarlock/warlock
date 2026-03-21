"""Fortinet FortiGate normalizer — transforms raw FortiGate API responses into Findings.

Handles firewall policies, IPS threat logs, system status, VPN tunnels,
and antivirus events.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class FortinetNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "forti_firewall_policies": "_normalize_firewall_policies",
        "forti_threat_logs": "_normalize_threat_logs",
        "forti_system_status": "_normalize_system_status",
        "forti_vpn_tunnels": "_normalize_vpn_tunnels",
        "forti_antivirus": "_normalize_antivirus",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "fortinet" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Fortinet findings."""
        return {
            "raw_event_id": raw.id,
            "source": "fortinet",
            "source_type": SourceType.NETWORK,
            "provider": "fortinet",
            "observed_at": raw.observed_at,
        }

    # -- Firewall Policies --

    def _normalize_firewall_policies(self, raw: RawEventData) -> list[FindingData]:
        """Inventory firewall policies; flag disabled and overly permissive rules."""
        findings = []
        policies = raw.raw_data.get("policies", [])

        for policy in policies:
            policy_id = str(policy.get("policyid", policy.get("id", "")))
            name = policy.get("name", f"policy-{policy_id}")
            status = policy.get("status", "enable")
            action = policy.get("action", "")
            srcaddr = policy.get("srcaddr", [])
            dstaddr = policy.get("dstaddr", [])
            service = policy.get("service", [])
            srcintf = policy.get("srcintf", [])
            dstintf = policy.get("dstintf", [])
            logtraffic = policy.get("logtraffic", "")

            src_names = self._get_addr_names(srcaddr)
            dst_names = self._get_addr_names(dstaddr)
            svc_names = self._get_addr_names(service)

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Firewall policy: {name} ({action})",
                    detail={
                        "policy_id": policy_id,
                        "name": name,
                        "status": status,
                        "action": action,
                        "srcaddr": src_names,
                        "dstaddr": dst_names,
                        "service": svc_names,
                        "srcintf": self._get_addr_names(srcintf),
                        "dstintf": self._get_addr_names(dstintf),
                        "logtraffic": logtraffic,
                    },
                    resource_id=policy_id,
                    resource_type="fortinet_firewall_policy",
                    resource_name=name,
                    severity="info",
                )
            )

            # Flag disabled policies
            if status == "disable":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Firewall policy disabled: {name}",
                        detail={
                            "policy_id": policy_id,
                            "name": name,
                            "status": status,
                            "issue": "Firewall policy is disabled and not enforcing rules",
                        },
                        resource_id=policy_id,
                        resource_type="fortinet_firewall_policy",
                        resource_name=name,
                        severity="medium",
                    )
                )

            # Flag overly permissive rules (srcaddr/dstaddr = "all")
            is_all_src = "all" in src_names
            is_all_dst = "all" in dst_names
            is_accept = action in ("accept", "")

            if is_accept and is_all_src and is_all_dst:
                severity = "critical" if "ALL" in svc_names or "all" in svc_names else "high"
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Overly permissive policy: {name} (all/all)",
                        detail={
                            "policy_id": policy_id,
                            "name": name,
                            "action": action,
                            "srcaddr": src_names,
                            "dstaddr": dst_names,
                            "service": svc_names,
                            "issue": "Policy allows traffic from all sources to all destinations",
                        },
                        resource_id=policy_id,
                        resource_type="fortinet_firewall_policy",
                        resource_name=name,
                        severity=severity,
                    )
                )

            # Flag policies with logging disabled
            if logtraffic == "disable":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Traffic logging disabled on policy: {name}",
                        detail={
                            "policy_id": policy_id,
                            "name": name,
                            "logtraffic": logtraffic,
                            "issue": "Traffic logging is disabled — reduces audit trail visibility",
                        },
                        resource_id=policy_id,
                        resource_type="fortinet_firewall_policy",
                        resource_name=name,
                        severity="medium",
                    )
                )

        return findings

    @staticmethod
    def _get_addr_names(addr_list: list | str) -> list[str]:
        """Extract address names from FortiGate address objects."""
        if isinstance(addr_list, str):
            return [addr_list]
        if isinstance(addr_list, list):
            names = []
            for item in addr_list:
                if isinstance(item, dict):
                    names.append(item.get("name", item.get("q_origin_key", "")))
                else:
                    names.append(str(item))
            return names
        return []

    # -- Threat Logs (IPS) --

    def _normalize_threat_logs(self, raw: RawEventData) -> list[FindingData]:
        """Flag IPS threat detections."""
        findings = []
        logs = raw.raw_data.get("logs", [])

        for entry in logs:
            attack_name = entry.get("attack", entry.get("msg", ""))
            severity_str = entry.get("severity", "medium").lower()
            src_ip = entry.get("srcip", entry.get("src", ""))
            dst_ip = entry.get("dstip", entry.get("dst", ""))
            action = entry.get("action", "")
            proto = entry.get("proto", entry.get("service", ""))
            ref_url = entry.get("ref", "")

            severity = severity_str if severity_str in ("critical", "high", "medium", "low", "info") else "medium"

            # Elevate critical IPS detections
            if severity_str == "critical" or entry.get("crscore", 0) >= 40:
                severity = "critical"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"IPS threat detected: {attack_name}",
                    detail={
                        "attack_name": attack_name,
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "action": action,
                        "protocol": proto,
                        "reference": ref_url,
                        "original_severity": severity_str,
                    },
                    resource_id=f"{src_ip}->{dst_ip}",
                    resource_type="fortinet_ips_threat",
                    resource_name=str(attack_name),
                    severity=severity,
                )
            )

        return findings

    # -- System Status --

    def _normalize_system_status(self, raw: RawEventData) -> list[FindingData]:
        """Inventory system status."""
        findings = []
        status = raw.raw_data.get("status", {})

        hostname = status.get("hostname", "unknown")
        version = status.get("version", "")
        serial = status.get("serial", "")

        findings.append(
            FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"FortiGate system: {hostname} (v{version})",
                detail={
                    "hostname": hostname,
                    "version": version,
                    "serial": serial,
                    "status": status,
                },
                resource_id=serial or hostname,
                resource_type="fortinet_system",
                resource_name=hostname,
                severity="info",
            )
        )

        return findings

    # -- VPN Tunnels --

    def _normalize_vpn_tunnels(self, raw: RawEventData) -> list[FindingData]:
        """Inventory VPN tunnels; flag expired certs and down tunnels."""
        findings = []
        tunnels = raw.raw_data.get("tunnels", [])

        for tunnel in tunnels:
            tunnel_name = tunnel.get("name", tunnel.get("p2name", ""))
            status = tunnel.get("status", "").lower()
            incoming_bytes = tunnel.get("incoming_bytes", 0)
            outgoing_bytes = tunnel.get("outgoing_bytes", 0)
            rgwy = tunnel.get("rgwy", "")  # remote gateway
            comments = tunnel.get("comments", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"VPN tunnel: {tunnel_name} ({status})",
                    detail={
                        "tunnel_name": tunnel_name,
                        "status": status,
                        "remote_gateway": rgwy,
                        "incoming_bytes": incoming_bytes,
                        "outgoing_bytes": outgoing_bytes,
                        "comments": comments,
                    },
                    resource_id=tunnel_name,
                    resource_type="fortinet_vpn_tunnel",
                    resource_name=tunnel_name,
                    severity="info",
                )
            )

            # Flag down tunnels
            if status in ("down", "inactive"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"VPN tunnel down: {tunnel_name}",
                        detail={
                            "tunnel_name": tunnel_name,
                            "status": status,
                            "remote_gateway": rgwy,
                            "issue": "IPsec VPN tunnel is down — connectivity and encryption at risk",
                        },
                        resource_id=tunnel_name,
                        resource_type="fortinet_vpn_tunnel",
                        resource_name=tunnel_name,
                        severity="high",
                    )
                )

            # Flag expired certificates
            cert_expiry = tunnel.get("cert_expiry", tunnel.get("certificate_expiry", ""))
            if cert_expiry and "expired" in str(cert_expiry).lower():
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"VPN certificate expired: {tunnel_name}",
                        detail={
                            "tunnel_name": tunnel_name,
                            "cert_expiry": cert_expiry,
                            "issue": "VPN tunnel certificate has expired — authentication and encryption compromised",
                        },
                        resource_id=tunnel_name,
                        resource_type="fortinet_vpn_tunnel",
                        resource_name=tunnel_name,
                        severity="critical",
                    )
                )

        return findings

    # -- Antivirus --

    def _normalize_antivirus(self, raw: RawEventData) -> list[FindingData]:
        """Flag antivirus detections."""
        findings = []
        events = raw.raw_data.get("events", [])

        for event in events:
            virus_name = event.get("virus", event.get("msg", ""))
            src_ip = event.get("srcip", event.get("src", ""))
            dst_ip = event.get("dstip", event.get("dst", ""))
            action = event.get("action", "")
            filename = event.get("filename", "")
            severity_str = event.get("severity", "high").lower()

            severity = severity_str if severity_str in ("critical", "high", "medium", "low", "info") else "high"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Antivirus detection: {virus_name}",
                    detail={
                        "virus_name": virus_name,
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "action": action,
                        "filename": filename,
                        "original_severity": severity_str,
                    },
                    resource_id=f"{src_ip}:{filename}",
                    resource_type="fortinet_antivirus",
                    resource_name=str(virus_name),
                    severity=severity,
                )
            )

        return findings


# Register
registry.register(FortinetNormalizer())
