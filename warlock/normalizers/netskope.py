"""Netskope normalizer — transforms raw Netskope API responses into Findings.

Handles alerts (DLP, anomaly, compromised credential), events
(application, page, network), and client status.
Flags DLP policy violations, compromised credential alerts, unsanctioned
app usage, and malware detections.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Alert types that indicate high risk
HIGH_RISK_ALERT_TYPES = {
    "Compromised Credential",
    "compromised_credential",
    "DLP",
    "dlp",
    "Malware",
    "malware",
    "Ransomware",
    "ransomware",
    "malsite",
}

# DLP violation types involving sensitive data
SENSITIVE_DLP_PROFILES = {
    "PII",
    "PCI",
    "PHI",
    "HIPAA",
    "GDPR",
    "SSN",
    "Credit Card",
    "credit_card",
    "social_security",
    "passport",
    "financial",
}


class NetskopeNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "netskope_alerts": "_normalize_alerts",
        "netskope_events": "_normalize_events",
        "netskope_clients": "_normalize_clients",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "netskope" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Netskope findings."""
        return {
            "raw_event_id": raw.id,
            "source": "netskope",
            "source_type": SourceType.DLP,
            "provider": "netskope",
            "observed_at": raw.observed_at,
        }

    # -- Alerts --

    def _normalize_alerts(self, raw: RawEventData) -> list[FindingData]:
        """Normalize alerts; flag DLP violations, compromised credentials, malware."""
        findings = []
        alerts = raw.raw_data.get("alerts", [])

        for alert in alerts:
            alert_id = alert.get("_id", alert.get("alert_id", ""))
            alert_type = alert.get("alert_type", alert.get("type", ""))
            alert_name = alert.get("alert_name", alert.get("name", ""))
            severity_val = alert.get("severity", "").lower()
            user = alert.get("user", "")
            app = alert.get("app", "")
            activity = alert.get("activity", "")
            policy_name = alert.get("policy", alert.get("dlp_profile", ""))
            dlp_rule = alert.get("dlp_rule", "")
            file_name = alert.get("file_name", alert.get("object", ""))
            timestamp = alert.get("timestamp", alert.get("alert_time", ""))
            action = alert.get("action", "")
            category = alert.get("category", "")
            alert.get("site", "")
            src_location = alert.get("src_location", "")
            alert.get("dst_location", "")
            access_method = alert.get("access_method", "")
            alert.get("cci", "")  # Cloud Confidence Index

            # Map severity
            severity_map = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "info": "info",
                "warning": "medium",
            }
            severity = severity_map.get(severity_val, "medium")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Netskope alert: {alert_type} — {alert_name}",
                    detail={
                        "alert_id": alert_id,
                        "alert_type": alert_type,
                        "alert_name": alert_name,
                        "severity": severity_val,
                        "user": user,
                        "app": app,
                        "activity": activity,
                        "policy_name": policy_name,
                        "dlp_rule": dlp_rule,
                        "file_name": file_name,
                        "timestamp": timestamp,
                        "action": action,
                        "category": category,
                        "access_method": access_method,
                    },
                    resource_id=alert_id,
                    resource_type="netskope_alert",
                    resource_name=f"{alert_type}:{alert_id[:8] if alert_id else 'unknown'}",
                    severity=severity,
                )
            )

            # Flag DLP policy violations
            if alert_type.lower() in ("dlp", "policy"):
                dlp_severity = (
                    "critical"
                    if any(p.lower() in (policy_name or "").lower() for p in SENSITIVE_DLP_PROFILES)
                    else "high"
                )

                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"DLP violation: {policy_name} by {user}",
                        detail={
                            "alert_id": alert_id,
                            "user": user,
                            "app": app,
                            "policy_name": policy_name,
                            "dlp_rule": dlp_rule,
                            "file_name": file_name,
                            "activity": activity,
                            "issue": f"DLP policy '{policy_name}' violated — sensitive data may be exposed",
                        },
                        resource_id=alert_id,
                        resource_type="netskope_dlp_violation",
                        resource_name=f"DLP:{policy_name}",
                        severity=dlp_severity,
                    )
                )

            # Flag compromised credential alerts
            if alert_type.lower() in ("compromised credential", "compromised_credential"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Compromised credential detected: {user}",
                        detail={
                            "alert_id": alert_id,
                            "user": user,
                            "app": app,
                            "src_location": src_location,
                            "access_method": access_method,
                            "issue": "User credentials may be compromised — immediate password reset and investigation required",
                        },
                        resource_id=alert_id,
                        resource_type="netskope_compromised_credential",
                        resource_name=f"compromised:{user}",
                        severity="critical",
                    )
                )

            # Flag malware detections
            if alert_type.lower() in ("malware", "ransomware", "malsite"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Malware detected: {alert_name} via {app}",
                        detail={
                            "alert_id": alert_id,
                            "alert_type": alert_type,
                            "user": user,
                            "app": app,
                            "file_name": file_name,
                            "action": action,
                            "issue": f"Malware/{alert_type} detected — quarantine and investigate",
                        },
                        resource_id=alert_id,
                        resource_type="netskope_malware",
                        resource_name=f"malware:{alert_id[:8] if alert_id else 'unknown'}",
                        severity="critical",
                    )
                )

        return findings

    # -- Events --

    def _normalize_events(self, raw: RawEventData) -> list[FindingData]:
        """Normalize application events; flag unsanctioned app usage."""
        findings = []
        events = raw.raw_data.get("events", [])

        for event in events:
            event_id = event.get("_id", event.get("event_id", ""))
            user = event.get("user", "")
            app = event.get("app", "")
            activity = event.get("activity", "")
            category = event.get("category", "")
            cci = event.get("cci", 0)  # Cloud Confidence Index (0-100)
            ccl = event.get("ccl", "")  # Cloud Confidence Level
            event.get("app_session_id", "") != "" or event.get("sanctioned_instance", False)
            access_method = event.get("access_method", "")
            traffic_type = event.get("traffic_type", "")
            timestamp = event.get("timestamp", "")
            event.get("src_location", "")
            object_name = event.get("object", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Cloud app activity: {user} on {app} ({activity})",
                    detail={
                        "event_id": event_id,
                        "user": user,
                        "app": app,
                        "activity": activity,
                        "category": category,
                        "cci": cci,
                        "ccl": ccl,
                        "access_method": access_method,
                        "traffic_type": traffic_type,
                        "timestamp": timestamp,
                        "object": object_name,
                    },
                    resource_id=event_id,
                    resource_type="netskope_event",
                    resource_name=f"{app}:{activity}",
                    severity="info",
                )
            )

            # Flag unsanctioned app usage (low CCI or explicitly unsanctioned)
            if ccl in ("poor", "low") or (isinstance(cci, (int, float)) and cci < 40):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"Unsanctioned app usage: {user} on {app} (CCI={cci})",
                        detail={
                            "event_id": event_id,
                            "user": user,
                            "app": app,
                            "activity": activity,
                            "cci": cci,
                            "ccl": ccl,
                            "category": category,
                            "issue": f"Application {app} has low confidence index (CCI={cci}) — potential shadow IT risk",
                        },
                        resource_id=event_id,
                        resource_type="netskope_unsanctioned_app",
                        resource_name=f"shadow:{app}",
                        severity="medium",
                    )
                )

        return findings

    # -- Clients --

    def _normalize_clients(self, raw: RawEventData) -> list[FindingData]:
        """Inventory Netskope client (agent) status; flag disconnected/outdated clients."""
        findings = []
        clients = raw.raw_data.get("clients", [])

        for client_info in clients:
            client_id = client_info.get("client_id", client_info.get("device_id", ""))
            user = client_info.get(
                "user", client_info.get("users", [""])[0] if client_info.get("users") else ""
            )
            device_name = client_info.get("host_info", {}).get(
                "hostname", client_info.get("hostname", "")
            )
            os_info = client_info.get("host_info", {}).get("os", client_info.get("os", ""))
            client_version = client_info.get("client_version", "")
            status = client_info.get("status", client_info.get("client_status", ""))
            last_event = client_info.get("last_event_timestamp", client_info.get("last_event", ""))

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Netskope client: {device_name} ({status})",
                    detail={
                        "client_id": client_id,
                        "user": user,
                        "device_name": device_name,
                        "os": os_info,
                        "client_version": client_version,
                        "status": status,
                        "last_event": last_event,
                    },
                    resource_id=client_id,
                    resource_type="netskope_client",
                    resource_name=f"{device_name}:{user}",
                    severity="info",
                )
            )

            # Flag disconnected clients
            if status.lower() in ("disconnected", "disabled", "inactive"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Netskope client disconnected: {device_name} ({user})",
                        detail={
                            "client_id": client_id,
                            "user": user,
                            "device_name": device_name,
                            "status": status,
                            "client_version": client_version,
                            "issue": "Netskope client is disconnected — device traffic is not being inspected",
                        },
                        resource_id=client_id,
                        resource_type="netskope_client",
                        resource_name=f"{device_name}:{user}",
                        severity="medium",
                    )
                )

        return findings


# Register
registry.register(NetskopeNormalizer())
