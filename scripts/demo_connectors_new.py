"""Demo mock connectors for 84 new sources (imported by demo_seed.py)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
)

NOW = datetime.now(timezone.utc)
EXPIRED = (NOW - timedelta(days=45)).isoformat()
EXPIRING_SOON = (NOW + timedelta(days=20)).isoformat()
VALID = (NOW + timedelta(days=300)).isoformat()


# ---------------------------------------------------------------------------
# 1. PagerDuty
# ---------------------------------------------------------------------------
class DemoPagerDutyConnector(BaseConnector):
    """Simulates PagerDuty collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="pagerduty",
            source_type=SourceType.ITSM,
            provider="pagerduty",
        )
        result.events.append(
            RawEventData(
                source="pagerduty",
                source_type=SourceType.ITSM,
                provider="pagerduty",
                event_type="pagerduty_incidents",
                raw_data={
                    "response": [
                        {
                            "id": "PD-001",
                            "title": "DB connection pool exhausted",
                            "status": "resolved",
                            "urgency": "high",
                            "service": {"summary": "prod-db"},
                            "created_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "PD-002",
                            "title": "API latency spike > 5s",
                            "status": "triggered",
                            "urgency": "high",
                            "service": {"summary": "api-gateway"},
                            "created_at": (NOW - timedelta(hours=1)).isoformat(),
                        },
                        {
                            "id": "PD-003",
                            "title": "Cert expiry warning",
                            "status": "acknowledged",
                            "urgency": "low",
                            "service": {"summary": "edge-proxy"},
                            "created_at": (NOW - timedelta(days=2)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="pagerduty",
                source_type=SourceType.ITSM,
                provider="pagerduty",
                event_type="pagerduty_services",
                raw_data={
                    "response": [
                        {
                            "id": "SVC-001",
                            "name": "prod-db",
                            "status": "active",
                            "escalation_policy": {"summary": "Default"},
                        },
                        {
                            "id": "SVC-002",
                            "name": "api-gateway",
                            "status": "active",
                            "escalation_policy": {"summary": "Default"},
                        },
                        {
                            "id": "SVC-003",
                            "name": "edge-proxy",
                            "status": "active",
                            "escalation_policy": {"summary": "Secondary"},
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="pagerduty",
                source_type=SourceType.ITSM,
                provider="pagerduty",
                event_type="pagerduty_oncalls",
                raw_data={
                    "response": [
                        {
                            "user": {"summary": "alice@acme.com"},
                            "schedule": {"summary": "Primary", "id": "SCH-01"},
                            "escalation_level": 1,
                        },
                        {
                            "user": {"summary": "bob@acme.com"},
                            "schedule": {"summary": "Secondary", "id": "SCH-02"},
                            "escalation_level": 2,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="pagerduty",
                source_type=SourceType.ITSM,
                provider="pagerduty",
                event_type="pagerduty_escalation_policies",
                raw_data={
                    "response": [
                        {
                            "id": "EP-001",
                            "name": "Default Escalation",
                            "num_loops": 3,
                            "escalation_rules": [{"id": "R1"}, {"id": "R2"}],
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 2. Opsgenie
# ---------------------------------------------------------------------------
class DemoOpsgenieConnector(BaseConnector):
    """Simulates Opsgenie collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="opsgenie",
            source_type=SourceType.ITSM,
            provider="opsgenie",
        )
        result.events.append(
            RawEventData(
                source="opsgenie",
                source_type=SourceType.ITSM,
                provider="opsgenie",
                event_type="opsgenie_alerts",
                raw_data={
                    "response": [
                        {
                            "id": "OG-001",
                            "message": "High CPU on prod-web-01",
                            "status": "open",
                            "priority": "P1",
                            "source": "datadog",
                            "createdAt": (NOW - timedelta(hours=2)).isoformat(),
                        },
                        {
                            "id": "OG-002",
                            "message": "Disk usage > 90%",
                            "status": "acknowledged",
                            "priority": "P2",
                            "source": "nagios",
                            "createdAt": (NOW - timedelta(hours=5)).isoformat(),
                        },
                        {
                            "id": "OG-003",
                            "message": "SSL cert expires in 15 days",
                            "status": "closed",
                            "priority": "P3",
                            "source": "prometheus",
                            "createdAt": (NOW - timedelta(days=1)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="opsgenie",
                source_type=SourceType.ITSM,
                provider="opsgenie",
                event_type="opsgenie_incidents",
                raw_data={
                    "response": [
                        {
                            "id": "INC-001",
                            "message": "Payment service degraded",
                            "status": "open",
                            "priority": "P1",
                            "tags": ["payments", "prod"],
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="opsgenie",
                source_type=SourceType.ITSM,
                provider="opsgenie",
                event_type="opsgenie_schedules",
                raw_data={
                    "response": [
                        {
                            "id": "SCH-001",
                            "name": "Primary On-Call",
                            "enabled": True,
                            "timezone": "America/New_York",
                        },
                        {
                            "id": "SCH-002",
                            "name": "Secondary On-Call",
                            "enabled": True,
                            "timezone": "America/Los_Angeles",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="opsgenie",
                source_type=SourceType.ITSM,
                provider="opsgenie",
                event_type="opsgenie_escalations",
                raw_data={
                    "response": [
                        {
                            "id": "ESC-001",
                            "name": "Default Escalation",
                            "rules": [{"delay": 5}, {"delay": 15}],
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 3. Axonius
# ---------------------------------------------------------------------------
class DemoAxoniusConnector(BaseConnector):
    """Simulates Axonius asset intelligence collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="axonius",
            source_type=SourceType.CUSTOM,
            provider="axonius",
        )
        result.events.append(
            RawEventData(
                source="axonius",
                source_type=SourceType.CUSTOM,
                provider="axonius",
                event_type="axonius_devices",
                raw_data={
                    "response": [
                        {
                            "internal_axon_id": "ax-dev-001",
                            "specific_data": {
                                "data": {
                                    "hostname": "prod-web-01",
                                    "os": {"type": "Linux"},
                                    "last_seen": NOW.isoformat(),
                                }
                            },
                        },
                        {
                            "internal_axon_id": "ax-dev-002",
                            "specific_data": {
                                "data": {
                                    "hostname": "prod-db-01",
                                    "os": {"type": "Linux"},
                                    "last_seen": NOW.isoformat(),
                                }
                            },
                        },
                        {
                            "internal_axon_id": "ax-dev-003",
                            "specific_data": {
                                "data": {
                                    "hostname": "legacy-win-01",
                                    "os": {"type": "Windows"},
                                    "last_seen": (NOW - timedelta(days=30)).isoformat(),
                                }
                            },
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="axonius",
                source_type=SourceType.CUSTOM,
                provider="axonius",
                event_type="axonius_users",
                raw_data={
                    "response": [
                        {
                            "internal_axon_id": "ax-usr-001",
                            "specific_data": {
                                "data": {
                                    "username": "alice",
                                    "email": "alice@acme.com",
                                    "is_admin": True,
                                    "last_seen": NOW.isoformat(),
                                }
                            },
                        },
                        {
                            "internal_axon_id": "ax-usr-002",
                            "specific_data": {
                                "data": {
                                    "username": "stale_svc_account",
                                    "email": "svc@acme.com",
                                    "is_admin": False,
                                    "last_seen": (NOW - timedelta(days=120)).isoformat(),
                                }
                            },
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="axonius",
                source_type=SourceType.CUSTOM,
                provider="axonius",
                event_type="axonius_adapters",
                raw_data={
                    "response": [
                        {
                            "internal_axon_id": "ax-adp-001",
                            "specific_data": {
                                "data": {"adapter_name": "aws_adapter", "status": "success"}
                            },
                        },
                        {
                            "internal_axon_id": "ax-adp-002",
                            "specific_data": {
                                "data": {"adapter_name": "okta_adapter", "status": "success"}
                            },
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 4. ServiceNow CMDB
# ---------------------------------------------------------------------------
class DemoServiceNowCMDBConnector(BaseConnector):
    """Simulates ServiceNow CMDB collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="servicenow_cmdb",
            source_type=SourceType.ITSM,
            provider="servicenow_cmdb",
        )
        result.events.append(
            RawEventData(
                source="servicenow_cmdb",
                source_type=SourceType.ITSM,
                provider="servicenow_cmdb",
                event_type="servicenow_cmdb_cis",
                raw_data={
                    "response": [
                        {
                            "sys_id": "ci-001",
                            "name": "prod-web-01",
                            "sys_class_name": "cmdb_ci_linux_server",
                            "ip_address": "10.0.1.10",
                            "operational_status": "1",
                            "environment": "production",
                        },
                        {
                            "sys_id": "ci-002",
                            "name": "prod-db-01",
                            "sys_class_name": "cmdb_ci_linux_server",
                            "ip_address": "10.0.1.20",
                            "operational_status": "1",
                            "environment": "production",
                        },
                        {
                            "sys_id": "ci-003",
                            "name": "dev-box-01",
                            "sys_class_name": "cmdb_ci_linux_server",
                            "ip_address": "10.0.2.10",
                            "operational_status": "2",
                            "environment": "development",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="servicenow_cmdb",
                source_type=SourceType.ITSM,
                provider="servicenow_cmdb",
                event_type="servicenow_cmdb_relationships",
                raw_data={
                    "response": [
                        {
                            "sys_id": "rel-001",
                            "type": {"display_value": "Runs on"},
                            "parent": {"display_value": "prod-app"},
                            "child": {"display_value": "prod-web-01"},
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="servicenow_cmdb",
                source_type=SourceType.ITSM,
                provider="servicenow_cmdb",
                event_type="servicenow_cmdb_classes",
                raw_data={
                    "response": [
                        {
                            "sys_id": "cls-001",
                            "name": "cmdb_ci_linux_server",
                            "label": "Linux Server",
                        },
                        {"sys_id": "cls-002", "name": "cmdb_ci_database", "label": "Database"},
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 5. runZero
# ---------------------------------------------------------------------------
class DemoRunZeroConnector(BaseConnector):
    """Simulates runZero network discovery collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="runzero",
            source_type=SourceType.CUSTOM,
            provider="runzero",
        )
        result.events.append(
            RawEventData(
                source="runzero",
                source_type=SourceType.CUSTOM,
                provider="runzero",
                event_type="runzero_assets",
                raw_data={
                    "response": [
                        {
                            "id": "rz-001",
                            "names": ["prod-web-01"],
                            "addresses": ["10.0.1.10"],
                            "os": "Ubuntu 22.04",
                            "type": "server",
                            "alive": True,
                            "first_seen": (NOW - timedelta(days=90)).isoformat(),
                        },
                        {
                            "id": "rz-002",
                            "names": ["unknown-device"],
                            "addresses": ["10.0.1.99"],
                            "os": "unknown",
                            "type": "unknown",
                            "alive": True,
                            "first_seen": (NOW - timedelta(hours=2)).isoformat(),
                        },
                        {
                            "id": "rz-003",
                            "names": ["iot-sensor-01"],
                            "addresses": ["10.0.3.5"],
                            "os": "embedded",
                            "type": "iot",
                            "alive": True,
                            "first_seen": (NOW - timedelta(days=10)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="runzero",
                source_type=SourceType.CUSTOM,
                provider="runzero",
                event_type="runzero_services",
                raw_data={
                    "response": [
                        {
                            "id": "rsvc-001",
                            "asset_id": "rz-001",
                            "port": 443,
                            "protocol": "tcp",
                            "service": "https",
                            "transport": "tcp",
                        },
                        {
                            "id": "rsvc-002",
                            "asset_id": "rz-002",
                            "port": 23,
                            "protocol": "tcp",
                            "service": "telnet",
                            "transport": "tcp",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="runzero",
                source_type=SourceType.CUSTOM,
                provider="runzero",
                event_type="runzero_wireless",
                raw_data={
                    "response": [
                        {
                            "id": "rwifi-001",
                            "ssid": "ACME-Corp",
                            "bssid": "aa:bb:cc:dd:ee:ff",
                            "encryption": "WPA3",
                            "signal": -65,
                        },
                        {
                            "id": "rwifi-002",
                            "ssid": "ACME-Guest",
                            "bssid": "aa:bb:cc:dd:ee:01",
                            "encryption": "WPA2",
                            "signal": -70,
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 6. Patch Mgmt Microsoft
# ---------------------------------------------------------------------------
class DemoPatchMgmtMicrosoftConnector(BaseConnector):
    """Simulates Microsoft Update Compliance / WSUS collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="patch_mgmt_microsoft",
            source_type=SourceType.MDM,
            provider="patch_mgmt_microsoft",
        )
        result.events.append(
            RawEventData(
                source="patch_mgmt_microsoft",
                source_type=SourceType.MDM,
                provider="patch_mgmt_microsoft",
                event_type="microsoft_compliance_policies",
                raw_data={
                    "response": [
                        {
                            "id": "pol-001",
                            "displayName": "Windows Update Policy - Prod",
                            "complianceStatus": "compliant",
                            "lastModifiedDateTime": NOW.isoformat(),
                        },
                        {
                            "id": "pol-002",
                            "displayName": "Windows Update Policy - Dev",
                            "complianceStatus": "nonCompliant",
                            "lastModifiedDateTime": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="patch_mgmt_microsoft",
                source_type=SourceType.MDM,
                provider="patch_mgmt_microsoft",
                event_type="microsoft_managed_devices",
                raw_data={
                    "response": [
                        {
                            "id": "dev-001",
                            "deviceName": "DESKTOP-PROD01",
                            "operatingSystem": "Windows",
                            "osVersion": "10.0.19044",
                            "complianceState": "compliant",
                            "lastSyncDateTime": NOW.isoformat(),
                        },
                        {
                            "id": "dev-002",
                            "deviceName": "DESKTOP-PROD02",
                            "operatingSystem": "Windows",
                            "osVersion": "10.0.17763",
                            "complianceState": "noncompliant",
                            "lastSyncDateTime": (NOW - timedelta(days=45)).isoformat(),
                        },
                        {
                            "id": "dev-003",
                            "deviceName": "LAPTOP-ENG01",
                            "operatingSystem": "Windows",
                            "osVersion": "10.0.22621",
                            "complianceState": "compliant",
                            "lastSyncDateTime": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 7. Ivanti
# ---------------------------------------------------------------------------
class DemoIvantiConnector(BaseConnector):
    """Simulates Ivanti Neurons patch management collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name, source="ivanti", source_type=SourceType.MDM, provider="ivanti"
        )
        result.events.append(
            RawEventData(
                source="ivanti",
                source_type=SourceType.MDM,
                provider="ivanti",
                event_type="ivanti_machines",
                raw_data={
                    "response": [
                        {
                            "id": "ivm-001",
                            "name": "srv-prod-01",
                            "os": "Windows Server 2022",
                            "domain": "acme.local",
                            "lastSeen": NOW.isoformat(),
                            "agentVersion": "10.5.1",
                        },
                        {
                            "id": "ivm-002",
                            "name": "srv-prod-02",
                            "os": "Windows Server 2019",
                            "domain": "acme.local",
                            "lastSeen": (NOW - timedelta(days=7)).isoformat(),
                            "agentVersion": "10.4.0",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ivanti",
                source_type=SourceType.MDM,
                provider="ivanti",
                event_type="ivanti_patches",
                raw_data={
                    "response": [
                        {
                            "id": "ivp-001",
                            "patchName": "KB5030219",
                            "severity": "Critical",
                            "status": "Missing",
                            "affectedMachines": 2,
                        },
                        {
                            "id": "ivp-002",
                            "patchName": "KB5028185",
                            "severity": "Important",
                            "status": "Missing",
                            "affectedMachines": 1,
                        },
                        {
                            "id": "ivp-003",
                            "patchName": "KB5025221",
                            "severity": "Low",
                            "status": "Installed",
                            "affectedMachines": 0,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ivanti",
                source_type=SourceType.MDM,
                provider="ivanti",
                event_type="ivanti_deployments",
                raw_data={
                    "response": [
                        {
                            "id": "ivd-001",
                            "name": "Critical Patch Deployment",
                            "status": "Failed",
                            "startDate": (NOW - timedelta(hours=3)).isoformat(),
                            "completionDate": (NOW - timedelta(hours=2)).isoformat(),
                        },
                        {
                            "id": "ivd-002",
                            "name": "Monthly Patch Cycle",
                            "status": "Completed",
                            "startDate": (NOW - timedelta(days=5)).isoformat(),
                            "completionDate": (NOW - timedelta(days=4)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 8. Venafi
# ---------------------------------------------------------------------------
class DemoVenafiConnector(BaseConnector):
    """Simulates Venafi certificate lifecycle management collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="venafi",
            source_type=SourceType.CUSTOM,
            provider="venafi",
        )
        result.events.append(
            RawEventData(
                source="venafi",
                source_type=SourceType.CUSTOM,
                provider="venafi",
                event_type="venafi_certificates",
                raw_data={
                    "response": [
                        {
                            "Guid": "{ven-cert-001}",
                            "CN": "api.acme.com",
                            "ValidTo": VALID,
                            "Issuer": "DigiCert CA",
                            "KeyAlgorithm": "RSA",
                            "KeySize": "2048",
                        },
                        {
                            "Guid": "{ven-cert-002}",
                            "CN": "legacy.acme.com",
                            "ValidTo": EXPIRED,
                            "Issuer": "Let's Encrypt",
                            "KeyAlgorithm": "RSA",
                            "KeySize": "2048",
                        },
                        {
                            "Guid": "{ven-cert-003}",
                            "CN": "staging.acme.com",
                            "ValidTo": EXPIRING_SOON,
                            "Issuer": "DigiCert CA",
                            "KeyAlgorithm": "EC",
                            "KeySize": "256",
                        },
                        {
                            "Guid": "{ven-cert-004}",
                            "CN": "internal.acme.com",
                            "ValidTo": VALID,
                            "Issuer": "Internal CA",
                            "KeyAlgorithm": "RSA",
                            "KeySize": "4096",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="venafi",
                source_type=SourceType.CUSTOM,
                provider="venafi",
                event_type="venafi_config",
                raw_data={
                    "response": [
                        {
                            "DN": "\\VED\\Policy\\Production",
                            "Name": "Production",
                            "ObjectClass": "Policy",
                        },
                        {
                            "DN": "\\VED\\Policy\\Development",
                            "Name": "Development",
                            "ObjectClass": "Policy",
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 9. AWS ACM
# ---------------------------------------------------------------------------
class DemoAWSACMConnector(BaseConnector):
    """Simulates AWS Certificate Manager collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="aws_acm",
            source_type=SourceType.CLOUD,
            provider="aws_acm",
        )
        result.events.append(
            RawEventData(
                source="aws_acm",
                source_type=SourceType.CLOUD,
                provider="aws_acm",
                event_type="aws_acm_certificates",
                raw_data={
                    "region": "us-east-1",
                    "response": [
                        {
                            "CertificateArn": "arn:aws:acm:us-east-1:123:certificate/aaa-001",
                            "DomainName": "api.acme.com",
                            "Status": "ISSUED",
                            "NotAfter": VALID,
                            "KeyAlgorithm": "RSA_2048",
                        },
                        {
                            "CertificateArn": "arn:aws:acm:us-east-1:123:certificate/aaa-002",
                            "DomainName": "old.acme.com",
                            "Status": "EXPIRED",
                            "NotAfter": EXPIRED,
                            "KeyAlgorithm": "RSA_2048",
                        },
                        {
                            "CertificateArn": "arn:aws:acm:us-east-1:123:certificate/aaa-003",
                            "DomainName": "app.acme.com",
                            "Status": "ISSUED",
                            "NotAfter": EXPIRING_SOON,
                            "KeyAlgorithm": "EC_prime256v1",
                        },
                    ],
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 10. DigiCert
# ---------------------------------------------------------------------------
class DemoDigiCertConnector(BaseConnector):
    """Simulates DigiCert certificate collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="digicert",
            source_type=SourceType.CUSTOM,
            provider="digicert",
        )
        result.events.append(
            RawEventData(
                source="digicert",
                source_type=SourceType.CUSTOM,
                provider="digicert",
                event_type="digicert_orders",
                raw_data={
                    "response": [
                        {
                            "id": "dc-ord-001",
                            "status": "issued",
                            "product": {"name": "OV SSL"},
                            "certificate": {"common_name": "www.acme.com", "valid_till": VALID},
                        },
                        {
                            "id": "dc-ord-002",
                            "status": "expired",
                            "product": {"name": "EV SSL"},
                            "certificate": {
                                "common_name": "secure.acme.com",
                                "valid_till": EXPIRED,
                            },
                        },
                        {
                            "id": "dc-ord-003",
                            "status": "issued",
                            "product": {"name": "Wildcard SSL"},
                            "certificate": {
                                "common_name": "*.acme.com",
                                "valid_till": EXPIRING_SOON,
                            },
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="digicert",
                source_type=SourceType.CUSTOM,
                provider="digicert",
                event_type="digicert_certificates",
                raw_data={
                    "response": [
                        {
                            "id": "dc-cert-001",
                            "common_name": "www.acme.com",
                            "valid_till": VALID,
                            "status": "active",
                            "key_size": 2048,
                        },
                        {
                            "id": "dc-cert-002",
                            "common_name": "legacy.acme.com",
                            "valid_till": EXPIRED,
                            "status": "expired",
                            "key_size": 2048,
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 11. AWS Secrets Manager
# ---------------------------------------------------------------------------
class DemoAWSSecretsConnector(BaseConnector):
    """Simulates AWS Secrets Manager metadata collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="aws_secrets",
            source_type=SourceType.CLOUD,
            provider="aws_secrets",
        )
        result.events.append(
            RawEventData(
                source="aws_secrets",
                source_type=SourceType.CLOUD,
                provider="aws_secrets",
                event_type="aws_secrets_metadata",
                raw_data={
                    "region": "us-east-1",
                    "response": [
                        {
                            "ARN": "arn:aws:secretsmanager:us-east-1:123:secret/prod/db-pass",
                            "Name": "prod/db-pass",
                            "RotationEnabled": True,
                            "LastRotatedDate": (NOW - timedelta(days=20)).isoformat(),
                            "LastChangedDate": (NOW - timedelta(days=20)).isoformat(),
                        },
                        {
                            "ARN": "arn:aws:secretsmanager:us-east-1:123:secret/prod/api-key",
                            "Name": "prod/api-key",
                            "RotationEnabled": False,
                            "LastRotatedDate": None,
                            "LastChangedDate": (NOW - timedelta(days=400)).isoformat(),
                        },
                        {
                            "ARN": "arn:aws:secretsmanager:us-east-1:123:secret/dev/db-pass",
                            "Name": "dev/db-pass",
                            "RotationEnabled": True,
                            "LastRotatedDate": (NOW - timedelta(days=5)).isoformat(),
                            "LastChangedDate": (NOW - timedelta(days=5)).isoformat(),
                        },
                    ],
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 12. Azure Key Vault
# ---------------------------------------------------------------------------
class DemoAzureKeyVaultConnector(BaseConnector):
    """Simulates Azure Key Vault collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="azure_keyvault",
            source_type=SourceType.CLOUD,
            provider="azure_keyvault",
        )
        result.events.append(
            RawEventData(
                source="azure_keyvault",
                source_type=SourceType.CLOUD,
                provider="azure_keyvault",
                event_type="azure_keyvault_secrets",
                raw_data={
                    "vault_url": "https://acme-prod.vault.azure.net",
                    "response": [
                        {
                            "id": "https://acme-prod.vault.azure.net/secrets/db-password/v1",
                            "attributes": {
                                "enabled": True,
                                "created": 1700000000,
                                "updated": 1700000000,
                            },
                        },
                        {
                            "id": "https://acme-prod.vault.azure.net/secrets/api-token/v1",
                            "attributes": {
                                "enabled": False,
                                "created": 1650000000,
                                "updated": 1650000000,
                            },
                        },
                    ],
                },
            )
        )
        result.events.append(
            RawEventData(
                source="azure_keyvault",
                source_type=SourceType.CLOUD,
                provider="azure_keyvault",
                event_type="azure_keyvault_keys",
                raw_data={
                    "vault_url": "https://acme-prod.vault.azure.net",
                    "response": [
                        {
                            "kid": "https://acme-prod.vault.azure.net/keys/master-key/v1",
                            "attributes": {
                                "enabled": True,
                                "created": 1700000000,
                                "updated": 1700000000,
                            },
                            "kty": "RSA",
                            "key_size": 2048,
                        },
                    ],
                },
            )
        )
        result.events.append(
            RawEventData(
                source="azure_keyvault",
                source_type=SourceType.CLOUD,
                provider="azure_keyvault",
                event_type="azure_keyvault_certificates",
                raw_data={
                    "vault_url": "https://acme-prod.vault.azure.net",
                    "response": [
                        {
                            "id": "https://acme-prod.vault.azure.net/certificates/tls-cert/v1",
                            "attributes": {
                                "enabled": True,
                                "expires": 9999999999,
                                "created": 1700000000,
                                "updated": 1700000000,
                            },
                        },
                    ],
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 13. GCP Secrets Manager
# ---------------------------------------------------------------------------
class DemoGCPSecretsConnector(BaseConnector):
    """Simulates GCP Secret Manager collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="gcp_secrets",
            source_type=SourceType.CLOUD,
            provider="gcp_secrets",
        )
        result.events.append(
            RawEventData(
                source="gcp_secrets",
                source_type=SourceType.CLOUD,
                provider="gcp_secrets",
                event_type="gcp_secrets_metadata",
                raw_data={
                    "project_id": "acme-prod-123",
                    "response": [
                        {
                            "name": "projects/acme-prod-123/secrets/db-password",
                            "createTime": (NOW - timedelta(days=90)).isoformat(),
                            "replication": {"automatic": {}},
                            "labels": {"env": "prod"},
                        },
                        {
                            "name": "projects/acme-prod-123/secrets/stale-api-key",
                            "createTime": (NOW - timedelta(days=500)).isoformat(),
                            "replication": {"automatic": {}},
                            "labels": {"env": "prod"},
                        },
                        {
                            "name": "projects/acme-prod-123/secrets/dev-secret",
                            "createTime": (NOW - timedelta(days=10)).isoformat(),
                            "replication": {
                                "userManaged": {"replicas": [{"location": "us-central1"}]}
                            },
                            "labels": {"env": "dev"},
                        },
                    ],
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 14. ServiceNow GRC
# ---------------------------------------------------------------------------
class DemoServiceNowGRCConnector(BaseConnector):
    """Simulates ServiceNow GRC collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="servicenow_grc",
            source_type=SourceType.ITSM,
            provider="servicenow_grc",
        )
        result.events.append(
            RawEventData(
                source="servicenow_grc",
                source_type=SourceType.ITSM,
                provider="servicenow_grc",
                event_type="servicenow_grc_policies",
                raw_data={
                    "response": [
                        {
                            "sys_id": "pol-001",
                            "name": "Access Control Policy",
                            "state": "published",
                            "category": "Security",
                            "effective_date": (NOW - timedelta(days=180)).isoformat(),
                        },
                        {
                            "sys_id": "pol-002",
                            "name": "Data Retention Policy",
                            "state": "draft",
                            "category": "Privacy",
                            "effective_date": None,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="servicenow_grc",
                source_type=SourceType.ITSM,
                provider="servicenow_grc",
                event_type="servicenow_grc_controls",
                raw_data={
                    "response": [
                        {
                            "sys_id": "ctrl-001",
                            "name": "MFA Enforcement",
                            "control_category": "Access Control",
                            "attestation_status": "Compliant",
                            "last_tested": (NOW - timedelta(days=30)).isoformat(),
                        },
                        {
                            "sys_id": "ctrl-002",
                            "name": "Backup Verification",
                            "control_category": "Availability",
                            "attestation_status": "Non-Compliant",
                            "last_tested": (NOW - timedelta(days=90)).isoformat(),
                        },
                        {
                            "sys_id": "ctrl-003",
                            "name": "Encryption at Rest",
                            "control_category": "Data Protection",
                            "attestation_status": "Compliant",
                            "last_tested": (NOW - timedelta(days=15)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="servicenow_grc",
                source_type=SourceType.ITSM,
                provider="servicenow_grc",
                event_type="servicenow_grc_risks",
                raw_data={
                    "response": [
                        {
                            "sys_id": "risk-001",
                            "name": "Third-party vendor breach",
                            "risk_rating": "High",
                            "state": "open",
                            "category": "Vendor Risk",
                        },
                        {
                            "sys_id": "risk-002",
                            "name": "Ransomware impact",
                            "risk_rating": "Critical",
                            "state": "mitigated",
                            "category": "Cyber Risk",
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 15. Nightfall DLP
# ---------------------------------------------------------------------------
class DemoNightfallConnector(BaseConnector):
    """Simulates Nightfall DLP collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="nightfall",
            source_type=SourceType.DLP,
            provider="nightfall",
        )
        result.events.append(
            RawEventData(
                source="nightfall",
                source_type=SourceType.DLP,
                provider="nightfall",
                event_type="nightfall_scans",
                raw_data={
                    "response": [
                        {
                            "id": "nf-scan-001",
                            "status": "completed",
                            "integration": "google_drive",
                            "findings_count": 15,
                            "created_at": (NOW - timedelta(hours=4)).isoformat(),
                        },
                        {
                            "id": "nf-scan-002",
                            "status": "completed",
                            "integration": "slack",
                            "findings_count": 3,
                            "created_at": (NOW - timedelta(hours=8)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="nightfall",
                source_type=SourceType.DLP,
                provider="nightfall",
                event_type="nightfall_policies",
                raw_data={
                    "response": [
                        {
                            "id": "nf-pol-001",
                            "name": "PII Detection",
                            "enabled": True,
                            "detectors": ["CREDIT_CARD", "SSN", "EMAIL"],
                        },
                        {
                            "id": "nf-pol-002",
                            "name": "API Keys",
                            "enabled": True,
                            "detectors": ["API_KEY", "AWS_CREDENTIALS"],
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="nightfall",
                source_type=SourceType.DLP,
                provider="nightfall",
                event_type="nightfall_alerts",
                raw_data={
                    "response": [
                        {
                            "id": "nf-alert-001",
                            "policy_name": "PII Detection",
                            "finding_type": "CREDIT_CARD",
                            "severity": "HIGH",
                            "location": "Google Drive / Shared Folder",
                            "created_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "nf-alert-002",
                            "policy_name": "API Keys",
                            "finding_type": "AWS_CREDENTIALS",
                            "severity": "CRITICAL",
                            "location": "Slack / #dev-general",
                            "created_at": (NOW - timedelta(hours=1)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 16. AWS Backup
# ---------------------------------------------------------------------------
class DemoAWSBackupConnector(BaseConnector):
    """Simulates AWS Backup collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="aws_backup",
            source_type=SourceType.BACKUP,
            provider="aws_backup",
        )
        result.events.append(
            RawEventData(
                source="aws_backup",
                source_type=SourceType.BACKUP,
                provider="aws_backup",
                event_type="aws_backup_plans",
                raw_data={
                    "region": "us-east-1",
                    "response": [
                        {
                            "BackupPlanId": "plan-001",
                            "BackupPlanName": "DailyBackup-Prod",
                            "VersionId": "v1",
                            "BackupPlanArn": "arn:aws:backup:us-east-1:123:plan/plan-001",
                            "LastExecutionDate": NOW.isoformat(),
                        },
                        {
                            "BackupPlanId": "plan-002",
                            "BackupPlanName": "WeeklyBackup-Dev",
                            "VersionId": "v1",
                            "BackupPlanArn": "arn:aws:backup:us-east-1:123:plan/plan-002",
                            "LastExecutionDate": (NOW - timedelta(days=7)).isoformat(),
                        },
                    ],
                },
            )
        )
        result.events.append(
            RawEventData(
                source="aws_backup",
                source_type=SourceType.BACKUP,
                provider="aws_backup",
                event_type="aws_backup_vaults",
                raw_data={
                    "region": "us-east-1",
                    "response": [
                        {
                            "BackupVaultName": "Default",
                            "BackupVaultArn": "arn:aws:backup:us-east-1:123:vault/Default",
                            "NumberOfRecoveryPoints": 42,
                            "EncryptionKeyArn": "arn:aws:kms:us-east-1:123:key/k-001",
                        },
                    ],
                },
            )
        )
        result.events.append(
            RawEventData(
                source="aws_backup",
                source_type=SourceType.BACKUP,
                provider="aws_backup",
                event_type="aws_backup_jobs",
                raw_data={
                    "region": "us-east-1",
                    "response": [
                        {
                            "BackupJobId": "job-001",
                            "State": "COMPLETED",
                            "ResourceArn": "arn:aws:rds:us-east-1:123:db:prod-db",
                            "ResourceType": "RDS",
                            "BackupVaultName": "Default",
                        },
                        {
                            "BackupJobId": "job-002",
                            "State": "FAILED",
                            "ResourceArn": "arn:aws:ec2:us-east-1:123:instance/i-001",
                            "ResourceType": "EC2",
                            "BackupVaultName": "Default",
                            "StatusMessage": "Snapshot creation failed",
                        },
                        {
                            "BackupJobId": "job-003",
                            "State": "COMPLETED",
                            "ResourceArn": "arn:aws:dynamodb:us-east-1:123:table/prod-sessions",
                            "ResourceType": "DynamoDB",
                            "BackupVaultName": "Default",
                        },
                    ],
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 17. Orca Security
# ---------------------------------------------------------------------------
class DemoOrcaConnector(BaseConnector):
    """Simulates Orca Security CSPM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name, source="orca", source_type=SourceType.CSPM, provider="orca"
        )
        result.events.append(
            RawEventData(
                source="orca",
                source_type=SourceType.CSPM,
                provider="orca",
                event_type="orca_alerts",
                raw_data={
                    "response": [
                        {
                            "id": "orca-001",
                            "type_string": "Public S3 bucket with sensitive data",
                            "severity": "critical",
                            "state": "open",
                            "asset_name": "acme-customer-data",
                            "asset_type": "S3Bucket",
                        },
                        {
                            "id": "orca-002",
                            "type_string": "EC2 instance with no IAM role",
                            "severity": "high",
                            "state": "open",
                            "asset_name": "i-0abc123",
                            "asset_type": "EC2Instance",
                        },
                        {
                            "id": "orca-003",
                            "type_string": "Unencrypted EBS volume",
                            "severity": "medium",
                            "state": "open",
                            "asset_name": "vol-001",
                            "asset_type": "EBSVolume",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="orca",
                source_type=SourceType.CSPM,
                provider="orca",
                event_type="orca_assets",
                raw_data={
                    "response": [
                        {
                            "asset_unique_id": "aws-s3-001",
                            "asset_type": "S3Bucket",
                            "asset_name": "acme-customer-data",
                            "cloud_provider": "AWS",
                            "cloud_account_id": "123456789",
                        },
                        {
                            "asset_unique_id": "aws-ec2-001",
                            "asset_type": "EC2Instance",
                            "asset_name": "i-0abc123",
                            "cloud_provider": "AWS",
                            "cloud_account_id": "123456789",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="orca",
                source_type=SourceType.CSPM,
                provider="orca",
                event_type="orca_compliance",
                raw_data={
                    "response": [
                        {
                            "framework": "CIS AWS",
                            "control_id": "1.1",
                            "control_name": "Avoid root account usage",
                            "status": "PASS",
                            "failed_count": 0,
                            "passed_count": 5,
                        },
                        {
                            "framework": "CIS AWS",
                            "control_id": "2.1",
                            "control_name": "S3 bucket logging enabled",
                            "status": "FAIL",
                            "failed_count": 3,
                            "passed_count": 10,
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 18. Lacework
# ---------------------------------------------------------------------------
class DemoLaceworkConnector(BaseConnector):
    """Simulates Lacework CSPM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="lacework",
            source_type=SourceType.CSPM,
            provider="lacework",
        )
        result.events.append(
            RawEventData(
                source="lacework",
                source_type=SourceType.CSPM,
                provider="lacework",
                event_type="lacework_alerts",
                raw_data={
                    "response": [
                        {
                            "alertId": "lw-001",
                            "alertName": "Unusual login activity detected",
                            "severity": "3",
                            "status": "OPEN",
                            "startTime": (NOW - timedelta(hours=2)).isoformat(),
                        },
                        {
                            "alertId": "lw-002",
                            "alertName": "New binary executed on host",
                            "severity": "2",
                            "status": "OPEN",
                            "startTime": (NOW - timedelta(hours=5)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="lacework",
                source_type=SourceType.CSPM,
                provider="lacework",
                event_type="lacework_vulnerabilities",
                raw_data={
                    "response": [
                        {
                            "vulnId": "CVE-2023-44487",
                            "severity": "HIGH",
                            "status": "Active",
                            "packageName": "libssl",
                            "packageVersion": "1.1.1",
                            "fixedVersion": "1.1.1w",
                            "hostCount": 5,
                        },
                        {
                            "vulnId": "CVE-2021-44228",
                            "severity": "CRITICAL",
                            "status": "Active",
                            "packageName": "log4j",
                            "packageVersion": "2.14.0",
                            "fixedVersion": "2.17.0",
                            "hostCount": 2,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="lacework",
                source_type=SourceType.CSPM,
                provider="lacework",
                event_type="lacework_compliance",
                raw_data={
                    "response": [
                        {
                            "id": "lw-comp-001",
                            "reportType": "AWS_CIS_14",
                            "recommendationId": "LW_AWS_IAM_1",
                            "title": "Ensure MFA is enabled for root account",
                            "status": "NonCompliant",
                            "severity": "Critical",
                        },
                        {
                            "id": "lw-comp-002",
                            "reportType": "AWS_CIS_14",
                            "recommendationId": "LW_AWS_S3_2",
                            "title": "Ensure S3 bucket policy does not allow public access",
                            "status": "Compliant",
                            "severity": "High",
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 19. Rapid7
# ---------------------------------------------------------------------------
class DemoRapid7Connector(BaseConnector):
    """Simulates Rapid7 InsightVM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="rapid7",
            source_type=SourceType.SCANNER,
            provider="rapid7",
        )
        result.events.append(
            RawEventData(
                source="rapid7",
                source_type=SourceType.SCANNER,
                provider="rapid7",
                event_type="rapid7_assets",
                raw_data={
                    "response": [
                        {
                            "id": "r7-asset-001",
                            "hostName": "prod-web-01",
                            "ip": "10.0.1.10",
                            "os": {"description": "Ubuntu 22.04 LTS"},
                            "riskScore": 650,
                            "assessedForVulnerabilities": True,
                        },
                        {
                            "id": "r7-asset-002",
                            "hostName": "prod-db-01",
                            "ip": "10.0.1.20",
                            "os": {"description": "CentOS 7"},
                            "riskScore": 1200,
                            "assessedForVulnerabilities": True,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="rapid7",
                source_type=SourceType.SCANNER,
                provider="rapid7",
                event_type="rapid7_vulnerabilities",
                raw_data={
                    "response": [
                        {
                            "id": "r7-vuln-001",
                            "title": "OpenSSL Heartbleed",
                            "cvss": {"v3": {"score": 7.5}},
                            "added": "2014-04-07",
                            "exploits": 5,
                            "malwareKits": 2,
                        },
                        {
                            "id": "r7-vuln-002",
                            "title": "Apache Log4Shell",
                            "cvss": {"v3": {"score": 10.0}},
                            "added": "2021-12-10",
                            "exploits": 100,
                            "malwareKits": 15,
                        },
                        {
                            "id": "r7-vuln-003",
                            "title": "TLS 1.0 Enabled",
                            "cvss": {"v3": {"score": 5.0}},
                            "added": "2020-01-01",
                            "exploits": 0,
                            "malwareKits": 0,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="rapid7",
                source_type=SourceType.SCANNER,
                provider="rapid7",
                event_type="rapid7_scans",
                raw_data={
                    "response": [
                        {
                            "id": "r7-scan-001",
                            "scanName": "Weekly Production Scan",
                            "status": "finished",
                            "assets": {"discovered": 45},
                            "vulnerabilities": {"total": 127},
                            "startTime": (NOW - timedelta(hours=12)).isoformat(),
                            "endTime": (NOW - timedelta(hours=10)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 20. CrowdStrike Spotlight
# ---------------------------------------------------------------------------
class DemoCrowdStrikeSpotlightConnector(BaseConnector):
    """Simulates CrowdStrike Spotlight vulnerability management collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="crowdstrike_spotlight",
            source_type=SourceType.SCANNER,
            provider="crowdstrike_spotlight",
        )
        result.events.append(
            RawEventData(
                source="crowdstrike_spotlight",
                source_type=SourceType.SCANNER,
                provider="crowdstrike_spotlight",
                event_type="crowdstrike_spotlight_vulnerabilities",
                raw_data={
                    "response": [
                        {
                            "id": "cs-spot-001",
                            "cve": {"id": "CVE-2023-44487", "base_score": 7.5},
                            "status": "open",
                            "severity": "HIGH",
                            "aid": "agent-001",
                            "hostname": "prod-web-01",
                            "created_timestamp": (NOW - timedelta(days=5)).isoformat(),
                        },
                        {
                            "id": "cs-spot-002",
                            "cve": {"id": "CVE-2021-44228", "base_score": 10.0},
                            "status": "open",
                            "severity": "CRITICAL",
                            "aid": "agent-002",
                            "hostname": "prod-db-01",
                            "created_timestamp": (NOW - timedelta(days=10)).isoformat(),
                        },
                        {
                            "id": "cs-spot-003",
                            "cve": {"id": "CVE-2022-0001", "base_score": 3.5},
                            "status": "closed",
                            "severity": "LOW",
                            "aid": "agent-001",
                            "hostname": "prod-web-01",
                            "created_timestamp": (NOW - timedelta(days=30)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="crowdstrike_spotlight",
                source_type=SourceType.SCANNER,
                provider="crowdstrike_spotlight",
                event_type="crowdstrike_spotlight_remediations",
                raw_data={
                    "response": [
                        {
                            "id": "cs-rem-001",
                            "action": "update_os",
                            "status": "completed",
                            "entities": {"aids": ["agent-001"]},
                            "created_time": (NOW - timedelta(days=2)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 21. Ping Identity
# ---------------------------------------------------------------------------
class DemoPingIdentityConnector(BaseConnector):
    """Simulates Ping Identity IAM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="ping_identity",
            source_type=SourceType.IAM,
            provider="ping_identity",
        )
        result.events.append(
            RawEventData(
                source="ping_identity",
                source_type=SourceType.IAM,
                provider="ping_identity",
                event_type="ping_users",
                raw_data={
                    "response": [
                        {
                            "id": "ping-usr-001",
                            "username": "alice",
                            "email": "alice@acme.com",
                            "enabled": True,
                            "mfaEnabled": True,
                            "lastSignOn": NOW.isoformat(),
                        },
                        {
                            "id": "ping-usr-002",
                            "username": "stale_bob",
                            "email": "bob@acme.com",
                            "enabled": True,
                            "mfaEnabled": False,
                            "lastSignOn": (NOW - timedelta(days=95)).isoformat(),
                        },
                        {
                            "id": "ping-usr-003",
                            "username": "svc_account",
                            "email": "svc@acme.com",
                            "enabled": True,
                            "mfaEnabled": False,
                            "lastSignOn": (NOW - timedelta(days=180)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ping_identity",
                source_type=SourceType.IAM,
                provider="ping_identity",
                event_type="ping_groups",
                raw_data={
                    "response": [
                        {"id": "ping-grp-001", "name": "Admins", "memberCount": 3},
                        {"id": "ping-grp-002", "name": "Developers", "memberCount": 15},
                        {"id": "ping-grp-003", "name": "ReadOnly", "memberCount": 30},
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ping_identity",
                source_type=SourceType.IAM,
                provider="ping_identity",
                event_type="ping_sign_on_policies",
                raw_data={
                    "response": [
                        {
                            "id": "ping-pol-001",
                            "name": "MFA Required",
                            "enabled": True,
                            "conditions": {"mfa": True},
                        },
                        {
                            "id": "ping-pol-002",
                            "name": "Legacy SSO",
                            "enabled": True,
                            "conditions": {"mfa": False},
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 22. OneLogin
# ---------------------------------------------------------------------------
class DemoOneLoginConnector(BaseConnector):
    """Simulates OneLogin IAM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="onelogin",
            source_type=SourceType.IAM,
            provider="onelogin",
        )
        result.events.append(
            RawEventData(
                source="onelogin",
                source_type=SourceType.IAM,
                provider="onelogin",
                event_type="onelogin_users",
                raw_data={
                    "response": [
                        {
                            "id": 1001,
                            "username": "alice.chen",
                            "email": "alice.chen@acme.com",
                            "status": 1,
                            "role_ids": [10, 20],
                            "last_login": NOW.isoformat(),
                        },
                        {
                            "id": 1002,
                            "username": "old.employee",
                            "email": "old@acme.com",
                            "status": 1,
                            "role_ids": [10],
                            "last_login": (NOW - timedelta(days=120)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="onelogin",
                source_type=SourceType.IAM,
                provider="onelogin",
                event_type="onelogin_roles",
                raw_data={
                    "response": [
                        {"id": 10, "name": "Standard User"},
                        {"id": 20, "name": "Admin"},
                        {"id": 30, "name": "Read Only"},
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="onelogin",
                source_type=SourceType.IAM,
                provider="onelogin",
                event_type="onelogin_events",
                raw_data={
                    "response": [
                        {
                            "id": "ev-001",
                            "type": 8,
                            "type_string": "User assumed role",
                            "user_name": "alice.chen",
                            "ipaddr": "203.0.113.5",
                            "created_at": NOW.isoformat(),
                        },
                        {
                            "id": "ev-002",
                            "type": 8,
                            "type_string": "Login failed",
                            "user_name": "unknown_user",
                            "ipaddr": "198.51.100.1",
                            "created_at": (NOW - timedelta(hours=1)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 23. Workspace ONE
# ---------------------------------------------------------------------------
class DemoWorkspaceOneConnector(BaseConnector):
    """Simulates VMware Workspace ONE MDM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="workspace_one",
            source_type=SourceType.MDM,
            provider="workspace_one",
        )
        result.events.append(
            RawEventData(
                source="workspace_one",
                source_type=SourceType.MDM,
                provider="workspace_one",
                event_type="workspace_one_devices",
                raw_data={
                    "response": [
                        {
                            "Id": {"Value": "ws1-dev-001"},
                            "DeviceFriendlyName": "MacBook-Alice",
                            "Platform": "AppleOsX",
                            "OSVersion": "14.2",
                            "ComplianceStatus": "Compliant",
                            "LastSeen": NOW.isoformat(),
                        },
                        {
                            "Id": {"Value": "ws1-dev-002"},
                            "DeviceFriendlyName": "iPhone-Bob",
                            "Platform": "Apple",
                            "OSVersion": "17.1",
                            "ComplianceStatus": "NonCompliant",
                            "LastSeen": (NOW - timedelta(days=20)).isoformat(),
                        },
                        {
                            "Id": {"Value": "ws1-dev-003"},
                            "DeviceFriendlyName": "Win-Laptop-03",
                            "Platform": "WinRT",
                            "OSVersion": "11.0",
                            "ComplianceStatus": "Compliant",
                            "LastSeen": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="workspace_one",
                source_type=SourceType.MDM,
                provider="workspace_one",
                event_type="workspace_one_profiles",
                raw_data={
                    "response": [
                        {
                            "ProfileId": "ws1-prof-001",
                            "Name": "Corporate WiFi",
                            "Platform": "AppleOsX",
                            "AssignedCount": 45,
                        },
                        {
                            "ProfileId": "ws1-prof-002",
                            "Name": "VPN Configuration",
                            "Platform": "Apple",
                            "AssignedCount": 80,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="workspace_one",
                source_type=SourceType.MDM,
                provider="workspace_one",
                event_type="workspace_one_apps",
                raw_data={
                    "response": [
                        {
                            "ApplicationId": "ws1-app-001",
                            "ApplicationName": "Slack",
                            "Platform": "Apple",
                            "InstalledDeviceCount": 75,
                        },
                        {
                            "ApplicationId": "ws1-app-002",
                            "ApplicationName": "CrowdStrike Falcon",
                            "Platform": "AppleOsX",
                            "InstalledDeviceCount": 45,
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 24. Sumo Logic
# ---------------------------------------------------------------------------
class DemoSumoLogicConnector(BaseConnector):
    """Simulates Sumo Logic SIEM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="sumo_logic",
            source_type=SourceType.SIEM,
            provider="sumo_logic",
        )
        result.events.append(
            RawEventData(
                source="sumo_logic",
                source_type=SourceType.SIEM,
                provider="sumo_logic",
                event_type="sumo_collectors",
                raw_data={
                    "response": [
                        {
                            "id": "sum-col-001",
                            "name": "prod-web-collector",
                            "alive": True,
                            "osName": "Linux",
                            "collectorVersion": "19.375-4",
                        },
                        {
                            "id": "sum-col-002",
                            "name": "prod-db-collector",
                            "alive": True,
                            "osName": "Linux",
                            "collectorVersion": "19.375-4",
                        },
                        {
                            "id": "sum-col-003",
                            "name": "legacy-collector",
                            "alive": False,
                            "osName": "Windows",
                            "collectorVersion": "19.300-1",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sumo_logic",
                source_type=SourceType.SIEM,
                provider="sumo_logic",
                event_type="sumo_dashboards",
                raw_data={
                    "response": [
                        {
                            "id": "sum-dash-001",
                            "title": "Security Overview",
                            "type": "DashboardV2",
                            "createdBy": "alice@acme.com",
                        },
                        {
                            "id": "sum-dash-002",
                            "title": "Compliance Monitoring",
                            "type": "DashboardV2",
                            "createdBy": "security@acme.com",
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 25. Cisco Umbrella
# ---------------------------------------------------------------------------
class DemoCiscoUmbrellaConnector(BaseConnector):
    """Simulates Cisco Umbrella DNS security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="cisco_umbrella",
            source_type=SourceType.NETWORK,
            provider="cisco_umbrella",
        )
        result.events.append(
            RawEventData(
                source="cisco_umbrella",
                source_type=SourceType.NETWORK,
                provider="cisco_umbrella",
                event_type="umbrella_roaming_computers",
                raw_data={
                    "response": [
                        {
                            "deviceId": "umb-dev-001",
                            "name": "LAPTOP-ALICE",
                            "type": "Windows",
                            "lastSyncStatus": "ok",
                            "version": "3.0.469",
                        },
                        {
                            "deviceId": "umb-dev-002",
                            "name": "LAPTOP-BOB",
                            "type": "Mac",
                            "lastSyncStatus": "ok",
                            "version": "1.4.18",
                        },
                        {
                            "deviceId": "umb-dev-003",
                            "name": "OLD-LAPTOP",
                            "type": "Windows",
                            "lastSyncStatus": "error",
                            "version": "2.1.0",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="cisco_umbrella",
                source_type=SourceType.NETWORK,
                provider="cisco_umbrella",
                event_type="umbrella_policies",
                raw_data={
                    "response": [
                        {
                            "id": "umb-pol-001",
                            "name": "Default Policy",
                            "status": "active",
                            "createdAt": (NOW - timedelta(days=365)).isoformat(),
                        },
                        {
                            "id": "umb-pol-002",
                            "name": "Strict Browsing",
                            "status": "active",
                            "createdAt": (NOW - timedelta(days=90)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="cisco_umbrella",
                source_type=SourceType.NETWORK,
                provider="cisco_umbrella",
                event_type="umbrella_destination_lists",
                raw_data={
                    "response": [
                        {
                            "id": "umb-dl-001",
                            "name": "Blocklist",
                            "type": "BLOCK",
                            "domainCount": 1250,
                        },
                        {
                            "id": "umb-dl-002",
                            "name": "Allowlist",
                            "type": "ALLOW",
                            "domainCount": 45,
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 26. Drata
# ---------------------------------------------------------------------------
class DemoDrataConnector(BaseConnector):
    """Simulates Drata GRC collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name, source="drata", source_type=SourceType.GRC, provider="drata"
        )
        result.events.append(
            RawEventData(
                source="drata",
                source_type=SourceType.GRC,
                provider="drata",
                event_type="drata_controls",
                raw_data={
                    "response": [
                        {
                            "id": "dr-ctrl-001",
                            "name": "Access Control",
                            "status": "passing",
                            "framework": "SOC2",
                            "owner": "alice@acme.com",
                        },
                        {
                            "id": "dr-ctrl-002",
                            "name": "Encryption at Rest",
                            "status": "failing",
                            "framework": "SOC2",
                            "owner": "bob@acme.com",
                        },
                        {
                            "id": "dr-ctrl-003",
                            "name": "Incident Response Plan",
                            "status": "passing",
                            "framework": "ISO27001",
                            "owner": "security@acme.com",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="drata",
                source_type=SourceType.GRC,
                provider="drata",
                event_type="drata_monitors",
                raw_data={
                    "response": [
                        {
                            "id": "dr-mon-001",
                            "name": "MFA enabled for all users",
                            "status": "passing",
                            "lastChecked": NOW.isoformat(),
                        },
                        {
                            "id": "dr-mon-002",
                            "name": "Vulnerability scans running weekly",
                            "status": "failing",
                            "lastChecked": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="drata",
                source_type=SourceType.GRC,
                provider="drata",
                event_type="drata_personnel",
                raw_data={
                    "response": [
                        {
                            "id": "dr-per-001",
                            "email": "alice@acme.com",
                            "status": "active",
                            "backgroundCheckStatus": "completed",
                            "securityTrainingStatus": "completed",
                        },
                        {
                            "id": "dr-per-002",
                            "email": "charlie@acme.com",
                            "status": "active",
                            "backgroundCheckStatus": "pending",
                            "securityTrainingStatus": "overdue",
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 27. Vanta
# ---------------------------------------------------------------------------
class DemoVantaConnector(BaseConnector):
    """Simulates Vanta GRC collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name, source="vanta", source_type=SourceType.GRC, provider="vanta"
        )
        result.events.append(
            RawEventData(
                source="vanta",
                source_type=SourceType.GRC,
                provider="vanta",
                event_type="vanta_resources",
                raw_data={
                    "response": [
                        {
                            "id": "vanta-res-001",
                            "name": "prod-db-01",
                            "resourceType": "COMPUTER",
                            "displayName": "prod-db-01",
                            "status": "active",
                        },
                        {
                            "id": "vanta-res-002",
                            "name": "alice@acme.com",
                            "resourceType": "USER",
                            "displayName": "Alice Chen",
                            "status": "active",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="vanta",
                source_type=SourceType.GRC,
                provider="vanta",
                event_type="vanta_results",
                raw_data={
                    "response": [
                        {
                            "id": "vanta-res-r-001",
                            "testName": "MFA enabled",
                            "result": "PASS",
                            "framework": "SOC2",
                            "lastUpdated": NOW.isoformat(),
                        },
                        {
                            "id": "vanta-res-r-002",
                            "testName": "Disk encryption enabled",
                            "result": "FAIL",
                            "framework": "SOC2",
                            "lastUpdated": NOW.isoformat(),
                        },
                        {
                            "id": "vanta-res-r-003",
                            "testName": "Security training completed",
                            "result": "PASS",
                            "framework": "ISO27001",
                            "lastUpdated": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 28. Archer GRC
# ---------------------------------------------------------------------------
class DemoArcherConnector(BaseConnector):
    """Simulates RSA Archer GRC collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name, source="archer", source_type=SourceType.GRC, provider="archer"
        )
        result.events.append(
            RawEventData(
                source="archer",
                source_type=SourceType.GRC,
                provider="archer",
                event_type="archer_content",
                raw_data={
                    "response": [
                        {
                            "ContentId": 1001,
                            "ApplicationId": 75,
                            "FieldContents": {
                                "Name": "AC-2 Account Management",
                                "Status": "Active",
                                "Owner": "CISO",
                            },
                        },
                        {
                            "ContentId": 1002,
                            "ApplicationId": 75,
                            "FieldContents": {
                                "Name": "IR-4 Incident Handling",
                                "Status": "Draft",
                                "Owner": "SOC Lead",
                            },
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="archer",
                source_type=SourceType.GRC,
                provider="archer",
                event_type="archer_applications",
                raw_data={
                    "response": [
                        {
                            "ApplicationId": 75,
                            "Name": "Controls Management",
                            "Type": "standard",
                            "RecordCount": 250,
                        },
                        {
                            "ApplicationId": 80,
                            "Name": "Risk Register",
                            "Type": "standard",
                            "RecordCount": 45,
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 29. Drata API
# ---------------------------------------------------------------------------
class DemoDrataAPIConnector(BaseConnector):
    """Simulates Drata API v2 collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="drata_api",
            source_type=SourceType.GRC,
            provider="drata_api",
        )
        result.events.append(
            RawEventData(
                source="drata_api",
                source_type=SourceType.GRC,
                provider="drata_api",
                event_type="drata_api_controls",
                raw_data={
                    "response": [
                        {
                            "id": "da-ctrl-001",
                            "code": "CC6.1",
                            "name": "Logical Access Controls",
                            "status": "PASSING",
                            "frameworks": ["SOC2"],
                        },
                        {
                            "id": "da-ctrl-002",
                            "code": "A1.2",
                            "name": "System Availability",
                            "status": "FAILING",
                            "frameworks": ["SOC2"],
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="drata_api",
                source_type=SourceType.GRC,
                provider="drata_api",
                event_type="drata_api_tests",
                raw_data={
                    "response": [
                        {
                            "id": "da-test-001",
                            "name": "All admins use MFA",
                            "result": "PASS",
                            "testedAt": NOW.isoformat(),
                        },
                        {
                            "id": "da-test-002",
                            "name": "Pen test completed annually",
                            "result": "FAIL",
                            "testedAt": NOW.isoformat(),
                        },
                        {
                            "id": "da-test-003",
                            "name": "Vendor risk assessed",
                            "result": "PASS",
                            "testedAt": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="drata_api",
                source_type=SourceType.GRC,
                provider="drata_api",
                event_type="drata_api_evidence",
                raw_data={
                    "response": [
                        {
                            "id": "da-ev-001",
                            "name": "MFA screenshot Q1",
                            "status": "accepted",
                            "uploadedAt": (NOW - timedelta(days=10)).isoformat(),
                        },
                        {
                            "id": "da-ev-002",
                            "name": "Pen test report 2024",
                            "status": "expired",
                            "uploadedAt": (NOW - timedelta(days=400)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 30. Vanta API
# ---------------------------------------------------------------------------
class DemoVantaAPIConnector(BaseConnector):
    """Simulates Vanta API v2 collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="vanta_api",
            source_type=SourceType.GRC,
            provider="vanta_api",
        )
        result.events.append(
            RawEventData(
                source="vanta_api",
                source_type=SourceType.GRC,
                provider="vanta_api",
                event_type="vanta_api_monitors",
                raw_data={
                    "response": [
                        {
                            "id": "va-mon-001",
                            "displayName": "MFA on all accounts",
                            "outcome": "PASS",
                            "lastCheckedAt": NOW.isoformat(),
                        },
                        {
                            "id": "va-mon-002",
                            "displayName": "No public S3 buckets",
                            "outcome": "FAIL",
                            "lastCheckedAt": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="vanta_api",
                source_type=SourceType.GRC,
                provider="vanta_api",
                event_type="vanta_api_tests",
                raw_data={
                    "response": [
                        {
                            "id": "va-test-001",
                            "testId": "mfa-all-users",
                            "outcome": "PASS",
                            "createdAt": NOW.isoformat(),
                        },
                        {
                            "id": "va-test-002",
                            "testId": "no-public-buckets",
                            "outcome": "FAIL",
                            "createdAt": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="vanta_api",
                source_type=SourceType.GRC,
                provider="vanta_api",
                event_type="vanta_api_vulnerabilities",
                raw_data={
                    "response": [
                        {
                            "id": "va-vuln-001",
                            "cve": "CVE-2023-44487",
                            "severity": "HIGH",
                            "status": "OPEN",
                            "assetId": "va-asset-001",
                            "assetName": "prod-web-01",
                        },
                        {
                            "id": "va-vuln-002",
                            "cve": "CVE-2021-44228",
                            "severity": "CRITICAL",
                            "status": "OPEN",
                            "assetId": "va-asset-002",
                            "assetName": "prod-db-01",
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 31. Secureframe
# ---------------------------------------------------------------------------
class DemoSecureframeConnector(BaseConnector):
    """Simulates Secureframe GRC collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="secureframe",
            source_type=SourceType.GRC,
            provider="secureframe",
        )
        result.events.append(
            RawEventData(
                source="secureframe",
                source_type=SourceType.GRC,
                provider="secureframe",
                event_type="secureframe_controls",
                raw_data={
                    "response": [
                        {
                            "id": "sf-ctrl-001",
                            "name": "Encryption in Transit",
                            "status": "passing",
                            "framework": "SOC2",
                        },
                        {
                            "id": "sf-ctrl-002",
                            "name": "Annual Access Review",
                            "status": "failing",
                            "framework": "SOC2",
                        },
                        {
                            "id": "sf-ctrl-003",
                            "name": "Security Awareness Training",
                            "status": "passing",
                            "framework": "ISO27001",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="secureframe",
                source_type=SourceType.GRC,
                provider="secureframe",
                event_type="secureframe_tests",
                raw_data={
                    "response": [
                        {
                            "id": "sf-test-001",
                            "name": "All production DBs encrypted",
                            "result": "passing",
                            "lastRun": NOW.isoformat(),
                        },
                        {
                            "id": "sf-test-002",
                            "name": "Access reviews completed",
                            "result": "failing",
                            "lastRun": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="secureframe",
                source_type=SourceType.GRC,
                provider="secureframe",
                event_type="secureframe_personnel",
                raw_data={
                    "response": [
                        {
                            "id": "sf-per-001",
                            "email": "alice@acme.com",
                            "trainingStatus": "complete",
                            "backgroundCheckStatus": "complete",
                        },
                        {
                            "id": "sf-per-002",
                            "email": "dave@acme.com",
                            "trainingStatus": "overdue",
                            "backgroundCheckStatus": "pending",
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 32. Salesforce
# ---------------------------------------------------------------------------
class DemoSalesforceConnector(BaseConnector):
    """Simulates Salesforce collaboration/CRM security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="salesforce",
            source_type=SourceType.COLLABORATION,
            provider="salesforce",
        )
        result.events.append(
            RawEventData(
                source="salesforce",
                source_type=SourceType.COLLABORATION,
                provider="salesforce",
                event_type="salesforce_users",
                raw_data={
                    "response": [
                        {
                            "Id": "sf-usr-001",
                            "Username": "alice@acme.com",
                            "IsActive": True,
                            "ProfileId": "admin",
                            "LastLoginDate": NOW.isoformat(),
                        },
                        {
                            "Id": "sf-usr-002",
                            "Username": "bob@acme.com",
                            "IsActive": True,
                            "ProfileId": "standard",
                            "LastLoginDate": (NOW - timedelta(days=60)).isoformat(),
                        },
                        {
                            "Id": "sf-usr-003",
                            "Username": "ex-emp@acme.com",
                            "IsActive": True,
                            "ProfileId": "standard",
                            "LastLoginDate": (NOW - timedelta(days=200)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="salesforce",
                source_type=SourceType.COLLABORATION,
                provider="salesforce",
                event_type="salesforce_profiles",
                raw_data={
                    "response": [
                        {
                            "Id": "prof-001",
                            "Name": "System Administrator",
                            "UserLicense": {"Name": "Salesforce"},
                            "Description": "Full admin access",
                        },
                        {
                            "Id": "prof-002",
                            "Name": "Standard User",
                            "UserLicense": {"Name": "Salesforce"},
                            "Description": "Standard access",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="salesforce",
                source_type=SourceType.COLLABORATION,
                provider="salesforce",
                event_type="salesforce_login_history",
                raw_data={
                    "response": [
                        {
                            "Id": "lh-001",
                            "UserId": "sf-usr-001",
                            "Status": "Success",
                            "SourceIp": "203.0.113.5",
                            "LoginTime": NOW.isoformat(),
                        },
                        {
                            "Id": "lh-002",
                            "UserId": "sf-usr-001",
                            "Status": "Failed",
                            "SourceIp": "198.51.100.1",
                            "LoginTime": (NOW - timedelta(hours=2)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 33. Teams Compliance
# ---------------------------------------------------------------------------
class DemoTeamsComplianceConnector(BaseConnector):
    """Simulates Microsoft Teams compliance collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="teams_compliance",
            source_type=SourceType.COLLABORATION,
            provider="teams_compliance",
        )
        result.events.append(
            RawEventData(
                source="teams_compliance",
                source_type=SourceType.COLLABORATION,
                provider="teams_compliance",
                event_type="teams_call_records",
                raw_data={
                    "response": [
                        {
                            "id": "tc-call-001",
                            "type": "groupCall",
                            "modalities": ["audio"],
                            "startDateTime": (NOW - timedelta(hours=3)).isoformat(),
                            "endDateTime": (NOW - timedelta(hours=2, minutes=30)).isoformat(),
                            "joinWebUrl": "https://teams.microsoft.com/meet/xxx",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="teams_compliance",
                source_type=SourceType.COLLABORATION,
                provider="teams_compliance",
                event_type="teams_inventory",
                raw_data={
                    "response": [
                        {
                            "id": "tc-team-001",
                            "displayName": "Security Team",
                            "visibility": "Private",
                            "memberCount": 8,
                        },
                        {
                            "id": "tc-team-002",
                            "displayName": "Engineering",
                            "visibility": "Private",
                            "memberCount": 25,
                        },
                        {
                            "id": "tc-team-003",
                            "displayName": "All Hands",
                            "visibility": "Public",
                            "memberCount": 120,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="teams_compliance",
                source_type=SourceType.COLLABORATION,
                provider="teams_compliance",
                event_type="teams_security_alerts",
                raw_data={
                    "response": [
                        {
                            "id": "tc-alert-001",
                            "category": "externalUserInvitation",
                            "severity": "medium",
                            "description": "External user joined sensitive channel",
                            "createdDateTime": (NOW - timedelta(hours=5)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 34. Zoom
# ---------------------------------------------------------------------------
class DemoZoomConnector(BaseConnector):
    """Simulates Zoom compliance collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="zoom",
            source_type=SourceType.COLLABORATION,
            provider="zoom",
        )
        result.events.append(
            RawEventData(
                source="zoom",
                source_type=SourceType.COLLABORATION,
                provider="zoom",
                event_type="zoom_users",
                raw_data={
                    "response": [
                        {
                            "id": "zoom-usr-001",
                            "email": "alice@acme.com",
                            "type": 2,
                            "status": "active",
                            "last_login_time": NOW.isoformat(),
                        },
                        {
                            "id": "zoom-usr-002",
                            "email": "external@partner.com",
                            "type": 1,
                            "status": "active",
                            "last_login_time": (NOW - timedelta(days=5)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="zoom",
                source_type=SourceType.COLLABORATION,
                provider="zoom",
                event_type="zoom_meetings",
                raw_data={
                    "response": [
                        {
                            "id": "zoom-meet-001",
                            "topic": "Weekly Security Review",
                            "password": "protected",
                            "waiting_room": True,
                            "start_time": (NOW + timedelta(hours=2)).isoformat(),
                            "duration": 60,
                        },
                        {
                            "id": "zoom-meet-002",
                            "topic": "Open Town Hall",
                            "password": "",
                            "waiting_room": False,
                            "start_time": (NOW + timedelta(days=1)).isoformat(),
                            "duration": 30,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="zoom",
                source_type=SourceType.COLLABORATION,
                provider="zoom",
                event_type="zoom_daily_report",
                raw_data={
                    "response": [
                        {
                            "date": NOW.strftime("%Y-%m-%d"),
                            "new_users": 2,
                            "meetings": 15,
                            "participants": 87,
                            "meeting_minutes": 1440,
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 35. Smarsh
# ---------------------------------------------------------------------------
class DemoSmarshConnector(BaseConnector):
    """Simulates Smarsh communications archiving collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="smarsh",
            source_type=SourceType.COLLABORATION,
            provider="smarsh",
        )
        result.events.append(
            RawEventData(
                source="smarsh",
                source_type=SourceType.COLLABORATION,
                provider="smarsh",
                event_type="smarsh_archives",
                raw_data={
                    "response": [
                        {
                            "id": "sm-arch-001",
                            "name": "Email Archive 2024",
                            "status": "active",
                            "messageCount": 458000,
                            "retentionPolicyId": "ret-7yr",
                        },
                        {
                            "id": "sm-arch-002",
                            "name": "Teams Archive 2024",
                            "status": "active",
                            "messageCount": 125000,
                            "retentionPolicyId": "ret-7yr",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="smarsh",
                source_type=SourceType.COLLABORATION,
                provider="smarsh",
                event_type="smarsh_policies",
                raw_data={
                    "response": [
                        {
                            "id": "sm-pol-001",
                            "name": "7 Year Retention",
                            "retentionDays": 2555,
                            "enabled": True,
                        },
                        {
                            "id": "sm-pol-002",
                            "name": "GDPR Compliant Retention",
                            "retentionDays": 1095,
                            "enabled": True,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="smarsh",
                source_type=SourceType.COLLABORATION,
                provider="smarsh",
                event_type="smarsh_violations",
                raw_data={
                    "response": [
                        {
                            "id": "sm-viol-001",
                            "policyName": "PII in External Email",
                            "severity": "high",
                            "status": "open",
                            "detectedAt": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "sm-viol-002",
                            "policyName": "Unauthorized Trading Discussion",
                            "severity": "critical",
                            "status": "escalated",
                            "detectedAt": (NOW - timedelta(days=1)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 36. Ansible
# ---------------------------------------------------------------------------
class DemoAnsibleConnector(BaseConnector):
    """Simulates Ansible Tower/AWX infrastructure collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="ansible",
            source_type=SourceType.INFRASTRUCTURE,
            provider="ansible",
        )
        result.events.append(
            RawEventData(
                source="ansible",
                source_type=SourceType.INFRASTRUCTURE,
                provider="ansible",
                event_type="ansible_hosts",
                raw_data={
                    "response": [
                        {
                            "id": 1,
                            "name": "prod-web-01",
                            "enabled": True,
                            "inventory": 1,
                            "last_job": {"status": "successful"},
                        },
                        {
                            "id": 2,
                            "name": "prod-db-01",
                            "enabled": True,
                            "inventory": 1,
                            "last_job": {"status": "successful"},
                        },
                        {
                            "id": 3,
                            "name": "legacy-srv",
                            "enabled": False,
                            "inventory": 2,
                            "last_job": {"status": "failed"},
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ansible",
                source_type=SourceType.INFRASTRUCTURE,
                provider="ansible",
                event_type="ansible_inventories",
                raw_data={
                    "response": [
                        {
                            "id": 1,
                            "name": "Production",
                            "host_count": 15,
                            "group_count": 4,
                            "inventory_sources_with_failures": 0,
                        },
                        {
                            "id": 2,
                            "name": "Development",
                            "host_count": 8,
                            "group_count": 2,
                            "inventory_sources_with_failures": 1,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ansible",
                source_type=SourceType.INFRASTRUCTURE,
                provider="ansible",
                event_type="ansible_job_templates",
                raw_data={
                    "response": [
                        {
                            "id": 10,
                            "name": "Deploy Application",
                            "status": "successful",
                            "last_job_run": NOW.isoformat(),
                            "project": {"name": "acme-app"},
                        },
                        {
                            "id": 11,
                            "name": "Patch Servers",
                            "status": "failed",
                            "last_job_run": (NOW - timedelta(days=2)).isoformat(),
                            "project": {"name": "security-ops"},
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 37. ADP
# ---------------------------------------------------------------------------
class DemoADPConnector(BaseConnector):
    """Simulates ADP HRIS collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name, source="adp", source_type=SourceType.HRIS, provider="adp"
        )
        result.events.append(
            RawEventData(
                source="adp",
                source_type=SourceType.HRIS,
                provider="adp",
                event_type="adp_workers",
                raw_data={
                    "response": [
                        {
                            "associateOID": "adp-001",
                            "person": {
                                "legalName": {"givenName": "Alice", "familyName": "Chen"},
                                "communicationEmails": [{"emailUri": "alice@acme.com"}],
                            },
                            "workerStatus": {"statusCode": {"codeValue": "Active"}},
                        },
                        {
                            "associateOID": "adp-002",
                            "person": {
                                "legalName": {"givenName": "Bob", "familyName": "Martinez"},
                                "communicationEmails": [{"emailUri": "bob@acme.com"}],
                            },
                            "workerStatus": {"statusCode": {"codeValue": "Active"}},
                        },
                        {
                            "associateOID": "adp-003",
                            "person": {
                                "legalName": {"givenName": "Dave", "familyName": "Ex"},
                                "communicationEmails": [{"emailUri": "dave@acme.com"}],
                            },
                            "workerStatus": {"statusCode": {"codeValue": "Terminated"}},
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="adp",
                source_type=SourceType.HRIS,
                provider="adp",
                event_type="adp_work_assignments",
                raw_data={
                    "response": [
                        {
                            "associateOID": "adp-001",
                            "workerDates": {"originalHireDate": "2023-01-15"},
                            "position": {
                                "jobTitle": "Security Engineer",
                                "organizationalUnits": [
                                    {
                                        "typeCode": {"codeValue": "Department"},
                                        "nameCode": {"shortName": "Engineering"},
                                    }
                                ],
                            },
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 38. UKG
# ---------------------------------------------------------------------------
class DemoUKGConnector(BaseConnector):
    """Simulates UKG Pro HRIS collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name, source="ukg", source_type=SourceType.HRIS, provider="ukg"
        )
        result.events.append(
            RawEventData(
                source="ukg",
                source_type=SourceType.HRIS,
                provider="ukg",
                event_type="ukg_employees",
                raw_data={
                    "response": [
                        {
                            "employeeId": "ukg-001",
                            "firstName": "Alice",
                            "lastName": "Chen",
                            "emailAddress": "alice@acme.com",
                            "employmentStatus": "Active",
                            "department": "Engineering",
                            "hireDate": "2023-01-15",
                        },
                        {
                            "employeeId": "ukg-002",
                            "firstName": "Carol",
                            "lastName": "Smith",
                            "emailAddress": "carol@acme.com",
                            "employmentStatus": "Active",
                            "department": "Finance",
                            "hireDate": "2022-06-01",
                        },
                        {
                            "employeeId": "ukg-003",
                            "firstName": "Dave",
                            "lastName": "Old",
                            "emailAddress": "dave@acme.com",
                            "employmentStatus": "Terminated",
                            "department": "Sales",
                            "hireDate": "2021-03-10",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ukg",
                source_type=SourceType.HRIS,
                provider="ukg",
                event_type="ukg_employment_records",
                raw_data={
                    "response": [
                        {
                            "employeeId": "ukg-001",
                            "jobTitle": "Security Engineer",
                            "effectiveDate": "2023-01-15",
                            "payGroup": "Exempt",
                            "managerId": "ukg-010",
                        },
                        {
                            "employeeId": "ukg-002",
                            "jobTitle": "Finance Analyst",
                            "effectiveDate": "2022-06-01",
                            "payGroup": "Exempt",
                            "managerId": "ukg-011",
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 39. SAP SuccessFactors
# ---------------------------------------------------------------------------
class DemoSAPSuccessFactorsConnector(BaseConnector):
    """Simulates SAP SuccessFactors HRIS collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="sap_successfactors",
            source_type=SourceType.HRIS,
            provider="sap_successfactors",
        )
        result.events.append(
            RawEventData(
                source="sap_successfactors",
                source_type=SourceType.HRIS,
                provider="sap_successfactors",
                event_type="sap_sf_users",
                raw_data={
                    "response": [
                        {
                            "userId": "sap-001",
                            "firstName": "Alice",
                            "lastName": "Chen",
                            "email": "alice@acme.com",
                            "status": "active",
                            "division": "Engineering",
                        },
                        {
                            "userId": "sap-002",
                            "firstName": "Bob",
                            "lastName": "Martinez",
                            "email": "bob@acme.com",
                            "status": "active",
                            "division": "Product",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sap_successfactors",
                source_type=SourceType.HRIS,
                provider="sap_successfactors",
                event_type="sap_sf_employment",
                raw_data={
                    "response": [
                        {
                            "userId": "sap-001",
                            "jobTitle": "Security Engineer",
                            "startDate": "2023-01-15",
                            "endDate": None,
                            "department": "Engineering",
                            "managerId": "sap-010",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sap_successfactors",
                source_type=SourceType.HRIS,
                provider="sap_successfactors",
                event_type="sap_sf_certificates",
                raw_data={
                    "response": [
                        {
                            "userId": "sap-001",
                            "certName": "CISSP",
                            "issueDate": "2023-06-01",
                            "expiryDate": VALID,
                            "issuer": "ISC2",
                        },
                        {
                            "userId": "sap-002",
                            "certName": "AWS SAA",
                            "issueDate": "2022-01-10",
                            "expiryDate": EXPIRED,
                            "issuer": "AWS",
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 40. Weights & Biases (wandb)
# ---------------------------------------------------------------------------
class DemoWandBConnector(BaseConnector):
    """Simulates Weights and Biases AI/ML governance collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name, source="wandb", source_type=SourceType.AI_ML, provider="wandb"
        )
        result.events.append(
            RawEventData(
                source="wandb",
                source_type=SourceType.AI_ML,
                provider="wandb",
                event_type="wandb_projects",
                raw_data={
                    "response": [
                        {
                            "id": "wb-proj-001",
                            "name": "fraud-detection-v2",
                            "entity": "acme-ml",
                            "access": "private",
                            "runCount": 142,
                        },
                        {
                            "id": "wb-proj-002",
                            "name": "churn-prediction",
                            "entity": "acme-ml",
                            "access": "public",
                            "runCount": 87,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="wandb",
                source_type=SourceType.AI_ML,
                provider="wandb",
                event_type="wandb_runs",
                raw_data={
                    "response": [
                        {
                            "id": "wb-run-001",
                            "name": "run-xkcd-001",
                            "state": "finished",
                            "project": "fraud-detection-v2",
                            "user": "alice",
                            "createdAt": (NOW - timedelta(hours=4)).isoformat(),
                            "config": {"lr": 0.001, "epochs": 10},
                        },
                        {
                            "id": "wb-run-002",
                            "name": "run-xkcd-002",
                            "state": "crashed",
                            "project": "fraud-detection-v2",
                            "user": "bob",
                            "createdAt": (NOW - timedelta(hours=2)).isoformat(),
                            "config": {"lr": 0.01, "epochs": 50},
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="wandb",
                source_type=SourceType.AI_ML,
                provider="wandb",
                event_type="wandb_artifacts",
                raw_data={
                    "response": [
                        {
                            "id": "wb-art-001",
                            "name": "fraud-model:v5",
                            "type": "model",
                            "project": "fraud-detection-v2",
                            "size": 52428800,
                            "createdAt": (NOW - timedelta(days=3)).isoformat(),
                        },
                        {
                            "id": "wb-art-002",
                            "name": "training-data:v12",
                            "type": "dataset",
                            "project": "fraud-detection-v2",
                            "size": 1073741824,
                            "createdAt": (NOW - timedelta(days=7)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 41. Vertex AI
# ---------------------------------------------------------------------------
class DemoVertexAIConnector(BaseConnector):
    """Simulates Google Vertex AI governance collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="vertex_ai",
            source_type=SourceType.AI_ML,
            provider="vertex_ai",
        )
        result.events.append(
            RawEventData(
                source="vertex_ai",
                source_type=SourceType.AI_ML,
                provider="vertex_ai",
                event_type="vertex_ai_models",
                raw_data={
                    "response": [
                        {
                            "name": "projects/acme/locations/us-central1/models/fraud-detector",
                            "displayName": "Fraud Detector v3",
                            "createTime": (NOW - timedelta(days=30)).isoformat(),
                            "trainingPipeline": "projects/acme/pipelines/fraud-pipeline",
                        },
                        {
                            "name": "projects/acme/locations/us-central1/models/churn-predictor",
                            "displayName": "Churn Predictor v1",
                            "createTime": (NOW - timedelta(days=90)).isoformat(),
                            "trainingPipeline": "projects/acme/pipelines/churn-pipeline",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="vertex_ai",
                source_type=SourceType.AI_ML,
                provider="vertex_ai",
                event_type="vertex_ai_endpoints",
                raw_data={
                    "response": [
                        {
                            "name": "projects/acme/locations/us-central1/endpoints/ep-001",
                            "displayName": "Fraud API Endpoint",
                            "deployedModels": [{"id": "dm-001"}],
                            "trafficSplit": {"dm-001": 100},
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="vertex_ai",
                source_type=SourceType.AI_ML,
                provider="vertex_ai",
                event_type="vertex_ai_datasets",
                raw_data={
                    "response": [
                        {
                            "name": "projects/acme/locations/us-central1/datasets/ds-001",
                            "displayName": "Fraud Training Data",
                            "metadataSchemaUri": "tabular",
                            "createTime": (NOW - timedelta(days=60)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 42. Mimecast
# ---------------------------------------------------------------------------
class DemoMimecastConnector(BaseConnector):
    """Simulates Mimecast email security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="mimecast",
            source_type=SourceType.EMAIL_SECURITY,
            provider="mimecast",
        )
        result.events.append(
            RawEventData(
                source="mimecast",
                source_type=SourceType.EMAIL_SECURITY,
                provider="mimecast",
                event_type="mimecast_url_logs",
                raw_data={
                    "response": [
                        {
                            "id": "mc-url-001",
                            "sender": "phish@evil.com",
                            "recipient": "alice@acme.com",
                            "url": "http://malicious.example.com/steal",
                            "action": "block",
                            "scanResult": "malicious",
                            "sendTime": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "mc-url-002",
                            "sender": "news@legit.com",
                            "recipient": "bob@acme.com",
                            "url": "https://legit.example.com/article",
                            "action": "allow",
                            "scanResult": "safe",
                            "sendTime": (NOW - timedelta(hours=1)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="mimecast",
                source_type=SourceType.EMAIL_SECURITY,
                provider="mimecast",
                event_type="mimecast_attachment_logs",
                raw_data={
                    "response": [
                        {
                            "id": "mc-att-001",
                            "sender": "unknown@external.com",
                            "recipient": "cfo@acme.com",
                            "filename": "invoice.exe",
                            "action": "block",
                            "scanResult": "malware",
                            "sendTime": (NOW - timedelta(hours=5)).isoformat(),
                        },
                        {
                            "id": "mc-att-002",
                            "sender": "partner@trusted.com",
                            "recipient": "legal@acme.com",
                            "filename": "contract.pdf",
                            "action": "allow",
                            "scanResult": "safe",
                            "sendTime": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="mimecast",
                source_type=SourceType.EMAIL_SECURITY,
                provider="mimecast",
                event_type="mimecast_audit_events",
                raw_data={
                    "response": [
                        {
                            "id": "mc-audit-001",
                            "eventType": "login",
                            "user": "alice@acme.com",
                            "ipAddress": "203.0.113.5",
                            "datetime": NOW.isoformat(),
                            "success": True,
                        },
                        {
                            "id": "mc-audit-002",
                            "eventType": "policy_change",
                            "user": "admin@acme.com",
                            "ipAddress": "10.0.0.5",
                            "datetime": (NOW - timedelta(hours=2)).isoformat(),
                            "success": True,
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 43. Chainguard
# ---------------------------------------------------------------------------
class DemoChainGuardConnector(BaseConnector):
    """Simulates Chainguard container security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="chainguard",
            source_type=SourceType.CONTAINER_SECURITY,
            provider="chainguard",
        )
        result.events.append(
            RawEventData(
                source="chainguard",
                source_type=SourceType.CONTAINER_SECURITY,
                provider="chainguard",
                event_type="chainguard_images",
                raw_data={
                    "response": [
                        {
                            "id": "cg-img-001",
                            "name": "cgr.dev/acme/python:3.12",
                            "digest": "sha256:abc123",
                            "vulnerabilities": 0,
                            "createdAt": (NOW - timedelta(days=5)).isoformat(),
                        },
                        {
                            "id": "cg-img-002",
                            "name": "cgr.dev/acme/node:20",
                            "digest": "sha256:def456",
                            "vulnerabilities": 0,
                            "createdAt": (NOW - timedelta(days=3)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="chainguard",
                source_type=SourceType.CONTAINER_SECURITY,
                provider="chainguard",
                event_type="chainguard_policies",
                raw_data={
                    "response": [
                        {
                            "id": "cg-pol-001",
                            "name": "No Critical CVEs",
                            "enforcement": "enforce",
                            "enabled": True,
                        },
                        {
                            "id": "cg-pol-002",
                            "name": "Signed Images Only",
                            "enforcement": "warn",
                            "enabled": True,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="chainguard",
                source_type=SourceType.CONTAINER_SECURITY,
                provider="chainguard",
                event_type="chainguard_vulnerabilities",
                raw_data={
                    "response": [
                        {
                            "id": "cg-vuln-001",
                            "image": "legacy-ubuntu:20.04",
                            "cve": "CVE-2023-29491",
                            "severity": "HIGH",
                            "fixed": False,
                        },
                        {
                            "id": "cg-vuln-002",
                            "image": "legacy-ubuntu:20.04",
                            "cve": "CVE-2022-4415",
                            "severity": "MEDIUM",
                            "fixed": True,
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 44. Syft/Grype
# ---------------------------------------------------------------------------
class DemoSyftGrypeConnector(BaseConnector):
    """Simulates Syft SBOM + Grype vulnerability scan collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="syft_grype",
            source_type=SourceType.CONTAINER_SECURITY,
            provider="syft_grype",
        )
        result.events.append(
            RawEventData(
                source="syft_grype",
                source_type=SourceType.CONTAINER_SECURITY,
                provider="syft_grype",
                event_type="syft_grype_vulnerabilities",
                raw_data={
                    "response": [
                        {
                            "vulnerability": {
                                "id": "CVE-2023-44487",
                                "severity": "High",
                                "description": "HTTP/2 Rapid Reset Attack",
                            },
                            "matchDetails": [{"type": "exact-direct-match"}],
                            "artifact": {
                                "name": "golang.org/x/net",
                                "version": "v0.10.0",
                                "type": "go-module",
                            },
                        },
                        {
                            "vulnerability": {
                                "id": "CVE-2021-44228",
                                "severity": "Critical",
                                "description": "Apache Log4Shell",
                            },
                            "matchDetails": [{"type": "exact-direct-match"}],
                            "artifact": {
                                "name": "log4j-core",
                                "version": "2.14.1",
                                "type": "java-archive",
                            },
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="syft_grype",
                source_type=SourceType.CONTAINER_SECURITY,
                provider="syft_grype",
                event_type="syft_grype_sbom",
                raw_data={
                    "response": [
                        {
                            "id": "sbom-001",
                            "image": "acme/api-server:latest",
                            "packageCount": 342,
                            "generatedAt": NOW.isoformat(),
                            "packages": [
                                {"name": "flask", "version": "2.3.3", "type": "python"},
                                {"name": "requests", "version": "2.31.0", "type": "python"},
                                {
                                    "name": "golang.org/x/net",
                                    "version": "v0.10.0",
                                    "type": "go-module",
                                },
                            ],
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 45. FOSSA
# ---------------------------------------------------------------------------
class DemoFossaConnector(BaseConnector):
    """Simulates FOSSA open source license compliance collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name, source="fossa", source_type=SourceType.CODE, provider="fossa"
        )
        result.events.append(
            RawEventData(
                source="fossa",
                source_type=SourceType.CODE,
                provider="fossa",
                event_type="fossa_projects",
                raw_data={
                    "response": [
                        {
                            "id": "fossa-proj-001",
                            "title": "acme-api",
                            "locator": "git+github.com/acme/api",
                            "isPublic": False,
                            "issueCount": 3,
                        },
                        {
                            "id": "fossa-proj-002",
                            "title": "acme-frontend",
                            "locator": "git+github.com/acme/frontend",
                            "isPublic": False,
                            "issueCount": 0,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="fossa",
                source_type=SourceType.CODE,
                provider="fossa",
                event_type="fossa_issues",
                raw_data={
                    "response": [
                        {
                            "id": "fossa-iss-001",
                            "type": "vulnerability",
                            "severity": "critical",
                            "title": "Prototype pollution in lodash",
                            "projectId": "fossa-proj-001",
                            "status": "unresolved",
                        },
                        {
                            "id": "fossa-iss-002",
                            "type": "license",
                            "severity": "high",
                            "title": "GPL-3.0 license incompatibility",
                            "projectId": "fossa-proj-001",
                            "status": "unresolved",
                        },
                        {
                            "id": "fossa-iss-003",
                            "type": "vulnerability",
                            "severity": "medium",
                            "title": "ReDoS in validator.js",
                            "projectId": "fossa-proj-001",
                            "status": "resolved",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="fossa",
                source_type=SourceType.CODE,
                provider="fossa",
                event_type="fossa_dependencies",
                raw_data={
                    "response": [
                        {
                            "locator": "npm+lodash$4.17.20",
                            "name": "lodash",
                            "version": "4.17.20",
                            "license": "MIT",
                            "projectId": "fossa-proj-001",
                        },
                        {
                            "locator": "npm+express$4.18.2",
                            "name": "express",
                            "version": "4.18.2",
                            "license": "MIT",
                            "projectId": "fossa-proj-001",
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 46. Snyk Container
# ---------------------------------------------------------------------------
class DemoSnykContainerConnector(BaseConnector):
    """Simulates Snyk Container security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="snyk_container",
            source_type=SourceType.CONTAINER_SECURITY,
            provider="snyk_container",
        )
        result.events.append(
            RawEventData(
                source="snyk_container",
                source_type=SourceType.CONTAINER_SECURITY,
                provider="snyk_container",
                event_type="snyk_container_images",
                raw_data={
                    "response": [
                        {
                            "id": "sc-img-001",
                            "name": "acme/api-server",
                            "tag": "latest",
                            "issueCountsBySeverity": {
                                "critical": 2,
                                "high": 5,
                                "medium": 12,
                                "low": 8,
                            },
                            "imageId": "sha256:abc123",
                        },
                        {
                            "id": "sc-img-002",
                            "name": "acme/worker",
                            "tag": "v1.2",
                            "issueCountsBySeverity": {
                                "critical": 0,
                                "high": 1,
                                "medium": 3,
                                "low": 5,
                            },
                            "imageId": "sha256:def456",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="snyk_container",
                source_type=SourceType.CONTAINER_SECURITY,
                provider="snyk_container",
                event_type="snyk_container_issues",
                raw_data={
                    "response": [
                        {
                            "id": "sc-iss-001",
                            "issueType": "vuln",
                            "pkgName": "openssl",
                            "pkgVersions": ["1.1.1"],
                            "issueData": {
                                "id": "SNYK-001",
                                "title": "OpenSSL Buffer Overflow",
                                "severity": "critical",
                                "cvssScore": 9.1,
                            },
                        },
                        {
                            "id": "sc-iss-002",
                            "issueType": "vuln",
                            "pkgName": "curl",
                            "pkgVersions": ["7.68.0"],
                            "issueData": {
                                "id": "SNYK-002",
                                "title": "curl SSRF",
                                "severity": "high",
                                "cvssScore": 7.5,
                            },
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 47. Socket.dev
# ---------------------------------------------------------------------------
class DemoSocketDevConnector(BaseConnector):
    """Simulates Socket.dev supply chain security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="socketdev",
            source_type=SourceType.CODE,
            provider="socketdev",
        )
        result.events.append(
            RawEventData(
                source="socketdev",
                source_type=SourceType.CODE,
                provider="socketdev",
                event_type="socketdev_repos",
                raw_data={
                    "response": [
                        {
                            "id": "sock-repo-001",
                            "fullName": "acme/api",
                            "riskScore": 25,
                            "alertCount": 3,
                            "defaultBranch": "main",
                        },
                        {
                            "id": "sock-repo-002",
                            "fullName": "acme/frontend",
                            "riskScore": 10,
                            "alertCount": 0,
                            "defaultBranch": "main",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="socketdev",
                source_type=SourceType.CODE,
                provider="socketdev",
                event_type="socketdev_alerts",
                raw_data={
                    "response": [
                        {
                            "id": "sock-alert-001",
                            "type": "installScripts",
                            "severity": "high",
                            "packageName": "malicious-pkg",
                            "packageVersion": "1.0.0",
                            "repoId": "sock-repo-001",
                            "createdAt": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "sock-alert-002",
                            "type": "networkAccess",
                            "severity": "medium",
                            "packageName": "telemetry-spy",
                            "packageVersion": "2.1.0",
                            "repoId": "sock-repo-001",
                            "createdAt": (NOW - timedelta(days=1)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 48. Salt Security
# ---------------------------------------------------------------------------
class DemoSaltSecurityConnector(BaseConnector):
    """Simulates Salt Security API protection collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="salt_security",
            source_type=SourceType.CUSTOM,
            provider="salt_security",
        )
        result.events.append(
            RawEventData(
                source="salt_security",
                source_type=SourceType.CUSTOM,
                provider="salt_security",
                event_type="salt_security_apis",
                raw_data={
                    "response": [
                        {
                            "id": "salt-api-001",
                            "name": "Payment API",
                            "host": "api.acme.com",
                            "basePath": "/v1/payments",
                            "riskScore": 75,
                            "endpointCount": 12,
                            "authType": "OAuth2",
                        },
                        {
                            "id": "salt-api-002",
                            "name": "User API",
                            "host": "api.acme.com",
                            "basePath": "/v1/users",
                            "riskScore": 45,
                            "endpointCount": 8,
                            "authType": "API_KEY",
                        },
                        {
                            "id": "salt-api-003",
                            "name": "Internal API",
                            "host": "internal.acme.com",
                            "basePath": "/internal",
                            "riskScore": 90,
                            "endpointCount": 5,
                            "authType": "NONE",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="salt_security",
                source_type=SourceType.CUSTOM,
                provider="salt_security",
                event_type="salt_security_alerts",
                raw_data={
                    "response": [
                        {
                            "id": "salt-alert-001",
                            "alertType": "BOLA",
                            "severity": "critical",
                            "apiId": "salt-api-001",
                            "description": "Broken Object Level Authorization detected",
                            "detectedAt": (NOW - timedelta(hours=2)).isoformat(),
                        },
                        {
                            "id": "salt-alert-002",
                            "alertType": "EXCESSIVE_DATA",
                            "severity": "high",
                            "apiId": "salt-api-002",
                            "description": "API returning excessive PII fields",
                            "detectedAt": (NOW - timedelta(hours=5)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="salt_security",
                source_type=SourceType.CUSTOM,
                provider="salt_security",
                event_type="salt_security_findings",
                raw_data={
                    "response": [
                        {
                            "id": "salt-find-001",
                            "title": "Unauthenticated endpoint exposed",
                            "severity": "critical",
                            "status": "open",
                            "apiId": "salt-api-003",
                            "category": "Broken Authentication",
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 49. Noname Security
# ---------------------------------------------------------------------------
class DemoNoNameConnector(BaseConnector):
    """Simulates Noname API security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="noname",
            source_type=SourceType.CUSTOM,
            provider="noname",
        )
        result.events.append(
            RawEventData(
                source="noname",
                source_type=SourceType.CUSTOM,
                provider="noname",
                event_type="noname_apis",
                raw_data={
                    "response": [
                        {
                            "id": "nn-api-001",
                            "name": "checkout-api",
                            "host": "shop.acme.com",
                            "environment": "production",
                            "sensitiveDataTypes": ["PII", "PCI"],
                            "riskLevel": "HIGH",
                        },
                        {
                            "id": "nn-api-002",
                            "name": "auth-api",
                            "host": "auth.acme.com",
                            "environment": "production",
                            "sensitiveDataTypes": ["PII"],
                            "riskLevel": "MEDIUM",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="noname",
                source_type=SourceType.CUSTOM,
                provider="noname",
                event_type="noname_issues",
                raw_data={
                    "response": [
                        {
                            "id": "nn-iss-001",
                            "title": "JWT algorithm confusion",
                            "severity": "CRITICAL",
                            "status": "open",
                            "apiId": "nn-api-002",
                            "category": "Auth",
                        },
                        {
                            "id": "nn-iss-002",
                            "title": "PCI data in logs",
                            "severity": "HIGH",
                            "status": "open",
                            "apiId": "nn-api-001",
                            "category": "Data Leakage",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="noname",
                source_type=SourceType.CUSTOM,
                provider="noname",
                event_type="noname_alerts",
                raw_data={
                    "response": [
                        {
                            "id": "nn-alert-001",
                            "type": "ANOMALY",
                            "severity": "high",
                            "description": "Unusual spike in 401 errors",
                            "apiId": "nn-api-002",
                            "timestamp": (NOW - timedelta(hours=1)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 50. Wallarm
# ---------------------------------------------------------------------------
class DemoWallarmConnector(BaseConnector):
    """Simulates Wallarm WAF/API security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="wallarm",
            source_type=SourceType.NETWORK,
            provider="wallarm",
        )
        result.events.append(
            RawEventData(
                source="wallarm",
                source_type=SourceType.NETWORK,
                provider="wallarm",
                event_type="wallarm_attacks",
                raw_data={
                    "response": [
                        {
                            "id": "wl-atk-001",
                            "type": "sqli",
                            "domain": "api.acme.com",
                            "clientip": "203.0.113.1",
                            "time": (NOW - timedelta(hours=2)).isoformat(),
                            "statuscode": 403,
                            "blocked": True,
                        },
                        {
                            "id": "wl-atk-002",
                            "type": "xss",
                            "domain": "shop.acme.com",
                            "clientip": "198.51.100.5",
                            "time": (NOW - timedelta(hours=4)).isoformat(),
                            "statuscode": 403,
                            "blocked": True,
                        },
                        {
                            "id": "wl-atk-003",
                            "type": "rce",
                            "domain": "api.acme.com",
                            "clientip": "192.0.2.1",
                            "time": (NOW - timedelta(minutes=30)).isoformat(),
                            "statuscode": 200,
                            "blocked": False,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="wallarm",
                source_type=SourceType.NETWORK,
                provider="wallarm",
                event_type="wallarm_vulns",
                raw_data={
                    "response": [
                        {
                            "id": "wl-vuln-001",
                            "type": "sqli",
                            "threat": 9,
                            "domain": "api.acme.com",
                            "path": "/v1/search",
                            "parameter": "q",
                            "status": "open",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="wallarm",
                source_type=SourceType.NETWORK,
                provider="wallarm",
                event_type="wallarm_rules",
                raw_data={
                    "response": [
                        {
                            "id": "wl-rule-001",
                            "type": "block",
                            "enabled": True,
                            "conditions": [{"type": "ip", "values": ["192.0.2.0/24"]}],
                        },
                        {
                            "id": "wl-rule-002",
                            "type": "allow",
                            "enabled": True,
                            "conditions": [{"type": "ip", "values": ["10.0.0.0/8"]}],
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 51. FortyTwoCrunch
# ---------------------------------------------------------------------------
class DemoFortyTwoCrunchConnector(BaseConnector):
    """Simulates 42Crunch API security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="fortytwocrunch",
            source_type=SourceType.CUSTOM,
            provider="fortytwocrunch",
        )
        result.events.append(
            RawEventData(
                source="fortytwocrunch",
                source_type=SourceType.CUSTOM,
                provider="fortytwocrunch",
                event_type="fortytwocrunch_apis",
                raw_data={
                    "response": [
                        {
                            "id": "42c-api-001",
                            "name": "payments-api",
                            "technicalName": "payments-api",
                            "numEndpoints": 15,
                            "overallScore": 68,
                            "criticality": 5,
                            "hasValidation": True,
                        },
                        {
                            "id": "42c-api-002",
                            "name": "legacy-api",
                            "technicalName": "legacy-api",
                            "numEndpoints": 8,
                            "overallScore": 32,
                            "criticality": 4,
                            "hasValidation": False,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="fortytwocrunch",
                source_type=SourceType.CUSTOM,
                provider="fortytwocrunch",
                event_type="fortytwocrunch_audits",
                raw_data={
                    "response": [
                        {
                            "id": "42c-audit-001",
                            "apiId": "42c-api-001",
                            "score": 68,
                            "issues": [
                                {
                                    "id": "v3-audit-security-schemes-list-empty",
                                    "severity": "high",
                                    "description": "No security scheme defined",
                                },
                            ],
                            "auditedAt": NOW.isoformat(),
                        },
                        {
                            "id": "42c-audit-002",
                            "apiId": "42c-api-002",
                            "score": 32,
                            "issues": [
                                {
                                    "id": "v3-audit-schema-additionalprops",
                                    "severity": "medium",
                                    "description": "Schema allows additional properties",
                                },
                                {
                                    "id": "v3-audit-security-schemes-list-empty",
                                    "severity": "high",
                                    "description": "No security scheme defined",
                                },
                            ],
                            "auditedAt": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 52. Tailscale
# ---------------------------------------------------------------------------
class DemoTailscaleConnector(BaseConnector):
    """Simulates Tailscale zero-trust network collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="tailscale",
            source_type=SourceType.NETWORK,
            provider="tailscale",
        )
        result.events.append(
            RawEventData(
                source="tailscale",
                source_type=SourceType.NETWORK,
                provider="tailscale",
                event_type="tailscale_devices",
                raw_data={
                    "response": [
                        {
                            "id": "ts-dev-001",
                            "hostname": "prod-web-01",
                            "os": "linux",
                            "addresses": ["100.64.0.1"],
                            "user": "alice@acme.com",
                            "lastSeen": NOW.isoformat(),
                            "isExternal": False,
                            "keyExpiryDisabled": False,
                            "expires": VALID,
                        },
                        {
                            "id": "ts-dev-002",
                            "hostname": "laptop-bob",
                            "os": "darwin",
                            "addresses": ["100.64.0.5"],
                            "user": "bob@acme.com",
                            "lastSeen": (NOW - timedelta(days=5)).isoformat(),
                            "isExternal": False,
                            "keyExpiryDisabled": False,
                            "expires": EXPIRING_SOON,
                        },
                        {
                            "id": "ts-dev-003",
                            "hostname": "old-server",
                            "os": "linux",
                            "addresses": ["100.64.0.9"],
                            "user": "admin@acme.com",
                            "lastSeen": (NOW - timedelta(days=90)).isoformat(),
                            "isExternal": False,
                            "keyExpiryDisabled": True,
                            "expires": EXPIRED,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="tailscale",
                source_type=SourceType.NETWORK,
                provider="tailscale",
                event_type="tailscale_acl",
                raw_data={
                    "response": [
                        {
                            "id": "ts-acl-001",
                            "action": "accept",
                            "src": ["group:engineering"],
                            "dst": ["tag:prod:443"],
                        },
                        {
                            "id": "ts-acl-002",
                            "action": "accept",
                            "src": ["group:admins"],
                            "dst": ["*:*"],
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 53. Twingate
# ---------------------------------------------------------------------------
class DemoTwingateConnector(BaseConnector):
    """Simulates Twingate zero-trust access collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="twingate",
            source_type=SourceType.NETWORK,
            provider="twingate",
        )
        result.events.append(
            RawEventData(
                source="twingate",
                source_type=SourceType.NETWORK,
                provider="twingate",
                event_type="twingate_resources",
                raw_data={
                    "response": [
                        {
                            "id": "tg-res-001",
                            "name": "Prod DB",
                            "address": {"value": "10.0.1.20"},
                            "isActive": True,
                            "groups": [{"name": "Admins"}, {"name": "DBAs"}],
                        },
                        {
                            "id": "tg-res-002",
                            "name": "Internal Wiki",
                            "address": {"value": "10.0.2.5"},
                            "isActive": True,
                            "groups": [{"name": "All Staff"}],
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="twingate",
                source_type=SourceType.NETWORK,
                provider="twingate",
                event_type="twingate_connectors",
                raw_data={
                    "response": [
                        {
                            "id": "tg-conn-001",
                            "name": "prod-connector",
                            "state": "ALIVE",
                            "remoteNetwork": {"name": "Production VPC"},
                        },
                        {
                            "id": "tg-conn-002",
                            "name": "dev-connector",
                            "state": "DEAD",
                            "remoteNetwork": {"name": "Dev VPC"},
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="twingate",
                source_type=SourceType.NETWORK,
                provider="twingate",
                event_type="twingate_users",
                raw_data={
                    "response": [
                        {
                            "id": "tg-usr-001",
                            "email": "alice@acme.com",
                            "state": "ACTIVE",
                            "role": "ADMIN",
                            "groups": [{"name": "Admins"}],
                        },
                        {
                            "id": "tg-usr-002",
                            "email": "bob@acme.com",
                            "state": "ACTIVE",
                            "role": "MEMBER",
                            "groups": [{"name": "Engineering"}],
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 54. Banyan Security
# ---------------------------------------------------------------------------
class DemoBanyanConnector(BaseConnector):
    """Simulates Banyan Security zero-trust network collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="banyan",
            source_type=SourceType.NETWORK,
            provider="banyan",
        )
        result.events.append(
            RawEventData(
                source="banyan",
                source_type=SourceType.NETWORK,
                provider="banyan",
                event_type="banyan_services",
                raw_data={
                    "response": [
                        {
                            "id": "bn-svc-001",
                            "ServiceName": "prod-db",
                            "Type": "TCP",
                            "Enabled": True,
                            "ClusterName": "prod-cluster",
                        },
                        {
                            "id": "bn-svc-002",
                            "ServiceName": "internal-wiki",
                            "Type": "WEB",
                            "Enabled": True,
                            "ClusterName": "prod-cluster",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="banyan",
                source_type=SourceType.NETWORK,
                provider="banyan",
                event_type="banyan_policies",
                raw_data={
                    "response": [
                        {
                            "id": "bn-pol-001",
                            "PolicyName": "High Trust Level Required",
                            "Enabled": True,
                            "Mode": "enforcing",
                        },
                        {
                            "id": "bn-pol-002",
                            "PolicyName": "Device Trust Check",
                            "Enabled": True,
                            "Mode": "permissive",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="banyan",
                source_type=SourceType.NETWORK,
                provider="banyan",
                event_type="banyan_devices",
                raw_data={
                    "response": [
                        {
                            "DeviceID": "bn-dev-001",
                            "DeviceName": "MacBook-Alice",
                            "Platform": "mac",
                            "TrustScore": 92,
                            "IsRegistered": True,
                        },
                        {
                            "DeviceID": "bn-dev-002",
                            "DeviceName": "Windows-Bob",
                            "Platform": "windows",
                            "TrustScore": 45,
                            "IsRegistered": True,
                        },
                        {
                            "DeviceID": "bn-dev-003",
                            "DeviceName": "Unknown-Device",
                            "Platform": "unknown",
                            "TrustScore": 0,
                            "IsRegistered": False,
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 55. Code42
# ---------------------------------------------------------------------------
class DemoCode42Connector(BaseConnector):
    """Simulates Code42 Incydr DLP collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name, source="code42", source_type=SourceType.DLP, provider="code42"
        )
        result.events.append(
            RawEventData(
                source="code42",
                source_type=SourceType.DLP,
                provider="code42",
                event_type="code42_alerts",
                raw_data={
                    "response": [
                        {
                            "id": "c42-alert-001",
                            "type": "FedEndpointExfiltration",
                            "severity": "CRITICAL",
                            "state": "OPEN",
                            "actor": "ex-employee@acme.com",
                            "createdAt": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "c42-alert-002",
                            "type": "CloudSharePermissions",
                            "severity": "HIGH",
                            "state": "OPEN",
                            "actor": "careless@acme.com",
                            "createdAt": (NOW - timedelta(hours=8)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="code42",
                source_type=SourceType.DLP,
                provider="code42",
                event_type="code42_file_events",
                raw_data={
                    "response": [
                        {
                            "id": "c42-fe-001",
                            "eventType": "MODIFIED",
                            "fileName": "customer_list.csv",
                            "filePath": "/Users/ex-emp/Downloads/",
                            "actor": "ex-employee@acme.com",
                            "deviceName": "LAPTOP-EX",
                            "eventTimestamp": (NOW - timedelta(hours=4)).isoformat(),
                        },
                        {
                            "id": "c42-fe-002",
                            "eventType": "READ",
                            "fileName": "financials_2024.xlsx",
                            "filePath": "/Volumes/SharedDrive/",
                            "actor": "alice@acme.com",
                            "deviceName": "LAPTOP-ALICE",
                            "eventTimestamp": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="code42",
                source_type=SourceType.DLP,
                provider="code42",
                event_type="code42_users",
                raw_data={
                    "response": [
                        {
                            "userId": "c42-usr-001",
                            "username": "alice@acme.com",
                            "status": "Active",
                            "riskScore": 15,
                        },
                        {
                            "userId": "c42-usr-002",
                            "username": "ex-employee@acme.com",
                            "status": "Deactivated",
                            "riskScore": 95,
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 56. Varonis
# ---------------------------------------------------------------------------
class DemoVaronisConnector(BaseConnector):
    """Simulates Varonis data security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="varonis",
            source_type=SourceType.DLP,
            provider="varonis",
        )
        result.events.append(
            RawEventData(
                source="varonis",
                source_type=SourceType.DLP,
                provider="varonis",
                event_type="varonis_alerts",
                raw_data={
                    "response": [
                        {
                            "id": "vr-alert-001",
                            "name": "Ransomware Behavior Detected",
                            "severity": "CRITICAL",
                            "status": "Open",
                            "userDisplayName": "Unknown Process",
                            "time": (NOW - timedelta(hours=1)).isoformat(),
                        },
                        {
                            "id": "vr-alert-002",
                            "name": "Abnormal File Access by User",
                            "severity": "HIGH",
                            "status": "Open",
                            "userDisplayName": "bob@acme.com",
                            "time": (NOW - timedelta(hours=5)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="varonis",
                source_type=SourceType.DLP,
                provider="varonis",
                event_type="varonis_data_classification",
                raw_data={
                    "response": [
                        {
                            "id": "vr-cls-001",
                            "path": "\\\\fileserver\\HR\\salaries.xlsx",
                            "classification": "PII",
                            "sensitiveFileCount": 1,
                            "lastScanned": NOW.isoformat(),
                        },
                        {
                            "id": "vr-cls-002",
                            "path": "\\\\fileserver\\Finance\\",
                            "classification": "Financial",
                            "sensitiveFileCount": 142,
                            "lastScanned": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="varonis",
                source_type=SourceType.DLP,
                provider="varonis",
                event_type="varonis_permissions",
                raw_data={
                    "response": [
                        {
                            "id": "vr-perm-001",
                            "path": "\\\\fileserver\\HR\\",
                            "account": "Everyone",
                            "permissionType": "FullControl",
                            "isInherited": False,
                        },
                        {
                            "id": "vr-perm-002",
                            "path": "\\\\fileserver\\Finance\\",
                            "account": "Finance-Dept",
                            "permissionType": "ReadWrite",
                            "isInherited": True,
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 57. BigID
# ---------------------------------------------------------------------------
class DemoBigIDConnector(BaseConnector):
    """Simulates BigID data governance collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="bigid",
            source_type=SourceType.DATA_GOVERNANCE,
            provider="bigid",
        )
        result.events.append(
            RawEventData(
                source="bigid",
                source_type=SourceType.DATA_GOVERNANCE,
                provider="bigid",
                event_type="bigid_data_catalog",
                raw_data={
                    "response": [
                        {
                            "id": "bid-cat-001",
                            "name": "customer_pii_db",
                            "type": "database",
                            "dataSourceType": "postgresql",
                            "piiObjectCount": 1500000,
                            "lastScanned": NOW.isoformat(),
                        },
                        {
                            "id": "bid-cat-002",
                            "name": "marketing_emails",
                            "type": "object_store",
                            "dataSourceType": "s3",
                            "piiObjectCount": 85000,
                            "lastScanned": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="bigid",
                source_type=SourceType.DATA_GOVERNANCE,
                provider="bigid",
                event_type="bigid_policies",
                raw_data={
                    "response": [
                        {
                            "id": "bid-pol-001",
                            "name": "GDPR Compliance Policy",
                            "type": "compliance",
                            "enabled": True,
                            "violationCount": 3,
                        },
                        {
                            "id": "bid-pol-002",
                            "name": "PCI DSS Data Minimization",
                            "type": "retention",
                            "enabled": True,
                            "violationCount": 0,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="bigid",
                source_type=SourceType.DATA_GOVERNANCE,
                provider="bigid",
                event_type="bigid_scans",
                raw_data={
                    "response": [
                        {
                            "id": "bid-scan-001",
                            "dataSourceId": "bid-cat-001",
                            "status": "completed",
                            "objectsScanned": 1500000,
                            "piiFound": True,
                            "startedAt": (NOW - timedelta(hours=4)).isoformat(),
                        },
                        {
                            "id": "bid-scan-002",
                            "dataSourceId": "bid-cat-002",
                            "status": "failed",
                            "objectsScanned": 0,
                            "piiFound": False,
                            "startedAt": (NOW - timedelta(hours=1)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 58. Rubrik Security Cloud (DLP)
# ---------------------------------------------------------------------------
class DemoRubrikSecurityConnector(BaseConnector):
    """Simulates Rubrik Security Cloud data protection collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="rubrik_security",
            source_type=SourceType.DLP,
            provider="rubrik_security",
        )
        result.events.append(
            RawEventData(
                source="rubrik_security",
                source_type=SourceType.DLP,
                provider="rubrik_security",
                event_type="rubrik_security_data_classification",
                raw_data={
                    "response": [
                        {
                            "id": "rbs-cls-001",
                            "objectName": "prod-db-backup",
                            "sensitiveHits": 15000,
                            "classifiers": ["PII", "PCI"],
                            "riskLevel": "HIGH",
                            "lastAnalyzed": NOW.isoformat(),
                        },
                        {
                            "id": "rbs-cls-002",
                            "objectName": "hr-files-backup",
                            "sensitiveHits": 5200,
                            "classifiers": ["PII"],
                            "riskLevel": "MEDIUM",
                            "lastAnalyzed": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="rubrik_security",
                source_type=SourceType.DLP,
                provider="rubrik_security",
                event_type="rubrik_security_anomalies",
                raw_data={
                    "response": [
                        {
                            "id": "rbs-ano-001",
                            "objectName": "prod-file-server",
                            "anomalyType": "ransomware",
                            "severity": "CRITICAL",
                            "detectedAt": (NOW - timedelta(hours=2)).isoformat(),
                            "affectedFiles": 12500,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="rubrik_security",
                source_type=SourceType.DLP,
                provider="rubrik_security",
                event_type="rubrik_security_sensitive_files",
                raw_data={
                    "response": [
                        {
                            "id": "rbs-sf-001",
                            "fileName": "ssn_list.csv",
                            "path": "/backups/hr/ssn_list.csv",
                            "classification": "SSN",
                            "hits": 5000,
                            "lastModified": (NOW - timedelta(days=30)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 59. Commvault
# ---------------------------------------------------------------------------
class DemoCommvaultConnector(BaseConnector):
    """Simulates Commvault backup collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="commvault",
            source_type=SourceType.BACKUP,
            provider="commvault",
        )
        result.events.append(
            RawEventData(
                source="commvault",
                source_type=SourceType.BACKUP,
                provider="commvault",
                event_type="commvault_clients",
                raw_data={
                    "response": [
                        {
                            "clientId": 101,
                            "clientName": "prod-db-01",
                            "platform": "Linux",
                            "version": "11.28",
                            "status": "ready",
                        },
                        {
                            "clientId": 102,
                            "clientName": "prod-web-01",
                            "platform": "Linux",
                            "version": "11.28",
                            "status": "ready",
                        },
                        {
                            "clientId": 103,
                            "clientName": "legacy-win-01",
                            "platform": "Windows",
                            "version": "11.20",
                            "status": "degraded",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="commvault",
                source_type=SourceType.BACKUP,
                provider="commvault",
                event_type="commvault_jobs",
                raw_data={
                    "response": [
                        {
                            "jobId": "cv-job-001",
                            "jobType": "Backup",
                            "status": "Completed",
                            "clientName": "prod-db-01",
                            "subclientName": "default",
                            "startTime": (NOW - timedelta(hours=6)).isoformat(),
                            "endTime": (NOW - timedelta(hours=5)).isoformat(),
                        },
                        {
                            "jobId": "cv-job-002",
                            "jobType": "Backup",
                            "status": "Failed",
                            "clientName": "legacy-win-01",
                            "subclientName": "default",
                            "startTime": (NOW - timedelta(hours=4)).isoformat(),
                            "endTime": (NOW - timedelta(hours=3, minutes=50)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="commvault",
                source_type=SourceType.BACKUP,
                provider="commvault",
                event_type="commvault_backupsets",
                raw_data={
                    "response": [
                        {
                            "backupSetId": 201,
                            "backupSetName": "defaultBackupSet",
                            "clientId": 101,
                            "lastBackupTime": NOW.isoformat(),
                        },
                        {
                            "backupSetId": 202,
                            "backupSetName": "defaultBackupSet",
                            "clientId": 102,
                            "lastBackupTime": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 60. Rubrik (Backup)
# ---------------------------------------------------------------------------
class DemoRubrikConnector(BaseConnector):
    """Simulates Rubrik CDM backup collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="rubrik",
            source_type=SourceType.BACKUP,
            provider="rubrik",
        )
        result.events.append(
            RawEventData(
                source="rubrik",
                source_type=SourceType.BACKUP,
                provider="rubrik",
                event_type="rubrik_cluster",
                raw_data={
                    "response": [
                        {
                            "id": "rub-cluster-001",
                            "name": "prod-rubrik-01",
                            "status": "Connected",
                            "version": "9.0.2",
                            "nodeCount": 4,
                            "totalStorage": 100000000000,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="rubrik",
                source_type=SourceType.BACKUP,
                provider="rubrik",
                event_type="rubrik_vms",
                raw_data={
                    "response": [
                        {
                            "id": "rub-vm-001",
                            "name": "prod-db-01",
                            "powerStatus": "poweredOn",
                            "slaAssigned": "Gold",
                            "protectionDate": (NOW - timedelta(days=1)).isoformat(),
                        },
                        {
                            "id": "rub-vm-002",
                            "name": "prod-web-01",
                            "powerStatus": "poweredOn",
                            "slaAssigned": "Gold",
                            "protectionDate": (NOW - timedelta(days=1)).isoformat(),
                        },
                        {
                            "id": "rub-vm-003",
                            "name": "old-dev-vm",
                            "powerStatus": "poweredOff",
                            "slaAssigned": "UNPROTECTED",
                            "protectionDate": None,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="rubrik",
                source_type=SourceType.BACKUP,
                provider="rubrik",
                event_type="rubrik_sla_domains",
                raw_data={
                    "response": [
                        {
                            "id": "rub-sla-001",
                            "name": "Gold",
                            "frequencies": [{"timeUnit": "Days", "frequency": 1}],
                            "localRetentionLimit": {"unit": "Days", "duration": 30},
                        },
                        {
                            "id": "rub-sla-002",
                            "name": "Silver",
                            "frequencies": [{"timeUnit": "Days", "frequency": 7}],
                            "localRetentionLimit": {"unit": "Days", "duration": 14},
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 61. Cohesity
# ---------------------------------------------------------------------------
class DemoCohesityConnector(BaseConnector):
    """Simulates Cohesity backup collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="cohesity",
            source_type=SourceType.BACKUP,
            provider="cohesity",
        )
        result.events.append(
            RawEventData(
                source="cohesity",
                source_type=SourceType.BACKUP,
                provider="cohesity",
                event_type="cohesity_protection_jobs",
                raw_data={
                    "response": [
                        {
                            "id": 1001,
                            "name": "Prod-DB-Daily",
                            "policyId": "pol-001",
                            "environment": "kVMware",
                            "isActive": True,
                            "lastRun": {"status": "kSuccess"},
                        },
                        {
                            "id": 1002,
                            "name": "Dev-VMs-Weekly",
                            "policyId": "pol-002",
                            "environment": "kVMware",
                            "isActive": True,
                            "lastRun": {"status": "kFailure"},
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="cohesity",
                source_type=SourceType.BACKUP,
                provider="cohesity",
                event_type="cohesity_protection_runs",
                raw_data={
                    "response": [
                        {
                            "jobRunId": 5001,
                            "jobId": 1001,
                            "status": "kSuccess",
                            "startTimeUsecs": int((NOW - timedelta(hours=6)).timestamp() * 1000000),
                            "endTimeUsecs": int((NOW - timedelta(hours=5)).timestamp() * 1000000),
                        },
                        {
                            "jobRunId": 5002,
                            "jobId": 1002,
                            "status": "kFailure",
                            "startTimeUsecs": int((NOW - timedelta(hours=3)).timestamp() * 1000000),
                            "endTimeUsecs": int(
                                (NOW - timedelta(hours=2, minutes=55)).timestamp() * 1000000
                            ),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 62. Druva
# ---------------------------------------------------------------------------
class DemoDruvaConnector(BaseConnector):
    """Simulates Druva cloud backup collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="druva",
            source_type=SourceType.BACKUP,
            provider="druva",
        )
        result.events.append(
            RawEventData(
                source="druva",
                source_type=SourceType.BACKUP,
                provider="druva",
                event_type="druva_endpoints",
                raw_data={
                    "response": [
                        {
                            "id": "dr-ep-001",
                            "name": "LAPTOP-ALICE",
                            "status": "Active",
                            "backupStatus": "Backed Up",
                            "lastBackup": NOW.isoformat(),
                            "os": "macOS 14.2",
                        },
                        {
                            "id": "dr-ep-002",
                            "name": "LAPTOP-BOB",
                            "status": "Active",
                            "backupStatus": "Backup Missed",
                            "lastBackup": (NOW - timedelta(days=8)).isoformat(),
                            "os": "Windows 11",
                        },
                        {
                            "id": "dr-ep-003",
                            "name": "DESKTOP-OLD",
                            "status": "Decommissioned",
                            "backupStatus": "Not Configured",
                            "lastBackup": None,
                            "os": "Windows 10",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="druva",
                source_type=SourceType.BACKUP,
                provider="druva",
                event_type="druva_backupsets",
                raw_data={
                    "response": [
                        {
                            "id": "dr-bs-001",
                            "name": "Default Backup Set",
                            "endpointId": "dr-ep-001",
                            "dataSize": 52428800,
                            "retentionDays": 90,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="druva",
                source_type=SourceType.BACKUP,
                provider="druva",
                event_type="druva_restores",
                raw_data={
                    "response": [
                        {
                            "id": "dr-rest-001",
                            "name": "Alice Finance Files Restore",
                            "status": "Completed",
                            "requestedBy": "alice@acme.com",
                            "startTime": (NOW - timedelta(days=2)).isoformat(),
                            "endTime": (NOW - timedelta(days=2, hours=-1)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 63. Ermetic (CSPM)
# ---------------------------------------------------------------------------
class DemoErmeticConnector(BaseConnector):
    """Simulates Ermetic cloud security posture collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="ermetic",
            source_type=SourceType.CSPM,
            provider="ermetic",
        )
        result.events.append(
            RawEventData(
                source="ermetic",
                source_type=SourceType.CSPM,
                provider="ermetic",
                event_type="ermetic_identities",
                raw_data={
                    "response": [
                        {
                            "id": "erm-id-001",
                            "name": "prod-app-role",
                            "type": "ROLE",
                            "cloud": "AWS",
                            "riskScore": 65,
                            "unusedPermissionsPercent": 78,
                        },
                        {
                            "id": "erm-id-002",
                            "name": "admin-user",
                            "type": "USER",
                            "cloud": "AWS",
                            "riskScore": 90,
                            "unusedPermissionsPercent": 30,
                        },
                        {
                            "id": "erm-id-003",
                            "name": "readonly-svc",
                            "type": "SERVICE_ACCOUNT",
                            "cloud": "GCP",
                            "riskScore": 10,
                            "unusedPermissionsPercent": 5,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ermetic",
                source_type=SourceType.CSPM,
                provider="ermetic",
                event_type="ermetic_permissions",
                raw_data={
                    "response": [
                        {
                            "id": "erm-perm-001",
                            "identityId": "erm-id-001",
                            "permission": "s3:*",
                            "resource": "arn:aws:s3:::*",
                            "isUnused": True,
                            "riskLevel": "HIGH",
                        },
                        {
                            "id": "erm-perm-002",
                            "identityId": "erm-id-002",
                            "permission": "iam:*",
                            "resource": "*",
                            "isUnused": False,
                            "riskLevel": "CRITICAL",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ermetic",
                source_type=SourceType.CSPM,
                provider="ermetic",
                event_type="ermetic_findings",
                raw_data={
                    "response": [
                        {
                            "id": "erm-find-001",
                            "title": "IAM role with wildcard permissions",
                            "severity": "CRITICAL",
                            "status": "open",
                            "identityId": "erm-id-002",
                            "category": "OverlyPermissive",
                        },
                        {
                            "id": "erm-find-002",
                            "title": "Unused 78% of permissions",
                            "severity": "HIGH",
                            "status": "open",
                            "identityId": "erm-id-001",
                            "category": "ExcessivePermissions",
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 64. TrustArc
# ---------------------------------------------------------------------------
class DemoTrustArcConnector(BaseConnector):
    """Simulates TrustArc privacy management collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="trustarc",
            source_type=SourceType.GRC,
            provider="trustarc",
        )
        result.events.append(
            RawEventData(
                source="trustarc",
                source_type=SourceType.GRC,
                provider="trustarc",
                event_type="trustarc_assessments",
                raw_data={
                    "response": [
                        {
                            "id": "ta-assess-001",
                            "name": "GDPR Readiness Assessment 2024",
                            "status": "completed",
                            "score": 82,
                            "completedAt": (NOW - timedelta(days=30)).isoformat(),
                        },
                        {
                            "id": "ta-assess-002",
                            "name": "CCPA Compliance Assessment",
                            "status": "in_progress",
                            "score": None,
                            "completedAt": None,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="trustarc",
                source_type=SourceType.GRC,
                provider="trustarc",
                event_type="trustarc_data_inventory",
                raw_data={
                    "response": [
                        {
                            "id": "ta-di-001",
                            "name": "Customer PII Database",
                            "dataCategory": "PII",
                            "processingPurpose": "Service Delivery",
                            "legalBasis": "Contract",
                            "retentionPeriod": "7 years",
                        },
                        {
                            "id": "ta-di-002",
                            "name": "Marketing Analytics",
                            "dataCategory": "Behavioral",
                            "processingPurpose": "Marketing",
                            "legalBasis": "Consent",
                            "retentionPeriod": "2 years",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="trustarc",
                source_type=SourceType.GRC,
                provider="trustarc",
                event_type="trustarc_cookie_consent",
                raw_data={
                    "response": [
                        {
                            "id": "ta-ck-001",
                            "domain": "acme.com",
                            "consentRate": 0.87,
                            "cookieCount": 45,
                            "lastScanned": NOW.isoformat(),
                        },
                        {
                            "id": "ta-ck-002",
                            "domain": "shop.acme.com",
                            "consentRate": 0.72,
                            "cookieCount": 62,
                            "lastScanned": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 65. Cookiebot
# ---------------------------------------------------------------------------
class DemoCookiebotConnector(BaseConnector):
    """Simulates Cookiebot consent management collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="cookiebot",
            source_type=SourceType.CUSTOM,
            provider="cookiebot",
        )
        result.events.append(
            RawEventData(
                source="cookiebot",
                source_type=SourceType.CUSTOM,
                provider="cookiebot",
                event_type="cookiebot_scans",
                raw_data={
                    "response": [
                        {
                            "id": "cb-scan-001",
                            "url": "acme.com",
                            "cookieCount": 45,
                            "status": "completed",
                            "scannedAt": NOW.isoformat(),
                        },
                        {
                            "id": "cb-scan-002",
                            "url": "shop.acme.com",
                            "cookieCount": 62,
                            "status": "completed",
                            "scannedAt": (NOW - timedelta(days=1)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="cookiebot",
                source_type=SourceType.CUSTOM,
                provider="cookiebot",
                event_type="cookiebot_consents",
                raw_data={
                    "response": [
                        {
                            "id": "cb-con-001",
                            "userId": "anon-001",
                            "consentGiven": True,
                            "categories": ["necessary", "statistics"],
                            "timestamp": NOW.isoformat(),
                            "domain": "acme.com",
                        },
                        {
                            "id": "cb-con-002",
                            "userId": "anon-002",
                            "consentGiven": False,
                            "categories": ["necessary"],
                            "timestamp": (NOW - timedelta(hours=1)).isoformat(),
                            "domain": "acme.com",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="cookiebot",
                source_type=SourceType.CUSTOM,
                provider="cookiebot",
                event_type="cookiebot_domains",
                raw_data={
                    "response": [
                        {
                            "id": "cb-dom-001",
                            "domain": "acme.com",
                            "consentBannerEnabled": True,
                            "iabEnabled": True,
                            "lastUpdated": NOW.isoformat(),
                        },
                        {
                            "id": "cb-dom-002",
                            "domain": "shop.acme.com",
                            "consentBannerEnabled": True,
                            "iabEnabled": False,
                            "lastUpdated": (NOW - timedelta(days=7)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 66. Osano
# ---------------------------------------------------------------------------
class DemoOsanoConnector(BaseConnector):
    """Simulates Osano privacy management collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="osano",
            source_type=SourceType.CUSTOM,
            provider="osano",
        )
        result.events.append(
            RawEventData(
                source="osano",
                source_type=SourceType.CUSTOM,
                provider="osano",
                event_type="osano_consent_records",
                raw_data={
                    "response": [
                        {
                            "id": "os-cr-001",
                            "subject": "user@example.com",
                            "consentedTo": ["marketing", "analytics"],
                            "timestamp": NOW.isoformat(),
                            "source": "web",
                        },
                        {
                            "id": "os-cr-002",
                            "subject": "user2@example.com",
                            "consentedTo": [],
                            "timestamp": (NOW - timedelta(hours=2)).isoformat(),
                            "source": "mobile",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="osano",
                source_type=SourceType.CUSTOM,
                provider="osano",
                event_type="osano_data_maps",
                raw_data={
                    "response": [
                        {
                            "id": "os-dm-001",
                            "name": "Customer Data Flow",
                            "dataTypes": ["PII", "Behavioral"],
                            "thirdParties": ["Stripe", "Google Analytics"],
                            "lastUpdated": (NOW - timedelta(days=14)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="osano",
                source_type=SourceType.CUSTOM,
                provider="osano",
                event_type="osano_vendor_assessments",
                raw_data={
                    "response": [
                        {
                            "id": "os-va-001",
                            "vendorName": "Stripe",
                            "score": 92,
                            "risk": "LOW",
                            "assessedAt": (NOW - timedelta(days=30)).isoformat(),
                        },
                        {
                            "id": "os-va-002",
                            "vendorName": "New Analytics Tool",
                            "score": 45,
                            "risk": "HIGH",
                            "assessedAt": (NOW - timedelta(days=2)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 67. Vulcan Cyber
# ---------------------------------------------------------------------------
class DemoVulcanConnector(BaseConnector):
    """Simulates Vulcan Cyber vulnerability remediation collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="vulcan",
            source_type=SourceType.SCANNER,
            provider="vulcan",
        )
        result.events.append(
            RawEventData(
                source="vulcan",
                source_type=SourceType.SCANNER,
                provider="vulcan",
                event_type="vulcan_assets",
                raw_data={
                    "response": [
                        {
                            "id": "vc-asset-001",
                            "name": "prod-web-01",
                            "type": "host",
                            "criticality": "critical",
                            "riskScore": 850,
                            "vulnerabilityCount": 12,
                        },
                        {
                            "id": "vc-asset-002",
                            "name": "prod-db-01",
                            "type": "host",
                            "criticality": "critical",
                            "riskScore": 1200,
                            "vulnerabilityCount": 5,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="vulcan",
                source_type=SourceType.SCANNER,
                provider="vulcan",
                event_type="vulcan_vulnerabilities",
                raw_data={
                    "response": [
                        {
                            "id": "vc-vuln-001",
                            "cve": "CVE-2021-44228",
                            "severity": "critical",
                            "cvssScore": 10.0,
                            "affectedAssets": 2,
                            "fixAvailable": True,
                            "dueDate": (NOW + timedelta(days=7)).isoformat(),
                        },
                        {
                            "id": "vc-vuln-002",
                            "cve": "CVE-2023-44487",
                            "severity": "high",
                            "cvssScore": 7.5,
                            "affectedAssets": 5,
                            "fixAvailable": True,
                            "dueDate": (NOW + timedelta(days=14)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="vulcan",
                source_type=SourceType.SCANNER,
                provider="vulcan",
                event_type="vulcan_campaigns",
                raw_data={
                    "response": [
                        {
                            "id": "vc-camp-001",
                            "name": "Critical Patch Sprint",
                            "status": "in_progress",
                            "vulnerabilityCount": 8,
                            "completionRate": 0.375,
                            "dueDate": (NOW + timedelta(days=7)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 68. Tanium
# ---------------------------------------------------------------------------
class DemoTaniumConnector(BaseConnector):
    """Simulates Tanium endpoint management collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name, source="tanium", source_type=SourceType.EDR, provider="tanium"
        )
        result.events.append(
            RawEventData(
                source="tanium",
                source_type=SourceType.EDR,
                provider="tanium",
                event_type="tanium_endpoints",
                raw_data={
                    "response": [
                        {
                            "id": "tan-ep-001",
                            "name": "PROD-WEB-01",
                            "ipAddress": "10.0.1.10",
                            "os": "Linux Red Hat 8.7",
                            "lastSeen": NOW.isoformat(),
                            "agentVersion": "7.4.8",
                            "online": True,
                        },
                        {
                            "id": "tan-ep-002",
                            "name": "PROD-DB-01",
                            "ipAddress": "10.0.1.20",
                            "os": "Linux Red Hat 8.7",
                            "lastSeen": NOW.isoformat(),
                            "agentVersion": "7.4.8",
                            "online": True,
                        },
                        {
                            "id": "tan-ep-003",
                            "name": "LEGACY-01",
                            "ipAddress": "10.0.5.1",
                            "os": "Windows Server 2012",
                            "lastSeen": (NOW - timedelta(days=15)).isoformat(),
                            "agentVersion": "7.2.0",
                            "online": False,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="tanium",
                source_type=SourceType.EDR,
                provider="tanium",
                event_type="tanium_patches",
                raw_data={
                    "response": [
                        {
                            "id": "tan-patch-001",
                            "title": "RHSA-2023:7213 Critical",
                            "severity": "Critical",
                            "status": "missing",
                            "affectedEndpoints": 2,
                            "cve": "CVE-2023-44487",
                        },
                        {
                            "id": "tan-patch-002",
                            "title": "RHSA-2023:5221 Important",
                            "severity": "Important",
                            "status": "installed",
                            "affectedEndpoints": 0,
                            "cve": "CVE-2023-38408",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="tanium",
                source_type=SourceType.EDR,
                provider="tanium",
                event_type="tanium_alerts",
                raw_data={
                    "response": [
                        {
                            "id": "tan-alert-001",
                            "type": "Detect.Match",
                            "severity": "HIGH",
                            "endpointName": "PROD-WEB-01",
                            "ruleName": "Suspicious PowerShell Execution",
                            "timestamp": (NOW - timedelta(hours=2)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 69. Automox
# ---------------------------------------------------------------------------
class DemoAutomoxConnector(BaseConnector):
    """Simulates Automox patch management collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="automox",
            source_type=SourceType.MDM,
            provider="automox",
        )
        result.events.append(
            RawEventData(
                source="automox",
                source_type=SourceType.MDM,
                provider="automox",
                event_type="automox_servers",
                raw_data={
                    "response": [
                        {
                            "id": "ax-srv-001",
                            "name": "prod-web-01",
                            "os_family": "Linux",
                            "os_version": "Ubuntu 22.04",
                            "compliant": True,
                            "last_update_time": NOW.isoformat(),
                            "pending_patches_count": 0,
                        },
                        {
                            "id": "ax-srv-002",
                            "name": "legacy-srv",
                            "os_family": "Windows",
                            "os_version": "Windows Server 2012",
                            "compliant": False,
                            "last_update_time": (NOW - timedelta(days=45)).isoformat(),
                            "pending_patches_count": 23,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="automox",
                source_type=SourceType.MDM,
                provider="automox",
                event_type="automox_policies",
                raw_data={
                    "response": [
                        {
                            "id": "ax-pol-001",
                            "name": "Critical Patch - 7 Day SLA",
                            "policy_type": "patch",
                            "enabled": True,
                            "serverCount": 15,
                        },
                        {
                            "id": "ax-pol-002",
                            "name": "Software Removal - Unapproved",
                            "policy_type": "custom",
                            "enabled": True,
                            "serverCount": 15,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="automox",
                source_type=SourceType.MDM,
                provider="automox",
                event_type="automox_patches",
                raw_data={
                    "response": [
                        {
                            "id": "ax-patch-001",
                            "name": "openssl-3.0.8",
                            "severity": "Critical",
                            "status": "unpatched",
                            "cve_score": 9.1,
                            "affected_servers": 2,
                        },
                        {
                            "id": "ax-patch-002",
                            "name": "curl-8.4.0",
                            "severity": "High",
                            "status": "patched",
                            "cve_score": 7.5,
                            "affected_servers": 0,
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 70. Fleet
# ---------------------------------------------------------------------------
class DemoFleetConnector(BaseConnector):
    """Simulates Fleet osquery device management collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name, source="fleet", source_type=SourceType.MDM, provider="fleet"
        )
        result.events.append(
            RawEventData(
                source="fleet",
                source_type=SourceType.MDM,
                provider="fleet",
                event_type="fleet_hosts",
                raw_data={
                    "response": [
                        {
                            "id": 1,
                            "hostname": "prod-web-01",
                            "platform": "ubuntu",
                            "os_version": "Ubuntu 22.04.3 LTS",
                            "status": "online",
                            "last_enrolled_at": (NOW - timedelta(days=30)).isoformat(),
                            "memory": 16384,
                            "cpu_type": "x86_64",
                        },
                        {
                            "id": 2,
                            "hostname": "macbook-alice",
                            "platform": "darwin",
                            "os_version": "macOS 14.2",
                            "status": "online",
                            "last_enrolled_at": (NOW - timedelta(days=10)).isoformat(),
                            "memory": 32768,
                            "cpu_type": "arm64",
                        },
                        {
                            "id": 3,
                            "hostname": "old-ubuntu",
                            "platform": "ubuntu",
                            "os_version": "Ubuntu 18.04.6 LTS",
                            "status": "offline",
                            "last_enrolled_at": (NOW - timedelta(days=90)).isoformat(),
                            "memory": 8192,
                            "cpu_type": "x86_64",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="fleet",
                source_type=SourceType.MDM,
                provider="fleet",
                event_type="fleet_queries",
                raw_data={
                    "response": [
                        {
                            "id": 10,
                            "name": "Find processes listening on port 22",
                            "query": "SELECT * FROM listening_ports WHERE port = 22;",
                            "interval": 3600,
                            "automations_enabled": True,
                        },
                        {
                            "id": 11,
                            "name": "Disk encryption status",
                            "query": "SELECT * FROM disk_encryption;",
                            "interval": 86400,
                            "automations_enabled": True,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="fleet",
                source_type=SourceType.MDM,
                provider="fleet",
                event_type="fleet_policies",
                raw_data={
                    "response": [
                        {
                            "id": 20,
                            "name": "Antivirus active",
                            "query": "SELECT 1 FROM processes WHERE name = 'falcond';",
                            "passing_host_count": 14,
                            "failing_host_count": 1,
                        },
                        {
                            "id": 21,
                            "name": "Firewall enabled",
                            "query": "SELECT 1 FROM iptables WHERE chain = 'INPUT' AND policy = 'DROP';",
                            "passing_host_count": 12,
                            "failing_host_count": 3,
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 71. Cobalt
# ---------------------------------------------------------------------------
class DemoCobaltConnector(BaseConnector):
    """Simulates Cobalt PtaaS pentest collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="cobalt",
            source_type=SourceType.CUSTOM,
            provider="cobalt",
        )
        result.events.append(
            RawEventData(
                source="cobalt",
                source_type=SourceType.CUSTOM,
                provider="cobalt",
                event_type="cobalt_assets",
                raw_data={
                    "response": [
                        {
                            "resource": {
                                "id": "cob-asset-001",
                                "title": "Production API",
                                "asset_type": "api",
                                "description": "Main production REST API",
                                "tags": ["production", "api"],
                            }
                        },
                        {
                            "resource": {
                                "id": "cob-asset-002",
                                "title": "Web Application",
                                "asset_type": "web",
                                "description": "Customer-facing web app",
                                "tags": ["production", "web"],
                            }
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="cobalt",
                source_type=SourceType.CUSTOM,
                provider="cobalt",
                event_type="cobalt_pentests",
                raw_data={
                    "response": [
                        {
                            "resource": {
                                "id": "cob-pt-001",
                                "title": "Q1 2024 API Pentest",
                                "state": "completed",
                                "objectives": "Test authentication and authorization",
                                "asset": {"id": "cob-asset-001"},
                                "start_date": "2024-01-15",
                                "end_date": "2024-01-30",
                                "methodology": "OWASP API Top 10",
                            }
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="cobalt",
                source_type=SourceType.CUSTOM,
                provider="cobalt",
                event_type="cobalt_findings",
                raw_data={
                    "response": [
                        {
                            "resource": {
                                "id": "cob-find-001",
                                "title": "SQL Injection in search endpoint",
                                "severity": "critical",
                                "state": "need_fix",
                                "type_category": "Injection",
                                "pentest": {"id": "cob-pt-001"},
                                "asset": {"id": "cob-asset-001"},
                                "description": "The /search endpoint is vulnerable to SQLi",
                                "impact": "Full database compromise",
                                "suggested_fix": "Use parameterized queries",
                                "cvss_score": 9.8,
                            }
                        },
                        {
                            "resource": {
                                "id": "cob-find-002",
                                "title": "Missing rate limiting on auth",
                                "severity": "high",
                                "state": "accepted_risk",
                                "type_category": "Auth",
                                "pentest": {"id": "cob-pt-001"},
                                "asset": {"id": "cob-asset-001"},
                                "description": "No rate limiting on /auth endpoint",
                                "impact": "Brute force attacks",
                                "suggested_fix": "Implement rate limiting",
                                "cvss_score": 7.5,
                            }
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 72. HackerOne
# ---------------------------------------------------------------------------
class DemoHackerOneConnector(BaseConnector):
    """Simulates HackerOne bug bounty collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="hackerone",
            source_type=SourceType.CUSTOM,
            provider="hackerone",
        )
        result.events.append(
            RawEventData(
                source="hackerone",
                source_type=SourceType.CUSTOM,
                provider="hackerone",
                event_type="hackerone_reports",
                raw_data={
                    "response": [
                        {
                            "id": "h1-report-001",
                            "title": "XSS in account settings page",
                            "severity": {"rating": "high", "score": 8.5},
                            "state": "triaged",
                            "substate": None,
                            "reporter": {"username": "h1-hacker-001"},
                            "created_at": (NOW - timedelta(days=3)).isoformat(),
                        },
                        {
                            "id": "h1-report-002",
                            "title": "IDOR allows viewing other users orders",
                            "severity": {"rating": "critical", "score": 9.1},
                            "state": "new",
                            "substate": None,
                            "reporter": {"username": "h1-hacker-002"},
                            "created_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                        {
                            "id": "h1-report-003",
                            "title": "Password policy too weak",
                            "severity": {"rating": "low", "score": 3.0},
                            "state": "resolved",
                            "substate": "fixed",
                            "reporter": {"username": "h1-hacker-001"},
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="hackerone",
                source_type=SourceType.CUSTOM,
                provider="hackerone",
                event_type="hackerone_programs",
                raw_data={
                    "response": [
                        {
                            "id": "h1-prog-001",
                            "handle": "acme-security",
                            "name": "ACME Bug Bounty",
                            "state": "public",
                            "minimum_bounty_table_value": 100,
                            "maximum_bounty_table_value": 50000,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="hackerone",
                source_type=SourceType.CUSTOM,
                provider="hackerone",
                event_type="hackerone_hackers",
                raw_data={
                    "response": [
                        {
                            "id": "h1-hacker-001",
                            "username": "security_researcher_1",
                            "reputation": 2500,
                            "signal": 8.2,
                            "impact": 9.0,
                        },
                        {
                            "id": "h1-hacker-002",
                            "username": "vuln_hunter",
                            "reputation": 1800,
                            "signal": 7.5,
                            "impact": 8.5,
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 73. Linode (Akamai Cloud)
# ---------------------------------------------------------------------------
class DemoLinodeConnector(BaseConnector):
    """Simulates Linode/Akamai Cloud collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="linode",
            source_type=SourceType.CLOUD,
            provider="linode",
        )
        result.events.append(
            RawEventData(
                source="linode",
                source_type=SourceType.CLOUD,
                provider="linode",
                event_type="linode_instances",
                raw_data={
                    "response": [
                        {
                            "id": 12345,
                            "label": "prod-web-01",
                            "status": "running",
                            "region": "us-east",
                            "type": "g6-standard-4",
                            "ipv4": ["203.0.113.10"],
                            "created": (NOW - timedelta(days=90)).isoformat(),
                        },
                        {
                            "id": 12346,
                            "label": "prod-db-01",
                            "status": "running",
                            "region": "us-east",
                            "type": "g6-standard-8",
                            "ipv4": ["10.0.0.1"],
                            "created": (NOW - timedelta(days=90)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="linode",
                source_type=SourceType.CLOUD,
                provider="linode",
                event_type="linode_firewalls",
                raw_data={
                    "response": [
                        {
                            "id": 777,
                            "label": "prod-firewall",
                            "status": "enabled",
                            "created": (NOW - timedelta(days=90)).isoformat(),
                            "rules": {"inbound_policy": "DROP", "outbound_policy": "ACCEPT"},
                        },
                        {
                            "id": 778,
                            "label": "dev-firewall",
                            "status": "enabled",
                            "created": (NOW - timedelta(days=60)).isoformat(),
                            "rules": {"inbound_policy": "ACCEPT", "outbound_policy": "ACCEPT"},
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="linode",
                source_type=SourceType.CLOUD,
                provider="linode",
                event_type="linode_events",
                raw_data={
                    "response": [
                        {
                            "id": 99001,
                            "action": "linode_reboot",
                            "entity": {"label": "prod-web-01"},
                            "status": "finished",
                            "created": (NOW - timedelta(hours=5)).isoformat(),
                        },
                        {
                            "id": 99002,
                            "action": "user_login",
                            "entity": {"label": "alice@acme.com"},
                            "status": "finished",
                            "created": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 74. Hetzner
# ---------------------------------------------------------------------------
class DemoHetznerConnector(BaseConnector):
    """Simulates Hetzner Cloud collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="hetzner",
            source_type=SourceType.CLOUD,
            provider="hetzner",
        )
        result.events.append(
            RawEventData(
                source="hetzner",
                source_type=SourceType.CLOUD,
                provider="hetzner",
                event_type="hetzner_servers",
                raw_data={
                    "response": [
                        {
                            "id": 5001,
                            "name": "prod-web-01",
                            "status": "running",
                            "server_type": {"name": "cpx31"},
                            "datacenter": {"location": {"name": "nbg1"}},
                            "public_net": {"ipv4": {"ip": "203.0.113.20"}},
                        },
                        {
                            "id": 5002,
                            "name": "prod-db-01",
                            "status": "running",
                            "server_type": {"name": "cpx51"},
                            "datacenter": {"location": {"name": "nbg1"}},
                            "public_net": {"ipv4": None},
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="hetzner",
                source_type=SourceType.CLOUD,
                provider="hetzner",
                event_type="hetzner_firewalls",
                raw_data={
                    "response": [
                        {
                            "id": 6001,
                            "name": "prod-fw",
                            "rules": [
                                {
                                    "direction": "in",
                                    "protocol": "tcp",
                                    "port": "443",
                                    "source_ips": ["0.0.0.0/0"],
                                },
                                {
                                    "direction": "in",
                                    "protocol": "tcp",
                                    "port": "22",
                                    "source_ips": ["10.0.0.0/8"],
                                },
                            ],
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="hetzner",
                source_type=SourceType.CLOUD,
                provider="hetzner",
                event_type="hetzner_certificates",
                raw_data={
                    "response": [
                        {
                            "id": 7001,
                            "name": "acme-com-cert",
                            "type": "managed",
                            "domain_names": ["acme.com", "www.acme.com"],
                            "not_valid_after": VALID,
                            "status": {"issuance": "completed"},
                        },
                        {
                            "id": 7002,
                            "name": "old-cert",
                            "type": "uploaded",
                            "domain_names": ["legacy.acme.com"],
                            "not_valid_after": EXPIRED,
                            "status": {"issuance": "completed"},
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 75. LogRhythm
# ---------------------------------------------------------------------------
class DemoLogRhythmConnector(BaseConnector):
    """Simulates LogRhythm SIEM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="logrhythm",
            source_type=SourceType.SIEM,
            provider="logrhythm",
        )
        result.events.append(
            RawEventData(
                source="logrhythm",
                source_type=SourceType.SIEM,
                provider="logrhythm",
                event_type="logrhythm_hosts",
                raw_data={
                    "response": [
                        {
                            "id": 101,
                            "name": "prod-web-01",
                            "hostZone": "Internal",
                            "riskThreshold": "MediumLow",
                            "status": "active",
                            "os": {"type": "Linux"},
                        },
                        {
                            "id": 102,
                            "name": "prod-db-01",
                            "hostZone": "Internal",
                            "riskThreshold": "High",
                            "status": "active",
                            "os": {"type": "Linux"},
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="logrhythm",
                source_type=SourceType.SIEM,
                provider="logrhythm",
                event_type="logrhythm_alarms",
                raw_data={
                    "response": [
                        {
                            "alarmId": 9001,
                            "alarmName": "Brute Force Authentication Attack",
                            "alarmStatus": "OpenAlarm",
                            "riskScore": 85,
                            "dateInserted": (NOW - timedelta(hours=2)).isoformat(),
                        },
                        {
                            "alarmId": 9002,
                            "alarmName": "Internal Reconnaissance Detected",
                            "alarmStatus": "Closed",
                            "riskScore": 60,
                            "dateInserted": (NOW - timedelta(hours=8)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="logrhythm",
                source_type=SourceType.SIEM,
                provider="logrhythm",
                event_type="logrhythm_log_sources",
                raw_data={
                    "response": [
                        {
                            "id": 201,
                            "name": "prod-web-01 syslog",
                            "systemType": "Syslog",
                            "status": "active",
                            "lastHeartbeat": NOW.isoformat(),
                        },
                        {
                            "id": 202,
                            "name": "prod-fw winlog",
                            "systemType": "WinEventLog",
                            "status": "degraded",
                            "lastHeartbeat": (NOW - timedelta(hours=3)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 76. Barracuda
# ---------------------------------------------------------------------------
class DemoBarracudaConnector(BaseConnector):
    """Simulates Barracuda network security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="barracuda",
            source_type=SourceType.NETWORK,
            provider="barracuda",
        )
        result.events.append(
            RawEventData(
                source="barracuda",
                source_type=SourceType.NETWORK,
                provider="barracuda",
                event_type="barracuda_firewalls",
                raw_data={
                    "response": [
                        {
                            "id": "barra-fw-001",
                            "name": "prod-edge-fw",
                            "model": "CloudGen F380",
                            "status": "active",
                            "firmwareVersion": "8.3.2",
                            "uptime": 1209600,
                        },
                        {
                            "id": "barra-fw-002",
                            "name": "backup-fw",
                            "model": "CloudGen F180",
                            "status": "standby",
                            "firmwareVersion": "8.2.1",
                            "uptime": 604800,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="barracuda",
                source_type=SourceType.NETWORK,
                provider="barracuda",
                event_type="barracuda_threats",
                raw_data={
                    "response": [
                        {
                            "id": "barra-thr-001",
                            "type": "Intrusion Attempt",
                            "severity": "high",
                            "sourceIP": "198.51.100.1",
                            "action": "blocked",
                            "timestamp": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "barra-thr-002",
                            "type": "Malware Download Attempt",
                            "severity": "critical",
                            "sourceIP": "203.0.113.50",
                            "action": "blocked",
                            "timestamp": (NOW - timedelta(hours=1)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="barracuda",
                source_type=SourceType.NETWORK,
                provider="barracuda",
                event_type="barracuda_policies",
                raw_data={
                    "response": [
                        {
                            "id": "barra-pol-001",
                            "name": "Block Tor Exit Nodes",
                            "enabled": True,
                            "ruleCount": 7500,
                        },
                        {
                            "id": "barra-pol-002",
                            "name": "Allow Corporate VPN",
                            "enabled": True,
                            "ruleCount": 3,
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 77. F5
# ---------------------------------------------------------------------------
class DemoF5Connector(BaseConnector):
    """Simulates F5 BIG-IP network collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name, source="f5", source_type=SourceType.NETWORK, provider="f5"
        )
        result.events.append(
            RawEventData(
                source="f5",
                source_type=SourceType.NETWORK,
                provider="f5",
                event_type="f5_virtual_servers",
                raw_data={
                    "response": [
                        {
                            "name": "/Common/prod-https-vs",
                            "partition": "Common",
                            "destination": "203.0.113.100:443",
                            "enabled": True,
                            "pool": "/Common/prod-web-pool",
                            "ipProtocol": "tcp",
                        },
                        {
                            "name": "/Common/prod-http-vs",
                            "partition": "Common",
                            "destination": "203.0.113.100:80",
                            "enabled": True,
                            "pool": "/Common/prod-web-pool",
                            "ipProtocol": "tcp",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="f5",
                source_type=SourceType.NETWORK,
                provider="f5",
                event_type="f5_performance",
                raw_data={
                    "response": [
                        {
                            "timestamp": NOW.isoformat(),
                            "throughputIn": 125000000,
                            "throughputOut": 85000000,
                            "connections": 4500,
                            "cpuUsage": 35,
                            "memoryUsage": 62,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="f5",
                source_type=SourceType.NETWORK,
                provider="f5",
                event_type="f5_firewall_policies",
                raw_data={
                    "response": [
                        {
                            "name": "/Common/block-scanners",
                            "partition": "Common",
                            "rulesCount": 250,
                            "defaultAction": "reject",
                        },
                        {
                            "name": "/Common/allow-internal",
                            "partition": "Common",
                            "rulesCount": 15,
                            "defaultAction": "accept",
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 78. Paylocity
# ---------------------------------------------------------------------------
class DemoPaylocityConnector(BaseConnector):
    """Simulates Paylocity HRIS collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="paylocity",
            source_type=SourceType.HRIS,
            provider="paylocity",
        )
        result.events.append(
            RawEventData(
                source="paylocity",
                source_type=SourceType.HRIS,
                provider="paylocity",
                event_type="paylocity_employees",
                raw_data={
                    "response": [
                        {
                            "employeeId": "pc-001",
                            "firstName": "Alice",
                            "lastName": "Chen",
                            "email": "alice@acme.com",
                            "status": "Active",
                            "department": "Engineering",
                            "hireDate": "2023-01-15",
                            "supervisorId": "pc-010",
                        },
                        {
                            "employeeId": "pc-002",
                            "firstName": "Bob",
                            "lastName": "Martinez",
                            "email": "bob@acme.com",
                            "status": "Active",
                            "department": "Product",
                            "hireDate": "2022-06-01",
                            "supervisorId": "pc-010",
                        },
                        {
                            "employeeId": "pc-003",
                            "firstName": "Carol",
                            "lastName": "Ex",
                            "email": None,
                            "status": "Terminated",
                            "department": "Sales",
                            "hireDate": "2021-01-01",
                            "supervisorId": None,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="paylocity",
                source_type=SourceType.HRIS,
                provider="paylocity",
                event_type="paylocity_earnings",
                raw_data={
                    "response": [
                        {
                            "employeeId": "pc-001",
                            "checkDate": NOW.strftime("%Y-%m-%d"),
                            "grossPay": 5000.00,
                            "netPay": 3750.00,
                            "payType": "Regular",
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 79. Kubecost
# ---------------------------------------------------------------------------
class DemoKubecostConnector(BaseConnector):
    """Simulates Kubecost cloud cost observability collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="kubecost",
            source_type=SourceType.OBSERVABILITY,
            provider="kubecost",
        )
        result.events.append(
            RawEventData(
                source="kubecost",
                source_type=SourceType.OBSERVABILITY,
                provider="kubecost",
                event_type="kubecost_allocation",
                raw_data={
                    "response": [
                        {
                            "name": "production/api-server",
                            "cpuCost": 45.20,
                            "memoryCost": 12.80,
                            "networkCost": 3.50,
                            "totalCost": 61.50,
                            "efficiency": 0.72,
                        },
                        {
                            "name": "production/worker",
                            "cpuCost": 20.10,
                            "memoryCost": 8.40,
                            "networkCost": 1.20,
                            "totalCost": 29.70,
                            "efficiency": 0.45,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="kubecost",
                source_type=SourceType.OBSERVABILITY,
                provider="kubecost",
                event_type="kubecost_assets",
                raw_data={
                    "response": [
                        {
                            "name": "node/prod-node-01",
                            "type": "Node",
                            "totalCost": 120.50,
                            "cpuCores": 8,
                            "ramBytes": 34359738368,
                        },
                        {
                            "name": "node/prod-node-02",
                            "type": "Node",
                            "totalCost": 120.50,
                            "cpuCores": 8,
                            "ramBytes": 34359738368,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="kubecost",
                source_type=SourceType.OBSERVABILITY,
                provider="kubecost",
                event_type="kubecost_savings",
                raw_data={
                    "response": [
                        {
                            "type": "rightsizing",
                            "monthlySavings": 350.00,
                            "recommendation": "Reduce api-server CPU requests from 2 to 1.5",
                        },
                        {
                            "type": "unused_resources",
                            "monthlySavings": 85.00,
                            "recommendation": "Terminate 2 idle development nodes",
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 80. Infracost
# ---------------------------------------------------------------------------
class DemoInfracostConnector(BaseConnector):
    """Simulates Infracost cloud cost observability collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="infracost",
            source_type=SourceType.OBSERVABILITY,
            provider="infracost",
        )
        result.events.append(
            RawEventData(
                source="infracost",
                source_type=SourceType.OBSERVABILITY,
                provider="infracost",
                event_type="infracost_projects",
                raw_data={
                    "response": [
                        {
                            "id": "ic-proj-001",
                            "name": "acme-prod-infra",
                            "slug": "acme-prod-infra",
                            "monthlyCost": 4250.75,
                            "lastRun": NOW.isoformat(),
                        },
                        {
                            "id": "ic-proj-002",
                            "name": "acme-staging-infra",
                            "slug": "acme-staging-infra",
                            "monthlyCost": 850.20,
                            "lastRun": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="infracost",
                source_type=SourceType.OBSERVABILITY,
                provider="infracost",
                event_type="infracost_runs",
                raw_data={
                    "response": [
                        {
                            "id": "ic-run-001",
                            "projectId": "ic-proj-001",
                            "status": "success",
                            "totalMonthlyCost": 4250.75,
                            "pastTotalMonthlyCost": 4100.00,
                            "diffTotalMonthlyCost": 150.75,
                            "createdAt": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="infracost",
                source_type=SourceType.OBSERVABILITY,
                provider="infracost",
                event_type="infracost_policies",
                raw_data={
                    "response": [
                        {
                            "id": "ic-pol-001",
                            "name": "Max monthly budget $5000",
                            "type": "budget",
                            "enabled": True,
                            "threshold": 5000.00,
                            "status": "passing",
                        },
                        {
                            "id": "ic-pol-002",
                            "name": "No untagged resources",
                            "type": "tagging",
                            "enabled": True,
                            "status": "failing",
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 81. Spot.io
# ---------------------------------------------------------------------------
class DemoSpotioConnector(BaseConnector):
    """Simulates Spot.io cloud cost optimization collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="spotio",
            source_type=SourceType.CLOUD,
            provider="spotio",
        )
        result.events.append(
            RawEventData(
                source="spotio",
                source_type=SourceType.CLOUD,
                provider="spotio",
                event_type="spotio_ec2_groups",
                raw_data={
                    "response": [
                        {
                            "id": "spot-grp-001",
                            "name": "prod-web-elastigroup",
                            "region": "us-east-1",
                            "capacity": {"target": 5, "min": 2, "max": 10},
                            "spotPercentage": 80,
                            "status": "ACTIVE",
                        },
                        {
                            "id": "spot-grp-002",
                            "name": "prod-worker-elastigroup",
                            "region": "us-east-1",
                            "capacity": {"target": 3, "min": 1, "max": 8},
                            "spotPercentage": 100,
                            "status": "ACTIVE",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="spotio",
                source_type=SourceType.CLOUD,
                provider="spotio",
                event_type="spotio_ocean_clusters",
                raw_data={
                    "response": [
                        {
                            "id": "spot-ocean-001",
                            "name": "prod-k8s-ocean",
                            "region": "us-east-1",
                            "clusterK8sVersion": "1.28",
                            "controllerVersion": "1.0.100",
                            "nodesCount": 8,
                            "actualVcpu": 32,
                            "savingsPercentage": 72,
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 82. ManageEngine
# ---------------------------------------------------------------------------
class DemoManageEngineConnector(BaseConnector):
    """Simulates ManageEngine ServiceDesk Plus collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="manageengine",
            source_type=SourceType.ITSM,
            provider="manageengine",
        )
        result.events.append(
            RawEventData(
                source="manageengine",
                source_type=SourceType.ITSM,
                provider="manageengine",
                event_type="manageengine_requests",
                raw_data={
                    "response": [
                        {
                            "id": "me-req-001",
                            "subject": "Laptop replacement needed",
                            "status": {"name": "Open"},
                            "priority": {"name": "High"},
                            "requester": {"email_id": "alice@acme.com"},
                            "created_time": {"value": NOW.isoformat()},
                        },
                        {
                            "id": "me-req-002",
                            "subject": "Software license request - Adobe",
                            "status": {"name": "Pending Approval"},
                            "priority": {"name": "Medium"},
                            "requester": {"email_id": "bob@acme.com"},
                            "created_time": {"value": (NOW - timedelta(hours=4)).isoformat()},
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="manageengine",
                source_type=SourceType.ITSM,
                provider="manageengine",
                event_type="manageengine_assets",
                raw_data={
                    "response": [
                        {
                            "id": "me-asset-001",
                            "name": "LAPTOP-ALICE",
                            "type": {"name": "Laptop"},
                            "state": {"name": "In Use"},
                            "location": {"name": "HQ"},
                            "assigned_user": {"email_id": "alice@acme.com"},
                        },
                        {
                            "id": "me-asset-002",
                            "name": "PRINTER-FLOOR2",
                            "type": {"name": "Printer"},
                            "state": {"name": "In Use"},
                            "location": {"name": "HQ Floor 2"},
                            "assigned_user": None,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="manageengine",
                source_type=SourceType.ITSM,
                provider="manageengine",
                event_type="manageengine_changes",
                raw_data={
                    "response": [
                        {
                            "id": "me-chg-001",
                            "subject": "Database upgrade to PostgreSQL 15",
                            "status": {"name": "Approved"},
                            "type": {"name": "Standard"},
                            "risk": {"name": "Low"},
                            "scheduled_start_time": {
                                "value": (NOW + timedelta(days=3)).isoformat()
                            },
                        },
                        {
                            "id": "me-chg-002",
                            "subject": "Emergency firewall rule change",
                            "status": {"name": "Completed"},
                            "type": {"name": "Emergency"},
                            "risk": {"name": "High"},
                            "scheduled_start_time": {
                                "value": (NOW - timedelta(hours=6)).isoformat()
                            },
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 83. Ivanti Patch
# ---------------------------------------------------------------------------
class DemoIvantiPatchConnector(BaseConnector):
    """Simulates Ivanti Patch for Endpoints collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="ivanti_patch",
            source_type=SourceType.MDM,
            provider="ivanti_patch",
        )
        result.events.append(
            RawEventData(
                source="ivanti_patch",
                source_type=SourceType.MDM,
                provider="ivanti_patch",
                event_type="ivanti_patch_machines",
                raw_data={
                    "response": [
                        {
                            "id": "ivp-mach-001",
                            "name": "WORKSTATION-ALICE",
                            "os": "Windows 11",
                            "domain": "acme.local",
                            "lastSeen": NOW.isoformat(),
                            "agentVersion": "2023.3",
                        },
                        {
                            "id": "ivp-mach-002",
                            "name": "SERVER-PROD-01",
                            "os": "Windows Server 2022",
                            "domain": "acme.local",
                            "lastSeen": NOW.isoformat(),
                            "agentVersion": "2023.3",
                        },
                        {
                            "id": "ivp-mach-003",
                            "name": "LEGACY-XP",
                            "os": "Windows XP",
                            "domain": "acme.local",
                            "lastSeen": (NOW - timedelta(days=30)).isoformat(),
                            "agentVersion": "2018.1",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ivanti_patch",
                source_type=SourceType.MDM,
                provider="ivanti_patch",
                event_type="ivanti_patch_patches",
                raw_data={
                    "response": [
                        {
                            "id": "ivp-patch-001",
                            "patchName": "MS23-OCT Critical",
                            "severity": "Critical",
                            "status": "Missing",
                            "affectedMachines": 3,
                            "cve": "CVE-2023-44487",
                        },
                        {
                            "id": "ivp-patch-002",
                            "patchName": "MS23-SEP Important",
                            "severity": "Important",
                            "status": "Installed",
                            "affectedMachines": 0,
                            "cve": "CVE-2023-36884",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ivanti_patch",
                source_type=SourceType.MDM,
                provider="ivanti_patch",
                event_type="ivanti_patch_deployments",
                raw_data={
                    "response": [
                        {
                            "id": "ivp-deploy-001",
                            "name": "October Critical Patches",
                            "status": "Failed",
                            "machineCount": 3,
                            "startDate": (NOW - timedelta(hours=5)).isoformat(),
                            "completionDate": (NOW - timedelta(hours=4)).isoformat(),
                        },
                        {
                            "id": "ivp-deploy-002",
                            "name": "September Patches",
                            "status": "Completed",
                            "machineCount": 3,
                            "startDate": (NOW - timedelta(days=10)).isoformat(),
                            "completionDate": (NOW - timedelta(days=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# 84. PlexTrac
# ---------------------------------------------------------------------------
class DemoPlexTracConnector(BaseConnector):
    """Simulates PlexTrac pentest management collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="plextrac",
            source_type=SourceType.CUSTOM,
            provider="plextrac",
        )
        result.events.append(
            RawEventData(
                source="plextrac",
                source_type=SourceType.CUSTOM,
                provider="plextrac",
                event_type="plextrac_clients",
                raw_data={
                    "response": [
                        {
                            "id": "pt-cli-001",
                            "name": "ACME Corp",
                            "status": "active",
                            "reportCount": 5,
                            "createdAt": (NOW - timedelta(days=365)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="plextrac",
                source_type=SourceType.CUSTOM,
                provider="plextrac",
                event_type="plextrac_reports",
                raw_data={
                    "response": [
                        {
                            "id": "pt-rpt-001",
                            "name": "Q1 2024 Pentest Report",
                            "status": "published",
                            "clientId": "pt-cli-001",
                            "findingCount": 12,
                            "createdAt": (NOW - timedelta(days=60)).isoformat(),
                        },
                        {
                            "id": "pt-rpt-002",
                            "name": "Q3 2024 Red Team Assessment",
                            "status": "in_review",
                            "clientId": "pt-cli-001",
                            "findingCount": 8,
                            "createdAt": (NOW - timedelta(days=10)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="plextrac",
                source_type=SourceType.CUSTOM,
                provider="plextrac",
                event_type="plextrac_findings",
                raw_data={
                    "response": [
                        {
                            "id": "pt-find-001",
                            "title": "Remote Code Execution via Deserialization",
                            "severity": "Critical",
                            "status": "open",
                            "reportId": "pt-rpt-001",
                            "cwe": "CWE-502",
                            "cvssScore": 9.8,
                            "recommendation": "Avoid Java deserialization of untrusted data",
                        },
                        {
                            "id": "pt-find-002",
                            "title": "Stored XSS in Admin Panel",
                            "severity": "High",
                            "status": "remediated",
                            "reportId": "pt-rpt-001",
                            "cwe": "CWE-79",
                            "cvssScore": 8.2,
                            "recommendation": "Implement output encoding",
                        },
                        {
                            "id": "pt-find-003",
                            "title": "Weak Password Policy",
                            "severity": "Medium",
                            "status": "open",
                            "reportId": "pt-rpt-002",
                            "cwe": "CWE-521",
                            "cvssScore": 5.0,
                            "recommendation": "Enforce minimum 12-char passwords with complexity",
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# Registry: all 84 connector classes
# ---------------------------------------------------------------------------
ALL_NEW_CONNECTORS = [
    DemoPagerDutyConnector,
    DemoOpsgenieConnector,
    DemoAxoniusConnector,
    DemoServiceNowCMDBConnector,
    DemoRunZeroConnector,
    DemoPatchMgmtMicrosoftConnector,
    DemoIvantiConnector,
    DemoVenafiConnector,
    DemoAWSACMConnector,
    DemoDigiCertConnector,
    DemoAWSSecretsConnector,
    DemoAzureKeyVaultConnector,
    DemoGCPSecretsConnector,
    DemoServiceNowGRCConnector,
    DemoNightfallConnector,
    DemoAWSBackupConnector,
    DemoOrcaConnector,
    DemoLaceworkConnector,
    DemoRapid7Connector,
    DemoCrowdStrikeSpotlightConnector,
    DemoPingIdentityConnector,
    DemoOneLoginConnector,
    DemoWorkspaceOneConnector,
    DemoSumoLogicConnector,
    DemoCiscoUmbrellaConnector,
    DemoDrataConnector,
    DemoVantaConnector,
    DemoArcherConnector,
    DemoDrataAPIConnector,
    DemoVantaAPIConnector,
    DemoSecureframeConnector,
    DemoSalesforceConnector,
    DemoTeamsComplianceConnector,
    DemoZoomConnector,
    DemoSmarshConnector,
    DemoAnsibleConnector,
    DemoADPConnector,
    DemoUKGConnector,
    DemoSAPSuccessFactorsConnector,
    DemoWandBConnector,
    DemoVertexAIConnector,
    DemoMimecastConnector,
    DemoChainGuardConnector,
    DemoSyftGrypeConnector,
    DemoFossaConnector,
    DemoSnykContainerConnector,
    DemoSocketDevConnector,
    DemoSaltSecurityConnector,
    DemoNoNameConnector,
    DemoWallarmConnector,
    DemoFortyTwoCrunchConnector,
    DemoTailscaleConnector,
    DemoTwingateConnector,
    DemoBanyanConnector,
    DemoCode42Connector,
    DemoVaronisConnector,
    DemoBigIDConnector,
    DemoRubrikSecurityConnector,
    DemoCommvaultConnector,
    DemoRubrikConnector,
    DemoCohesityConnector,
    DemoDruvaConnector,
    DemoErmeticConnector,
    DemoTrustArcConnector,
    DemoCookiebotConnector,
    DemoOsanoConnector,
    DemoVulcanConnector,
    DemoTaniumConnector,
    DemoAutomoxConnector,
    DemoFleetConnector,
    DemoCobaltConnector,
    DemoHackerOneConnector,
    DemoLinodeConnector,
    DemoHetznerConnector,
    DemoLogRhythmConnector,
    DemoBarracudaConnector,
    DemoF5Connector,
    DemoPaylocityConnector,
    DemoKubecostConnector,
    DemoInfracostConnector,
    DemoSpotioConnector,
    DemoManageEngineConnector,
    DemoIvantiPatchConnector,
    DemoPlexTracConnector,
]
