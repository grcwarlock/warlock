"""Tests for new connectors, normalizers, and assertions.

Covers: Workday, ServiceNow, KnowBe4, Snyk, Purview, Veeam, Intune,
Confluence, Verkada, OneTrust, Proofpoint, MLflow, Vault, Kubernetes,
GitHub, SecurityScorecard.
"""

from datetime import datetime, timezone, timedelta
from warlock.connectors.base import RawEventData, SourceType


# ===================================================================
# 1. ALL NEW CONNECTORS IMPORTABLE
# ===================================================================


def test_all_new_connectors_importable():
    """Test that all 16 new connectors import and register."""
    from warlock.connectors.base import registry
    from warlock.pipeline.loader import load_all_connectors

    load_all_connectors()
    new_providers = [
        "workday",
        "servicenow",
        "knowbe4",
        "snyk",
        "purview",
        "veeam",
        "intune",
        "confluence",
        "verkada",
        "onetrust",
        "proofpoint",
        "mlflow",
        "vault",
        "kubernetes",
        "github",
        "securityscorecard",
    ]
    registered = registry.list_types()
    for p in new_providers:
        assert p in registered, f"Connector {p} not registered"


# ===================================================================
# 2. ALL NEW NORMALIZERS IMPORTABLE
# ===================================================================


def test_all_new_normalizers_importable():
    """Test all 16 normalizers import and register with correct HANDLERS."""
    from warlock.normalizers.base import registry
    from warlock.pipeline.loader import load_all_normalizers

    load_all_normalizers()
    normalizer_names = [type(n).__name__ for n in registry._normalizers]
    expected = [
        "WorkdayNormalizer",
        "ServiceNowNormalizer",
        "KnowBe4Normalizer",
        "SnykNormalizer",
        "PurviewNormalizer",
        "VeeamNormalizer",
        "IntuneNormalizer",
        "ConfluenceNormalizer",
        "VerkadaNormalizer",
        "OneTrustNormalizer",
        "ProofpointNormalizer",
        "MLflowNormalizer",
        "VaultNormalizer",
        "KubernetesNormalizer",
        "GitHubNormalizer",
        "SecurityScorecardNormalizer",
    ]
    for name in expected:
        assert name in normalizer_names, f"Normalizer {name} not registered"


# ===================================================================
# 3. WORKDAY NORMALIZER
# ===================================================================


def test_workday_employees_normalizer():
    """Workday employees: active=inventory, terminated-still-active=policy_violation."""
    from warlock.normalizers.workday import WorkdayNormalizer

    norm = WorkdayNormalizer()
    # Use past termination date to trigger policy_violation
    past_date = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = RawEventData(
        source="workday",
        source_type=SourceType.HRIS,
        provider="workday",
        event_type="workday_employees",
        raw_data={
            "response": [
                {
                    "id": "W001",
                    "status": "active",
                    "descriptor": "Alice",
                    "hireDate": "2024-01-15",
                    "terminationDate": "",
                    "department": "Engineering",
                    "manager": "Bob",
                },
                {
                    "id": "W002",
                    "status": "active",
                    "descriptor": "Charlie",
                    "hireDate": "2023-06-01",
                    "terminationDate": past_date,
                    "department": "Sales",
                    "manager": "Dana",
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    assert len(findings) >= 2
    # One should be policy_violation for terminated-but-active
    violations = [f for f in findings if f.observation_type == "policy_violation"]
    assert len(violations) >= 1
    assert any("past termination" in f.title.lower() for f in violations)


def test_workday_background_checks():
    """Workday background checks: completed=inventory, not completed=policy_violation."""
    from warlock.normalizers.workday import WorkdayNormalizer

    norm = WorkdayNormalizer()
    raw = RawEventData(
        source="workday",
        source_type=SourceType.HRIS,
        provider="workday",
        event_type="workday_background_checks",
        raw_data={
            "response": [
                {
                    "worker_id": "W001",
                    "worker_name": "Alice",
                    "background_check": {"status": "completed"},
                },
                {
                    "worker_id": "W002",
                    "worker_name": "Bob",
                    "background_check": {"status": "pending"},
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    assert len(findings) == 2
    violations = [f for f in findings if f.observation_type == "policy_violation"]
    assert len(violations) >= 1  # Bob's pending check
    inventory = [f for f in findings if f.observation_type == "inventory"]
    assert len(inventory) >= 1  # Alice's completed check


def test_workday_agreements():
    """Workday agreements: unsigned -> policy_violation."""
    from warlock.normalizers.workday import WorkdayNormalizer

    norm = WorkdayNormalizer()
    raw = RawEventData(
        source="workday",
        source_type=SourceType.HRIS,
        provider="workday",
        event_type="workday_agreements",
        raw_data={
            "response": [
                {
                    "worker_id": "W001",
                    "worker_name": "Alice",
                    "employment_agreement_signed": True,
                    "nda_signed": False,
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    violations = [f for f in findings if f.observation_type == "policy_violation"]
    assert len(violations) >= 1  # NDA not signed


# ===================================================================
# 4. SERVICENOW NORMALIZER
# ===================================================================


def test_servicenow_change_requests():
    """ServiceNow changes: unapproved = policy_violation, no backout = misconfiguration."""
    from warlock.normalizers.servicenow import ServiceNowNormalizer

    norm = ServiceNowNormalizer()
    raw = RawEventData(
        source="servicenow",
        source_type=SourceType.ITSM,
        provider="servicenow",
        event_type="snow_change_requests",
        raw_data={
            "response": [
                {
                    "sys_id": "s1",
                    "number": "CHG001",
                    "approval": "approved",
                    "backout_plan": "Revert to v1.2",
                    "short_description": "Upgrade DB",
                    "type": "standard",
                },
                {
                    "sys_id": "s2",
                    "number": "CHG002",
                    "approval": "not yet requested",
                    "backout_plan": "",
                    "short_description": "Deploy feature",
                    "type": "normal",
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    assert len(findings) == 2
    violations = [f for f in findings if f.observation_type == "policy_violation"]
    assert len(violations) >= 1  # CHG002 not approved


def test_servicenow_incidents():
    """ServiceNow incidents: past SLA = alert."""
    from warlock.normalizers.servicenow import ServiceNowNormalizer

    norm = ServiceNowNormalizer()
    past_sla = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = RawEventData(
        source="servicenow",
        source_type=SourceType.ITSM,
        provider="servicenow",
        event_type="snow_incidents",
        raw_data={
            "response": [
                {
                    "sys_id": "i1",
                    "number": "INC001",
                    "state": "2",
                    "priority": "1",
                    "short_description": "Server down",
                    "sla_due": past_sla,
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    alerts = [f for f in findings if f.observation_type == "alert"]
    assert len(alerts) >= 1


# ===================================================================
# 5. KNOWBE4 NORMALIZER
# ===================================================================


def test_knowbe4_training_enrollments():
    """KnowBe4 enrollments: completed=inventory, overdue=policy_violation."""
    from warlock.normalizers.knowbe4 import KnowBe4Normalizer

    norm = KnowBe4Normalizer()
    past_due = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = RawEventData(
        source="knowbe4",
        source_type=SourceType.TRAINING,
        provider="knowbe4",
        event_type="kb4_training_enrollments",
        raw_data={
            "response": [
                {
                    "enrollment_id": "e1",
                    "user": {"name": "Alice"},
                    "module_name": "Security 101",
                    "status": "Passed",
                    "due_date": "",
                    "completion_date": "2025-01-15",
                },
                {
                    "enrollment_id": "e2",
                    "user": {"name": "Bob"},
                    "module_name": "Phishing 201",
                    "status": "In Progress",
                    "due_date": past_due,
                    "completion_date": "",
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    assert len(findings) >= 2
    violations = [f for f in findings if f.observation_type == "policy_violation"]
    assert len(violations) >= 1  # Bob overdue


def test_knowbe4_training_campaigns():
    """KnowBe4 campaigns: low completion = misconfiguration."""
    from warlock.normalizers.knowbe4 import KnowBe4Normalizer

    norm = KnowBe4Normalizer()
    raw = RawEventData(
        source="knowbe4",
        source_type=SourceType.TRAINING,
        provider="knowbe4",
        event_type="kb4_training_campaigns",
        raw_data={
            "response": [
                {
                    "campaign_id": "c1",
                    "name": "Q1 Training",
                    "completion_percentage": 80,
                    "status": "active",
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    misconfigs = [f for f in findings if f.observation_type == "misconfiguration"]
    assert len(misconfigs) >= 1  # 80% < 95% threshold


# ===================================================================
# 6. SNYK NORMALIZER
# ===================================================================


def test_snyk_issues():
    """Snyk issues: vulnerability findings with severity mapping."""
    from warlock.normalizers.snyk import SnykNormalizer

    norm = SnykNormalizer()
    raw = RawEventData(
        source="snyk",
        source_type=SourceType.CODE,
        provider="snyk",
        event_type="snyk_issues",
        raw_data={
            "response": [
                {
                    "id": "SNYK-JS-001",
                    "title": "Prototype Pollution",
                    "severity": "critical",
                    "pkgName": "lodash",
                    "version": "4.17.15",
                    "fixedIn": ["4.17.21"],
                },
                {
                    "id": "SNYK-JS-002",
                    "title": "ReDoS",
                    "severity": "low",
                    "pkgName": "validator",
                    "version": "10.0.0",
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    vulns = [f for f in findings if f.observation_type == "vulnerability"]
    assert len(vulns) >= 2
    critical = [f for f in vulns if f.severity == "critical"]
    assert len(critical) >= 1


# ===================================================================
# 7. PURVIEW NORMALIZER
# ===================================================================


def test_purview_dlp_alerts():
    """Purview DLP alerts: produces alert findings with severity mapping."""
    from warlock.normalizers.purview import PurviewNormalizer

    norm = PurviewNormalizer()
    raw = RawEventData(
        source="purview",
        source_type=SourceType.DLP,
        provider="purview",
        event_type="purview_dlp_alerts",
        raw_data={
            "records": [
                {
                    "id": "a1",
                    "title": "SSN detected in email",
                    "severity": "high",
                    "status": "new",
                    "category": "DLP",
                    "description": "Social security number found",
                    "createdDateTime": "2025-03-18T00:00:00Z",
                    "serviceSource": "Exchange",
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    alerts = [f for f in findings if f.observation_type == "alert"]
    assert len(alerts) >= 1
    assert alerts[0].severity == "high"


def test_purview_dlp_policies_disabled():
    """Purview DLP policies: disabled policy = misconfiguration."""
    from warlock.normalizers.purview import PurviewNormalizer

    norm = PurviewNormalizer()
    raw = RawEventData(
        source="purview",
        source_type=SourceType.DLP,
        provider="purview",
        event_type="purview_dlp_policies",
        raw_data={
            "records": [
                {
                    "id": "p1",
                    "name": "Credit Card Policy",
                    "isEnabled": False,
                    "description": "Blocks credit card numbers",
                },
                {"id": "p2", "name": "SSN Policy", "isEnabled": True, "description": "Blocks SSNs"},
            ]
        },
    )
    findings = norm.normalize(raw)
    misconfigs = [f for f in findings if f.observation_type == "misconfiguration"]
    assert len(misconfigs) >= 1  # Disabled policy


# ===================================================================
# 8. VEEAM NORMALIZER
# ===================================================================


def test_veeam_backup_sessions():
    """Veeam sessions: failed sessions = alert."""
    from warlock.normalizers.veeam import VeeamNormalizer

    norm = VeeamNormalizer()
    recent = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = RawEventData(
        source="veeam",
        source_type=SourceType.BACKUP,
        provider="veeam",
        event_type="veeam_backup_sessions",
        raw_data={
            "records": [
                {
                    "id": "s1",
                    "name": "Daily Backup",
                    "result": "success",
                    "endTime": recent,
                    "jobId": "j1",
                },
                {
                    "id": "s2",
                    "name": "Weekly Full",
                    "result": "failed",
                    "endTime": recent,
                    "jobId": "j2",
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    alerts = [f for f in findings if f.observation_type == "alert"]
    assert len(alerts) >= 1  # Failed job


def test_veeam_backup_jobs_disabled():
    """Veeam backup jobs: disabled job = misconfiguration."""
    from warlock.normalizers.veeam import VeeamNormalizer

    norm = VeeamNormalizer()
    raw = RawEventData(
        source="veeam",
        source_type=SourceType.BACKUP,
        provider="veeam",
        event_type="veeam_backup_jobs",
        raw_data={
            "records": [
                {
                    "id": "j1",
                    "name": "Daily Backup",
                    "type": "Backup",
                    "isDisabled": True,
                    "scheduleEnabled": False,
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    misconfigs = [f for f in findings if f.observation_type == "misconfiguration"]
    assert len(misconfigs) >= 1


# ===================================================================
# 9. INTUNE NORMALIZER
# ===================================================================


def test_intune_devices():
    """Intune devices: non-compliant = policy_violation, unencrypted = misconfiguration."""
    from warlock.normalizers.intune import IntuneNormalizer

    norm = IntuneNormalizer()
    raw = RawEventData(
        source="intune",
        source_type=SourceType.MDM,
        provider="intune",
        event_type="intune_devices",
        raw_data={
            "records": [
                {
                    "id": "D001",
                    "deviceName": "LAPTOP-001",
                    "complianceState": "compliant",
                    "isEncrypted": True,
                    "operatingSystem": "Windows",
                    "osVersion": "11.0",
                },
                {
                    "id": "D002",
                    "deviceName": "LAPTOP-002",
                    "complianceState": "noncompliant",
                    "isEncrypted": False,
                    "operatingSystem": "Windows",
                    "osVersion": "10.0",
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    violations = [f for f in findings if f.observation_type == "policy_violation"]
    assert len(violations) >= 1  # D002 non-compliant
    misconfigs = [f for f in findings if f.observation_type == "misconfiguration"]
    assert len(misconfigs) >= 1  # D002 unencrypted


# ===================================================================
# 10. CONFLUENCE NORMALIZER
# ===================================================================


def test_confluence_pages():
    """Confluence pages: stale page = misconfiguration, missing author = misconfiguration."""
    from warlock.normalizers.confluence import ConfluenceNormalizer

    norm = ConfluenceNormalizer()
    stale_date = (datetime.now(timezone.utc) - timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = RawEventData(
        source="confluence",
        source_type=SourceType.GRC,
        provider="confluence",
        event_type="confluence_pages",
        raw_data={
            "pages": [
                {
                    "id": "p1",
                    "title": "Security Policy",
                    "status": "current",
                    "authorId": "u1",
                    "version": {"createdAt": stale_date},
                },
                {
                    "id": "p2",
                    "title": "Orphan Page",
                    "status": "current",
                    "authorId": "",
                    "version": {"createdAt": stale_date},
                },
            ],
            "space_key": "SEC",
        },
    )
    findings = norm.normalize(raw)
    misconfigs = [f for f in findings if f.observation_type == "misconfiguration"]
    assert len(misconfigs) >= 2  # Stale page + missing author


# ===================================================================
# 11. VERKADA NORMALIZER
# ===================================================================


def test_verkada_doors():
    """Verkada doors: unlocked door = misconfiguration."""
    from warlock.normalizers.verkada import VerkadaNormalizer

    norm = VerkadaNormalizer()
    raw = RawEventData(
        source="verkada",
        source_type=SourceType.PHYSICAL,
        provider="verkada",
        event_type="verkada_doors",
        raw_data={
            "response": [
                {"door_id": "d1", "name": "Main Entrance", "lock_status": "locked", "site": "HQ"},
                {"door_id": "d2", "name": "Server Room", "lock_status": "unlocked", "site": "HQ"},
            ]
        },
    )
    findings = norm.normalize(raw)
    misconfigs = [f for f in findings if f.observation_type == "misconfiguration"]
    assert len(misconfigs) >= 1  # Unlocked server room door


def test_verkada_access_after_hours():
    """Verkada access events: after-hours access = access_anomaly."""
    from warlock.normalizers.verkada import VerkadaNormalizer

    norm = VerkadaNormalizer()
    # 3 AM is after hours
    after_hours = (
        datetime.now(timezone.utc).replace(hour=3, minute=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    raw = RawEventData(
        source="verkada",
        source_type=SourceType.PHYSICAL,
        provider="verkada",
        event_type="verkada_access_events",
        raw_data={
            "response": [
                {
                    "event_id": "e1",
                    "user_name": "Alice",
                    "door_name": "Main",
                    "event_time": after_hours,
                    "event_type": "access_granted",
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    anomalies = [f for f in findings if f.observation_type == "access_anomaly"]
    assert len(anomalies) >= 1


# ===================================================================
# 12. ONETRUST NORMALIZER
# ===================================================================


def test_onetrust_assessments():
    """OneTrust assessments: incomplete PIA = policy_violation."""
    from warlock.normalizers.onetrust import OneTrustNormalizer

    norm = OneTrustNormalizer()
    raw = RawEventData(
        source="onetrust",
        source_type=SourceType.GRC,
        provider="onetrust",
        event_type="onetrust_assessments",
        raw_data={
            "response": [
                {
                    "assessmentId": "a1",
                    "name": "Widget PIA",
                    "status": "in_progress",
                    "type": "PIA",
                },
                {
                    "assessmentId": "a2",
                    "name": "Data Flow Review",
                    "status": "completed",
                    "type": "review",
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    violations = [f for f in findings if f.observation_type == "policy_violation"]
    assert len(violations) >= 1  # Incomplete PIA


def test_onetrust_dsar_overdue():
    """OneTrust DSARs: overdue request = policy_violation."""
    from warlock.normalizers.onetrust import OneTrustNormalizer

    norm = OneTrustNormalizer()
    old_date = (datetime.now(timezone.utc) - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = RawEventData(
        source="onetrust",
        source_type=SourceType.GRC,
        provider="onetrust",
        event_type="onetrust_dsar_requests",
        raw_data={
            "response": [
                {
                    "requestId": "r1",
                    "subjectName": "John Doe",
                    "status": "open",
                    "type": "deletion",
                    "createdDate": old_date,
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    violations = [f for f in findings if f.observation_type == "policy_violation"]
    assert len(violations) >= 1


# ===================================================================
# 13. PROOFPOINT NORMALIZER
# ===================================================================


def test_proofpoint_delivered_threats():
    """Proofpoint delivered threats: produces alert findings with threat score severity."""
    from warlock.normalizers.proofpoint import ProofpointNormalizer

    norm = ProofpointNormalizer()
    raw = RawEventData(
        source="proofpoint",
        source_type=SourceType.EMAIL,
        provider="proofpoint",
        event_type="proofpoint_delivered_threats",
        raw_data={
            "response": [
                {
                    "GUID": "msg1",
                    "subject": "Urgent invoice",
                    "sender": "attacker@evil.com",
                    "recipient": "user@co.com",
                    "threatsInfoMap": {
                        "url": {"threatScore": 85, "classification": "malware"},
                    },
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    alerts = [f for f in findings if f.observation_type == "alert"]
    assert len(alerts) >= 1
    assert alerts[0].severity == "high"  # score 85 > 75


# ===================================================================
# 14. MLFLOW NORMALIZER
# ===================================================================


def test_mlflow_registered_models():
    """MLflow models: model without description = misconfiguration."""
    from warlock.normalizers.mlflow import MLflowNormalizer

    norm = MLflowNormalizer()
    raw = RawEventData(
        source="mlflow",
        source_type=SourceType.CUSTOM,
        provider="mlflow",
        event_type="mlflow_registered_models",
        raw_data={
            "response": [
                {"name": "fraud-detector", "description": "Detects fraud"},
                {"name": "risk-scorer", "description": ""},
            ]
        },
    )
    findings = norm.normalize(raw)
    misconfigs = [f for f in findings if f.observation_type == "misconfiguration"]
    assert len(misconfigs) >= 1  # risk-scorer has no description


# ===================================================================
# 15. VAULT NORMALIZER
# ===================================================================


def test_vault_audit_devices_empty():
    """Vault audit devices: no audit devices = critical policy_violation."""
    from warlock.normalizers.vault import VaultNormalizer

    norm = VaultNormalizer()
    raw = RawEventData(
        source="vault",
        source_type=SourceType.IAM,
        provider="vault",
        event_type="vault_audit_devices",
        raw_data={"response": {}},
    )
    findings = norm.normalize(raw)
    violations = [f for f in findings if f.observation_type == "policy_violation"]
    assert len(violations) >= 1
    assert any(f.severity == "critical" for f in violations)


def test_vault_audit_devices_present():
    """Vault audit devices: present devices = inventory."""
    from warlock.normalizers.vault import VaultNormalizer

    norm = VaultNormalizer()
    raw = RawEventData(
        source="vault",
        source_type=SourceType.IAM,
        provider="vault",
        event_type="vault_audit_devices",
        raw_data={
            "response": {
                "file/": {"type": "file", "description": "File audit log"},
            }
        },
    )
    findings = norm.normalize(raw)
    inventory = [f for f in findings if f.observation_type == "inventory"]
    assert len(inventory) >= 1
    violations = [f for f in findings if f.observation_type == "policy_violation"]
    assert len(violations) == 0


def test_vault_seal_status():
    """Vault seal status: sealed = critical alert."""
    from warlock.normalizers.vault import VaultNormalizer

    norm = VaultNormalizer()
    raw = RawEventData(
        source="vault",
        source_type=SourceType.IAM,
        provider="vault",
        event_type="vault_seal_status",
        raw_data={
            "response": {
                "sealed": True,
                "initialized": True,
                "cluster_name": "prod-vault",
            }
        },
    )
    findings = norm.normalize(raw)
    alerts = [f for f in findings if f.observation_type == "alert"]
    assert len(alerts) >= 1
    assert any(f.severity == "critical" for f in alerts)


# ===================================================================
# 16. KUBERNETES NORMALIZER
# ===================================================================


def test_kubernetes_pods():
    """K8s pods: privileged container = critical misconfiguration."""
    from warlock.normalizers.kubernetes import KubernetesNormalizer

    norm = KubernetesNormalizer()
    raw = RawEventData(
        source="kubernetes",
        source_type=SourceType.CLOUD,
        provider="kubernetes",
        event_type="k8s_running_pods",
        raw_data={
            "response": [
                {
                    "metadata": {"name": "web-app", "namespace": "production", "uid": "u1"},
                    "spec": {
                        "containers": [
                            {"name": "app", "securityContext": {"privileged": True}},
                        ]
                    },
                },
                {
                    "metadata": {"name": "api-svc", "namespace": "production", "uid": "u2"},
                    "spec": {
                        "containers": [
                            {
                                "name": "api",
                                "securityContext": {"runAsNonRoot": True},
                                "resources": {"limits": {"memory": "512Mi"}},
                            },
                        ]
                    },
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    misconfigs = [f for f in findings if f.observation_type == "misconfiguration"]
    assert len(misconfigs) >= 1  # Privileged container
    critical = [f for f in misconfigs if f.severity == "critical"]
    assert len(critical) >= 1


def test_kubernetes_no_network_policies():
    """K8s network policies: none found = misconfiguration."""
    from warlock.normalizers.kubernetes import KubernetesNormalizer

    norm = KubernetesNormalizer()
    raw = RawEventData(
        source="kubernetes",
        source_type=SourceType.CLOUD,
        provider="kubernetes",
        event_type="k8s_network_policies",
        raw_data={"response": []},
    )
    findings = norm.normalize(raw)
    misconfigs = [f for f in findings if f.observation_type == "misconfiguration"]
    assert len(misconfigs) >= 1


# ===================================================================
# 17. GITHUB NORMALIZER
# ===================================================================


def test_github_secret_scanning():
    """GitHub secret scanning alerts: open secret = critical alert."""
    from warlock.normalizers.github import GitHubNormalizer

    norm = GitHubNormalizer()
    raw = RawEventData(
        source="github",
        source_type=SourceType.CODE,
        provider="github",
        event_type="github_secret_scanning_alerts",
        raw_data={
            "response": [
                {
                    "number": 1,
                    "secret_type": "aws_access_key_id",
                    "state": "open",
                    "repository": {"full_name": "org/repo"},
                    "created_at": "2025-03-18T00:00:00Z",
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    alerts = [f for f in findings if f.observation_type == "alert"]
    assert len(alerts) >= 1
    assert any(f.severity == "critical" for f in alerts)


def test_github_repos_public():
    """GitHub repos: public repo = misconfiguration."""
    from warlock.normalizers.github import GitHubNormalizer

    norm = GitHubNormalizer()
    raw = RawEventData(
        source="github",
        source_type=SourceType.CODE,
        provider="github",
        event_type="github_repos",
        raw_data={
            "response": [
                {
                    "id": 1,
                    "full_name": "org/public-repo",
                    "visibility": "public",
                    "private": False,
                    "default_branch": "main",
                },
                {
                    "id": 2,
                    "full_name": "org/private-repo",
                    "visibility": "private",
                    "private": True,
                    "default_branch": "main",
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    misconfigs = [f for f in findings if f.observation_type == "misconfiguration"]
    assert len(misconfigs) >= 1  # Public repo


# ===================================================================
# 18. SECURITYSCORECARD NORMALIZER
# ===================================================================


def test_securityscorecard_companies():
    """SSC companies: low score = critical/high alert."""
    from warlock.normalizers.securityscorecard import SecurityScorecardNormalizer

    norm = SecurityScorecardNormalizer()
    raw = RawEventData(
        source="securityscorecard",
        source_type=SourceType.GRC,
        provider="securityscorecard",
        event_type="ssc_companies",
        raw_data={
            "response": [
                {"domain": "vendor1.com", "name": "Vendor One", "score": 45},
                {"domain": "vendor2.com", "name": "Vendor Two", "score": 92},
            ]
        },
    )
    findings = norm.normalize(raw)
    alerts = [f for f in findings if f.observation_type == "alert"]
    assert len(alerts) >= 1  # Vendor One has score < 50
    critical = [f for f in alerts if f.severity == "critical"]
    assert len(critical) >= 1


def test_securityscorecard_factors():
    """SSC factors: low grade = misconfiguration."""
    from warlock.normalizers.securityscorecard import SecurityScorecardNormalizer

    norm = SecurityScorecardNormalizer()
    raw = RawEventData(
        source="securityscorecard",
        source_type=SourceType.GRC,
        provider="securityscorecard",
        event_type="ssc_factors",
        raw_data={
            "response": [
                {
                    "domain": "vendor.com",
                    "factors": [
                        {"name": "network_security", "grade": "F", "score": 20},
                        {"name": "patching_cadence", "grade": "A", "score": 95},
                    ],
                },
            ]
        },
    )
    findings = norm.normalize(raw)
    misconfigs = [f for f in findings if f.observation_type == "misconfiguration"]
    assert len(misconfigs) >= 1  # Grade F factor
    assert any(f.severity == "critical" for f in misconfigs)


# ===================================================================
# 19. ASSERTION: BACKGROUND CHECK
# ===================================================================


def test_assertion_background_check():
    """background_check_completed assertion: completed passes, pending fails."""
    from warlock.assessors.assertions import engine

    passed, reasons = engine.evaluate(
        "background_check_completed",
        {"background_check_status": "completed"},
        {},
    )
    assert passed

    passed, reasons = engine.evaluate(
        "background_check_completed",
        {"background_check_status": "pending", "employee_name": "Bob"},
        {},
    )
    assert not passed
    assert "Bob" in reasons[0]


# ===================================================================
# 20. ASSERTION: CHANGE REQUEST
# ===================================================================


def test_assertion_change_request():
    """change_request_approved assertion: approved+backout passes, unapproved fails."""
    from warlock.assessors.assertions import engine

    passed, reasons = engine.evaluate(
        "change_request_approved",
        {"approval": "approved", "backout_plan": "Revert to v1.2"},
        {},
    )
    assert passed

    passed, reasons = engine.evaluate(
        "change_request_approved",
        {"approval": "not requested", "number": "CHG001"},
        {},
    )
    assert not passed
    assert "CHG001" in reasons[0]


# ===================================================================
# 21. ASSERTION: TRAINING COMPLETION
# ===================================================================


def test_assertion_training_completion():
    """training_completion_rate assertion: >= 95% passes, < 95% fails."""
    from warlock.assessors.assertions import engine

    passed, _ = engine.evaluate(
        "training_completion_rate",
        {"completion_pct": 98.5},
        {},
    )
    assert passed

    passed, reasons = engine.evaluate(
        "training_completion_rate",
        {"completion_pct": 82.0, "campaign_name": "Q1 Training"},
        {},
    )
    assert not passed
    assert "Q1 Training" in reasons[0]


# ===================================================================
# 22. ASSERTION: BACKUP JOB SUCCESSFUL
# ===================================================================


def test_assertion_backup_successful():
    """backup_job_successful assertion: Success passes, Failed fails."""
    from warlock.assessors.assertions import engine

    passed, _ = engine.evaluate(
        "backup_job_successful",
        {"status": "Success", "job_name": "Daily"},
        {},
    )
    assert passed

    passed, reasons = engine.evaluate(
        "backup_job_successful",
        {"status": "Failed", "job_name": "Weekly"},
        {},
    )
    assert not passed
    assert "Weekly" in reasons[0]


# ===================================================================
# 23. ASSERTION: DEVICE COMPLIANT
# ===================================================================


def test_assertion_device_compliant():
    """device_compliant assertion: compliant+encrypted passes, noncompliant fails."""
    from warlock.assessors.assertions import engine

    passed, _ = engine.evaluate(
        "device_compliant",
        {"complianceState": "compliant", "isEncrypted": True},
        {},
    )
    assert passed

    passed, reasons = engine.evaluate(
        "device_compliant",
        {"complianceState": "noncompliant", "deviceName": "LAPTOP-X"},
        {},
    )
    assert not passed
    assert "LAPTOP-X" in reasons[0]


# ===================================================================
# 24. SOURCE TYPE ENUM
# ===================================================================


def test_new_source_types():
    """SourceType enum includes all new source types."""
    new_types = [
        "hris",
        "itsm",
        "training",
        "physical",
        "code",
        "dlp",
        "backup",
        "mdm",
        "grc",
        "email",
    ]
    for t in new_types:
        assert SourceType(t), f"SourceType {t} not in enum"


# ===================================================================
# 25. API MODULE IMPORTS
# ===================================================================


def test_api_modules_import():
    """API auth module: password hashing, API key generation, RBAC."""
    from warlock.api.auth import (
        hash_password,
        verify_password,
        generate_api_key,
        PERMISSIONS,
    )

    # Test password hashing
    pw = hash_password("test123")
    assert verify_password("test123", pw)
    assert not verify_password("wrong", pw)

    # Test API key generation
    raw, hashed = generate_api_key()
    assert raw.startswith("wlk_")
    assert len(hashed) == 64

    # Test RBAC
    assert "read" in PERMISSIONS["viewer"]
    assert "write" not in PERMISSIONS["viewer"]
    assert "manage_users" in PERMISSIONS["admin"]


# ===================================================================
# 26. NEW DB MODELS
# ===================================================================


def test_new_db_models():
    """New database models have correct table names."""
    from warlock.db.models import (
        AuditEntry,
        PostureSnapshot,
        User,
        APIKey,
        AuditEngagement,
    )

    assert AuditEntry.__tablename__ == "audit_entries"
    assert PostureSnapshot.__tablename__ == "posture_snapshots"
    assert User.__tablename__ == "users"
    assert APIKey.__tablename__ == "api_keys"
    assert AuditEngagement.__tablename__ == "audit_engagements"


# ===================================================================
# 27. NORMALIZER CAN_HANDLE CORRECTNESS
# ===================================================================


def test_normalizers_reject_wrong_source():
    """Each normalizer rejects events from a different source."""
    from warlock.normalizers.workday import WorkdayNormalizer
    from warlock.normalizers.servicenow import ServiceNowNormalizer
    from warlock.normalizers.github import GitHubNormalizer

    raw = RawEventData(
        source="unknown",
        source_type=SourceType.CUSTOM,
        provider="unknown",
        event_type="workday_employees",
        raw_data={},
    )
    assert not WorkdayNormalizer().can_handle(raw)
    assert not ServiceNowNormalizer().can_handle(raw)
    assert not GitHubNormalizer().can_handle(raw)


def test_normalizers_reject_wrong_event_type():
    """Each normalizer rejects events with unknown event types."""
    from warlock.normalizers.workday import WorkdayNormalizer
    from warlock.normalizers.kubernetes import KubernetesNormalizer

    raw = RawEventData(
        source="workday",
        source_type=SourceType.HRIS,
        provider="workday",
        event_type="nonexistent_event",
        raw_data={},
    )
    assert not WorkdayNormalizer().can_handle(raw)

    raw2 = RawEventData(
        source="kubernetes",
        source_type=SourceType.CLOUD,
        provider="kubernetes",
        event_type="nonexistent_event",
        raw_data={},
    )
    assert not KubernetesNormalizer().can_handle(raw2)


# ===================================================================
# 28. NEW ASSERTIONS REGISTERED
# ===================================================================


def test_new_assertions_registered():
    """All new assertion names are registered in the engine."""
    from warlock.assessors.assertions import engine

    new_assertions = [
        "background_check_completed",
        "employment_agreement_signed",
        "change_request_approved",
        "training_completion_rate",
        "phishing_failure_rate",
        "no_critical_code_vulns",
        "backup_job_successful",
        "device_compliant",
        "policy_reviewed_within_year",
        "dlp_policies_active",
    ]
    for name in new_assertions:
        assert name in engine._assertions, f"Assertion '{name}' not registered"
