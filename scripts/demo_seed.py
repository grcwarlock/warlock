#!/usr/bin/env python3
"""Seed a demo environment with realistic data from AWS, Okta, and CrowdStrike.

No real credentials needed. Creates mock raw events that flow through the real
pipeline (normalize -> map -> assess) so every CLI command has data to show.

Usage:
    python scripts/demo_seed.py          # seed + run pipeline
    warlock results                      # see control results
    warlock coverage                     # see compliance coverage
    warlock findings                     # see findings
    warlock issues                       # see issues (after issues-auto-create)
"""

from __future__ import annotations

import hashlib
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure warlock package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import func

from warlock.connectors.base import (
    BaseConnector,
    ConnectorConfig,
    ConnectorRegistry,
    ConnectorResult,
    RawEventData,
    SourceType,
)
from warlock.db.engine import get_session, init_db
from warlock.db.models import (
    AuditEngagement,
    AuditorEngagementAssignment,
    Base,
    ChangeEvent,
    CompensatingControl,
    ComplianceDrift,
    ControlInheritance,
    ControlMapping,
    ControlResult,
    DataSilo,
    EvidenceRequest,
    ExternalAuditor,
    Finding,
    Issue,
    LegalHold,
    Personnel,
    POAM,
    PolicyOverride,
    PostureSnapshot,
    RiskAcceptance,
    SystemDependency,
    SystemProfile,
)
from warlock.normalizers.aws import AWSNormalizer
from warlock.normalizers.base import NormalizerRegistry
from warlock.normalizers.confluence import ConfluenceNormalizer
from warlock.normalizers.crowdstrike import CrowdStrikeNormalizer
from warlock.normalizers.generic import GenericNormalizer
from warlock.normalizers.knowbe4 import KnowBe4Normalizer
from warlock.normalizers.okta import OktaNormalizer
from warlock.normalizers.securityscorecard import SecurityScorecardNormalizer
from warlock.normalizers.workday import WorkdayNormalizer
from warlock.assessors.engine import Assessor, engine as assertion_engine
from warlock.mappers.control_mapper import ControlMapper
from warlock.pipeline.bus import EventBus
from warlock.pipeline.loader import load_assertions, load_framework_configs
from warlock.pipeline.orchestrator import Pipeline


NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Mock connectors
# ---------------------------------------------------------------------------


class DemoAWSConnector(BaseConnector):
    """Simulates an AWS collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="aws",
            source_type=SourceType.CLOUD,
            provider="aws",
        )

        # IAM credential report: root with access keys, user without MFA
        result.events.append(RawEventData(
            source="aws", source_type=SourceType.CLOUD, provider="aws",
            event_type="iam_credential_report",
            raw_data={
                "service": "iam", "method": "get_credential_report",
                "region": "us-east-1", "account_id": "912345678012",
                "response": {"Content": (
                    "user,arn,user_creation_time,password_enabled,password_last_used,"
                    "password_last_changed,password_next_rotation,mfa_active,"
                    "access_key_1_active,access_key_1_last_rotated,"
                    "access_key_2_active,access_key_2_last_rotated\n"
                    # Root account with access keys (critical)
                    "<root_account>,arn:aws:iam::912345678012:root,"
                    "2021-03-15T00:00:00+00:00,not_supported,"
                    "2024-11-01T00:00:00+00:00,not_supported,not_supported,true,"
                    "true,2023-06-01T00:00:00+00:00,false,N/A\n"
                    # Developer without MFA (high)
                    "alice.chen,arn:aws:iam::912345678012:user/alice.chen,"
                    "2024-02-01T00:00:00+00:00,true,"
                    "2024-12-01T00:00:00+00:00,2024-02-01T00:00:00+00:00,N/A,false,"
                    "true,2024-02-01T00:00:00+00:00,false,N/A\n"
                    # DevOps engineer with MFA (compliant)
                    "bob.martinez,arn:aws:iam::912345678012:user/bob.martinez,"
                    "2023-08-15T00:00:00+00:00,true,"
                    "2024-11-15T00:00:00+00:00,2024-06-01T00:00:00+00:00,N/A,true,"
                    "true,2024-09-01T00:00:00+00:00,false,N/A\n"
                    # Service account (compliant, no console)
                    "svc-deploy,arn:aws:iam::912345678012:user/svc-deploy,"
                    "2024-01-01T00:00:00+00:00,false,N/A,N/A,N/A,false,"
                    "true,2024-10-01T00:00:00+00:00,false,N/A\n"
                )},
            },
        ))

        # Security groups: open SSH, open RDP, and a properly restricted one
        result.events.append(RawEventData(
            source="aws", source_type=SourceType.CLOUD, provider="aws",
            event_type="ec2_security_groups",
            raw_data={
                "service": "ec2", "method": "describe_security_groups",
                "region": "us-east-1", "account_id": "912345678012",
                "response": {"SecurityGroups": [
                    {
                        "GroupId": "sg-0a1b2c3d4e5f",
                        "GroupName": "web-bastion",
                        "IpPermissions": [{
                            "FromPort": 22, "ToPort": 22, "IpProtocol": "tcp",
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }],
                    },
                    {
                        "GroupId": "sg-1f2e3d4c5b6a",
                        "GroupName": "legacy-windows",
                        "IpPermissions": [{
                            "FromPort": 3389, "ToPort": 3389, "IpProtocol": "tcp",
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }],
                    },
                    {
                        "GroupId": "sg-9z8y7x6w5v4u",
                        "GroupName": "api-internal",
                        "IpPermissions": [{
                            "FromPort": 443, "ToPort": 443, "IpProtocol": "tcp",
                            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                        }],
                    },
                ]},
            },
        ))

        # GuardDuty enabled
        result.events.append(RawEventData(
            source="aws", source_type=SourceType.CLOUD, provider="aws",
            event_type="guardduty_detectors",
            raw_data={
                "service": "guardduty", "method": "list_detectors",
                "region": "us-east-1", "account_id": "912345678012",
                "response": {"DetectorIds": ["d-abc123def456"]},
            },
        ))

        # CloudTrail: single-region only (misconfiguration)
        result.events.append(RawEventData(
            source="aws", source_type=SourceType.CLOUD, provider="aws",
            event_type="cloudtrail_trails",
            raw_data={
                "service": "cloudtrail", "method": "describe_trails",
                "region": "us-east-1", "account_id": "912345678012",
                "response": {"trailList": [{
                    "Name": "prod-trail",
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:912345678012:trail/prod-trail",
                    "IsMultiRegionTrail": False,
                    "LogFileValidationEnabled": True,
                }]},
            },
        ))

        # SecurityHub enabled
        result.events.append(RawEventData(
            source="aws", source_type=SourceType.CLOUD, provider="aws",
            event_type="securityhub_hub",
            raw_data={
                "service": "securityhub", "method": "describe_hub",
                "region": "us-east-1", "account_id": "912345678012",
                "response": {
                    "HubArn": "arn:aws:securityhub:us-east-1:912345678012:hub/default",
                },
            },
        ))

        # Password policy: weak (no symbols, short min length, no expiration)
        result.events.append(RawEventData(
            source="aws", source_type=SourceType.CLOUD, provider="aws",
            event_type="iam_password_policy",
            raw_data={
                "service": "iam", "method": "get_account_password_policy",
                "region": "us-east-1", "account_id": "912345678012",
                "response": {"PasswordPolicy": {
                    "MinimumPasswordLength": 8,
                    "RequireSymbols": False,
                    "RequireNumbers": True,
                    "RequireUppercaseCharacters": True,
                    "RequireLowercaseCharacters": True,
                    "MaxPasswordAge": 0,
                }},
            },
        ))

        # Config recorder enabled
        result.events.append(RawEventData(
            source="aws", source_type=SourceType.CLOUD, provider="aws",
            event_type="config_recorders",
            raw_data={
                "service": "config", "method": "describe_configuration_recorders",
                "region": "us-east-1", "account_id": "912345678012",
                "response": {"ConfigurationRecorders": [{
                    "name": "default",
                    "recordingGroup": {"allSupported": True},
                }]},
            },
        ))

        # S3 buckets: one public, one encrypted
        result.events.append(RawEventData(
            source="aws", source_type=SourceType.CLOUD, provider="aws",
            event_type="s3_buckets",
            raw_data={
                "service": "s3", "method": "list_buckets",
                "region": "us-east-1", "account_id": "912345678012",
                "response": {"Buckets": [
                    {"Name": "acme-public-assets", "CreationDate": "2023-01-15"},
                    {"Name": "acme-prod-data", "CreationDate": "2022-06-01"},
                    {"Name": "acme-logs", "CreationDate": "2022-06-01"},
                ]},
            },
        ))

        # RDS instances: encrypted production database
        result.events.append(RawEventData(
            source="aws", source_type=SourceType.CLOUD, provider="aws",
            event_type="rds_instances",
            raw_data={
                "service": "rds", "method": "describe_db_instances",
                "region": "us-east-1", "account_id": "912345678012",
                "response": {"DBInstances": [{
                    "DBInstanceIdentifier": "prod-customers",
                    "DBInstanceArn": "arn:aws:rds:us-east-1:912345678012:db/prod-customers",
                    "Engine": "postgres",
                    "EngineVersion": "15.4",
                    "DBInstanceClass": "db.r6g.xlarge",
                    "StorageEncrypted": True,
                    "BackupRetentionPeriod": 30,
                    "MultiAZ": True,
                    "PubliclyAccessible": False,
                    "DBInstanceStatus": "available",
                }]},
            },
        ))

        # Redshift clusters: encrypted but no automated snapshots
        result.events.append(RawEventData(
            source="aws", source_type=SourceType.CLOUD, provider="aws",
            event_type="redshift_clusters",
            raw_data={
                "service": "redshift", "method": "describe_clusters",
                "region": "us-east-1", "account_id": "912345678012",
                "response": {"Clusters": [{
                    "ClusterIdentifier": "analytics-warehouse",
                    "ClusterNamespaceArn": "arn:aws:redshift:us-east-1:912345678012:namespace/analytics-warehouse",
                    "NodeType": "ra3.xlplus",
                    "NumberOfNodes": 2,
                    "Encrypted": True,
                    "AutomatedSnapshotRetentionPeriod": 0,
                    "ClusterStatus": "available",
                    "PubliclyAccessible": False,
                }]},
            },
        ))

        result.complete()
        return result


class DemoOktaConnector(BaseConnector):
    """Simulates Okta IAM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="okta",
            source_type=SourceType.IAM,
            provider="okta",
        )

        # Users: mix of active, suspended, stale
        result.events.append(RawEventData(
            source="okta", source_type=SourceType.IAM, provider="okta",
            event_type="okta_users",
            raw_data={
                "domain": "acme.okta.com",
                "response": [
                    {
                        "id": "00u1a2b3c4d5e6f7g",
                        "status": "ACTIVE",
                        "profile": {"login": "alice.chen@acme.com", "firstName": "Alice", "lastName": "Chen"},
                        "lastLogin": (NOW - timedelta(hours=2)).isoformat(),
                    },
                    {
                        "id": "00u2b3c4d5e6f7g8h",
                        "status": "ACTIVE",
                        "profile": {"login": "bob.martinez@acme.com", "firstName": "Bob", "lastName": "Martinez"},
                        "lastLogin": (NOW - timedelta(days=1)).isoformat(),
                    },
                    {
                        "id": "00u3c4d5e6f7g8h9i",
                        "status": "ACTIVE",
                        "profile": {"login": "carol.park@acme.com", "firstName": "Carol", "lastName": "Park"},
                        "lastLogin": (NOW - timedelta(days=120)).isoformat(),  # stale
                    },
                    {
                        "id": "00u4d5e6f7g8h9i0j",
                        "status": "SUSPENDED",
                        "profile": {"login": "dave.thompson@acme.com", "firstName": "Dave", "lastName": "Thompson"},
                        "lastLogin": (NOW - timedelta(days=45)).isoformat(),
                    },
                    {
                        "id": "00u5e6f7g8h9i0j1k",
                        "status": "ACTIVE",
                        "profile": {"login": "eve.nakamura@acme.com", "firstName": "Eve", "lastName": "Nakamura"},
                        "lastLogin": None,  # never logged in
                    },
                ],
            },
        ))

        # System log: failed logins, MFA failure, privilege grant
        result.events.append(RawEventData(
            source="okta", source_type=SourceType.IAM, provider="okta",
            event_type="okta_system_log",
            raw_data={
                "domain": "acme.okta.com",
                "response": [
                    {
                        "eventType": "user.session.start",
                        "outcome": {"result": "FAILURE"},
                        "actor": {"displayName": "unknown-user@external.com", "id": "ext001"},
                    },
                    {
                        "eventType": "user.session.start",
                        "outcome": {"result": "FAILURE"},
                        "actor": {"displayName": "unknown-user@external.com", "id": "ext001"},
                    },
                    {
                        "eventType": "user.authentication.auth_via_mfa",
                        "outcome": {"result": "FAILURE"},
                        "actor": {"displayName": "alice.chen@acme.com", "id": "00u1a2b3c4d5e6f7g"},
                    },
                    {
                        "eventType": "user.account.privilege.grant",
                        "outcome": {"result": "SUCCESS"},
                        "actor": {"displayName": "bob.martinez@acme.com", "id": "00u2b3c4d5e6f7g8h"},
                        "target": [{"displayName": "Super Admin", "id": "grp-admin-01"}],
                    },
                ],
            },
        ))

        # Policies: weak password policy
        result.events.append(RawEventData(
            source="okta", source_type=SourceType.IAM, provider="okta",
            event_type="okta_policies",
            raw_data={
                "domain": "acme.okta.com",
                "response": [
                    {
                        "id": "pol-001",
                        "type": "PASSWORD",
                        "name": "Default Password Policy",
                        "settings": {
                            "password": {
                                "complexity": {
                                    "minLength": 8,
                                    "minUpperCase": 1,
                                    "minNumber": 1,
                                    "minSymbol": 0,
                                },
                                "age": {"maxAgeDays": 0},
                            },
                        },
                    },
                ],
            },
        ))

        # MFA factors: one user missing MFA
        result.events.append(RawEventData(
            source="okta", source_type=SourceType.IAM, provider="okta",
            event_type="okta_factors",
            raw_data={
                "domain": "acme.okta.com",
                "response": [
                    {
                        "user_id": "00u1a2b3c4d5e6f7g",
                        "factors": [
                            {"factorType": "push", "provider": "OKTA", "status": "ACTIVE"},
                        ],
                    },
                    {
                        "user_id": "00u5e6f7g8h9i0j1k",
                        "factors": [],  # no MFA enrolled
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoCrowdStrikeConnector(BaseConnector):
    """Simulates CrowdStrike Falcon EDR collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="crowdstrike",
            source_type=SourceType.EDR,
            provider="crowdstrike",
        )

        # Detections: malware + suspicious activity
        result.events.append(RawEventData(
            source="crowdstrike", source_type=SourceType.EDR, provider="crowdstrike",
            event_type="falcon_detection_details",
            raw_data={
                "detections": [
                    {
                        "detection_id": "ldt:abc123:1001",
                        "status": "new",
                        "max_severity": 5,
                        "behaviors": [{
                            "tactic": "Execution",
                            "technique": "PowerShell",
                            "description": "Suspicious PowerShell execution with encoded command",
                        }],
                        "device": {
                            "device_id": "dev-001",
                            "hostname": "ws-finance-01",
                            "platform_name": "Windows",
                        },
                    },
                    {
                        "detection_id": "ldt:abc123:1002",
                        "status": "new",
                        "max_severity": 4,
                        "behaviors": [{
                            "tactic": "Credential Access",
                            "technique": "LSASS Memory",
                            "description": "Credential dumping via LSASS memory access",
                        }],
                        "device": {
                            "device_id": "dev-002",
                            "hostname": "srv-dc-01",
                            "platform_name": "Windows",
                        },
                    },
                    {
                        "detection_id": "ldt:abc123:1003",
                        "status": "in_progress",
                        "max_severity": 3,
                        "behaviors": [{
                            "tactic": "Defense Evasion",
                            "technique": "Masquerading",
                            "description": "Process masquerading as legitimate system binary",
                        }],
                        "device": {
                            "device_id": "dev-003",
                            "hostname": "ws-dev-05",
                            "platform_name": "macOS",
                        },
                    },
                ],
            },
        ))

        # Spotlight vulnerabilities
        result.events.append(RawEventData(
            source="crowdstrike", source_type=SourceType.EDR, provider="crowdstrike",
            event_type="falcon_vulnerabilities",
            raw_data={
                "vulnerabilities": [
                    {
                        "id": "vuln-001",
                        "cve": {"id": "CVE-2024-3094", "base_score_severity": "Critical"},
                        "status": "open",
                        "host_info": {"hostname": "srv-web-01", "device_id": "dev-004"},
                        "app": {"product_name_version": "xz-utils 5.6.0"},
                    },
                    {
                        "id": "vuln-002",
                        "cve": {"id": "CVE-2024-21762", "base_score_severity": "Critical"},
                        "status": "open",
                        "host_info": {"hostname": "fw-edge-01", "device_id": "dev-005"},
                        "app": {"product_name_version": "FortiOS 7.2.3"},
                    },
                    {
                        "id": "vuln-003",
                        "cve": {"id": "CVE-2023-44487", "base_score_severity": "High"},
                        "status": "open",
                        "host_info": {"hostname": "srv-api-02", "device_id": "dev-006"},
                        "app": {"product_name_version": "nginx 1.24.0"},
                    },
                    {
                        "id": "vuln-004",
                        "cve": {"id": "CVE-2024-1234", "base_score_severity": "Medium"},
                        "status": "patched",
                        "host_info": {"hostname": "ws-dev-05", "device_id": "dev-003"},
                        "app": {"product_name_version": "openssl 3.1.2"},
                    },
                ],
            },
        ))

        # Device compliance
        result.events.append(RawEventData(
            source="crowdstrike", source_type=SourceType.EDR, provider="crowdstrike",
            event_type="falcon_device_details",
            raw_data={
                "devices": [
                    {
                        "device_id": "dev-001",
                        "hostname": "ws-finance-01",
                        "platform_name": "Windows",
                        "os_version": "Windows 11 23H2",
                        "agent_version": "7.10.16303",
                        "status": "normal",
                        "reduced_functionality_mode": "no",
                        "device_policies": {"prevention": {"applied": True}},
                    },
                    {
                        "device_id": "dev-002",
                        "hostname": "srv-dc-01",
                        "platform_name": "Windows",
                        "os_version": "Windows Server 2022",
                        "agent_version": "7.10.16303",
                        "status": "normal",
                        "reduced_functionality_mode": "no",
                        "device_policies": {"prevention": {"applied": True}},
                    },
                    {
                        "device_id": "dev-007",
                        "hostname": "ws-marketing-03",
                        "platform_name": "macOS",
                        "os_version": "14.3",
                        "agent_version": "7.08.15201",
                        "status": "contained",
                        "reduced_functionality_mode": "yes",
                        "device_policies": {"prevention": {"applied": False}},
                    },
                ],
            },
        ))

        # Zero Trust assessments
        result.events.append(RawEventData(
            source="crowdstrike", source_type=SourceType.EDR, provider="crowdstrike",
            event_type="falcon_zero_trust",
            raw_data={
                "assessments": [
                    {"aid": "dev-001", "overall": 85},
                    {"aid": "dev-002", "overall": 92},
                    {"aid": "dev-007", "overall": 35},
                ],
            },
        ))

        result.complete()
        return result


class DemoWorkdayConnector(BaseConnector):
    """Simulates Workday HRIS collection with employee data."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="workday",
            source_type=SourceType.HRIS,
            provider="workday",
        )

        # 8 employees matching the Acme Corp story
        result.events.append(RawEventData(
            source="workday", source_type=SourceType.HRIS, provider="workday",
            event_type="workday_employees",
            raw_data={
                "tenant": "acme-prod",
                "response": [
                    {"id": "WD-001", "descriptor": "Alice Chen", "status": "Active",
                     "hireDate": "2022-03-15", "department": "Engineering", "manager": "frank.torres@acme.com"},
                    {"id": "WD-002", "descriptor": "Bob Martinez", "status": "Active",
                     "hireDate": "2021-08-01", "department": "DevOps", "manager": "frank.torres@acme.com"},
                    {"id": "WD-003", "descriptor": "Carol Park", "status": "Active",
                     "hireDate": "2020-01-10", "department": "Finance", "manager": "hassan.ali@acme.com"},
                    {"id": "WD-004", "descriptor": "Dave Thompson", "status": "Terminated",
                     "hireDate": "2023-06-01", "department": "Sales", "manager": "hassan.ali@acme.com",
                     "terminationDate": (NOW - timedelta(days=30)).isoformat()},
                    {"id": "WD-005", "descriptor": "Eve Nakamura", "status": "Active",
                     "hireDate": (NOW - timedelta(days=14)).strftime("%Y-%m-%d"),
                     "department": "Security", "manager": "grace.kim@acme.com"},
                    {"id": "WD-006", "descriptor": "Frank Torres", "status": "Active",
                     "hireDate": "2019-11-20", "department": "Engineering", "manager": "hassan.ali@acme.com"},
                    {"id": "WD-007", "descriptor": "Grace Kim", "status": "Active",
                     "hireDate": (NOW - timedelta(days=7)).strftime("%Y-%m-%d"),
                     "department": "Legal", "manager": "hassan.ali@acme.com"},
                    {"id": "WD-008", "descriptor": "Hassan Ali", "status": "Active",
                     "hireDate": "2021-04-15", "department": "Product", "manager": ""},
                ],
            },
        ))

        # Background checks: Eve in_progress, Grace pending, rest completed
        result.events.append(RawEventData(
            source="workday", source_type=SourceType.HRIS, provider="workday",
            event_type="workday_background_checks",
            raw_data={
                "tenant": "acme-prod",
                "response": [
                    {"worker_id": "WD-001", "worker_name": "Alice Chen",
                     "background_check": {"status": "completed", "completed_date": "2022-03-10"}},
                    {"worker_id": "WD-002", "worker_name": "Bob Martinez",
                     "background_check": {"status": "completed", "completed_date": "2021-07-25"}},
                    {"worker_id": "WD-003", "worker_name": "Carol Park",
                     "background_check": {"status": "completed", "completed_date": "2019-12-20"}},
                    {"worker_id": "WD-004", "worker_name": "Dave Thompson",
                     "background_check": {"status": "completed", "completed_date": "2023-05-20"}},
                    {"worker_id": "WD-005", "worker_name": "Eve Nakamura",
                     "background_check": {"status": "in_progress", "submitted_date": (NOW - timedelta(days=10)).strftime("%Y-%m-%d")}},
                    {"worker_id": "WD-006", "worker_name": "Frank Torres",
                     "background_check": {"status": "completed", "completed_date": "2019-11-01"}},
                    {"worker_id": "WD-007", "worker_name": "Grace Kim",
                     "background_check": {"status": "pending", "submitted_date": (NOW - timedelta(days=3)).strftime("%Y-%m-%d")}},
                    {"worker_id": "WD-008", "worker_name": "Hassan Ali",
                     "background_check": {"status": "completed", "completed_date": "2021-04-01"}},
                ],
            },
        ))

        # Agreements: Eve missing NDA, Grace missing both, rest signed
        result.events.append(RawEventData(
            source="workday", source_type=SourceType.HRIS, provider="workday",
            event_type="workday_agreements",
            raw_data={
                "tenant": "acme-prod",
                "response": [
                    {"worker_id": "WD-001", "worker_name": "Alice Chen",
                     "employment_agreement_signed": True, "nda_signed": True},
                    {"worker_id": "WD-002", "worker_name": "Bob Martinez",
                     "employment_agreement_signed": True, "nda_signed": True},
                    {"worker_id": "WD-003", "worker_name": "Carol Park",
                     "employment_agreement_signed": True, "nda_signed": True},
                    {"worker_id": "WD-004", "worker_name": "Dave Thompson",
                     "employment_agreement_signed": True, "nda_signed": True},
                    {"worker_id": "WD-005", "worker_name": "Eve Nakamura",
                     "employment_agreement_signed": True, "nda_signed": False},
                    {"worker_id": "WD-006", "worker_name": "Frank Torres",
                     "employment_agreement_signed": True, "nda_signed": True},
                    {"worker_id": "WD-007", "worker_name": "Grace Kim",
                     "employment_agreement_signed": False, "nda_signed": False},
                    {"worker_id": "WD-008", "worker_name": "Hassan Ali",
                     "employment_agreement_signed": True, "nda_signed": True},
                ],
            },
        ))

        result.complete()
        return result


class DemoKnowBe4Connector(BaseConnector):
    """Simulates KnowBe4 security awareness training collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="knowbe4",
            source_type=SourceType.TRAINING,
            provider="knowbe4",
        )

        # Training enrollments: Alice overdue 30d, Carol overdue 60d, Grace overdue 15d,
        # Eve in_progress, Bob/Dave/Frank/Hassan completed
        result.events.append(RawEventData(
            source="knowbe4", source_type=SourceType.TRAINING, provider="knowbe4",
            event_type="kb4_training_enrollments",
            raw_data={
                "region": "US",
                "response": [
                    {"enrollment_id": "enr-001", "user_name": "Alice Chen",
                     "user": {"name": "Alice Chen"},
                     "module_name": "Security Awareness 2025", "status": "not_started",
                     "due_date": (NOW - timedelta(days=30)).isoformat()},
                    {"enrollment_id": "enr-002", "user_name": "Bob Martinez",
                     "user": {"name": "Bob Martinez"},
                     "module_name": "Security Awareness 2025", "status": "completed",
                     "due_date": (NOW + timedelta(days=30)).isoformat(),
                     "completion_date": (NOW - timedelta(days=10)).isoformat()},
                    {"enrollment_id": "enr-003", "user_name": "Carol Park",
                     "user": {"name": "Carol Park"},
                     "module_name": "Security Awareness 2025", "status": "not_started",
                     "due_date": (NOW - timedelta(days=60)).isoformat()},
                    {"enrollment_id": "enr-004", "user_name": "Dave Thompson",
                     "user": {"name": "Dave Thompson"},
                     "module_name": "Security Awareness 2025", "status": "completed",
                     "due_date": (NOW - timedelta(days=90)).isoformat(),
                     "completion_date": (NOW - timedelta(days=100)).isoformat()},
                    {"enrollment_id": "enr-005", "user_name": "Eve Nakamura",
                     "user": {"name": "Eve Nakamura"},
                     "module_name": "New Hire Security Onboarding", "status": "in_progress",
                     "due_date": (NOW + timedelta(days=14)).isoformat()},
                    {"enrollment_id": "enr-006", "user_name": "Frank Torres",
                     "user": {"name": "Frank Torres"},
                     "module_name": "Security Awareness 2025", "status": "completed",
                     "due_date": (NOW + timedelta(days=30)).isoformat(),
                     "completion_date": (NOW - timedelta(days=20)).isoformat()},
                    {"enrollment_id": "enr-007", "user_name": "Grace Kim",
                     "user": {"name": "Grace Kim"},
                     "module_name": "New Hire Onboarding", "status": "not_started",
                     "due_date": (NOW - timedelta(days=15)).isoformat()},
                    {"enrollment_id": "enr-008", "user_name": "Hassan Ali",
                     "user": {"name": "Hassan Ali"},
                     "module_name": "Security Awareness 2025", "status": "completed",
                     "due_date": (NOW + timedelta(days=30)).isoformat(),
                     "completion_date": (NOW - timedelta(days=15)).isoformat()},
                ],
            },
        ))

        # Phishing results: 1 test, 6 recipients, Carol and Grace clicked
        result.events.append(RawEventData(
            source="knowbe4", source_type=SourceType.TRAINING, provider="knowbe4",
            event_type="kb4_phishing_results",
            raw_data={
                "region": "US",
                "response": [{
                    "pst_id": "pst-001",
                    "name": "Q1 2025 Phishing Test",
                    "recipients": [
                        {"recipient_id": "rec-001", "email": "alice.chen@acme.com",
                         "user": {"name": "Alice Chen"}, "clicked_link": False, "opened_email": True, "reported": True},
                        {"recipient_id": "rec-002", "email": "bob.martinez@acme.com",
                         "user": {"name": "Bob Martinez"}, "clicked_link": False, "opened_email": True, "reported": True},
                        {"recipient_id": "rec-003", "email": "carol.park@acme.com",
                         "user": {"name": "Carol Park"}, "clicked_link": True, "opened_email": True, "reported": False},
                        {"recipient_id": "rec-004", "email": "dave.thompson@acme.com",
                         "user": {"name": "Dave Thompson"}, "clicked_link": False, "opened_email": True, "reported": False},
                        {"recipient_id": "rec-005", "email": "grace.kim@acme.com",
                         "user": {"name": "Grace Kim"}, "clicked_link": True, "opened_email": True, "reported": False},
                        {"recipient_id": "rec-006", "email": "hassan.ali@acme.com",
                         "user": {"name": "Hassan Ali"}, "clicked_link": False, "opened_email": False, "reported": True},
                    ],
                }],
            },
        ))

        # Training campaigns: 2 campaigns with completion rates
        result.events.append(RawEventData(
            source="knowbe4", source_type=SourceType.TRAINING, provider="knowbe4",
            event_type="kb4_training_campaigns",
            raw_data={
                "region": "US",
                "response": [
                    {"campaign_id": "camp-001", "name": "Security Awareness 2025",
                     "status": "in_progress", "completion_percentage": 50,
                     "start_date": (NOW - timedelta(days=60)).isoformat(),
                     "end_date": (NOW + timedelta(days=30)).isoformat()},
                    {"campaign_id": "camp-002", "name": "New Hire Onboarding",
                     "status": "in_progress", "completion_percentage": 0,
                     "start_date": (NOW - timedelta(days=14)).isoformat(),
                     "end_date": (NOW + timedelta(days=14)).isoformat()},
                ],
            },
        ))

        result.complete()
        return result


class DemoSecurityScorecardConnector(BaseConnector):
    """Simulates SecurityScorecard vendor risk collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="securityscorecard",
            source_type=SourceType.GRC,
            provider="securityscorecard",
        )

        # 5 vendors with varying scores
        result.events.append(RawEventData(
            source="securityscorecard", source_type=SourceType.GRC, provider="securityscorecard",
            event_type="ssc_companies",
            raw_data={
                "response": [
                    {"domain": "stripe.com", "name": "Stripe", "score": 92,
                     "grade": "A", "industry": "Financial Services", "size": "large",
                     "last_score_change": (NOW - timedelta(days=7)).isoformat()},
                    {"domain": "datadoghq.com", "name": "Datadog", "score": 88,
                     "grade": "A", "industry": "Technology", "size": "large",
                     "last_score_change": (NOW - timedelta(days=14)).isoformat()},
                    {"domain": "acmestaffing.example.com", "name": "Acme Staffing Co", "score": 58,
                     "grade": "D", "industry": "Staffing", "size": "small",
                     "last_score_change": (NOW - timedelta(days=3)).isoformat()},
                    {"domain": "cloudbackuppro.example.com", "name": "CloudBackup Pro", "score": 45,
                     "grade": "F", "industry": "Technology", "size": "small",
                     "last_score_change": (NOW - timedelta(days=1)).isoformat()},
                    {"domain": "quickdocs.example.com", "name": "QuickDocs", "score": 72,
                     "grade": "C", "industry": "SaaS", "size": "medium",
                     "last_score_change": (NOW - timedelta(days=10)).isoformat()},
                ],
            },
        ))

        # Risk factors per vendor (4 each)
        result.events.append(RawEventData(
            source="securityscorecard", source_type=SourceType.GRC, provider="securityscorecard",
            event_type="ssc_factors",
            raw_data={
                "response": [
                    {"domain": "stripe.com", "factors": [
                        {"name": "Network Security", "grade": "A", "score": 95, "issue_count": 0},
                        {"name": "Patching Cadence", "grade": "A", "score": 90, "issue_count": 0},
                        {"name": "Endpoint Security", "grade": "A", "score": 92, "issue_count": 0},
                        {"name": "DNS Health", "grade": "A", "score": 94, "issue_count": 0},
                    ]},
                    {"domain": "datadoghq.com", "factors": [
                        {"name": "Network Security", "grade": "A", "score": 90, "issue_count": 0},
                        {"name": "Patching Cadence", "grade": "B", "score": 82, "issue_count": 1},
                        {"name": "Endpoint Security", "grade": "A", "score": 91, "issue_count": 0},
                        {"name": "DNS Health", "grade": "A", "score": 88, "issue_count": 0},
                    ]},
                    {"domain": "acmestaffing.example.com", "factors": [
                        {"name": "Network Security", "grade": "D", "score": 55, "issue_count": 3},
                        {"name": "Patching Cadence", "grade": "D", "score": 50, "issue_count": 4},
                        {"name": "Endpoint Security", "grade": "C", "score": 65, "issue_count": 2},
                        {"name": "DNS Health", "grade": "D", "score": 58, "issue_count": 2},
                    ]},
                    {"domain": "cloudbackuppro.example.com", "factors": [
                        {"name": "Network Security", "grade": "F", "score": 35, "issue_count": 5},
                        {"name": "Patching Cadence", "grade": "F", "score": 40, "issue_count": 6},
                        {"name": "Endpoint Security", "grade": "D", "score": 52, "issue_count": 3},
                        {"name": "DNS Health", "grade": "F", "score": 38, "issue_count": 4},
                    ]},
                    {"domain": "quickdocs.example.com", "factors": [
                        {"name": "Network Security", "grade": "C", "score": 70, "issue_count": 2},
                        {"name": "Patching Cadence", "grade": "B", "score": 78, "issue_count": 1},
                        {"name": "Endpoint Security", "grade": "C", "score": 72, "issue_count": 1},
                        {"name": "DNS Health", "grade": "C", "score": 68, "issue_count": 2},
                    ]},
                ],
            },
        ))

        # Issues for the bad vendors
        result.events.append(RawEventData(
            source="securityscorecard", source_type=SourceType.GRC, provider="securityscorecard",
            event_type="ssc_issues",
            raw_data={
                "response": [
                    {"_domain": "acmestaffing.example.com", "type": "tlscert_expired",
                     "severity": "high", "count": 2,
                     "first_seen_time": (NOW - timedelta(days=45)).isoformat(),
                     "last_seen_time": NOW.isoformat()},
                    {"_domain": "acmestaffing.example.com", "type": "open_port_25",
                     "severity": "medium", "count": 1,
                     "first_seen_time": (NOW - timedelta(days=90)).isoformat(),
                     "last_seen_time": NOW.isoformat()},
                    {"_domain": "cloudbackuppro.example.com", "type": "tlscert_no_revocation",
                     "severity": "critical", "count": 3,
                     "first_seen_time": (NOW - timedelta(days=60)).isoformat(),
                     "last_seen_time": NOW.isoformat()},
                    {"_domain": "cloudbackuppro.example.com", "type": "cve_detected",
                     "severity": "critical", "count": 5,
                     "first_seen_time": (NOW - timedelta(days=30)).isoformat(),
                     "last_seen_time": NOW.isoformat()},
                    {"_domain": "cloudbackuppro.example.com", "type": "spf_record_missing",
                     "severity": "high", "count": 1,
                     "first_seen_time": (NOW - timedelta(days=120)).isoformat(),
                     "last_seen_time": NOW.isoformat()},
                    {"_domain": "quickdocs.example.com", "type": "hsts_missing",
                     "severity": "medium", "count": 1,
                     "first_seen_time": (NOW - timedelta(days=15)).isoformat(),
                     "last_seen_time": NOW.isoformat()},
                ],
            },
        ))

        result.complete()
        return result


class DemoConfluenceConnector(BaseConnector):
    """Simulates Confluence policy document collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="confluence",
            source_type=SourceType.GRC,
            provider="confluence",
        )

        # 7 policy documents in the SEC space
        result.events.append(RawEventData(
            source="confluence", source_type=SourceType.GRC, provider="confluence",
            event_type="confluence_pages",
            raw_data={
                "space_key": "SEC",
                "pages": [
                    {"id": "page-101", "title": "Access Control Policy", "status": "current",
                     "authorId": "usr-ciso-01",
                     "version": {"createdAt": (NOW - timedelta(days=45)).isoformat()}},
                    {"id": "page-102", "title": "Incident Response Plan", "status": "current",
                     "authorId": "usr-ciso-01",
                     "version": {"createdAt": (NOW - timedelta(days=30)).isoformat()}},
                    {"id": "page-103", "title": "Change Management Policy", "status": "current",
                     "authorId": "usr-itsec-02",
                     "version": {"createdAt": (NOW - timedelta(days=90)).isoformat()}},
                    {"id": "page-104", "title": "Data Classification Standard", "status": "current",
                     "authorId": "usr-itsec-02",
                     "version": {"createdAt": (NOW - timedelta(days=120)).isoformat()}},
                    {"id": "page-105", "title": "Business Continuity Plan", "status": "current",
                     "authorId": "usr-ciso-01",
                     "version": {"createdAt": (NOW - timedelta(days=200)).isoformat()}},
                    {"id": "page-106", "title": "Encryption and Key Management Policy", "status": "current",
                     "authorId": "usr-itsec-02",
                     "version": {"createdAt": (NOW - timedelta(days=60)).isoformat()}},
                    {"id": "page-107", "title": "Acceptable Use Policy", "status": "current",
                     "authorId": "usr-hr-01",
                     "version": {"createdAt": (NOW - timedelta(days=150)).isoformat()}},
                ],
            },
        ))

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Post-pipeline seed functions
# ---------------------------------------------------------------------------


def seed_systems(session):
    """Create 5 SystemProfile records representing Acme Corp's systems."""
    systems = [
        SystemProfile(
            name="Acme Production Platform", acronym="APP",
            description="Primary SaaS platform serving customer workloads. Hosts APIs, web app, and background workers on AWS.",
            confidentiality_impact="high", integrity_impact="high",
            availability_impact="high", overall_impact="high",
            frameworks=["nist_800_53", "soc2", "iso_27001"],
            connector_scope=["aws", "crowdstrike", "okta"],
            cloud_accounts=[{"provider": "aws", "account_id": "912345678012", "regions": ["us-east-1", "us-west-2"]}],
            network_boundaries=[{"cidr": "10.0.0.0/16", "description": "Production VPC"}],
            system_owner="Frank Torres", system_owner_email="frank.torres@acme.com",
            isso="Eve Nakamura", isso_email="eve.nakamura@acme.com",
            authorizing_official="Hassan Ali", ao_email="hassan.ali@acme.com",
            authorization_status="authorized",
            authorization_date=NOW - timedelta(days=180),
            authorization_expiry=NOW + timedelta(days=185),
            deployment_model="cloud", service_model="IaaS",
        ),
        SystemProfile(
            name="Customer Data Warehouse", acronym="CDW",
            description="Analytics and reporting platform. Ingests customer telemetry into Redshift for BI dashboards.",
            confidentiality_impact="high", integrity_impact="high",
            availability_impact="moderate", overall_impact="high",
            frameworks=["nist_800_53", "soc2", "iso_27701"],
            connector_scope=["aws"],
            cloud_accounts=[{"provider": "aws", "account_id": "912345678012", "regions": ["us-east-1"]}],
            system_owner="Carol Park", system_owner_email="carol.park@acme.com",
            authorization_status="in_process",
            deployment_model="cloud", service_model="IaaS",
        ),
        SystemProfile(
            name="Corporate IT", acronym="CIT",
            description="Internal IT services: identity, email, endpoint management, and collaboration tools.",
            confidentiality_impact="moderate", integrity_impact="moderate",
            availability_impact="moderate", overall_impact="moderate",
            frameworks=["iso_27001", "soc2"],
            connector_scope=["okta", "crowdstrike"],
            system_owner="Bob Martinez", system_owner_email="bob.martinez@acme.com",
            authorization_status="authorized",
            authorization_date=NOW - timedelta(days=365),
            authorization_expiry=NOW + timedelta(days=1),
            deployment_model="hybrid", service_model="SaaS",
        ),
        SystemProfile(
            name="AI/ML Analytics Platform", acronym="AIML",
            description="Machine learning model training and inference. Processes anonymized customer data for product insights.",
            confidentiality_impact="moderate", integrity_impact="moderate",
            availability_impact="low", overall_impact="moderate",
            frameworks=["iso_42001", "nist_800_53"],
            connector_scope=["aws"],
            system_owner="Alice Chen", system_owner_email="alice.chen@acme.com",
            authorization_status="not_authorized",
            deployment_model="cloud", service_model="PaaS",
        ),
        SystemProfile(
            name="Development and Staging", acronym="DEV",
            description="Non-production environments for development, testing, and staging. No real customer data.",
            confidentiality_impact="low", integrity_impact="low",
            availability_impact="low", overall_impact="low",
            frameworks=["soc2"],
            connector_scope=["aws", "crowdstrike"],
            system_owner="Frank Torres", system_owner_email="frank.torres@acme.com",
            authorization_status="authorized",
            authorization_date=NOW - timedelta(days=90),
            authorization_expiry=NOW + timedelta(days=275),
            deployment_model="cloud", service_model="IaaS",
        ),
    ]
    for system in systems:
        session.add(system)
    session.commit()
    return len(systems)


def seed_personnel(session):
    """Sync personnel records from pipeline findings (HR, IdP, training)."""
    from warlock.workflows.personnel import PersonnelManager

    manager = PersonnelManager()
    hr = manager.sync_from_hr(session)
    idp = manager.sync_from_idp(session)
    training = manager.sync_from_training(session)
    return {"hr": hr, "idp": idp, "training": training, "total": session.query(Personnel).count()}


def seed_questionnaires(session):
    """Create questionnaire templates and vendor questionnaire instances."""
    from warlock.workflows.questionnaires import QuestionnaireManager

    manager = QuestionnaireManager()
    templates = manager.seed_default_templates(session)
    sig_template = next((t for t in templates if "sig" in t.name.lower()), None)
    ddq_template = next((t for t in templates if "ddq" in t.name.lower() or "due diligence" in t.name.lower()), None)
    created = []
    if sig_template:
        q = manager.create_questionnaire(
            session, template_id=sig_template.id, vendor_name="Stripe",
            vendor_email="security@stripe.com", due_days=30, created_by="eve.nakamura@acme.com",
        )
        responses = {}
        for question in sig_template.questions[:18]:
            qid = question["id"]
            if question.get("response_type") == "yes_no":
                responses[qid] = {"answer": "yes", "notes": "Verified via SOC 2 Type II report"}
            elif question.get("response_type") == "rating":
                responses[qid] = {"answer": "4", "notes": "Strong controls in place"}
            else:
                responses[qid] = {"answer": "Implemented and documented", "notes": ""}
        manager.submit_bulk_responses(session, q.id, responses)
        manager.score_responses(session, q.id)
        created.append("Stripe (SIG Lite, completed)")
    if ddq_template:
        q = manager.create_questionnaire(
            session, template_id=ddq_template.id, vendor_name="CloudBackup Pro",
            vendor_email="compliance@cloudbackuppro.example.com", due_days=30,
            created_by="eve.nakamura@acme.com",
        )
        responses = {}
        for question in ddq_template.questions[:4]:
            qid = question["id"]
            if question.get("response_type") == "yes_no":
                responses[qid] = {"answer": "no", "notes": "In progress"}
            else:
                responses[qid] = {"answer": "Under review", "notes": ""}
        manager.submit_bulk_responses(session, q.id, responses)
        created.append("CloudBackup Pro (DDQ, in_progress)")
    return {"templates": len(templates), "questionnaires": created}


def seed_data_silos(session):
    """Discover data silos from findings and add direct silo records."""
    from warlock.workflows.data_silos import DataSiloManager

    manager = DataSiloManager()
    result = manager.discover_from_findings(session)
    direct_silos = [
        DataSilo(name="acme-prod-data", silo_type="s3_bucket", provider="aws",
            location="arn:aws:s3:::acme-prod-data", data_classification="confidential",
            contains_pii=True, encrypted_at_rest=True, encrypted_in_transit=True,
            access_logging_enabled=True, backup_enabled=True, retention_days=365,
            owner="Frank Torres", team="Engineering",
            applicable_frameworks=["soc2", "iso_27001"]),
        DataSilo(name="acme-public-assets", silo_type="s3_bucket", provider="aws",
            location="arn:aws:s3:::acme-public-assets", data_classification="public",
            contains_pii=False, encrypted_at_rest=False, encrypted_in_transit=True,
            access_logging_enabled=False, backup_enabled=False,
            owner="Bob Martinez", team="DevOps", applicable_frameworks=[]),
        DataSilo(name="acme-logs", silo_type="s3_bucket", provider="aws",
            location="arn:aws:s3:::acme-logs", data_classification="internal",
            contains_pii=False, encrypted_at_rest=True, encrypted_in_transit=True,
            access_logging_enabled=True, backup_enabled=True, retention_days=1095,
            owner="Bob Martinez", team="DevOps",
            applicable_frameworks=["nist_800_53"]),
        DataSilo(name="prod-customers", silo_type="rds_database", provider="aws",
            location="arn:aws:rds:us-east-1:912345678012:db/prod-customers",
            data_classification="restricted", contains_pii=True, contains_pci=True,
            encrypted_at_rest=True, encrypted_in_transit=True,
            access_logging_enabled=True, backup_enabled=True, retention_days=30,
            owner="Frank Torres", team="Engineering",
            applicable_frameworks=["pci_dss", "soc2", "iso_27001"]),
        DataSilo(name="analytics-warehouse", silo_type="redshift", provider="aws",
            location="arn:aws:redshift:us-east-1:912345678012:namespace/analytics-warehouse",
            data_classification="confidential", contains_pii=True, contains_phi=True,
            encrypted_at_rest=True, encrypted_in_transit=True,
            access_logging_enabled=False, backup_enabled=False,
            owner="Carol Park", team="Finance",
            applicable_frameworks=["hipaa", "soc2"]),
        DataSilo(name="eng-wiki", silo_type="sharepoint_site", provider="sharepoint",
            location="https://acme.sharepoint.com/sites/engineering",
            data_classification="internal", contains_pii=False,
            encrypted_at_rest=False, encrypted_in_transit=True,
            access_logging_enabled=True, backup_enabled=True,
            owner="Frank Torres", team="Engineering",
            applicable_frameworks=["iso_27001"]),
        DataSilo(name="acme-app", silo_type="github_repo", provider="github",
            location="https://github.com/acme-corp/acme-app",
            data_classification="confidential", contains_credentials=True,
            encrypted_at_rest=True, encrypted_in_transit=True,
            access_logging_enabled=True, backup_enabled=True,
            owner="Frank Torres", team="Engineering",
            applicable_frameworks=["soc2", "iso_27001"],
            scan_findings=[
                {"field_name": ".env.production", "data_type": "credential", "confidence": 0.95},
                {"field_name": "config/secrets.yml", "data_type": "credential", "confidence": 0.88},
            ],
            sensitive_field_count=2, scan_status="completed",
            last_scan_date=NOW - timedelta(days=7)),
    ]
    existing_names = {row[0] for row in session.query(DataSilo.name).all()}
    added = 0
    for silo in direct_silos:
        if silo.name not in existing_names:
            session.add(silo)
            added += 1
    session.commit()
    return {"discovered": result.get("created", 0), "direct": added}


def seed_legal_holds(session):
    """Create legal hold records."""
    holds = [
        LegalHold(
            reason="FTC investigation — preserve all authentication and access logs",
            start_date=NOW - timedelta(days=60), end_date=None,
            created_by="grace.kim@acme.com", is_active=True,
        ),
        LegalHold(
            reason="Q3 2025 SOC 2 audit evidence preservation",
            start_date=NOW - timedelta(days=120), end_date=NOW - timedelta(days=30),
            created_by="eve.nakamura@acme.com", is_active=False,
        ),
    ]
    for hold in holds:
        session.add(hold)
    session.commit()
    return len(holds)


def seed_issues(session):
    """Auto-create issues from non-compliant results + add manual issues."""
    from warlock.workflows.issues import IssueManager

    manager = IssueManager()
    auto = manager.auto_create_from_results(session)
    manual_issues = [
        Issue(
            title="Vendor risk acceptance needed: CloudBackup Pro",
            description="CloudBackup Pro scored 45/100 on SecurityScorecard. Evaluate alternatives or accept risk with compensating controls.",
            framework="soc2", control_id="CC9.1", status="open", priority="high",
            assigned_to="eve.nakamura@acme.com", due_date=NOW + timedelta(days=14),
            source="manual", tags=["vendor-risk", "third-party"],
            created_by="hassan.ali@acme.com",
        ),
        Issue(
            title="Overdue access review for Product department",
            description="Product department has not completed quarterly access review. Last review was 120+ days ago.",
            framework="iso_27001", control_id="A.5.18", status="assigned", priority="medium",
            assigned_to="hassan.ali@acme.com", assigned_by="eve.nakamura@acme.com",
            assigned_at=NOW - timedelta(days=7), due_date=NOW + timedelta(days=7),
            source="manual", tags=["access-review", "overdue"],
            created_by="eve.nakamura@acme.com",
        ),
        Issue(
            title="Policy gap: No Audit Logging Policy documented",
            description="Policy coverage check shows AU-family controls have no mapped policy document. Need to draft and publish.",
            framework="nist_800_53", control_id="AU-1", status="in_progress", priority="medium",
            assigned_to="grace.kim@acme.com", assigned_by="eve.nakamura@acme.com",
            assigned_at=NOW - timedelta(days=14), due_date=NOW + timedelta(days=21),
            remediation_plan="Draft AU policy in Confluence, route through legal review, publish to SEC space.",
            source="manual", tags=["policy-gap", "documentation"],
            created_by="eve.nakamura@acme.com",
        ),
    ]
    for issue in manual_issues:
        session.add(issue)
    session.commit()
    return {"auto_created": len(auto), "manual": len(manual_issues)}


# ---------------------------------------------------------------------------
# Phase 2-5 seed functions
# ---------------------------------------------------------------------------


def _sha(data: str) -> str:
    """Helper to produce SHA256 hex digest for demo records."""
    return hashlib.sha256(data.encode()).hexdigest()


def seed_phase2_poams(session) -> int:
    """Create 18 POA&Ms across frameworks with realistic lifecycle states."""
    # Get a system profile for linking
    prod = session.query(SystemProfile).filter(SystemProfile.acronym == "APP").first()
    cdw = session.query(SystemProfile).filter(SystemProfile.acronym == "CDW").first()
    cit = session.query(SystemProfile).filter(SystemProfile.acronym == "CIT").first()

    poams = [
        # --- 5 draft (auto-created from pipeline) ---
        POAM(
            framework="nist_800_53", control_id="AC-2",
            weakness_description="Root account has active access keys enabling unauthenticated programmatic access",
            severity="critical", risk_level="very_high", status="draft",
            system_profile_id=prod.id if prod else None,
            created_by="pipeline",
        ),
        POAM(
            framework="nist_800_53", control_id="IA-2",
            weakness_description="MFA not enforced for privileged users across all console and API access",
            severity="high", risk_level="high", status="draft",
            system_profile_id=prod.id if prod else None,
            created_by="pipeline",
        ),
        POAM(
            framework="nist_800_53", control_id="AU-6",
            weakness_description="CloudTrail is single-region only; events in us-west-2, eu-west-1 are not captured",
            severity="high", risk_level="high", status="draft",
            system_profile_id=prod.id if prod else None,
            created_by="pipeline",
        ),
        POAM(
            framework="soc2", control_id="CC6.1",
            weakness_description="Okta password policy allows 8-char minimum with no symbol requirement",
            severity="medium", risk_level="moderate", status="draft",
            system_profile_id=cit.id if cit else None,
            created_by="pipeline",
        ),
        POAM(
            framework="iso_27001", control_id="A.8.9",
            weakness_description="Security group sg-0a1b2c3d4e5f allows SSH (port 22) from 0.0.0.0/0",
            severity="high", risk_level="high", status="draft",
            system_profile_id=prod.id if prod else None,
            created_by="pipeline",
        ),
        # --- 4 open with milestones ---
        POAM(
            framework="nist_800_53", control_id="SI-4",
            weakness_description="GuardDuty findings not forwarded to centralized SIEM for correlation",
            severity="medium", risk_level="moderate", status="open",
            system_profile_id=prod.id if prod else None,
            scheduled_completion=NOW + timedelta(days=45),
            milestones=[
                {"description": "Evaluate SIEM integration options", "due_date": (NOW + timedelta(days=15)).isoformat(), "status": "not_started"},
                {"description": "Deploy GuardDuty-to-SIEM forwarder", "due_date": (NOW + timedelta(days=30)).isoformat(), "status": "not_started"},
                {"description": "Validate alert correlation rules", "due_date": (NOW + timedelta(days=45)).isoformat(), "status": "not_started"},
            ],
            created_by="eve.nakamura@acme.com",
        ),
        POAM(
            framework="nist_800_53", control_id="CM-6",
            weakness_description="AWS Config recorder not deployed in us-west-2 region; configuration drift undetected",
            severity="medium", risk_level="moderate", status="open",
            system_profile_id=prod.id if prod else None,
            scheduled_completion=NOW + timedelta(days=30),
            milestones=[
                {"description": "Enable Config recorder in us-west-2", "due_date": (NOW + timedelta(days=10)).isoformat(), "status": "not_started"},
                {"description": "Deploy conformance pack", "due_date": (NOW + timedelta(days=25)).isoformat(), "status": "not_started"},
            ],
            created_by="bob.martinez@acme.com",
        ),
        POAM(
            framework="nist_800_53", control_id="SC-7",
            weakness_description="Legacy Windows security group allows RDP (3389) from any source IP",
            severity="high", risk_level="high", status="open",
            system_profile_id=prod.id if prod else None,
            scheduled_completion=NOW + timedelta(days=21),
            milestones=[
                {"description": "Identify active RDP sessions", "due_date": (NOW + timedelta(days=7)).isoformat(), "status": "not_started"},
                {"description": "Restrict RDP to VPN CIDR", "due_date": (NOW + timedelta(days=14)).isoformat(), "status": "not_started"},
                {"description": "Decommission legacy-windows SG", "due_date": (NOW + timedelta(days=21)).isoformat(), "status": "not_started"},
            ],
            created_by="eve.nakamura@acme.com",
        ),
        POAM(
            framework="soc2", control_id="CC7.2",
            weakness_description="CrowdStrike prevention policy not applied on 1 contained endpoint (ws-marketing-03)",
            severity="medium", risk_level="moderate", status="open",
            system_profile_id=cit.id if cit else None,
            scheduled_completion=NOW + timedelta(days=14),
            milestones=[
                {"description": "Investigate containment reason", "due_date": (NOW + timedelta(days=5)).isoformat(), "status": "not_started"},
                {"description": "Re-enable prevention policy or decommission", "due_date": (NOW + timedelta(days=14)).isoformat(), "status": "not_started"},
            ],
            created_by="eve.nakamura@acme.com",
        ),
        # --- 3 in_progress with partial milestone completion ---
        POAM(
            framework="nist_800_53", control_id="IA-5",
            weakness_description="Password policy minimum length is 8 characters; NIST 800-63B recommends 12+",
            severity="medium", risk_level="moderate", status="in_progress",
            system_profile_id=cit.id if cit else None,
            scheduled_completion=NOW + timedelta(days=14),
            milestones=[
                {"description": "Draft updated password policy", "due_date": (NOW - timedelta(days=14)).isoformat(), "completed_date": (NOW - timedelta(days=12)).isoformat(), "status": "completed"},
                {"description": "Get CISO approval", "due_date": (NOW - timedelta(days=7)).isoformat(), "completed_date": (NOW - timedelta(days=5)).isoformat(), "status": "completed"},
                {"description": "Deploy to Okta and AWS IAM", "due_date": (NOW + timedelta(days=7)).isoformat(), "status": "in_progress"},
                {"description": "Validate enforcement", "due_date": (NOW + timedelta(days=14)).isoformat(), "status": "not_started"},
            ],
            created_by="bob.martinez@acme.com", updated_by="bob.martinez@acme.com",
        ),
        POAM(
            framework="nist_800_53", control_id="RA-5",
            weakness_description="Critical CVE-2024-3094 (xz-utils) on srv-web-01 not remediated within 48-hour SLA",
            severity="critical", risk_level="very_high", status="in_progress",
            system_profile_id=prod.id if prod else None,
            scheduled_completion=NOW + timedelta(days=3),
            milestones=[
                {"description": "Identify affected hosts", "due_date": (NOW - timedelta(days=5)).isoformat(), "completed_date": (NOW - timedelta(days=5)).isoformat(), "status": "completed"},
                {"description": "Test patch in staging", "due_date": (NOW - timedelta(days=2)).isoformat(), "completed_date": (NOW - timedelta(days=1)).isoformat(), "status": "completed"},
                {"description": "Deploy patch to production", "due_date": (NOW + timedelta(days=1)).isoformat(), "status": "in_progress"},
                {"description": "Verify and close vulnerability", "due_date": (NOW + timedelta(days=3)).isoformat(), "status": "not_started"},
            ],
            created_by="eve.nakamura@acme.com", updated_by="frank.torres@acme.com",
        ),
        POAM(
            framework="iso_27001", control_id="A.5.15",
            weakness_description="Stale Okta accounts (120+ days inactive) not disabled per access lifecycle policy",
            severity="medium", risk_level="moderate", status="in_progress",
            system_profile_id=cit.id if cit else None,
            scheduled_completion=NOW + timedelta(days=10),
            milestones=[
                {"description": "Run access review report", "due_date": (NOW - timedelta(days=7)).isoformat(), "completed_date": (NOW - timedelta(days=6)).isoformat(), "status": "completed"},
                {"description": "Notify managers of stale accounts", "due_date": (NOW - timedelta(days=3)).isoformat(), "status": "in_progress"},
                {"description": "Disable confirmed stale accounts", "due_date": (NOW + timedelta(days=10)).isoformat(), "status": "not_started"},
            ],
            created_by="bob.martinez@acme.com",
        ),
        # --- 2 completed ---
        POAM(
            framework="nist_800_53", control_id="SC-28",
            weakness_description="S3 bucket acme-public-assets did not have server-side encryption enabled",
            severity="medium", risk_level="moderate", status="completed",
            system_profile_id=prod.id if prod else None,
            scheduled_completion=NOW - timedelta(days=30),
            actual_completion=NOW - timedelta(days=35),
            milestones=[
                {"description": "Enable SSE-S3 default encryption", "due_date": (NOW - timedelta(days=40)).isoformat(), "completed_date": (NOW - timedelta(days=38)).isoformat(), "status": "completed"},
                {"description": "Verify existing objects encrypted", "due_date": (NOW - timedelta(days=30)).isoformat(), "completed_date": (NOW - timedelta(days=35)).isoformat(), "status": "completed"},
            ],
            created_by="bob.martinez@acme.com", approved_by="hassan.ali@acme.com",
            approved_at=NOW - timedelta(days=35),
        ),
        POAM(
            framework="soc2", control_id="CC6.6",
            weakness_description="Redshift cluster analytics-warehouse had automated snapshots disabled",
            severity="high", risk_level="high", status="completed",
            system_profile_id=cdw.id if cdw else None,
            scheduled_completion=NOW - timedelta(days=14),
            actual_completion=NOW - timedelta(days=18),
            milestones=[
                {"description": "Enable automated snapshots with 7-day retention", "due_date": (NOW - timedelta(days=20)).isoformat(), "completed_date": (NOW - timedelta(days=19)).isoformat(), "status": "completed"},
                {"description": "Validate backup restore procedure", "due_date": (NOW - timedelta(days=14)).isoformat(), "completed_date": (NOW - timedelta(days=18)).isoformat(), "status": "completed"},
            ],
            created_by="carol.park@acme.com", approved_by="hassan.ali@acme.com",
            approved_at=NOW - timedelta(days=18),
        ),
        # --- 2 overdue (scheduled_completion in past, still open) ---
        POAM(
            framework="nist_800_53", control_id="AC-6",
            weakness_description="Bob Martinez granted Super Admin role in Okta without documented approval workflow",
            severity="high", risk_level="high", status="open",
            system_profile_id=cit.id if cit else None,
            scheduled_completion=NOW - timedelta(days=10),
            milestones=[
                {"description": "Review privilege grant audit trail", "due_date": (NOW - timedelta(days=20)).isoformat(), "status": "not_started"},
                {"description": "Implement approval workflow in Okta", "due_date": (NOW - timedelta(days=10)).isoformat(), "status": "not_started"},
            ],
            created_by="eve.nakamura@acme.com",
        ),
        POAM(
            framework="iso_27001", control_id="A.7.2",
            weakness_description="3 employees have overdue security awareness training (30-60 days past due date)",
            severity="medium", risk_level="moderate", status="open",
            system_profile_id=cit.id if cit else None,
            scheduled_completion=NOW - timedelta(days=7),
            milestones=[
                {"description": "Send escalation notices to managers", "due_date": (NOW - timedelta(days=14)).isoformat(), "status": "not_started"},
                {"description": "Enforce training completion or account suspension", "due_date": (NOW - timedelta(days=7)).isoformat(), "status": "not_started"},
            ],
            created_by="eve.nakamura@acme.com",
        ),
        # --- 2 with delay_count > 0 ---
        POAM(
            framework="nist_800_53", control_id="AU-2",
            weakness_description="CloudTrail log file validation enabled but no S3 bucket integrity monitoring",
            severity="medium", risk_level="moderate", status="in_progress",
            system_profile_id=prod.id if prod else None,
            scheduled_completion=NOW + timedelta(days=30),
            delay_count=2,
            delay_justifications=[
                {"date": (NOW - timedelta(days=60)).isoformat(), "justification": "Engineering resource re-allocated to critical CVE remediation", "approved_by": "hassan.ali@acme.com"},
                {"date": (NOW - timedelta(days=20)).isoformat(), "justification": "Vendor tooling integration delayed; new ETA from vendor confirmed", "approved_by": "hassan.ali@acme.com"},
            ],
            milestones=[
                {"description": "Select S3 integrity monitoring tool", "due_date": (NOW - timedelta(days=45)).isoformat(), "completed_date": (NOW - timedelta(days=40)).isoformat(), "status": "completed"},
                {"description": "Deploy monitoring to prod trail bucket", "due_date": (NOW + timedelta(days=15)).isoformat(), "status": "in_progress"},
                {"description": "Validate alerting pipeline", "due_date": (NOW + timedelta(days=30)).isoformat(), "status": "not_started"},
            ],
            created_by="bob.martinez@acme.com", updated_by="hassan.ali@acme.com",
        ),
        POAM(
            framework="soc2", control_id="CC8.1",
            weakness_description="Change management approval records missing for 3 production deployments in last quarter",
            severity="high", risk_level="high", status="open",
            system_profile_id=prod.id if prod else None,
            scheduled_completion=NOW + timedelta(days=7),
            delay_count=1,
            delay_justifications=[
                {"date": (NOW - timedelta(days=15)).isoformat(), "justification": "ServiceNow integration delayed due to API rate limiting; workaround identified", "approved_by": "hassan.ali@acme.com"},
            ],
            milestones=[
                {"description": "Enforce PR approval requirement in GitHub", "due_date": (NOW - timedelta(days=5)).isoformat(), "status": "not_started"},
                {"description": "Link ServiceNow change requests to deployments", "due_date": (NOW + timedelta(days=7)).isoformat(), "status": "not_started"},
            ],
            created_by="frank.torres@acme.com",
        ),
    ]

    for p in poams:
        session.add(p)
    session.commit()
    return len(poams)


def seed_phase2_compensating_controls(session) -> int:
    """Create 10 compensating controls with realistic lifecycle states."""
    prod = session.query(SystemProfile).filter(SystemProfile.acronym == "APP").first()
    cit = session.query(SystemProfile).filter(SystemProfile.acronym == "CIT").first()

    # Grab some POA&M IDs to link
    poam_ac2 = session.query(POAM).filter(POAM.control_id == "AC-2").first()
    poam_ia2 = session.query(POAM).filter(POAM.control_id == "IA-2").first()
    poam_sc7 = session.query(POAM).filter(POAM.control_id == "SC-7").first()
    poam_ac6 = session.query(POAM).filter(POAM.control_id == "AC-6").first()

    controls = [
        # --- 3 active with effectiveness_score ---
        CompensatingControl(
            original_framework="nist_800_53", original_control_id="AC-2",
            poam_id=poam_ac2.id if poam_ac2 else None,
            system_profile_id=prod.id if prod else None,
            title="Weekly privileged access review by team leads",
            description="All team leads conduct a weekly manual review of privileged accounts in their scope. Findings reported to ISSO via Jira ticket.",
            implementation_details="Team leads receive automated Monday 8am email with current privileged user list. They confirm or flag revocations within 48 hours via Jira SEC project.",
            evidence_references=[{"type": "process", "description": "Jira SEC project tickets", "url": "https://acme.atlassian.net/projects/SEC"}],
            status="active",
            approved_by="hassan.ali@acme.com", approved_at=NOW - timedelta(days=60),
            expiry_date=NOW + timedelta(days=120),
            review_frequency="monthly",
            last_reviewed=NOW - timedelta(days=15),
            effectiveness_score=78.0,
            created_by="eve.nakamura@acme.com",
        ),
        CompensatingControl(
            original_framework="nist_800_53", original_control_id="IA-2",
            poam_id=poam_ia2.id if poam_ia2 else None,
            system_profile_id=prod.id if prod else None,
            title="Hardware security key requirement for privileged accounts",
            description="All AWS IAM users with admin or power-user policies must use YubiKey 5 for MFA. Software MFA tokens disabled for privileged roles.",
            implementation_details="AWS IAM policy condition requires hardware MFA (aws:MultiFactorAuthPresent with FIDO2). Okta enrollment forced for hardware key factor.",
            evidence_references=[{"type": "configuration", "description": "IAM policy document", "url": "s3://acme-policies/iam-mfa-policy.json"}],
            status="active",
            approved_by="hassan.ali@acme.com", approved_at=NOW - timedelta(days=45),
            expiry_date=NOW + timedelta(days=180),
            review_frequency="quarterly",
            last_reviewed=NOW - timedelta(days=10),
            effectiveness_score=92.0,
            created_by="eve.nakamura@acme.com",
        ),
        CompensatingControl(
            original_framework="nist_800_53", original_control_id="SC-7",
            poam_id=poam_sc7.id if poam_sc7 else None,
            system_profile_id=prod.id if prod else None,
            title="Network segmentation via micro-segmentation with AWS PrivateLink",
            description="Until legacy SG is decommissioned, micro-segmentation isolates legacy-windows instances. PrivateLink enforces private connectivity for all API traffic.",
            implementation_details="VPC endpoint policies restrict legacy-windows subnet to approved internal CIDRs only. PrivateLink endpoints configured for S3, STS, and SSM.",
            evidence_references=[{"type": "configuration", "description": "VPC endpoint policies", "url": ""}],
            status="active",
            approved_by="hassan.ali@acme.com", approved_at=NOW - timedelta(days=30),
            expiry_date=NOW + timedelta(days=60),
            review_frequency="monthly",
            last_reviewed=NOW - timedelta(days=5),
            effectiveness_score=65.0,
            created_by="bob.martinez@acme.com",
        ),
        # --- 2 proposed ---
        CompensatingControl(
            original_framework="nist_800_53", original_control_id="CM-6",
            system_profile_id=prod.id if prod else None,
            title="Quarterly manual vulnerability scan of non-Config regions",
            description="Until AWS Config is deployed to all regions, conduct quarterly Nessus scans of infrastructure in us-west-2 and eu-west-1.",
            implementation_details="Nessus Professional scans scheduled quarterly. Results triaged by SecOps and fed into Jira SEC.",
            status="proposed",
            created_by="eve.nakamura@acme.com",
        ),
        CompensatingControl(
            original_framework="soc2", original_control_id="CC8.1",
            system_profile_id=prod.id if prod else None,
            title="Manual deployment approval via Slack sign-off",
            description="Until ServiceNow integration is complete, all production deployments require explicit Slack approval from engineering lead in #deployments channel.",
            implementation_details="GitHub Actions deployment workflow blocked until Slack bot confirms approval reaction from authorized deployers.",
            status="proposed",
            created_by="frank.torres@acme.com",
        ),
        # --- 2 approved ---
        CompensatingControl(
            original_framework="nist_800_53", original_control_id="AC-6",
            poam_id=poam_ac6.id if poam_ac6 else None,
            system_profile_id=cit.id if cit else None,
            title="Just-in-time privileged access via Okta workflows",
            description="Privileged Okta roles granted for 4-hour windows only, with automatic revocation. Permanent admin assignments eliminated.",
            implementation_details="Okta Workflows configured with time-boxed group membership. Slack approval from ISSO required before elevation.",
            status="approved",
            approved_by="hassan.ali@acme.com", approved_at=NOW - timedelta(days=3),
            expiry_date=NOW + timedelta(days=90),
            review_frequency="monthly",
            created_by="bob.martinez@acme.com",
        ),
        CompensatingControl(
            original_framework="iso_27001", original_control_id="A.7.2",
            system_profile_id=cit.id if cit else None,
            title="Manager-led monthly security briefing for overdue training personnel",
            description="For employees with overdue security awareness training, their direct managers deliver a 15-minute monthly security briefing covering current threat landscape.",
            implementation_details="Calendar invites auto-generated from KnowBe4 overdue report. Attendance tracked in Workday.",
            status="approved",
            approved_by="hassan.ali@acme.com", approved_at=NOW - timedelta(days=5),
            expiry_date=NOW + timedelta(days=60),
            review_frequency="monthly",
            created_by="eve.nakamura@acme.com",
        ),
        # --- 1 expired ---
        CompensatingControl(
            original_framework="nist_800_53", original_control_id="AU-6",
            system_profile_id=prod.id if prod else None,
            title="Daily manual CloudTrail log review by SecOps analyst",
            description="SecOps analyst manually reviews CloudTrail events for suspicious activity daily at 9am ET. Superseded by automated SIEM integration.",
            implementation_details="Analyst queries CloudTrail via Athena using pre-built queries. Findings logged in Jira SEC.",
            status="expired",
            approved_by="hassan.ali@acme.com", approved_at=NOW - timedelta(days=120),
            expiry_date=NOW - timedelta(days=30),
            review_frequency="monthly",
            last_reviewed=NOW - timedelta(days=45),
            effectiveness_score=45.0,
            created_by="eve.nakamura@acme.com",
        ),
        # --- 2 more active for diversity ---
        CompensatingControl(
            original_framework="nist_800_53", original_control_id="RA-5",
            system_profile_id=prod.id if prod else None,
            title="Automated container image scanning in CI/CD pipeline",
            description="Trivy scans all container images on PR and blocks merge on critical/high CVEs. Compensates for delayed host-level patching SLA.",
            implementation_details="GitHub Actions workflow runs trivy image scan. Fail threshold: CRITICAL or HIGH with fix available.",
            evidence_references=[{"type": "automation", "description": "GitHub Actions workflow", "url": "https://github.com/acme-corp/acme-app/actions/workflows/trivy.yml"}],
            status="active",
            approved_by="frank.torres@acme.com", approved_at=NOW - timedelta(days=90),
            expiry_date=NOW + timedelta(days=90),
            review_frequency="quarterly",
            last_reviewed=NOW - timedelta(days=30),
            effectiveness_score=88.0,
            created_by="frank.torres@acme.com",
        ),
        CompensatingControl(
            original_framework="nist_800_53", original_control_id="SI-4",
            system_profile_id=prod.id if prod else None,
            title="Enhanced VPC flow log analysis with anomaly detection",
            description="Until GuardDuty-to-SIEM integration is complete, VPC flow logs are analyzed with CloudWatch Anomaly Detection for network-based threat indicators.",
            implementation_details="CloudWatch Anomaly Detection enabled on VPC flow log metric filters for rejected connections, unusual port access, and data exfiltration patterns.",
            status="active",
            approved_by="hassan.ali@acme.com", approved_at=NOW - timedelta(days=20),
            expiry_date=NOW + timedelta(days=60),
            review_frequency="monthly",
            last_reviewed=NOW - timedelta(days=8),
            effectiveness_score=72.0,
            created_by="bob.martinez@acme.com",
        ),
    ]

    for c in controls:
        session.add(c)
    session.commit()
    return len(controls)


def seed_phase2_risk_acceptances(session) -> int:
    """Create 7 risk acceptances with varied lifecycle states."""
    prod = session.query(SystemProfile).filter(SystemProfile.acronym == "APP").first()
    cit = session.query(SystemProfile).filter(SystemProfile.acronym == "CIT").first()
    dev = session.query(SystemProfile).filter(SystemProfile.acronym == "DEV").first()

    poam_ac2 = session.query(POAM).filter(POAM.control_id == "AC-2", POAM.framework == "nist_800_53").first()

    acceptances = [
        # --- 3 active with future expiry ---
        RiskAcceptance(
            framework="nist_800_53", control_id="AC-2",
            poam_id=poam_ac2.id if poam_ac2 else None,
            system_profile_id=prod.id if prod else None,
            risk_description="Root account access keys remain active pending organizational migration to AWS Organizations with SCP-enforced root lockout. Compensating control in place for weekly privileged access review.",
            risk_level="high", residual_risk_level="moderate",
            conditions=[
                {"condition": "Weekly privileged access reviews must continue", "met": True},
                {"condition": "Root account CloudTrail alerts must be active", "met": True},
                {"condition": "Migration to AWS Organizations must begin within 90 days", "met": False},
            ],
            status="active",
            requested_by="eve.nakamura@acme.com",
            reviewed_by="frank.torres@acme.com", reviewed_at=NOW - timedelta(days=58),
            approved_by="hassan.ali@acme.com", approved_at=NOW - timedelta(days=55),
            expiry_date=NOW + timedelta(days=125),
            auto_reeval_triggers={"severity_change": True, "new_finding": True},
        ),
        RiskAcceptance(
            framework="soc2", control_id="CC6.1",
            system_profile_id=cit.id if cit else None,
            risk_description="Okta password policy minimum length remains at 8 characters pending organization-wide rollout of passkey authentication. Users with passkeys bypass password entirely.",
            risk_level="moderate", residual_risk_level="low",
            conditions=[
                {"condition": "Passkey rollout must cover 50% of users within 60 days", "met": True},
                {"condition": "Phishing-resistant MFA must remain enforced", "met": True},
            ],
            status="active",
            requested_by="bob.martinez@acme.com",
            reviewed_by="eve.nakamura@acme.com", reviewed_at=NOW - timedelta(days=30),
            approved_by="hassan.ali@acme.com", approved_at=NOW - timedelta(days=28),
            expiry_date=NOW + timedelta(days=92),
            auto_reeval_triggers={"severity_change": True},
        ),
        RiskAcceptance(
            framework="nist_800_53", control_id="SC-7",
            system_profile_id=dev.id if dev else None,
            risk_description="Development environment allows broader network access (SSH from office CIDR) to support rapid iteration. No customer data in dev environment.",
            risk_level="low", residual_risk_level="low",
            conditions=[
                {"condition": "No customer or production data in dev environment", "met": True},
                {"condition": "Dev environment isolated from production VPC", "met": True},
            ],
            status="active",
            requested_by="frank.torres@acme.com",
            reviewed_by="eve.nakamura@acme.com", reviewed_at=NOW - timedelta(days=80),
            approved_by="hassan.ali@acme.com", approved_at=NOW - timedelta(days=78),
            expiry_date=NOW + timedelta(days=287),
        ),
        # --- 1 expired (status still active to test checker) ---
        RiskAcceptance(
            framework="nist_800_53", control_id="AU-6",
            system_profile_id=prod.id if prod else None,
            risk_description="Single-region CloudTrail accepted while multi-region deployment was planned. Risk acceptance has expired and must be renewed or control remediated.",
            risk_level="high", residual_risk_level="moderate",
            conditions=[
                {"condition": "Daily manual log review compensating control must be active", "met": False},
            ],
            status="active",
            requested_by="bob.martinez@acme.com",
            reviewed_by="eve.nakamura@acme.com", reviewed_at=NOW - timedelta(days=100),
            approved_by="hassan.ali@acme.com", approved_at=NOW - timedelta(days=98),
            expiry_date=NOW - timedelta(days=8),
        ),
        # --- 1 requested pending approval ---
        RiskAcceptance(
            framework="iso_27001", control_id="A.7.2",
            system_profile_id=cit.id if cit else None,
            risk_description="3 employees (Alice Chen, Carol Park, Grace Kim) have overdue security awareness training. Requesting 30-day risk acceptance while escalated remediation proceeds.",
            risk_level="moderate", residual_risk_level="moderate",
            conditions=[
                {"condition": "Manager-led security briefing compensating control must be approved", "met": True},
                {"condition": "Affected employees must not have access to restricted data", "met": True},
            ],
            status="requested",
            requested_by="eve.nakamura@acme.com",
            expiry_date=NOW + timedelta(days=30),
        ),
        # --- 1 revoked ---
        RiskAcceptance(
            framework="nist_800_53", control_id="IA-5",
            system_profile_id=cit.id if cit else None,
            risk_description="8-character minimum password policy was accepted pending password manager rollout. Revoked after phishing incident demonstrated credential stuffing risk.",
            risk_level="moderate", residual_risk_level="high",
            status="revoked",
            requested_by="bob.martinez@acme.com",
            reviewed_by="eve.nakamura@acme.com", reviewed_at=NOW - timedelta(days=60),
            approved_by="hassan.ali@acme.com", approved_at=NOW - timedelta(days=58),
            expiry_date=NOW + timedelta(days=30),
        ),
        # --- 1 more active for coverage ---
        RiskAcceptance(
            framework="nist_800_53", control_id="CM-6",
            system_profile_id=prod.id if prod else None,
            risk_description="AWS Config not deployed in us-west-2. Minimal production workloads in that region (only DR standby). Quarterly manual scans compensate.",
            risk_level="moderate", residual_risk_level="low",
            conditions=[
                {"condition": "No primary workloads deployed to us-west-2", "met": True},
                {"condition": "Quarterly manual Nessus scans completed on time", "met": True},
            ],
            status="active",
            requested_by="bob.martinez@acme.com",
            reviewed_by="eve.nakamura@acme.com", reviewed_at=NOW - timedelta(days=25),
            approved_by="hassan.ali@acme.com", approved_at=NOW - timedelta(days=23),
            expiry_date=NOW + timedelta(days=67),
        ),
    ]

    for a in acceptances:
        session.add(a)
    session.commit()
    return len(acceptances)


def seed_phase3_inheritance(session) -> int:
    """Create 25 ControlInheritance records across system profiles."""
    profiles = {sp.acronym: sp for sp in session.query(SystemProfile).all()}
    prod = profiles.get("APP")
    cdw = profiles.get("CDW")
    cit = profiles.get("CIT")
    aiml = profiles.get("AIML")
    dev = profiles.get("DEV")

    if not all([prod, cdw, cit]):
        return 0

    records = []

    # PE-* (Physical and Environmental): inherited from AWS for all cloud systems
    pe_controls = ["PE-1", "PE-2", "PE-3", "PE-6", "PE-10", "PE-11", "PE-12", "PE-13", "PE-14"]
    cloud_systems = [s for s in [prod, cdw, aiml, dev] if s]
    for ctrl in pe_controls:
        for sys in cloud_systems:
            records.append(ControlInheritance(
                system_profile_id=sys.id, framework="nist_800_53", control_id=ctrl,
                inheritance_type="inherited",
                provider_description="AWS is responsible for physical security of data center facilities per shared responsibility model.",
                responsibility_description="Customer inherits physical controls from AWS. No customer action required.",
                evidence_requirement="provider_only", status="active",
            ))

    # AC-2, IA-2: shared between Corporate IT (provider) and Production/CDW/AIML (consumer)
    shared_identity_controls = ["AC-2", "IA-2"]
    identity_consumers = [s for s in [prod, cdw, aiml, dev] if s]
    for ctrl in shared_identity_controls:
        for sys in identity_consumers:
            records.append(ControlInheritance(
                system_profile_id=sys.id, framework="nist_800_53", control_id=ctrl,
                inheritance_type="shared",
                provider_system_id=cit.id,
                provider_description="Corporate IT manages Okta IdP, SSO federation, and MFA enforcement for all employees.",
                responsibility_description="Consumer system must enforce Okta SSO integration and implement application-level RBAC.",
                evidence_requirement="both", status="active",
            ))

    # AT-* (Awareness and Training): common (org-wide)
    at_controls = ["AT-1", "AT-2", "AT-3", "AT-4"]
    all_systems = [s for s in [prod, cdw, cit, aiml, dev] if s]
    for ctrl in at_controls:
        for sys in all_systems:
            records.append(ControlInheritance(
                system_profile_id=sys.id, framework="nist_800_53", control_id=ctrl,
                inheritance_type="common",
                provider_description="Organization-wide security awareness and training program managed by Security team.",
                responsibility_description="All personnel must complete organization-wide training. No system-specific training required.",
                evidence_requirement="provider_only", status="active",
            ))

    # SC-*, CM-* some controls: system_specific for production
    system_specific_controls = ["SC-7", "SC-8", "SC-28", "CM-6", "CM-7", "CM-8"]
    if prod:
        for ctrl in system_specific_controls:
            records.append(ControlInheritance(
                system_profile_id=prod.id, framework="nist_800_53", control_id=ctrl,
                inheritance_type="system_specific",
                responsibility_description="Production platform team is fully responsible for implementation and evidence.",
                evidence_requirement="consumer_only", status="active",
            ))

    for r in records:
        session.add(r)
    session.commit()
    return len(records)


def seed_phase3_dependencies(session) -> int:
    """Create 6 SystemDependency records modeling cross-system relationships."""
    profiles = {sp.acronym: sp for sp in session.query(SystemProfile).all()}
    prod = profiles.get("APP")
    cdw = profiles.get("CDW")
    cit = profiles.get("CIT")
    aiml = profiles.get("AIML")
    dev = profiles.get("DEV")

    if not all([prod, cdw, cit]):
        return 0

    deps = [
        SystemDependency(
            consumer_system_id=prod.id, provider_system_id=cit.id,
            shared_controls=["nist_800_53:AC-2", "nist_800_53:IA-2", "nist_800_53:IA-5", "soc2:CC6.1"],
            dependency_type="identity",
            description="Production platform relies on Corporate IT for identity federation via Okta SSO, MFA enforcement, and password policy.",
        ),
        SystemDependency(
            consumer_system_id=cdw.id, provider_system_id=prod.id,
            shared_controls=["nist_800_53:AC-4", "nist_800_53:SC-8"],
            dependency_type="application",
            description="Customer Data Warehouse ingests data from Production platform via encrypted ETL pipeline. Data classification controls inherited from source.",
        ),
        SystemDependency(
            consumer_system_id=aiml.id if aiml else prod.id,
            provider_system_id=prod.id,
            shared_controls=["nist_800_53:AC-4", "nist_800_53:SC-13", "nist_800_53:MP-5"],
            dependency_type="infrastructure",
            description="AI/ML platform consumes anonymized datasets from Production. Depends on Production for data anonymization and encryption in transit.",
        ),
        SystemDependency(
            consumer_system_id=dev.id if dev else prod.id,
            provider_system_id=cit.id,
            shared_controls=["nist_800_53:AC-2", "nist_800_53:IA-2", "nist_800_53:IA-5"],
            dependency_type="identity",
            description="Dev/Staging environment uses Corporate IT Okta for developer authentication. Same SSO and MFA policies as production.",
        ),
        SystemDependency(
            consumer_system_id=cdw.id, provider_system_id=cit.id,
            shared_controls=["nist_800_53:AC-2", "nist_800_53:IA-2"],
            dependency_type="identity",
            description="Data Warehouse team authenticates via Corporate IT Okta. Analysts access Redshift through SSO-federated IAM roles.",
        ),
        SystemDependency(
            consumer_system_id=aiml.id if aiml else prod.id,
            provider_system_id=cit.id,
            shared_controls=["nist_800_53:AC-2", "nist_800_53:IA-2"],
            dependency_type="identity",
            description="AI/ML engineers authenticate via Corporate IT Okta for SageMaker and notebook access.",
        ),
    ]

    for d in deps:
        session.add(d)
    session.commit()
    return len(deps)


def seed_phase4_change_events(session) -> int:
    """Create 40 ChangeEvent records from CloudTrail, GitHub, and ServiceNow."""
    random.seed(42)  # Deterministic demo data
    events = []

    actors_aws = [
        "arn:aws:iam::912345678012:user/bob.martinez",
        "arn:aws:iam::912345678012:user/alice.chen",
        "arn:aws:iam::912345678012:user/svc-deploy",
        "arn:aws:iam::912345678012:role/github-actions-deploy",
        "arn:aws:iam::912345678012:root",
    ]
    actors_github = ["alice.chen", "bob.martinez", "frank.torres", "svc-deploy"]
    actors_snow = ["eve.nakamura@acme.com", "bob.martinez@acme.com", "frank.torres@acme.com"]

    # CloudTrail IAM events
    cloudtrail_events = [
        ("PutUserPolicy", "arn:aws:iam::912345678012:user/alice.chen", "iam_user", "Inline policy attached granting S3 full access"),
        ("AttachRolePolicy", "arn:aws:iam::912345678012:role/lambda-processor", "iam_role", "AmazonS3FullAccess policy attached to Lambda role"),
        ("CreateAccessKey", "arn:aws:iam::912345678012:user/svc-deploy", "iam_user", "New access key created for service account"),
        ("DeleteTrail", "arn:aws:cloudtrail:us-east-1:912345678012:trail/dev-trail", "cloudtrail", "Dev environment CloudTrail deleted"),
        ("PutBucketPolicy", "arn:aws:s3:::acme-public-assets", "s3_bucket", "Bucket policy updated to allow public read"),
        ("AuthorizeSecurityGroupIngress", "sg-0a1b2c3d4e5f", "security_group", "Ingress rule added: TCP/22 from 0.0.0.0/0"),
        ("AuthorizeSecurityGroupIngress", "sg-9z8y7x6w5v4u", "security_group", "Ingress rule added: TCP/443 from 10.0.0.0/8"),
        ("ModifyDBInstance", "arn:aws:rds:us-east-1:912345678012:db/prod-customers", "rds_instance", "Multi-AZ enabled, backup retention changed to 30d"),
        ("DeactivateMFADevice", "arn:aws:iam::912345678012:user/carol.park", "iam_user", "MFA device deactivated for carol.park"),
        ("CreateRole", "arn:aws:iam::912345678012:role/data-pipeline-v2", "iam_role", "New IAM role for data pipeline v2"),
        ("PutBucketEncryption", "arn:aws:s3:::acme-prod-data", "s3_bucket", "AES-256 server-side encryption enabled"),
        ("UpdateDetector", "d-abc123def456", "guardduty_detector", "GuardDuty S3 protection enabled"),
        ("StopConfigurationRecorder", "default", "config_recorder", "Config recorder stopped in us-east-1"),
        ("PutBucketPublicAccessBlock", "arn:aws:s3:::acme-logs", "s3_bucket", "Public access block enabled on logs bucket"),
        ("ConsoleLogin", "arn:aws:iam::912345678012:root", "iam_root", "Root account console login from 203.0.113.42"),
    ]

    for i, (action, resource_id, resource_type, detail_text) in enumerate(cloudtrail_events):
        events.append(ChangeEvent(
            source="cloudtrail", source_type="cloud_audit",
            event_type=f"AwsApiCall:{action}",
            actor=random.choice(actors_aws),
            action=action,
            resource_id=resource_id,
            resource_type=resource_type,
            detail={"description": detail_text, "region": "us-east-1", "account_id": "912345678012"},
            occurred_at=NOW - timedelta(days=random.randint(0, 29), hours=random.randint(0, 23)),
            sha256=_sha(f"cloudtrail-{i}-{action}-{resource_id}"),
        ))

    # GitHub events
    github_events = [
        ("pull_request.merged", "acme-corp/acme-app#342", "repository", "feat: Add rate limiting to API gateway"),
        ("pull_request.merged", "acme-corp/acme-app#345", "repository", "fix: Patch xz-utils CVE-2024-3094 in base image"),
        ("pull_request.merged", "acme-corp/acme-app#348", "repository", "chore: Update Terraform AWS provider to 5.40"),
        ("pull_request.merged", "acme-corp/infra#112", "repository", "feat: Enable GuardDuty S3 protection"),
        ("deployment.created", "acme-corp/acme-app@v2.14.0", "deployment", "Production deployment v2.14.0"),
        ("deployment.created", "acme-corp/acme-app@v2.14.1", "deployment", "Hotfix deployment v2.14.1 (CVE patch)"),
        ("branch_protection.updated", "acme-corp/acme-app:main", "branch", "Require 2 approvals for main branch"),
        ("secret_scanning.alert", "acme-corp/acme-app", "repository", "AWS access key detected in commit history"),
        ("pull_request.merged", "acme-corp/infra#115", "repository", "feat: Deploy Config recorder to us-west-2"),
        ("dependabot.alert", "acme-corp/acme-app", "repository", "Critical vulnerability in transitive dependency"),
    ]

    for i, (event_type, resource_id, resource_type, detail_text) in enumerate(github_events):
        events.append(ChangeEvent(
            source="github", source_type="ci_cd",
            event_type=event_type,
            actor=random.choice(actors_github),
            action=event_type.split(".")[1] if "." in event_type else event_type,
            resource_id=resource_id,
            resource_type=resource_type,
            detail={"description": detail_text, "repository": resource_id.split("#")[0] if "#" in resource_id else resource_id},
            occurred_at=NOW - timedelta(days=random.randint(0, 29), hours=random.randint(0, 23)),
            sha256=_sha(f"github-{i}-{event_type}-{resource_id}"),
        ))

    # ServiceNow events
    snow_events = [
        ("change_request.approved", "CHG0045123", "change_request", "Enable multi-region CloudTrail", "standard"),
        ("change_request.implemented", "CHG0045124", "change_request", "Patch xz-utils on srv-web-01", "emergency"),
        ("change_request.approved", "CHG0045125", "change_request", "Deploy AWS Config to us-west-2", "standard"),
        ("change_request.implemented", "CHG0045126", "change_request", "Update Okta password policy to 12-char minimum", "standard"),
        ("change_request.approved", "CHG0045127", "change_request", "Decommission legacy-windows security group", "standard"),
        ("change_request.rejected", "CHG0045128", "change_request", "Open port 8080 on production ALB", "standard"),
        ("change_request.implemented", "CHG0045129", "change_request", "Enable S3 bucket encryption on acme-public-assets", "standard"),
        ("incident.resolved", "INC0089001", "incident", "Resolved: CrowdStrike agent in reduced functionality mode on ws-marketing-03", "P2"),
        ("incident.created", "INC0089002", "incident", "Suspicious PowerShell execution on ws-finance-01", "P1"),
        ("change_request.implemented", "CHG0045130", "change_request", "Rotate svc-deploy IAM access keys", "standard"),
        ("change_request.approved", "CHG0045131", "change_request", "Enable GuardDuty S3 protection", "standard"),
        ("change_request.implemented", "CHG0045132", "change_request", "Enable public access block on acme-logs bucket", "standard"),
        ("change_request.approved", "CHG0045133", "change_request", "Implement GitHub branch protection (2 approvals)", "standard"),
        ("incident.created", "INC0089003", "incident", "Credential dumping detected on srv-dc-01", "P1"),
        ("change_request.implemented", "CHG0045134", "change_request", "Restrict RDP SG to VPN CIDR (10.100.0.0/16)", "emergency"),
    ]

    for i, (event_type, resource_id, resource_type, detail_text, cat) in enumerate(snow_events):
        events.append(ChangeEvent(
            source="servicenow", source_type="itsm",
            event_type=event_type,
            actor=random.choice(actors_snow),
            action=event_type.split(".")[1] if "." in event_type else event_type,
            resource_id=resource_id,
            resource_type=resource_type,
            detail={"description": detail_text, "category": cat},
            occurred_at=NOW - timedelta(days=random.randint(0, 29), hours=random.randint(0, 23)),
            sha256=_sha(f"snow-{i}-{event_type}-{resource_id}"),
        ))

    for e in events:
        session.add(e)
    session.commit()
    return len(events)


def seed_phase4_posture_snapshots(session) -> int:
    """Create 30 days of daily posture snapshots for 12 key controls."""
    random.seed(42)
    prod = session.query(SystemProfile).filter(SystemProfile.acronym == "APP").first()
    cit = session.query(SystemProfile).filter(SystemProfile.acronym == "CIT").first()

    # Define controls with their trend behavior
    controls = [
        # (framework, control_id, system, base_score, trend, base_status)
        # Degrading
        ("nist_800_53", "AC-6", prod, 90.0, "degrade", "compliant"),
        # Improving
        ("nist_800_53", "IA-2", prod, 40.0, "improve", "non_compliant"),
        # Stable
        ("nist_800_53", "SC-7", prod, 85.0, "stable", "partial"),
        # Various stable controls
        ("nist_800_53", "AC-2", prod, 72.0, "stable", "partial"),
        ("nist_800_53", "AU-6", prod, 55.0, "stable", "non_compliant"),
        ("nist_800_53", "CM-6", prod, 68.0, "stable", "partial"),
        ("nist_800_53", "RA-5", prod, 45.0, "slight_improve", "non_compliant"),
        ("nist_800_53", "SI-4", prod, 78.0, "stable", "partial"),
        ("nist_800_53", "IA-5", cit, 60.0, "improve", "non_compliant"),
        ("nist_800_53", "SC-28", prod, 82.0, "slight_improve", "compliant"),
        ("soc2", "CC6.1", cit, 65.0, "stable", "partial"),
        ("soc2", "CC7.2", cit, 88.0, "stable", "compliant"),
    ]

    count = 0
    for day_offset in range(30, 0, -1):
        snapshot_date = NOW - timedelta(days=day_offset)
        day_index = 30 - day_offset  # 0..29

        for fw, ctrl, sys_profile, base, trend, base_status in controls:
            noise = random.uniform(-3.0, 3.0)

            if trend == "degrade":
                score = base - (day_index * 1.0) + noise  # 90 -> ~60
            elif trend == "improve":
                score = base + (day_index * 1.33) + noise  # 40 -> ~80
            elif trend == "slight_improve":
                score = base + (day_index * 0.4) + noise
            else:  # stable
                score = base + noise

            score = max(0.0, min(100.0, round(score, 1)))

            if score >= 80:
                status = "compliant"
            elif score >= 50:
                status = "partial"
            else:
                status = "non_compliant"

            # Realistic evidence metrics
            total = random.randint(3, 12)
            compliant_count = max(0, int(total * score / 100))
            non_compliant_count = total - compliant_count
            sufficiency = min(100.0, max(0.0, score + random.uniform(-10, 10)))

            snapshot = PostureSnapshot(
                snapshot_date=snapshot_date,
                framework=fw, control_id=ctrl,
                status=status, posture_score=score,
                total_findings=total,
                compliant_findings=compliant_count,
                non_compliant_findings=non_compliant_count,
                evidence_sources=["aws", "okta", "crowdstrike"] if sys_profile == prod else ["okta", "crowdstrike"],
                evidence_freshness_hours=random.uniform(1.0, 24.0),
                sufficiency_score=round(sufficiency, 1),
                sufficiency_details={"source_count": random.randint(2, 4), "evidence_types": ["config", "telemetry", "process"]},
                system_profile_id=sys_profile.id if sys_profile else None,
                uptime_pct=round(max(50.0, min(100.0, score + random.uniform(-5, 5))), 1),
                mttr_hours=round(max(0.5, (100 - score) / 10 + random.uniform(-1, 2)), 1),
                drift_count=random.randint(0, 3) if score < 70 else random.randint(0, 1),
            )
            session.add(snapshot)
            count += 1

    session.commit()
    return count


def seed_phase4_drift(session) -> int:
    """Create 10 ComplianceDrift records linked to posture snapshots and change events."""
    prod = session.query(SystemProfile).filter(SystemProfile.acronym == "APP").first()
    cit = session.query(SystemProfile).filter(SystemProfile.acronym == "CIT").first()

    # Get some change event IDs for correlation
    change_events = session.query(ChangeEvent).limit(10).all()
    ce_ids = [ce.id for ce in change_events]

    drifts = [
        # Degraded controls
        ComplianceDrift(
            framework="nist_800_53", control_id="AC-6",
            system_profile_id=prod.id if prod else None,
            previous_status="compliant", new_status="partial",
            drift_direction="degraded",
            previous_posture_score=90.0, new_posture_score=72.0,
            correlated_change_event_ids=ce_ids[:2] if len(ce_ids) >= 2 else [],
            root_cause_summary="Privilege escalation via Okta Super Admin grant to bob.martinez without approval workflow. IAM policy change detected in CloudTrail.",
            correlation_confidence=0.92,
            detected_at=NOW - timedelta(days=15),
        ),
        ComplianceDrift(
            framework="nist_800_53", control_id="AC-6",
            system_profile_id=prod.id if prod else None,
            previous_status="partial", new_status="non_compliant",
            drift_direction="degraded",
            previous_posture_score=72.0, new_posture_score=60.0,
            correlated_change_event_ids=[ce_ids[2]] if len(ce_ids) >= 3 else [],
            root_cause_summary="Additional inline policy attached to alice.chen granting S3 full access. No change request found in ServiceNow.",
            correlation_confidence=0.85,
            detected_at=NOW - timedelta(days=5),
        ),
        ComplianceDrift(
            framework="nist_800_53", control_id="AU-6",
            system_profile_id=prod.id if prod else None,
            previous_status="partial", new_status="non_compliant",
            drift_direction="degraded",
            previous_posture_score=60.0, new_posture_score=52.0,
            correlated_change_event_ids=[ce_ids[3]] if len(ce_ids) >= 4 else [],
            root_cause_summary="Dev environment CloudTrail deleted. Single-region trail in prod remains only audit coverage.",
            correlation_confidence=0.88,
            detected_at=NOW - timedelta(days=12),
        ),
        ComplianceDrift(
            framework="nist_800_53", control_id="SC-7",
            system_profile_id=prod.id if prod else None,
            previous_status="compliant", new_status="partial",
            drift_direction="degraded",
            previous_posture_score=88.0, new_posture_score=82.0,
            correlated_change_event_ids=[ce_ids[5]] if len(ce_ids) >= 6 else [],
            root_cause_summary="New security group ingress rule added allowing SSH from 0.0.0.0/0 to web-bastion.",
            correlation_confidence=0.95,
            detected_at=NOW - timedelta(days=20),
        ),
        # Improved controls
        ComplianceDrift(
            framework="nist_800_53", control_id="IA-2",
            system_profile_id=prod.id if prod else None,
            previous_status="non_compliant", new_status="partial",
            drift_direction="improved",
            previous_posture_score=40.0, new_posture_score=58.0,
            correlated_change_event_ids=[],
            root_cause_summary="Hardware security key compensating control deployed. 60% of privileged users now on FIDO2 MFA.",
            correlation_confidence=0.78,
            detected_at=NOW - timedelta(days=18),
        ),
        ComplianceDrift(
            framework="nist_800_53", control_id="IA-2",
            system_profile_id=prod.id if prod else None,
            previous_status="partial", new_status="compliant",
            drift_direction="improved",
            previous_posture_score=58.0, new_posture_score=80.0,
            correlated_change_event_ids=[],
            root_cause_summary="All privileged users now enrolled in hardware MFA. Compensating control fully effective.",
            correlation_confidence=0.90,
            detected_at=NOW - timedelta(days=3),
        ),
        ComplianceDrift(
            framework="nist_800_53", control_id="SC-28",
            system_profile_id=prod.id if prod else None,
            previous_status="partial", new_status="compliant",
            drift_direction="improved",
            previous_posture_score=75.0, new_posture_score=88.0,
            correlated_change_event_ids=[ce_ids[6]] if len(ce_ids) >= 7 else [],
            root_cause_summary="S3 bucket encryption enabled on acme-public-assets. All data silos now encrypted at rest.",
            correlation_confidence=0.97,
            detected_at=NOW - timedelta(days=22),
        ),
        ComplianceDrift(
            framework="nist_800_53", control_id="IA-5",
            system_profile_id=cit.id if cit else None,
            previous_status="non_compliant", new_status="partial",
            drift_direction="improved",
            previous_posture_score=55.0, new_posture_score=70.0,
            correlated_change_event_ids=[],
            root_cause_summary="Password policy update in progress. Okta policy updated to 12-char minimum, AWS IAM pending.",
            correlation_confidence=0.82,
            detected_at=NOW - timedelta(days=8),
        ),
        ComplianceDrift(
            framework="nist_800_53", control_id="RA-5",
            system_profile_id=prod.id if prod else None,
            previous_status="non_compliant", new_status="partial",
            drift_direction="improved",
            previous_posture_score=45.0, new_posture_score=55.0,
            correlated_change_event_ids=[ce_ids[1]] if len(ce_ids) >= 2 else [],
            root_cause_summary="CVE-2024-3094 patch deployed to staging. Container image scanning compensating control blocking new critical vulnerabilities.",
            correlation_confidence=0.75,
            detected_at=NOW - timedelta(days=2),
        ),
        ComplianceDrift(
            framework="soc2", control_id="CC6.1",
            system_profile_id=cit.id if cit else None,
            previous_status="non_compliant", new_status="partial",
            drift_direction="improved",
            previous_posture_score=50.0, new_posture_score=65.0,
            correlated_change_event_ids=[],
            root_cause_summary="Passkey rollout reached 50% adoption. Effective password strength improved through passwordless authentication.",
            correlation_confidence=0.70,
            detected_at=NOW - timedelta(days=10),
        ),
    ]

    for d in drifts:
        session.add(d)
    session.commit()
    return len(drifts)


def seed_phase5_auditor_engagement(session) -> int:
    """Create external auditors, an engagement, assignments, and evidence requests."""
    # Create 2 auditors
    auditor1 = ExternalAuditor(
        email="sarah.chen@deloitte.com", name="Sarah Chen", firm="Deloitte",
        is_active=True,
    )
    auditor2 = ExternalAuditor(
        email="marcus.johnson@ey.com", name="Marcus Johnson", firm="Ernst & Young",
        is_active=True,
    )
    session.add(auditor1)
    session.add(auditor2)
    session.flush()

    # Create or find an engagement
    engagement = session.query(AuditEngagement).first()
    if not engagement:
        engagement = AuditEngagement(
            name="SOC 2 Type II 2025-2026",
            framework="soc2",
            period_start=NOW - timedelta(days=180),
            period_end=NOW + timedelta(days=185),
            status="active",
            auditor_name="Sarah Chen",
            auditor_firm="Deloitte",
        )
        session.add(engagement)
        session.flush()

    # Create a second engagement for NIST
    nist_engagement = AuditEngagement(
        name="NIST 800-53 Annual Assessment 2026",
        framework="nist_800_53",
        period_start=NOW - timedelta(days=30),
        period_end=NOW + timedelta(days=60),
        status="active",
        auditor_name="Marcus Johnson",
        auditor_firm="Ernst & Young",
    )
    session.add(nist_engagement)
    session.flush()

    # Assign auditors to engagements
    session.add(AuditorEngagementAssignment(
        auditor_id=auditor1.id, engagement_id=engagement.id,
    ))
    session.add(AuditorEngagementAssignment(
        auditor_id=auditor2.id, engagement_id=nist_engagement.id,
    ))
    session.flush()

    # Create evidence requests
    evidence_requests = [
        EvidenceRequest(
            engagement_id=engagement.id, auditor_id=auditor1.id,
            framework="soc2", control_id="CC6.1",
            description="Provide IAM credential report showing MFA enrollment status for all users with console access.",
            status="fulfilled",
            fulfilled_by="eve.nakamura@acme.com", fulfilled_at=NOW - timedelta(days=5),
            fulfillment_notes="Credential report exported from AWS IAM. Shows 3/4 console users with MFA enabled.",
        ),
        EvidenceRequest(
            engagement_id=engagement.id, auditor_id=auditor1.id,
            framework="soc2", control_id="CC6.6",
            description="Provide encryption at rest configuration evidence for all data stores containing customer data.",
            status="fulfilled",
            fulfilled_by="bob.martinez@acme.com", fulfilled_at=NOW - timedelta(days=3),
            fulfillment_notes="S3 bucket encryption configs and RDS encryption status exported. All customer data stores encrypted.",
        ),
        EvidenceRequest(
            engagement_id=engagement.id, auditor_id=auditor1.id,
            framework="soc2", control_id="CC7.2",
            description="Provide CrowdStrike deployment coverage report showing agent status across all endpoints.",
            status="requested",
        ),
        EvidenceRequest(
            engagement_id=engagement.id, auditor_id=auditor1.id,
            framework="soc2", control_id="CC8.1",
            description="Provide change management records for all production deployments in the audit period, including approval evidence.",
            status="in_progress",
        ),
        EvidenceRequest(
            engagement_id=nist_engagement.id, auditor_id=auditor2.id,
            framework="nist_800_53", control_id="AC-2",
            description="Provide evidence of account management procedures including provisioning, modification, and deprovisioning workflows.",
            status="requested",
        ),
        EvidenceRequest(
            engagement_id=nist_engagement.id, auditor_id=auditor2.id,
            framework="nist_800_53", control_id="RA-5",
            description="Provide vulnerability scan reports for the last 90 days covering all production hosts and containers.",
            status="fulfilled",
            fulfilled_by="eve.nakamura@acme.com", fulfilled_at=NOW - timedelta(days=2),
            fulfillment_notes="CrowdStrike Spotlight vulnerability report and Trivy container scan results provided.",
        ),
        EvidenceRequest(
            engagement_id=nist_engagement.id, auditor_id=auditor2.id,
            framework="nist_800_53", control_id="AU-6",
            description="Provide evidence of audit log review procedures and any findings from log analysis over the audit period.",
            status="requested",
        ),
    ]

    for er in evidence_requests:
        session.add(er)
    session.commit()
    return {"auditors": 2, "engagements": 2, "evidence_requests": len(evidence_requests)}


def seed_phase5_policy_overrides(session) -> int:
    """Create 3 PolicyOverride records with realistic Rego policies."""
    overrides = [
        PolicyOverride(
            name="Emergency break-glass access escalation",
            description="Allows security team members to temporarily bypass approval workflows during active incidents. Requires incident ID and auto-revokes after 4 hours.",
            policy_rego="""package grc.overrides.break_glass

import rego.v1

default allow := false

allow if {
    input.user.role == "security"
    input.context.incident_id != ""
    input.context.duration_hours <= 4
}

audit_note := sprintf("Break-glass access granted for incident %s", [input.context.incident_id])
""",
            is_active=True,
            created_by="hassan.ali@acme.com",
        ),
        PolicyOverride(
            name="Auditor read-only scope expansion",
            description="Extends auditor read access to include raw evidence and finding details during active engagements. Scoped to assigned engagement only.",
            policy_rego="""package grc.overrides.auditor_scope

import rego.v1

default allow := false

allow if {
    input.user.role == "auditor"
    input.action in {"read_finding", "read_evidence", "read_raw_event"}
    input.context.engagement_id in input.user.assigned_engagements
}
""",
            is_active=True,
            created_by="eve.nakamura@acme.com",
        ),
        PolicyOverride(
            name="System owner remediation approval",
            description="Allows system owners to approve low-severity POA&M closures without AO sign-off. Medium and above still require AO.",
            policy_rego="""package grc.overrides.poam_approval

import rego.v1

default allow := false

allow if {
    input.user.role == "owner"
    input.action == "close_poam"
    input.poam.severity == "low"
    input.poam.system_profile_id in input.user.owned_systems
}
""",
            is_active=True,
            created_by="hassan.ali@acme.com",
        ),
    ]

    for o in overrides:
        session.add(o)
    session.commit()
    return len(overrides)


def seed_50_personnel(session) -> int:
    """Expand personnel to ~50 users with diverse departments and compliance states."""
    # Count existing personnel
    existing_count = session.query(Personnel).count()
    existing_emails = {row[0] for row in session.query(Personnel.email).all()}

    random.seed(42)

    departments = ["Engineering", "Product", "Finance", "Legal", "HR", "Sales", "Marketing", "Security", "DevOps", "Data Science"]
    first_names = [
        "Aiden", "Bella", "Carlos", "Diana", "Ethan", "Fatima", "George", "Hannah",
        "Isaac", "Julia", "Kevin", "Luna", "Marco", "Nadia", "Oscar", "Priya",
        "Quinn", "Rosa", "Samuel", "Tanya", "Umar", "Victoria", "Wei", "Xena",
        "Yuki", "Zara", "Adrian", "Bianca", "Chase", "Daria", "Eli", "Fiona",
        "Gabriel", "Holly", "Ivan", "Jade", "Kyle", "Lily", "Miguel", "Nina",
        "Oliver", "Petra", "Ravi", "Sofia",
    ]
    last_names = [
        "Anderson", "Bharati", "Costa", "Diaz", "Evans", "Fischer", "Garcia",
        "Huang", "Ibrahim", "Jensen", "Kim", "Lopez", "Muller", "Ng", "Olsen",
        "Patel", "Quinn", "Reyes", "Singh", "Tanaka", "Ueda", "Vasquez", "Wang",
        "Xu", "Yamamoto", "Zhang", "Baker", "Chen", "Davis", "Edwards", "Foster",
        "Gonzalez", "Hill", "Ishida", "Jackson", "Klein", "Lee", "Martinez", "Nelson",
        "Ortiz", "Park", "Reed", "Smith",
    ]

    new_personnel = []
    target = 50 - existing_count
    if target <= 0:
        return existing_count

    for i in range(min(target, len(first_names))):
        first = first_names[i]
        last = last_names[i % len(last_names)]
        email = f"{first.lower()}.{last.lower()}@acme.com"
        if email in existing_emails:
            continue

        dept = departments[i % len(departments)]
        hire_days_ago = random.randint(30, 1800)

        # Determine status
        if i in (38, 39, 40):  # 3 terminated but still active IdP
            hr_status = "terminated"
            idp_status = "active"
            is_active = False
            termination_date = NOW - timedelta(days=random.randint(10, 60))
            flags = ["terminated_but_active_idp"]
            risk_score = random.uniform(70.0, 95.0)
        elif i == 37:
            hr_status = "leave"
            idp_status = "suspended"
            is_active = True
            termination_date = None
            flags = []
            risk_score = random.uniform(10.0, 30.0)
        elif i == 36:
            hr_status = "leave"
            idp_status = "active"
            is_active = True
            termination_date = None
            flags = []
            risk_score = random.uniform(5.0, 20.0)
        else:
            hr_status = "active"
            idp_status = "active"
            is_active = True
            termination_date = None
            flags = []
            risk_score = random.uniform(0.0, 25.0)

        # MFA: ~80% enabled
        mfa = random.random() < 0.80
        if not mfa and hr_status == "active":
            flags.append("no_mfa")
            risk_score = max(risk_score, random.uniform(40.0, 65.0))

        # Training
        training_roll = random.random()
        if training_roll < 0.60:
            training_status = "current"
            last_training = NOW - timedelta(days=random.randint(1, 90))
        elif training_roll < 0.85:
            training_status = "overdue"
            last_training = NOW - timedelta(days=random.randint(120, 365))
            flags.append("training_overdue")
            risk_score = max(risk_score, random.uniform(30.0, 50.0))
        else:
            training_status = "not_enrolled"
            last_training = None
            if hr_status == "active":
                flags.append("training_not_enrolled")
                risk_score = max(risk_score, random.uniform(20.0, 40.0))

        # Background check
        if hire_days_ago > 60:
            bg_status = "completed"
            bg_date = NOW - timedelta(days=hire_days_ago - random.randint(5, 15))
        elif hire_days_ago > 14:
            bg_status = "completed"
            bg_date = NOW - timedelta(days=hire_days_ago - 5)
        else:
            bg_status = "in_progress"
            bg_date = None

        p = Personnel(
            email=email,
            full_name=f"{first} {last}",
            department=dept,
            title=random.choice(["Engineer", "Senior Engineer", "Manager", "Analyst", "Director", "Lead", "Specialist"]),
            manager_email=f"manager.{dept.lower()}@acme.com",
            employee_type=random.choice(["employee", "employee", "employee", "contractor"]) if i not in (38, 39, 40) else "employee",
            hr_employee_id=f"WD-{100 + i:03d}",
            hire_date=NOW - timedelta(days=hire_days_ago),
            termination_date=termination_date,
            hr_status=hr_status,
            background_check_status=bg_status,
            background_check_date=bg_date,
            agreements_signed=[{"type": "employment_agreement", "signed_date": (NOW - timedelta(days=hire_days_ago)).isoformat()},
                               {"type": "nda", "signed_date": (NOW - timedelta(days=hire_days_ago)).isoformat()}],
            idp_user_id=f"00u{i:04d}",
            idp_provider="okta",
            idp_status=idp_status,
            idp_last_login=NOW - timedelta(days=random.randint(0, 30)) if idp_status == "active" else NOW - timedelta(days=random.randint(30, 120)),
            mfa_enabled=mfa,
            training_status=training_status,
            last_training_date=last_training,
            phishing_score=round(random.uniform(40.0, 100.0), 1),
            last_access_review=NOW - timedelta(days=random.randint(10, 120)),
            access_review_status="completed" if random.random() < 0.7 else "overdue",
            flags=flags,
            risk_score=round(risk_score, 1),
            is_active=is_active,
            last_synced=NOW,
        )
        new_personnel.append(p)

    for p in new_personnel:
        session.add(p)
    session.commit()
    return session.query(Personnel).count()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _assign_findings_to_systems(session):
    """Assign findings to system profiles based on connector_scope matching."""
    systems = session.query(SystemProfile).all()
    if not systems:
        return 0

    # Build source -> system mapping from connector_scope
    source_to_system = {}
    for sp in systems:
        for source in (sp.connector_scope or []):
            # First match wins (most specific system)
            if source not in source_to_system:
                source_to_system[source] = sp.id

    findings = session.query(Finding).filter(Finding.system_profile_id.is_(None)).all()
    assigned = 0
    for f in findings:
        sys_id = source_to_system.get(f.source)
        if sys_id:
            f.system_profile_id = sys_id
            assigned += 1

    # Also propagate to control results
    from warlock.db.models import ControlResult as CR
    results = session.query(CR).filter(CR.system_profile_id.is_(None)).all()
    finding_system_map = {f.id: f.system_profile_id for f in findings if f.system_profile_id}
    for r in results:
        if r.finding_id in finding_system_map:
            r.system_profile_id = finding_system_map[r.finding_id]

    session.commit()
    return assigned


def _backfill_monitoring_frequency(session):
    """Backfill monitoring_frequency on control mappings from framework YAML data."""
    import yaml

    # Load frequencies from YAML files
    freq_map = {}  # (framework, control_id) -> frequency
    fw_dir = Path(__file__).resolve().parent.parent / "warlock" / "frameworks"
    for yaml_path in fw_dir.glob("*.yaml"):
        if "crosswalk" in yaml_path.name:
            continue
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        fw_id = data.get("framework_id", yaml_path.stem)
        for family_id, family in data.get("control_families", {}).items():
            for ctrl_id, ctrl in family.get("controls", {}).items():
                freq = ctrl.get("monitoring_frequency", "monthly")
                freq_map[(fw_id, ctrl_id)] = freq

    # Update mappings missing frequency
    from warlock.db.models import ControlMapping as CM
    mappings = session.query(CM).filter(CM.monitoring_frequency.is_(None)).all()
    updated = 0
    for m in mappings:
        freq = freq_map.get((m.framework, m.control_id))
        if freq:
            m.monitoring_frequency = freq
            updated += 1

    session.commit()
    return updated


def _create_demo_users(session):
    """Create demo user accounts for API testing."""
    from warlock.api.auth import hash_password
    from warlock.db.models import User as UserModel

    demo_users = [
        UserModel(
            email="admin@acme.com", name="Admin User",
            hashed_password=hash_password("WarlockAdmin2026!"),
            role="admin",
        ),
        UserModel(
            email="eve.nakamura@acme.com", name="Eve Nakamura",
            hashed_password=hash_password("SecurityFirst2026!"),
            role="auditor",
        ),
        UserModel(
            email="frank.torres@acme.com", name="Frank Torres",
            hashed_password=hash_password("EngineerBuild2026!"),
            role="owner",
            allowed_frameworks=["nist_800_53", "soc2", "iso_27001"],
            allowed_sources=["aws", "crowdstrike", "okta"],
        ),
        UserModel(
            email="carol.park@acme.com", name="Carol Park",
            hashed_password=hash_password("FinanceReview2026!"),
            role="viewer",
            allowed_frameworks=["soc2"],
        ),
    ]

    created = 0
    existing_emails = {row[0] for row in session.query(UserModel.email).all()}
    for user in demo_users:
        if user.email not in existing_emails:
            session.add(user)
            created += 1

    session.commit()
    return created


def main():
    print("=" * 60)
    print("  Warlock Demo Seed")
    print("=" * 60)

    # 1. Init DB
    print("\n[1/20] Initializing database...")
    init_db()

    # 2. Build pipeline with real framework configs + assertions
    print("[2/20] Loading frameworks, assertions, and normalizers...")
    bus = EventBus()
    load_assertions()

    connectors = ConnectorRegistry()
    connectors.register("aws", DemoAWSConnector)
    connectors.register("okta", DemoOktaConnector)
    connectors.register("crowdstrike", DemoCrowdStrikeConnector)
    connectors.register("workday", DemoWorkdayConnector)
    connectors.register("knowbe4", DemoKnowBe4Connector)
    connectors.register("securityscorecard", DemoSecurityScorecardConnector)
    connectors.register("confluence", DemoConfluenceConnector)
    connectors.create(ConnectorConfig(
        name="demo-aws", source_type=SourceType.CLOUD, provider="aws",
    ))
    connectors.create(ConnectorConfig(
        name="demo-okta", source_type=SourceType.IAM, provider="okta",
    ))
    connectors.create(ConnectorConfig(
        name="demo-crowdstrike", source_type=SourceType.EDR, provider="crowdstrike",
    ))
    connectors.create(ConnectorConfig(
        name="demo-workday", source_type=SourceType.HRIS, provider="workday",
    ))
    connectors.create(ConnectorConfig(
        name="demo-knowbe4", source_type=SourceType.TRAINING, provider="knowbe4",
    ))
    connectors.create(ConnectorConfig(
        name="demo-securityscorecard", source_type=SourceType.GRC, provider="securityscorecard",
    ))
    connectors.create(ConnectorConfig(
        name="demo-confluence", source_type=SourceType.GRC, provider="confluence",
    ))

    normalizers = NormalizerRegistry()
    normalizers.register(AWSNormalizer())
    normalizers.register(OktaNormalizer())
    normalizers.register(CrowdStrikeNormalizer())
    normalizers.register(WorkdayNormalizer())
    normalizers.register(KnowBe4Normalizer())
    normalizers.register(SecurityScorecardNormalizer())
    normalizers.register(ConfluenceNormalizer())
    normalizers.register(GenericNormalizer())

    mapper = ControlMapper()
    framework_dir = str(Path(__file__).resolve().parent.parent / "warlock" / "frameworks")
    load_framework_configs(framework_dir, mapper)

    assessor = Assessor(engine=assertion_engine)

    pipeline = Pipeline(
        connectors=connectors,
        normalizers=normalizers,
        mapper=mapper,
        assessor=assessor,
        bus=bus,
    )

    # 3. Run pipeline
    print("[3/20] Running pipeline (collect -> normalize -> map -> assess)...")
    with get_session() as session:
        stats = pipeline.run(session)

    # 4. Print results
    print("[4/20] Done with pipeline!\n")
    print("-" * 60)
    print(f"  Raw events collected:   {stats.raw_events_collected}")
    print(f"  Findings normalized:    {stats.findings_normalized}")
    print(f"  Controls mapped:        {stats.controls_mapped}")
    print(f"  Results assessed:       {stats.results_assessed}")
    print(f"  Connectors succeeded:   {stats.connectors_succeeded}")
    print(f"  Connectors failed:      {stats.connectors_failed}")
    print(f"  Duration:               {stats.duration_seconds:.2f}s")
    if stats.errors:
        print(f"  Errors:                 {len(stats.errors)}")
        for err in stats.errors[:5]:
            print(f"    - {err}")
    print("-" * 60)

    # Show framework breakdown
    with get_session() as session:
        frameworks = (
            session.query(ControlResult.framework, func.count(ControlResult.id))
            .group_by(ControlResult.framework)
            .all()
        )
        if frameworks:
            print("\n  Results by framework:")
            for fw, count in sorted(frameworks):
                print(f"    {fw:20s}  {count} results")

        statuses = (
            session.query(ControlResult.status, func.count(ControlResult.id))
            .group_by(ControlResult.status)
            .all()
        )
        if statuses:
            print("\n  Results by status:")
            for status, count in sorted(statuses):
                print(f"    {status:20s}  {count}")

    print("[5/20] Seeding system profiles...")
    with get_session() as session:
        n = seed_systems(session)
        print(f"       Created {n} system profiles")

    print("[6/20] Syncing personnel from HR + IdP + training...")
    with get_session() as session:
        p = seed_personnel(session)
        print(f"       Personnel: {p['total']} records synced")

    print("[7/20] Seeding questionnaire templates and instances...")
    with get_session() as session:
        q = seed_questionnaires(session)
        print(f"       Templates: {q['templates']}, Questionnaires: {len(q['questionnaires'])}")

    print("[8/20] Seeding data silos, legal holds, and issues...")
    with get_session() as session:
        ds = seed_data_silos(session)
        print(f"       Data silos: {ds['discovered']} discovered + {ds['direct']} direct")
        lh = seed_legal_holds(session)
        print(f"       Legal holds: {lh}")
        issues = seed_issues(session)
        print(f"       Issues: {issues['auto_created']} auto + {issues['manual']} manual")

    # --- Phase 2: POA&Ms, compensating controls, risk acceptances ---

    print("[9/20] Seeding POA&Ms...")
    with get_session() as session:
        n_poams = seed_phase2_poams(session)
        print(f"       POA&Ms: {n_poams}")

    print("[10/20] Seeding compensating controls...")
    with get_session() as session:
        n_cc = seed_phase2_compensating_controls(session)
        print(f"       Compensating controls: {n_cc}")

    print("[11/20] Seeding risk acceptances...")
    with get_session() as session:
        n_ra = seed_phase2_risk_acceptances(session)
        print(f"       Risk acceptances: {n_ra}")

    # --- Phase 3: Inheritance and dependencies ---

    print("[12/20] Seeding control inheritance records...")
    with get_session() as session:
        n_ci = seed_phase3_inheritance(session)
        print(f"       Control inheritances: {n_ci}")

    print("[13/20] Seeding system dependencies...")
    with get_session() as session:
        n_sd = seed_phase3_dependencies(session)
        print(f"       System dependencies: {n_sd}")

    # --- Phase 4: Change events, posture snapshots, drift ---

    print("[14/20] Seeding change events...")
    with get_session() as session:
        n_ce = seed_phase4_change_events(session)
        print(f"       Change events: {n_ce}")

    print("[15/20] Seeding posture snapshots (30 days)...")
    with get_session() as session:
        n_ps = seed_phase4_posture_snapshots(session)
        print(f"       Posture snapshots: {n_ps}")

    print("[16/20] Seeding compliance drift records...")
    with get_session() as session:
        n_drift = seed_phase4_drift(session)
        print(f"       Compliance drifts: {n_drift}")

    # --- Phase 5: Auditor engagement, policy overrides ---

    print("[17/20] Seeding auditor engagement and evidence requests...")
    with get_session() as session:
        ae = seed_phase5_auditor_engagement(session)
        print(f"       Auditors: {ae['auditors']}, Engagements: {ae['engagements']}, Evidence requests: {ae['evidence_requests']}")

    print("[18/20] Seeding policy overrides...")
    with get_session() as session:
        n_po = seed_phase5_policy_overrides(session)
        print(f"       Policy overrides: {n_po}")

    # --- Expand personnel ---

    print("[19/20] Expanding personnel to 50 users...")
    with get_session() as session:
        total_personnel = seed_50_personnel(session)
        print(f"       Total personnel: {total_personnel}")

    # --- Post-pipeline data enrichment ---

    print("[20/23] Assigning findings to system profiles...")
    with get_session() as session:
        assigned = _assign_findings_to_systems(session)
        print(f"       Findings assigned: {assigned}")

    print("[21/23] Backfilling monitoring_frequency on control mappings...")
    with get_session() as session:
        backfilled = _backfill_monitoring_frequency(session)
        print(f"       Mappings updated: {backfilled}")

    print("[22/23] Creating demo user accounts...")
    with get_session() as session:
        users_created = _create_demo_users(session)
        print(f"       Users created: {users_created}")

    print("[23/23] Seed complete!\n")

    print("=" * 60)
    print("  Try these commands:")
    print("=" * 60)
    print("  warlock results                    # control results")
    print("  warlock results --status non_compliant")
    print("  warlock coverage                   # compliance summary")
    print("  warlock findings                   # all findings")
    print("  warlock sources                    # registered sources")
    print("  warlock systems                    # system profiles")
    print("  warlock personnel                  # HR/IdP/training records")
    print("  warlock vendors                    # vendor risk scores")
    print("  warlock questionnaires             # vendor questionnaires")
    print("  warlock data-silos                 # storage inventory")
    print("  warlock retention                  # retention & legal holds")
    print("  warlock issues                     # compliance issues")
    print("  warlock policy-coverage -f iso_27001  # policy gaps")
    print("  warlock risk -f nist_800_53        # FAIR risk analysis")
    print("  warlock oscal                      # export OSCAL JSON")
    print()
    print("  --- Phase 2-5 commands ---")
    print("  warlock poams                      # POA&M tracking")
    print("  warlock poams --overdue            # overdue POA&Ms")
    print("  warlock compensating-controls      # compensating controls")
    print("  warlock risk-acceptances           # risk acceptances")
    print("  warlock inheritance                # control inheritance map")
    print("  warlock drift                      # compliance drift events")
    print("  warlock posture-history            # posture score trends")
    print("  warlock cadence                    # monitoring cadence")
    print("  warlock sufficiency                # evidence sufficiency")
    print("  warlock effectiveness              # control effectiveness")
    print("  warlock simulate-audit             # simulate audit readiness")
    print("  warlock framework-diff             # cross-framework delta")
    print("=" * 60)


if __name__ == "__main__":
    main()
