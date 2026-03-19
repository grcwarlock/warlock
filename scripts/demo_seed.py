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
    Base, ControlMapping, ControlResult, DataSilo, Finding,
    Issue, LegalHold, Personnel, SystemProfile,
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
# Main
# ---------------------------------------------------------------------------


def main():
    print("=" * 60)
    print("  Warlock Demo Seed")
    print("=" * 60)

    # 1. Init DB
    print("\n[1/9] Initializing database...")
    init_db()

    # 2. Build pipeline with real framework configs + assertions
    print("[2/9] Loading frameworks, assertions, and normalizers...")
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
    print("[3/9] Running pipeline (collect -> normalize -> map -> assess)...")
    with get_session() as session:
        stats = pipeline.run(session)

    # 4. Print results
    print("[4/9] Done with pipeline!\n")
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

    print("[5/9] Seeding system profiles...")
    with get_session() as session:
        n = seed_systems(session)
        print(f"       Created {n} system profiles")

    print("[6/9] Syncing personnel from HR + IdP + training...")
    with get_session() as session:
        p = seed_personnel(session)
        print(f"       Personnel: {p['total']} records synced")

    print("[7/9] Seeding questionnaire templates and instances...")
    with get_session() as session:
        q = seed_questionnaires(session)
        print(f"       Templates: {q['templates']}, Questionnaires: {len(q['questionnaires'])}")

    print("[8/9] Seeding data silos, legal holds, and issues...")
    with get_session() as session:
        ds = seed_data_silos(session)
        print(f"       Data silos: {ds['discovered']} discovered + {ds['direct']} direct")
        lh = seed_legal_holds(session)
        print(f"       Legal holds: {lh}")
        issues = seed_issues(session)
        print(f"       Issues: {issues['auto_created']} auto + {issues['manual']} manual")

    print("[9/9] Seed complete!\n")

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
    print("=" * 60)


if __name__ == "__main__":
    main()
