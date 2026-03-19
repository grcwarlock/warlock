#!/usr/bin/env python3
"""Seed a full-stack demo environment with all 40 connectors.

No real credentials or API keys needed. 40 mock connectors produce realistic
events from cloud, IAM, EDR, SIEM, scanners, ITSM, code security, DLP, backup,
physical security, and more. All events flow through the real pipeline
(collect -> normalize -> map -> assess) exercising every normalizer (41),
every assertion (25), and every framework (6).

Usage:
    python scripts/demo_seed.py          # seed + run pipeline (~7s)
    warlock coverage                     # compliance summary across 6 frameworks
    warlock findings                     # 547+ findings from 40 sources
    warlock results --status non_compliant
    warlock sources                      # 40 connectors + 41 normalizers
    warlock systems                      # 5 system profiles
    warlock issues                       # 541 compliance issues
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
from warlock.normalizers.cyberark import CyberArkNormalizer
from warlock.normalizers.entra_id import EntraIDNormalizer
from warlock.normalizers.sailpoint import SailPointNormalizer
from warlock.normalizers.vault import VaultNormalizer
from warlock.normalizers.alibaba import AlibabaNormalizer
from warlock.normalizers.azure import AzureNormalizer
from warlock.normalizers.cloudflare import CloudflareNormalizer
from warlock.normalizers.defender import DefenderNormalizer
from warlock.normalizers.digitalocean import DigitalOceanNormalizer
from warlock.normalizers.elastic import ElasticNormalizer
from warlock.normalizers.gcp import GCPNormalizer
from warlock.normalizers.github import GitHubNormalizer
from warlock.normalizers.huawei import HuaweiNormalizer
from warlock.normalizers.ibm_cloud import IBMCloudNormalizer
from warlock.normalizers.intune import IntuneNormalizer
from warlock.normalizers.kubernetes import KubernetesNormalizer
from warlock.normalizers.mlflow import MLflowNormalizer
from warlock.normalizers.oci import OCINormalizer
from warlock.normalizers.onetrust import OneTrustNormalizer
from warlock.normalizers.ovh import OVHNormalizer
from warlock.normalizers.prisma import PrismaNormalizer
from warlock.normalizers.proofpoint import ProofpointNormalizer
from warlock.normalizers.purview import PurviewNormalizer
from warlock.normalizers.qualys import QualysNormalizer
from warlock.normalizers.sentinel import SentinelNormalizer
from warlock.normalizers.sentinelone import SentinelOneNormalizer
from warlock.normalizers.servicenow import ServiceNowNormalizer
from warlock.normalizers.snyk import SnykNormalizer
from warlock.normalizers.splunk import SplunkNormalizer
from warlock.normalizers.tenable import TenableNormalizer
from warlock.normalizers.veeam import VeeamNormalizer
from warlock.normalizers.verkada import VerkadaNormalizer
from warlock.normalizers.wiz import WizNormalizer
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


# --- Identity & Access Management Demo Connectors ---


class DemoEntraIDConnector(BaseConnector):
    """Simulates Entra ID collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="entra_id",
            source_type=SourceType.IAM,
            provider="entra_id",
        )

        # Users: mix of active, stale, disabled, never-signed-in
        result.events.append(RawEventData(
            source="entra_id", source_type=SourceType.IAM, provider="entra_id",
            event_type="entra_users",
            raw_data={
                "tenant_id": "acme-tenant-001",
                "response": [
                    {
                        "id": "entra-u-001",
                        "userPrincipalName": "alice.chen@acme.onmicrosoft.com",
                        "accountEnabled": True,
                        "signInActivity": {
                            "lastSignInDateTime": (NOW - timedelta(hours=3)).isoformat(),
                        },
                    },
                    {
                        "id": "entra-u-002",
                        "userPrincipalName": "bob.martinez@acme.onmicrosoft.com",
                        "accountEnabled": True,
                        "signInActivity": {
                            "lastSignInDateTime": (NOW - timedelta(days=1)).isoformat(),
                        },
                    },
                    {
                        "id": "entra-u-003",
                        "userPrincipalName": "carol.park@acme.onmicrosoft.com",
                        "accountEnabled": True,
                        "signInActivity": {
                            "lastSignInDateTime": (NOW - timedelta(days=120)).isoformat(),
                        },
                    },
                    {
                        "id": "entra-u-004",
                        "userPrincipalName": "dave.thompson@acme.onmicrosoft.com",
                        "accountEnabled": False,
                        "signInActivity": {
                            "lastSignInDateTime": (NOW - timedelta(days=45)).isoformat(),
                        },
                    },
                    {
                        "id": "entra-u-005",
                        "userPrincipalName": "eve.nakamura@acme.onmicrosoft.com",
                        "accountEnabled": True,
                        "signInActivity": None,
                    },
                ],
            },
        ))

        # Risky users: bob high, carol medium
        result.events.append(RawEventData(
            source="entra_id", source_type=SourceType.IAM, provider="entra_id",
            event_type="entra_risky_users",
            raw_data={
                "tenant_id": "acme-tenant-001",
                "response": [
                    {
                        "id": "entra-u-002",
                        "userPrincipalName": "bob.martinez@acme.onmicrosoft.com",
                        "riskLevel": "high",
                        "riskState": "atRisk",
                        "riskDetail": "unfamiliarFeatures",
                        "riskLastUpdatedDateTime": (NOW - timedelta(hours=6)).isoformat(),
                    },
                    {
                        "id": "entra-u-003",
                        "userPrincipalName": "carol.park@acme.onmicrosoft.com",
                        "riskLevel": "medium",
                        "riskState": "atRisk",
                        "riskDetail": "suspiciousActivity",
                        "riskLastUpdatedDateTime": (NOW - timedelta(days=2)).isoformat(),
                    },
                    {
                        "id": "entra-u-001",
                        "userPrincipalName": "alice.chen@acme.onmicrosoft.com",
                        "riskLevel": "none",
                        "riskState": "none",
                        "riskDetail": "",
                        "riskLastUpdatedDateTime": "",
                    },
                ],
            },
        ))

        # Sign-ins: failed sign-in, risky sign-in, CA-blocked sign-in, success
        result.events.append(RawEventData(
            source="entra_id", source_type=SourceType.IAM, provider="entra_id",
            event_type="entra_sign_ins",
            raw_data={
                "tenant_id": "acme-tenant-001",
                "response": [
                    {
                        "userId": "entra-u-002",
                        "userPrincipalName": "bob.martinez@acme.onmicrosoft.com",
                        "status": {"errorCode": 50126, "failureReason": "Invalid username or password"},
                        "riskLevelDuringSignIn": "high",
                        "conditionalAccessStatus": "notApplied",
                        "ipAddress": "198.51.100.42",
                        "location": {"city": "Moscow", "countryOrRegion": "RU"},
                    },
                    {
                        "userId": "entra-u-003",
                        "userPrincipalName": "carol.park@acme.onmicrosoft.com",
                        "status": {"errorCode": 53003, "failureReason": "Blocked by Conditional Access"},
                        "riskLevelDuringSignIn": "medium",
                        "conditionalAccessStatus": "failure",
                        "ipAddress": "203.0.113.99",
                        "location": {"city": "Shanghai", "countryOrRegion": "CN"},
                    },
                    {
                        "userId": "entra-u-001",
                        "userPrincipalName": "alice.chen@acme.onmicrosoft.com",
                        "status": {"errorCode": 0, "failureReason": ""},
                        "riskLevelDuringSignIn": "none",
                        "conditionalAccessStatus": "success",
                        "ipAddress": "10.0.1.50",
                        "location": {"city": "San Francisco", "countryOrRegion": "US"},
                    },
                ],
            },
        ))

        # Directory audits: privilege change + normal activity
        result.events.append(RawEventData(
            source="entra_id", source_type=SourceType.IAM, provider="entra_id",
            event_type="entra_directory_audits",
            raw_data={
                "tenant_id": "acme-tenant-001",
                "response": [
                    {
                        "id": "audit-001",
                        "activityDisplayName": "Add member to role",
                        "initiatedBy": {
                            "user": {"userPrincipalName": "bob.martinez@acme.onmicrosoft.com"},
                        },
                        "result": "success",
                        "targetResources": [
                            {"displayName": "Global Administrator", "type": "Role"},
                        ],
                    },
                    {
                        "id": "audit-002",
                        "activityDisplayName": "Update user",
                        "initiatedBy": {
                            "user": {"userPrincipalName": "alice.chen@acme.onmicrosoft.com"},
                        },
                        "result": "success",
                        "targetResources": [
                            {"displayName": "eve.nakamura@acme.onmicrosoft.com", "type": "User"},
                        ],
                    },
                ],
            },
        ))

        # Conditional access policies: enabled, disabled, and report-only
        result.events.append(RawEventData(
            source="entra_id", source_type=SourceType.IAM, provider="entra_id",
            event_type="entra_conditional_access_policies",
            raw_data={
                "tenant_id": "acme-tenant-001",
                "response": [
                    {
                        "id": "ca-001",
                        "displayName": "Require MFA for admins",
                        "state": "enabled",
                        "conditions": {"users": {"includeRoles": ["Global Administrator"]}},
                        "grantControls": {"builtInControls": ["mfa"]},
                    },
                    {
                        "id": "ca-002",
                        "displayName": "Block legacy authentication",
                        "state": "disabled",
                        "conditions": {"clientAppTypes": ["exchangeActiveSync", "other"]},
                        "grantControls": {"builtInControls": ["block"]},
                    },
                    {
                        "id": "ca-003",
                        "displayName": "Require compliant device",
                        "state": "enabledForReportingButNotEnforced",
                        "conditions": {"platforms": {"includePlatforms": ["all"]}},
                        "grantControls": {"builtInControls": ["compliantDevice"]},
                    },
                ],
            },
        ))

        # Service principals: one overprivileged, one clean
        result.events.append(RawEventData(
            source="entra_id", source_type=SourceType.IAM, provider="entra_id",
            event_type="entra_service_principals",
            raw_data={
                "tenant_id": "acme-tenant-001",
                "response": [
                    {
                        "id": "sp-001",
                        "appId": "app-legacy-sync-001",
                        "displayName": "Legacy Data Sync",
                        "accountEnabled": True,
                        "appRoles": [
                            {"value": "Directory.ReadWrite.All", "isEnabled": True},
                            {"value": "Application.ReadWrite.All", "isEnabled": True},
                        ],
                        "oauth2PermissionScopes": [
                            {"value": "User.ReadWrite.All"},
                        ],
                    },
                    {
                        "id": "sp-002",
                        "appId": "app-monitoring-002",
                        "displayName": "Monitoring Agent",
                        "accountEnabled": True,
                        "appRoles": [
                            {"value": "Directory.Read.All", "isEnabled": True},
                        ],
                        "oauth2PermissionScopes": [],
                    },
                ],
            },
        ))

        # App registrations
        result.events.append(RawEventData(
            source="entra_id", source_type=SourceType.IAM, provider="entra_id",
            event_type="entra_app_registrations",
            raw_data={
                "tenant_id": "acme-tenant-001",
                "response": [
                    {
                        "id": "app-reg-001",
                        "displayName": "Acme Customer Portal",
                        "signInAudience": "AzureADMyOrg",
                        "createdDateTime": (NOW - timedelta(days=180)).isoformat(),
                    },
                    {
                        "id": "app-reg-002",
                        "displayName": "Acme Internal Tools",
                        "signInAudience": "AzureADMyOrg",
                        "createdDateTime": (NOW - timedelta(days=365)).isoformat(),
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoCyberArkConnector(BaseConnector):
    """Simulates CyberArk collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="cyberark",
            source_type=SourceType.IAM,
            provider="cyberark",
        )

        # Accounts: compliant, overdue rotation, auto-mgmt disabled, unused
        result.events.append(RawEventData(
            source="cyberark", source_type=SourceType.IAM, provider="cyberark",
            event_type="cyberark_accounts",
            raw_data={
                "base_url": "https://acme.privilegecloud.cyberark.cloud",
                "response": [
                    {
                        "id": "ca-acct-001",
                        "name": "svc-prod-db-admin",
                        "platformId": "UnixSSH",
                        "safeName": "Prod-Database-Accounts",
                        "secretManagement": {
                            "lastModifiedTime": int((NOW - timedelta(days=15)).timestamp()),
                            "automaticManagementEnabled": True,
                        },
                        "lastUsedDate": int((NOW - timedelta(days=2)).timestamp()),
                    },
                    {
                        "id": "ca-acct-002",
                        "name": "svc-legacy-app",
                        "platformId": "WinDomain",
                        "safeName": "Legacy-Accounts",
                        "secretManagement": {
                            "lastModifiedTime": int((NOW - timedelta(days=180)).timestamp()),
                            "automaticManagementEnabled": False,
                        },
                        "lastUsedDate": int((NOW - timedelta(days=120)).timestamp()),
                    },
                    {
                        "id": "ca-acct-003",
                        "name": "admin-aws-root",
                        "platformId": "AWSAccessKeys",
                        "safeName": "Cloud-Root-Accounts",
                        "secretManagement": {
                            "lastModifiedTime": int((NOW - timedelta(days=30)).timestamp()),
                            "automaticManagementEnabled": True,
                        },
                        "lastUsedDate": int((NOW - timedelta(days=5)).timestamp()),
                    },
                    {
                        "id": "ca-acct-004",
                        "name": "svc-deprecated-api",
                        "platformId": "UnixSSH",
                        "safeName": "Legacy-Accounts",
                        "secretManagement": {
                            "lastModifiedTime": int((NOW - timedelta(days=200)).timestamp()),
                            "automaticManagementEnabled": False,
                        },
                        "lastUsedDate": int((NOW - timedelta(days=150)).timestamp()),
                    },
                ],
            },
        ))

        # Safes: one with members, one empty
        result.events.append(RawEventData(
            source="cyberark", source_type=SourceType.IAM, provider="cyberark",
            event_type="cyberark_safes",
            raw_data={
                "base_url": "https://acme.privilegecloud.cyberark.cloud",
                "response": [
                    {
                        "safeName": "Prod-Database-Accounts",
                        "safeUrlId": "Prod-Database-Accounts",
                        "numberOfMembers": 4,
                    },
                    {
                        "safeName": "Legacy-Accounts",
                        "safeUrlId": "Legacy-Accounts",
                        "numberOfMembers": 2,
                    },
                    {
                        "safeName": "Cloud-Root-Accounts",
                        "safeUrlId": "Cloud-Root-Accounts",
                        "numberOfMembers": 3,
                    },
                    {
                        "safeName": "Orphaned-Safe",
                        "safeUrlId": "Orphaned-Safe",
                        "numberOfMembers": 0,
                    },
                ],
            },
        ))

        # Platforms: active and inactive
        result.events.append(RawEventData(
            source="cyberark", source_type=SourceType.IAM, provider="cyberark",
            event_type="cyberark_platforms",
            raw_data={
                "base_url": "https://acme.privilegecloud.cyberark.cloud",
                "response": [
                    {"PlatformID": "UnixSSH", "Name": "Unix via SSH", "Active": True},
                    {"PlatformID": "WinDomain", "Name": "Windows Domain", "Active": True},
                    {"PlatformID": "AWSAccessKeys", "Name": "AWS Access Keys", "Active": True},
                    {"PlatformID": "OracleDB", "Name": "Oracle Database", "Active": False},
                ],
            },
        ))

        # Session recordings
        result.events.append(RawEventData(
            source="cyberark", source_type=SourceType.IAM, provider="cyberark",
            event_type="cyberark_recordings",
            raw_data={
                "base_url": "https://acme.privilegecloud.cyberark.cloud",
                "response": [
                    {
                        "SessionID": "sess-001",
                        "User": "alice.chen@acme.com",
                        "AccountUserName": "svc-prod-db-admin",
                        "Duration": 1800,
                        "Start": (NOW - timedelta(hours=4)).isoformat(),
                    },
                    {
                        "SessionID": "sess-002",
                        "User": "bob.martinez@acme.com",
                        "AccountUserName": "admin-aws-root",
                        "Duration": 420,
                        "Start": (NOW - timedelta(hours=8)).isoformat(),
                    },
                ],
            },
        ))

        # Password compliance: reuse same accounts for summary view
        result.events.append(RawEventData(
            source="cyberark", source_type=SourceType.IAM, provider="cyberark",
            event_type="cyberark_password_compliance",
            raw_data={
                "base_url": "https://acme.privilegecloud.cyberark.cloud",
                "response": [
                    {
                        "secretManagement": {
                            "lastModifiedTime": int((NOW - timedelta(days=15)).timestamp()),
                            "status": "success",
                        },
                    },
                    {
                        "secretManagement": {
                            "lastModifiedTime": int((NOW - timedelta(days=180)).timestamp()),
                            "status": "failure",
                        },
                    },
                    {
                        "secretManagement": {
                            "lastModifiedTime": int((NOW - timedelta(days=30)).timestamp()),
                            "status": "success",
                        },
                    },
                    {
                        "secretManagement": {
                            "lastModifiedTime": int((NOW - timedelta(days=200)).timestamp()),
                            "status": "failure",
                        },
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoSailPointConnector(BaseConnector):
    """Simulates SailPoint collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="sailpoint",
            source_type=SourceType.IAM,
            provider="sailpoint",
        )

        # Identities: active, inactive, excessive entitlements
        result.events.append(RawEventData(
            source="sailpoint", source_type=SourceType.IAM, provider="sailpoint",
            event_type="sailpoint_identities",
            raw_data={
                "tenant": "acme-prod",
                "response": [
                    {
                        "id": "sp-id-001",
                        "name": "Alice Chen",
                        "alias": "alice.chen",
                        "status": "ACTIVE",
                        "isActive": True,
                        "accountCount": 5,
                        "entitlementCount": 22,
                    },
                    {
                        "id": "sp-id-002",
                        "name": "Bob Martinez",
                        "alias": "bob.martinez",
                        "status": "ACTIVE",
                        "isActive": True,
                        "accountCount": 12,
                        "entitlementCount": 65,
                    },
                    {
                        "id": "sp-id-003",
                        "name": "Carol Park",
                        "alias": "carol.park",
                        "status": "ACTIVE",
                        "isActive": True,
                        "accountCount": 3,
                        "entitlementCount": 15,
                    },
                    {
                        "id": "sp-id-004",
                        "name": "Dave Thompson",
                        "alias": "dave.thompson",
                        "status": "INACTIVE",
                        "isActive": False,
                        "accountCount": 4,
                        "entitlementCount": 18,
                    },
                ],
            },
        ))

        # Certifications: completed, overdue, low-completion, not started
        result.events.append(RawEventData(
            source="sailpoint", source_type=SourceType.IAM, provider="sailpoint",
            event_type="sailpoint_certifications",
            raw_data={
                "tenant": "acme-prod",
                "response": [
                    {
                        "id": "cert-001",
                        "name": "Q1 2026 Access Review - Engineering",
                        "status": "COMPLETED",
                        "type": "IDENTITY",
                        "deadline": (NOW - timedelta(days=10)).isoformat(),
                        "completedCount": 45,
                        "totalCount": 45,
                    },
                    {
                        "id": "cert-002",
                        "name": "Q1 2026 Access Review - Finance",
                        "status": "ACTIVE",
                        "type": "IDENTITY",
                        "deadline": (NOW - timedelta(days=5)).isoformat(),
                        "completedCount": 8,
                        "totalCount": 30,
                    },
                    {
                        "id": "cert-003",
                        "name": "Privileged Access Certification",
                        "status": "ACTIVE",
                        "type": "ROLE_COMPOSITION",
                        "deadline": (NOW + timedelta(days=14)).isoformat(),
                        "completedCount": 3,
                        "totalCount": 20,
                    },
                    {
                        "id": "cert-004",
                        "name": "Q2 2026 SOX Certification",
                        "status": "STAGED",
                        "type": "IDENTITY",
                        "deadline": (NOW + timedelta(days=60)).isoformat(),
                        "completedCount": 0,
                        "totalCount": 50,
                    },
                ],
            },
        ))

        # Roles
        result.events.append(RawEventData(
            source="sailpoint", source_type=SourceType.IAM, provider="sailpoint",
            event_type="sailpoint_roles",
            raw_data={
                "tenant": "acme-prod",
                "response": [
                    {
                        "id": "role-001",
                        "name": "Engineering - Developer",
                        "requestable": True,
                        "enabled": True,
                        "membershipCount": 35,
                    },
                    {
                        "id": "role-002",
                        "name": "Finance - Analyst",
                        "requestable": True,
                        "enabled": True,
                        "membershipCount": 12,
                    },
                    {
                        "id": "role-003",
                        "name": "Deprecated - Legacy Admin",
                        "requestable": False,
                        "enabled": False,
                        "membershipCount": 0,
                    },
                ],
            },
        ))

        # Entitlements: privileged with owner, privileged without owner, normal
        result.events.append(RawEventData(
            source="sailpoint", source_type=SourceType.IAM, provider="sailpoint",
            event_type="sailpoint_entitlements",
            raw_data={
                "tenant": "acme-prod",
                "response": [
                    {
                        "id": "ent-001",
                        "name": "AWS-Admin-FullAccess",
                        "source": {"name": "AWS Production"},
                        "privileged": True,
                        "owner": {"name": "Frank Torres", "id": "sp-id-006"},
                    },
                    {
                        "id": "ent-002",
                        "name": "DB-Root-Access",
                        "source": {"name": "Prod Database"},
                        "privileged": True,
                        "owner": {},
                    },
                    {
                        "id": "ent-003",
                        "name": "Jira-User",
                        "source": {"name": "Jira Cloud"},
                        "privileged": False,
                        "owner": {"name": "Bob Martinez", "id": "sp-id-002"},
                    },
                    {
                        "id": "ent-004",
                        "name": "GitHub-OrgOwner",
                        "source": {"name": "GitHub Enterprise"},
                        "privileged": True,
                        "owner": {},
                    },
                ],
            },
        ))

        # Accounts: correlated, orphan, disabled-with-identity
        result.events.append(RawEventData(
            source="sailpoint", source_type=SourceType.IAM, provider="sailpoint",
            event_type="sailpoint_accounts",
            raw_data={
                "tenant": "acme-prod",
                "response": [
                    {
                        "id": "acct-001",
                        "name": "alice.chen",
                        "sourceName": "Active Directory",
                        "identityId": "sp-id-001",
                        "disabled": False,
                        "uncorrelated": False,
                    },
                    {
                        "id": "acct-002",
                        "name": "svc-etl-legacy",
                        "sourceName": "Active Directory",
                        "identityId": "",
                        "disabled": False,
                        "uncorrelated": True,
                    },
                    {
                        "id": "acct-003",
                        "name": "dave.thompson",
                        "sourceName": "Active Directory",
                        "identityId": "sp-id-004",
                        "disabled": True,
                        "uncorrelated": False,
                    },
                    {
                        "id": "acct-004",
                        "name": "temp-contractor-07",
                        "sourceName": "AWS IAM",
                        "identityId": "",
                        "disabled": False,
                        "uncorrelated": True,
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoVaultConnector(BaseConnector):
    """Simulates Vault collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="vault",
            source_type=SourceType.IAM,
            provider="vault",
        )

        # Secret engines: KV with no max TTL, PKI with max TTL, system/identity
        result.events.append(RawEventData(
            source="vault", source_type=SourceType.IAM, provider="vault",
            event_type="vault_secret_engines",
            raw_data={
                "response": {
                    "secret/": {
                        "type": "kv",
                        "description": "Key-Value secret store",
                        "options": {"version": "2"},
                        "config": {"max_lease_ttl": 0},
                    },
                    "pki/": {
                        "type": "pki",
                        "description": "Internal CA",
                        "options": {},
                        "config": {"max_lease_ttl": 31536000},
                    },
                    "database/": {
                        "type": "database",
                        "description": "Dynamic database credentials",
                        "options": {},
                        "config": {"max_lease_ttl": 0},
                    },
                    "sys/": {
                        "type": "system",
                        "description": "system endpoint",
                        "options": {},
                        "config": {"max_lease_ttl": 0},
                    },
                    "identity/": {
                        "type": "identity",
                        "description": "identity store",
                        "options": {},
                        "config": {"max_lease_ttl": 0},
                    },
                    "cubbyhole/": {
                        "type": "cubbyhole",
                        "description": "per-token secret storage",
                        "options": {},
                        "config": {"max_lease_ttl": 0},
                    },
                },
            },
        ))

        # Auth methods: token only (no MFA-capable method)
        result.events.append(RawEventData(
            source="vault", source_type=SourceType.IAM, provider="vault",
            event_type="vault_auth_methods",
            raw_data={
                "response": {
                    "token/": {
                        "type": "token",
                        "description": "token based credentials",
                        "config": {"default_lease_ttl": 0, "max_lease_ttl": 0},
                    },
                    "approle/": {
                        "type": "approle",
                        "description": "AppRole auth for services",
                        "config": {"default_lease_ttl": 3600, "max_lease_ttl": 14400},
                    },
                },
            },
        ))

        # Policies: default, root, and custom
        result.events.append(RawEventData(
            source="vault", source_type=SourceType.IAM, provider="vault",
            event_type="vault_policies",
            raw_data={
                "response": {
                    "keys": [
                        "default",
                        "root",
                        "acme-app-read",
                        "acme-admin",
                        "acme-pki-issue",
                    ],
                },
            },
        ))

        # Audit devices: file-based audit logging enabled
        result.events.append(RawEventData(
            source="vault", source_type=SourceType.IAM, provider="vault",
            event_type="vault_audit_devices",
            raw_data={
                "response": {
                    "file/": {
                        "type": "file",
                        "description": "File-based audit log",
                        "options": {"file_path": "/var/log/vault/audit.log"},
                    },
                },
            },
        ))

        # Seal status: unsealed, healthy, HA configured
        result.events.append(RawEventData(
            source="vault", source_type=SourceType.IAM, provider="vault",
            event_type="vault_seal_status",
            raw_data={
                "response": {
                    "sealed": False,
                    "initialized": True,
                    "cluster_name": "acme-vault-prod",
                    "cluster_id": "vault-cluster-abc123",
                    "version": "1.15.4",
                    "t": 3,
                    "n": 5,
                    "progress": 0,
                },
            },
        ))

        # Health: active node
        result.events.append(RawEventData(
            source="vault", source_type=SourceType.IAM, provider="vault",
            event_type="vault_health",
            raw_data={
                "response": {
                    "initialized": True,
                    "sealed": False,
                    "standby": False,
                    "performance_standby": False,
                    "replication_performance_mode": "disabled",
                    "replication_dr_mode": "disabled",
                    "server_time_utc": int(NOW.timestamp()),
                    "version": "1.15.4",
                    "cluster_name": "acme-vault-prod",
                    "cluster_id": "vault-cluster-abc123",
                },
            },
        ))

        result.complete()
        return result




# --- Cloud Provider Demo Connectors ---


class DemoAzureConnector(BaseConnector):
    """Simulates Azure collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="azure", source_type=SourceType.CLOUD, provider="azure",
        )

        # Policy compliance: one compliant, one non-compliant with security group
        result.events.append(RawEventData(
            source="azure", source_type=SourceType.CLOUD, provider="azure",
            event_type="policy_compliance",
            raw_data={
                "subscription_id": "sub-acme-prod-001",
                "region": "eastus",
                "response": {"policy_states": [
                    {
                        "compliance_state": "NonCompliant",
                        "policy_definition_name": "require-https-storage",
                        "policy_assignment_name": "acme-security-baseline",
                        "resource_id": "/subscriptions/sub-acme-prod-001/resourceGroups/acme-prod-rg/providers/Microsoft.Storage/storageAccounts/acmelegacydata",
                        "resource_type": "Microsoft.Storage/storageAccounts",
                        "resource_name": "acmelegacydata",
                        "policy_definition_group_names": ["security-baseline"],
                    },
                    {
                        "compliance_state": "Compliant",
                        "policy_definition_name": "require-https-storage",
                        "policy_assignment_name": "acme-security-baseline",
                        "resource_id": "/subscriptions/sub-acme-prod-001/resourceGroups/acme-prod-rg/providers/Microsoft.Storage/storageAccounts/acmeproddata",
                        "resource_type": "Microsoft.Storage/storageAccounts",
                        "resource_name": "acmeproddata",
                        "policy_definition_group_names": ["security-baseline"],
                    },
                    {
                        "compliance_state": "NonCompliant",
                        "policy_definition_name": "deny-public-ip",
                        "policy_assignment_name": "acme-network-policy",
                        "resource_id": "/subscriptions/sub-acme-prod-001/resourceGroups/acme-prod-rg/providers/Microsoft.Compute/virtualMachines/acme-jumpbox",
                        "resource_type": "Microsoft.Compute/virtualMachines",
                        "resource_name": "acme-jumpbox",
                        "policy_definition_group_names": ["network-isolation"],
                    },
                ]},
            },
        ))

        # Defender alerts: one high, one medium
        result.events.append(RawEventData(
            source="azure", source_type=SourceType.CLOUD, provider="azure",
            event_type="defender_alerts",
            raw_data={
                "subscription_id": "sub-acme-prod-001",
                "region": "eastus",
                "response": {"alerts": [
                    {
                        "id": "/subscriptions/sub-acme-prod-001/providers/Microsoft.Security/alerts/alert-001",
                        "properties": {
                            "alertDisplayName": "Suspicious authentication activity",
                            "alertType": "VM_LoginBruteForce",
                            "severity": "High",
                            "description": "Multiple failed login attempts detected on acme-prod-web-01",
                            "status": "Active",
                            "compromisedEntity": "acme-prod-web-01",
                            "intent": "Probing",
                        },
                    },
                    {
                        "id": "/subscriptions/sub-acme-prod-001/providers/Microsoft.Security/alerts/alert-002",
                        "properties": {
                            "alertDisplayName": "Unusual Azure AD sign-in",
                            "alertType": "AzureAD_AnomalousSignIn",
                            "severity": "Medium",
                            "description": "Sign-in from unfamiliar location for bob.martinez@acme.com",
                            "status": "Active",
                            "compromisedEntity": "bob.martinez@acme.com",
                            "intent": "InitialAccess",
                        },
                    },
                ]},
            },
        ))

        # Entra sign-ins: risky sign-in and failed sign-in
        result.events.append(RawEventData(
            source="azure", source_type=SourceType.CLOUD, provider="azure",
            event_type="entra_sign_ins",
            raw_data={
                "subscription_id": "sub-acme-prod-001",
                "region": "eastus",
                "response": {"value": [
                    {
                        "userPrincipalName": "carol.park@acme.com",
                        "userId": "uid-carol-001",
                        "appDisplayName": "Azure Portal",
                        "ipAddress": "198.51.100.42",
                        "location": {"city": "Unknown", "countryOrRegion": "CN"},
                        "riskLevelDuringSignIn": "high",
                        "status": {"errorCode": 0},
                        "conditionalAccessStatus": "notApplied",
                    },
                    {
                        "userPrincipalName": "eve.nakamura@acme.com",
                        "userId": "uid-eve-001",
                        "appDisplayName": "Microsoft Teams",
                        "ipAddress": "203.0.113.15",
                        "location": {"city": "Tokyo", "countryOrRegion": "JP"},
                        "riskLevelDuringSignIn": "none",
                        "status": {"errorCode": 50126, "failureReason": "Invalid username or password"},
                        "conditionalAccessStatus": "notApplied",
                    },
                ]},
            },
        ))

        # Network security groups: one open SSH, one restricted
        result.events.append(RawEventData(
            source="azure", source_type=SourceType.CLOUD, provider="azure",
            event_type="network_security_groups",
            raw_data={
                "subscription_id": "sub-acme-prod-001",
                "region": "eastus",
                "response": {"network_security_groups": [
                    {
                        "name": "acme-jumpbox-nsg",
                        "id": "/subscriptions/sub-acme-prod-001/resourceGroups/acme-prod-rg/providers/Microsoft.Network/networkSecurityGroups/acme-jumpbox-nsg",
                        "security_rules": [
                            {
                                "name": "allow-ssh-any",
                                "direction": "Inbound",
                                "access": "Allow",
                                "source_address_prefix": "0.0.0.0/0",
                                "destination_port_range": "22",
                                "protocol": "Tcp",
                            },
                        ],
                    },
                    {
                        "name": "acme-app-nsg",
                        "id": "/subscriptions/sub-acme-prod-001/resourceGroups/acme-prod-rg/providers/Microsoft.Network/networkSecurityGroups/acme-app-nsg",
                        "security_rules": [
                            {
                                "name": "allow-https-internal",
                                "direction": "Inbound",
                                "access": "Allow",
                                "source_address_prefix": "10.0.0.0/8",
                                "destination_port_range": "443",
                                "protocol": "Tcp",
                            },
                        ],
                    },
                ]},
            },
        ))

        # Key Vault: one compliant, one missing purge protection
        result.events.append(RawEventData(
            source="azure", source_type=SourceType.CLOUD, provider="azure",
            event_type="key_vault",
            raw_data={
                "subscription_id": "sub-acme-prod-001",
                "region": "eastus",
                "response": {"vaults": [
                    {
                        "name": "acme-prod-kv",
                        "id": "/subscriptions/sub-acme-prod-001/resourceGroups/acme-prod-rg/providers/Microsoft.KeyVault/vaults/acme-prod-kv",
                        "properties": {
                            "enable_soft_delete": True,
                            "enable_purge_protection": True,
                        },
                    },
                    {
                        "name": "acme-dev-kv",
                        "id": "/subscriptions/sub-acme-prod-001/resourceGroups/acme-dev-rg/providers/Microsoft.KeyVault/vaults/acme-dev-kv",
                        "properties": {
                            "enable_soft_delete": True,
                            "enable_purge_protection": False,
                        },
                    },
                ]},
            },
        ))

        # Storage accounts: one with public blob access, one compliant
        result.events.append(RawEventData(
            source="azure", source_type=SourceType.CLOUD, provider="azure",
            event_type="storage_accounts",
            raw_data={
                "subscription_id": "sub-acme-prod-001",
                "region": "eastus",
                "response": {"storage_accounts": [
                    {
                        "name": "acmelegacydata",
                        "id": "/subscriptions/sub-acme-prod-001/resourceGroups/acme-prod-rg/providers/Microsoft.Storage/storageAccounts/acmelegacydata",
                        "properties": {
                            "supports_https_traffic_only": False,
                            "encryption": {"require_infrastructure_encryption": False},
                            "network_rule_set": {"default_action": "Allow"},
                            "allow_blob_public_access": True,
                        },
                    },
                    {
                        "name": "acmeproddata",
                        "id": "/subscriptions/sub-acme-prod-001/resourceGroups/acme-prod-rg/providers/Microsoft.Storage/storageAccounts/acmeproddata",
                        "properties": {
                            "supports_https_traffic_only": True,
                            "encryption": {"require_infrastructure_encryption": True},
                            "network_rule_set": {"default_action": "Deny"},
                            "allow_blob_public_access": False,
                        },
                    },
                ]},
            },
        ))

        # Activity log: error-level operation
        result.events.append(RawEventData(
            source="azure", source_type=SourceType.CLOUD, provider="azure",
            event_type="activity_log",
            raw_data={
                "subscription_id": "sub-acme-prod-001",
                "region": "eastus",
                "response": {"activity_logs": [
                    {
                        "level": "Error",
                        "operation_name": {"value": "Microsoft.Authorization/roleAssignments/write"},
                        "caller": "dave.thompson@acme.com",
                        "status": {"value": "Failed"},
                        "resource_id": "/subscriptions/sub-acme-prod-001/resourceGroups/acme-prod-rg",
                        "event_timestamp": NOW.isoformat(),
                    },
                    {
                        "level": "Warning",
                        "operation_name": {"value": "Microsoft.Compute/virtualMachines/delete"},
                        "caller": "bob.martinez@acme.com",
                        "status": {"value": "Succeeded"},
                        "resource_id": "/subscriptions/sub-acme-prod-001/resourceGroups/acme-dev-rg/providers/Microsoft.Compute/virtualMachines/acme-test-vm",
                        "event_timestamp": (NOW - timedelta(hours=3)).isoformat(),
                    },
                ]},
            },
        ))

        # Monitor alerts: one Sev1
        result.events.append(RawEventData(
            source="azure", source_type=SourceType.CLOUD, provider="azure",
            event_type="monitor_alerts",
            raw_data={
                "subscription_id": "sub-acme-prod-001",
                "region": "eastus",
                "response": {"alerts": [
                    {
                        "id": "/subscriptions/sub-acme-prod-001/providers/Microsoft.AlertsManagement/alerts/mon-alert-001",
                        "properties": {
                            "severity": "Sev1",
                            "alert_rule": "acme-prod-cpu-critical",
                            "monitor_condition": "Fired",
                            "target_resource": "/subscriptions/sub-acme-prod-001/resourceGroups/acme-prod-rg/providers/Microsoft.Compute/virtualMachines/acme-prod-api-01",
                            "target_resource_type": "Microsoft.Compute/virtualMachines",
                            "signal_type": "Metric",
                            "description": "CPU utilization exceeded 95% for 10 minutes",
                        },
                    },
                ]},
            },
        ))

        result.complete()
        return result


class DemoGCPConnector(BaseConnector):
    """Simulates GCP collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="gcp", source_type=SourceType.CLOUD, provider="gcp",
        )

        # SCC findings: one active misconfiguration, one active threat, one inactive
        result.events.append(RawEventData(
            source="gcp", source_type=SourceType.CLOUD, provider="gcp",
            event_type="scc_findings",
            raw_data={
                "project_id": "acme-gcp-project-01",
                "region": "us-central1",
                "response": {"findings": [
                    {
                        "category": "PUBLIC_BUCKET_ACL",
                        "severity": "HIGH",
                        "state": "ACTIVE",
                        "finding_class": "MISCONFIGURATION",
                        "resource_name": "//storage.googleapis.com/projects/acme-gcp-project-01/buckets/acme-public-uploads",
                        "source_properties": {"explanation": "Bucket has public ACL granting allUsers read access"},
                        "external_uri": "https://console.cloud.google.com/storage/browser/acme-public-uploads",
                        "description": "Cloud Storage bucket has public ACL",
                    },
                    {
                        "category": "MALWARE_DETECTED",
                        "severity": "CRITICAL",
                        "state": "ACTIVE",
                        "finding_class": "THREAT",
                        "resource_name": "//compute.googleapis.com/projects/acme-gcp-project-01/zones/us-central1-a/instances/acme-staging-worker-03",
                        "source_properties": {"malware_family": "Trojan.GenericKD"},
                        "external_uri": "",
                        "description": "Malware detected on Compute Engine instance",
                    },
                    {
                        "category": "OPEN_FIREWALL",
                        "severity": "MEDIUM",
                        "state": "INACTIVE",
                        "finding_class": "MISCONFIGURATION",
                        "resource_name": "//compute.googleapis.com/projects/acme-gcp-project-01/global/firewalls/allow-all-test",
                        "source_properties": {},
                        "external_uri": "",
                        "description": "Resolved: overly permissive firewall rule",
                    },
                ]},
            },
        ))

        # IAM policies: one risky owner binding, one safe viewer binding
        result.events.append(RawEventData(
            source="gcp", source_type=SourceType.CLOUD, provider="gcp",
            event_type="iam_policies",
            raw_data={
                "project_id": "acme-gcp-project-01",
                "region": "global",
                "response": {"bindings": [
                    {
                        "role": "roles/owner",
                        "members": [
                            "user:alice.chen@acme.com",
                            "user:bob.martinez@acme.com",
                            "serviceAccount:terraform@acme-gcp-project-01.iam.gserviceaccount.com",
                        ],
                    },
                    {
                        "role": "roles/viewer",
                        "members": [
                            "group:eng-team@acme.com",
                            "serviceAccount:monitoring@acme-gcp-project-01.iam.gserviceaccount.com",
                        ],
                    },
                    {
                        "role": "roles/editor",
                        "members": [
                            "allAuthenticatedUsers",
                        ],
                    },
                ]},
            },
        ))

        # Firewall rules: one open SSH, one restricted
        result.events.append(RawEventData(
            source="gcp", source_type=SourceType.CLOUD, provider="gcp",
            event_type="compute_firewall_rules",
            raw_data={
                "project_id": "acme-gcp-project-01",
                "region": "global",
                "response": {"firewall_rules": [
                    {
                        "name": "acme-allow-ssh-any",
                        "direction": "INGRESS",
                        "disabled": False,
                        "source_ranges": ["0.0.0.0/0"],
                        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                        "self_link": "projects/acme-gcp-project-01/global/firewalls/acme-allow-ssh-any",
                    },
                    {
                        "name": "acme-allow-https-internal",
                        "direction": "INGRESS",
                        "disabled": False,
                        "source_ranges": ["10.0.0.0/8"],
                        "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
                        "self_link": "projects/acme-gcp-project-01/global/firewalls/acme-allow-https-internal",
                    },
                    {
                        "name": "acme-disabled-rule",
                        "direction": "INGRESS",
                        "disabled": True,
                        "source_ranges": ["0.0.0.0/0"],
                        "allowed": [{"IPProtocol": "tcp", "ports": ["3389"]}],
                        "self_link": "projects/acme-gcp-project-01/global/firewalls/acme-disabled-rule",
                    },
                ]},
            },
        ))

        # Storage buckets: one without versioning, one compliant
        result.events.append(RawEventData(
            source="gcp", source_type=SourceType.CLOUD, provider="gcp",
            event_type="storage_buckets",
            raw_data={
                "project_id": "acme-gcp-project-01",
                "region": "us-central1",
                "response": {"buckets": [
                    {
                        "name": "acme-prod-backups",
                        "versioning_enabled": True,
                        "iam_configuration": {"uniform_bucket_level_access_enabled": True},
                    },
                    {
                        "name": "acme-staging-uploads",
                        "versioning_enabled": False,
                        "iam_configuration": {"uniform_bucket_level_access_enabled": False},
                    },
                ]},
            },
        ))

        # Audit logs: one error, one warning
        result.events.append(RawEventData(
            source="gcp", source_type=SourceType.CLOUD, provider="gcp",
            event_type="audit_logs",
            raw_data={
                "project_id": "acme-gcp-project-01",
                "region": "global",
                "response": {"log_entries": [
                    {
                        "severity": "ERROR",
                        "log_name": "projects/acme-gcp-project-01/logs/cloudaudit.googleapis.com%2Factivity",
                        "resource": {
                            "type": "gce_instance",
                            "labels": {"project_id": "acme-gcp-project-01", "instance_id": "i-acme-staging-03"},
                        },
                        "payload": {"methodName": "v1.compute.instances.delete", "status": {"code": 7, "message": "PERMISSION_DENIED"}},
                        "timestamp": NOW.isoformat(),
                    },
                    {
                        "severity": "WARNING",
                        "log_name": "projects/acme-gcp-project-01/logs/cloudaudit.googleapis.com%2Fdata_access",
                        "resource": {
                            "type": "bigquery_dataset",
                            "labels": {"project_id": "acme-gcp-project-01", "dataset_id": "customer_analytics"},
                        },
                        "payload": {"methodName": "google.cloud.bigquery.v2.JobService.InsertJob"},
                        "timestamp": (NOW - timedelta(hours=1)).isoformat(),
                    },
                ]},
            },
        ))

        # GKE clusters: one with legacy ABAC, one compliant
        result.events.append(RawEventData(
            source="gcp", source_type=SourceType.CLOUD, provider="gcp",
            event_type="gke_clusters",
            raw_data={
                "project_id": "acme-gcp-project-01",
                "region": "us-central1",
                "response": {"clusters": [
                    {
                        "name": "acme-prod-cluster",
                        "location": "us-central1",
                        "legacy_abac": {"enabled": False},
                        "master_authorized_networks_config": {"enabled": True},
                        "network_policy": {"enabled": True},
                        "binary_authorization": {"enabled": True},
                        "shielded_nodes": {"enabled": True},
                        "self_link": "projects/acme-gcp-project-01/locations/us-central1/clusters/acme-prod-cluster",
                    },
                    {
                        "name": "acme-dev-cluster",
                        "location": "us-central1",
                        "legacy_abac": {"enabled": True},
                        "master_authorized_networks_config": {"enabled": False},
                        "network_policy": {"enabled": False},
                        "binary_authorization": {"enabled": False},
                        "shielded_nodes": {"enabled": False},
                        "self_link": "projects/acme-gcp-project-01/locations/us-central1/clusters/acme-dev-cluster",
                    },
                ]},
            },
        ))

        result.complete()
        return result


class DemoDigitalOceanConnector(BaseConnector):
    """Simulates DigitalOcean collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="digitalocean", source_type=SourceType.CLOUD, provider="digitalocean",
        )

        # Firewalls: one open SSH, one restricted
        result.events.append(RawEventData(
            source="digitalocean", source_type=SourceType.CLOUD, provider="digitalocean",
            event_type="do_firewalls",
            raw_data={
                "response": [
                    {
                        "id": "fw-acme-bastion-001",
                        "name": "acme-bastion-fw",
                        "droplet_ids": [301001, 301002],
                        "inbound_rules": [
                            {
                                "protocol": "tcp",
                                "ports": "22",
                                "sources": {"addresses": ["0.0.0.0/0", "::/0"]},
                            },
                        ],
                    },
                    {
                        "id": "fw-acme-web-001",
                        "name": "acme-web-fw",
                        "droplet_ids": [301003, 301004],
                        "inbound_rules": [
                            {
                                "protocol": "tcp",
                                "ports": "443",
                                "sources": {"addresses": ["0.0.0.0/0"]},
                            },
                        ],
                    },
                ],
            },
        ))

        # Droplets: one public without backups, one compliant
        result.events.append(RawEventData(
            source="digitalocean", source_type=SourceType.CLOUD, provider="digitalocean",
            event_type="do_droplets",
            raw_data={
                "response": [
                    {
                        "id": 301001,
                        "name": "acme-bastion-01",
                        "networks": {"v4": [{"type": "public", "ip_address": "198.51.100.10"}]},
                        "backup_ids": [],
                        "features": [],
                        "region": {"slug": "nyc1"},
                    },
                    {
                        "id": 301003,
                        "name": "acme-web-01",
                        "networks": {"v4": [
                            {"type": "public", "ip_address": "198.51.100.20"},
                            {"type": "private", "ip_address": "10.132.0.5"},
                        ]},
                        "backup_ids": [55001],
                        "features": ["backups", "monitoring"],
                        "region": {"slug": "nyc1"},
                    },
                ],
            },
        ))

        # Spaces: inventory
        result.events.append(RawEventData(
            source="digitalocean", source_type=SourceType.CLOUD, provider="digitalocean",
            event_type="do_spaces",
            raw_data={
                "response": [
                    {"name": "acme-cdn-assets", "region": {"slug": "nyc3"}},
                    {"name": "acme-backup-archives", "region": {"slug": "sfo3"}},
                ],
            },
        ))

        # Databases: one publicly accessible, one compliant
        result.events.append(RawEventData(
            source="digitalocean", source_type=SourceType.CLOUD, provider="digitalocean",
            event_type="do_databases",
            raw_data={
                "response": [
                    {
                        "id": "db-acme-legacy-001",
                        "name": "acme-legacy-mysql",
                        "engine": "mysql",
                        "version": "8.0",
                        "num_nodes": 1,
                        "region": "nyc1",
                        "rules": [{"type": "ip_addr", "value": "0.0.0.0/0"}],
                        "connection": {"ssl": False, "uri": "mysql://..."},
                        "private_connection": {},
                    },
                    {
                        "id": "db-acme-prod-001",
                        "name": "acme-prod-postgres",
                        "engine": "pg",
                        "version": "16",
                        "num_nodes": 3,
                        "region": "nyc1",
                        "rules": [{"type": "ip_addr", "value": "10.132.0.0/16"}],
                        "connection": {"ssl": True, "uri": "postgresql://..."},
                        "private_connection": {"ssl": True},
                    },
                ],
            },
        ))

        # Kubernetes: one without auto_upgrade, one compliant
        result.events.append(RawEventData(
            source="digitalocean", source_type=SourceType.CLOUD, provider="digitalocean",
            event_type="do_kubernetes",
            raw_data={
                "response": [
                    {
                        "id": "k8s-acme-prod-001",
                        "name": "acme-prod-doks",
                        "auto_upgrade": True,
                        "surge_upgrade": True,
                        "version_slug": "1.30.1-do.0",
                        "region": "nyc1",
                        "ha": True,
                        "node_pools": [{"name": "pool-web", "count": 3}],
                    },
                    {
                        "id": "k8s-acme-dev-001",
                        "name": "acme-dev-doks",
                        "auto_upgrade": False,
                        "surge_upgrade": False,
                        "version_slug": "1.28.2-do.0",
                        "region": "sfo3",
                        "ha": False,
                        "node_pools": [{"name": "pool-dev", "count": 1}],
                    },
                ],
            },
        ))

        # Load Balancers: one without HTTPS redirect
        result.events.append(RawEventData(
            source="digitalocean", source_type=SourceType.CLOUD, provider="digitalocean",
            event_type="do_load_balancers",
            raw_data={
                "response": [
                    {
                        "id": "lb-acme-web-001",
                        "name": "acme-web-lb",
                        "redirect_http_to_https": False,
                        "sticky_sessions": {"type": "none"},
                        "forwarding_rules": [
                            {"entry_protocol": "http", "entry_port": 80, "target_protocol": "http", "target_port": 80},
                            {"entry_protocol": "https", "entry_port": 443, "target_protocol": "http", "target_port": 80},
                        ],
                        "droplet_ids": [301003, 301004],
                        "region": {"slug": "nyc1"},
                    },
                ],
            },
        ))

        # Domains: inventory
        result.events.append(RawEventData(
            source="digitalocean", source_type=SourceType.CLOUD, provider="digitalocean",
            event_type="do_domains",
            raw_data={
                "response": [
                    {"name": "acme-corp.io", "ttl": 1800, "zone_file": "$ORIGIN acme-corp.io."},
                    {"name": "acme-internal.dev", "ttl": 300, "zone_file": "$ORIGIN acme-internal.dev."},
                ],
            },
        ))

        result.complete()
        return result


class DemoAlibabaConnector(BaseConnector):
    """Simulates Alibaba Cloud collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="alibaba", source_type=SourceType.CLOUD, provider="alibaba",
        )

        # Security Center alerts
        result.events.append(RawEventData(
            source="alibaba", source_type=SourceType.CLOUD, provider="alibaba",
            event_type="ali_security_alerts",
            raw_data={
                "region": "cn-hangzhou",
                "response": {"alerts": [
                    {
                        "Level": "serious",
                        "AlarmEventName": "Suspicious process execution",
                        "AlarmEventType": "Malicious Process",
                        "Name": "CryptoMiner detected",
                        "InstanceName": "acme-prod-worker-01",
                        "InstanceId": "i-acme-cn-prod-001",
                        "InternetIp": "47.98.100.10",
                        "IntranetIp": "172.16.0.10",
                        "Description": "Cryptocurrency mining process detected",
                        "Solution": "Terminate the process and investigate the entry point",
                        "CanCancelFault": False,
                        "Uuid": "alert-uuid-001",
                    },
                    {
                        "Level": "remind",
                        "AlarmEventName": "Unusual outbound connection",
                        "AlarmEventType": "Network Anomaly",
                        "Name": "Outbound connection to suspicious IP",
                        "InstanceName": "acme-staging-api-01",
                        "InstanceId": "i-acme-cn-staging-002",
                        "InternetIp": "47.98.100.20",
                        "IntranetIp": "172.16.0.20",
                        "Description": "Outbound connection to known C2 server",
                        "Solution": "Block the IP and review the process",
                        "CanCancelFault": True,
                        "Uuid": "alert-uuid-002",
                    },
                ]},
            },
        ))

        # RAM users: one without MFA, one stale, one compliant
        result.events.append(RawEventData(
            source="alibaba", source_type=SourceType.CLOUD, provider="alibaba",
            event_type="ali_ram_users",
            raw_data={
                "region": "cn-hangzhou",
                "response": {"users": [
                    {
                        "UserName": "alice.chen",
                        "UserId": "ram-uid-001",
                        "DisplayName": "Alice Chen",
                        "CreateDate": "2024-01-15T00:00:00Z",
                        "LastLoginDate": (NOW - timedelta(hours=5)).isoformat() + "Z",
                        "MFADevice": {"SerialNumber": "acs:ram::mfa/alice-virt-mfa"},
                    },
                    {
                        "UserName": "svc-deploy",
                        "UserId": "ram-uid-002",
                        "DisplayName": "Deploy Service Account",
                        "CreateDate": "2023-06-01T00:00:00Z",
                        "LastLoginDate": "",
                        "MFADevice": {},
                    },
                    {
                        "UserName": "bob.martinez",
                        "UserId": "ram-uid-003",
                        "DisplayName": "Bob Martinez",
                        "CreateDate": "2023-11-01T00:00:00Z",
                        "LastLoginDate": (NOW - timedelta(days=120)).isoformat() + "Z",
                        "MFADevice": {"SerialNumber": "acs:ram::mfa/bob-virt-mfa"},
                    },
                ]},
            },
        ))

        # ActionTrail: privilege escalation event and error event
        result.events.append(RawEventData(
            source="alibaba", source_type=SourceType.CLOUD, provider="alibaba",
            event_type="ali_actiontrail_events",
            raw_data={
                "region": "cn-hangzhou",
                "response": {"events": [
                    {
                        "eventName": "AttachPolicyToUser",
                        "eventSource": "ram.aliyuncs.com",
                        "eventTime": NOW.isoformat(),
                        "errorCode": "",
                        "errorMessage": "",
                        "userIdentity": {"principalId": "ram-uid-003", "userName": "bob.martinez"},
                        "sourceIpAddress": "203.0.113.50",
                        "userAgent": "aliyun-sdk-go/1.0",
                        "requestParameters": {"PolicyName": "AdministratorAccess", "UserName": "svc-deploy"},
                        "resourceId": "ram-uid-002",
                        "resourceType": "ram:User",
                        "accountId": "acme-alibaba-001",
                    },
                    {
                        "eventName": "DescribeInstances",
                        "eventSource": "ecs.aliyuncs.com",
                        "eventTime": (NOW - timedelta(minutes=30)).isoformat(),
                        "errorCode": "Forbidden",
                        "errorMessage": "User not authorized to perform ecs:DescribeInstances",
                        "userIdentity": {"principalId": "ram-uid-002", "userName": "svc-deploy"},
                        "sourceIpAddress": "172.16.0.10",
                        "userAgent": "aliyun-sdk-python/3.0",
                        "requestParameters": {},
                        "resourceId": "",
                        "resourceType": "ecs:Instance",
                        "accountId": "acme-alibaba-001",
                    },
                ]},
            },
        ))

        # Security groups: one open all ports, one restricted
        result.events.append(RawEventData(
            source="alibaba", source_type=SourceType.CLOUD, provider="alibaba",
            event_type="ali_security_groups",
            raw_data={
                "region": "cn-hangzhou",
                "response": {"security_groups": [
                    {
                        "SecurityGroupId": "sg-acme-legacy-001",
                        "SecurityGroupName": "acme-legacy-sg",
                        "VpcId": "vpc-acme-cn-001",
                        "Rules": [
                            {
                                "Direction": "ingress",
                                "SourceCidrIp": "0.0.0.0/0",
                                "PortRange": "1/65535",
                                "Policy": "Accept",
                                "IpProtocol": "tcp",
                            },
                        ],
                    },
                    {
                        "SecurityGroupId": "sg-acme-prod-001",
                        "SecurityGroupName": "acme-prod-sg",
                        "VpcId": "vpc-acme-cn-001",
                        "Rules": [
                            {
                                "Direction": "ingress",
                                "SourceCidrIp": "10.0.0.0/8",
                                "PortRange": "443/443",
                                "Policy": "Accept",
                                "IpProtocol": "tcp",
                            },
                        ],
                    },
                ]},
            },
        ))

        # KMS keys: one with rotation disabled, one pending deletion
        result.events.append(RawEventData(
            source="alibaba", source_type=SourceType.CLOUD, provider="alibaba",
            event_type="ali_kms_keys",
            raw_data={
                "region": "cn-hangzhou",
                "response": {"keys": [
                    {
                        "KeyId": "kms-acme-prod-001",
                        "KeyMetadata": {
                            "KeyState": "Enabled",
                            "Creator": "alice.chen",
                            "Description": "Acme production encryption key",
                            "KeyUsage": "ENCRYPT/DECRYPT",
                            "AutomaticRotation": "Disabled",
                            "CreationDate": "2024-01-15T00:00:00Z",
                            "Origin": "Aliyun_KMS",
                            "KeySpec": "Aliyun_AES_256",
                        },
                    },
                    {
                        "KeyId": "kms-acme-legacy-001",
                        "KeyMetadata": {
                            "KeyState": "PendingDeletion",
                            "Creator": "dave.thompson",
                            "Description": "Legacy key scheduled for removal",
                            "KeyUsage": "ENCRYPT/DECRYPT",
                            "AutomaticRotation": "",
                            "CreationDate": "2022-06-01T00:00:00Z",
                            "DeleteDate": (NOW + timedelta(days=7)).isoformat() + "Z",
                            "Origin": "Aliyun_KMS",
                            "KeySpec": "Aliyun_AES_256",
                        },
                    },
                ]},
            },
        ))

        # Config compliance: one non-compliant, one compliant
        result.events.append(RawEventData(
            source="alibaba", source_type=SourceType.CLOUD, provider="alibaba",
            event_type="ali_config_compliance",
            raw_data={
                "region": "cn-hangzhou",
                "response": {"results": [
                    {
                        "ComplianceType": "NON_COMPLIANT",
                        "ResourceId": "i-acme-cn-prod-001",
                        "ResourceType": "ACS::ECS::Instance",
                        "RiskLevel": 1,
                        "ConfigRuleName": "ecs-instance-no-public-ip",
                        "ConfigRuleId": "cr-acme-001",
                        "Annotation": "ECS instance has a public IP address assigned",
                        "InvocationTime": NOW.isoformat(),
                    },
                    {
                        "ComplianceType": "COMPLIANT",
                        "ResourceId": "i-acme-cn-prod-002",
                        "ResourceType": "ACS::ECS::Instance",
                        "RiskLevel": 1,
                        "ConfigRuleName": "ecs-instance-no-public-ip",
                        "ConfigRuleId": "cr-acme-001",
                        "Annotation": "",
                        "InvocationTime": NOW.isoformat(),
                    },
                ]},
            },
        ))

        # OSS buckets: one public-read-write, one encrypted and private
        result.events.append(RawEventData(
            source="alibaba", source_type=SourceType.CLOUD, provider="alibaba",
            event_type="ali_oss_buckets",
            raw_data={
                "region": "cn-hangzhou",
                "response": {"buckets": [
                    {
                        "Name": "acme-public-uploads",
                        "Location": "oss-cn-hangzhou",
                        "CreationDate": "2023-03-10T00:00:00Z",
                        "ACL": {"Grant": "public-read-write"},
                        "Encryption": {},
                    },
                    {
                        "Name": "acme-prod-data",
                        "Location": "oss-cn-hangzhou",
                        "CreationDate": "2023-01-05T00:00:00Z",
                        "ACL": {"Grant": "private"},
                        "Encryption": {"SSEAlgorithm": "AES256"},
                    },
                ]},
            },
        ))

        result.complete()
        return result


class DemoHuaweiConnector(BaseConnector):
    """Simulates Huawei Cloud collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="huawei", source_type=SourceType.CLOUD, provider="huawei",
        )

        # HSS events: one critical, one low
        result.events.append(RawEventData(
            source="huawei", source_type=SourceType.CLOUD, provider="huawei",
            event_type="huawei_hss_events",
            raw_data={
                "project_id": "acme-huawei-proj-01",
                "region": "cn-north-4",
                "response": {"events": [
                    {
                        "event_name": "Reverse shell detected",
                        "event_type": "backdoor",
                        "severity": "Critical",
                        "host_name": "acme-prod-app-01",
                        "host_id": "hid-acme-001",
                        "occur_time": NOW.isoformat(),
                        "description": "Reverse shell connection to external IP",
                        "handle_status": "unhandled",
                        "operate_detail": {"source_ip": "198.51.100.99"},
                    },
                    {
                        "event_name": "Weak password detected",
                        "event_type": "weak_password",
                        "severity": "Low",
                        "host_name": "acme-staging-db-01",
                        "host_id": "hid-acme-002",
                        "occur_time": (NOW - timedelta(hours=6)).isoformat(),
                        "description": "SSH user has weak password",
                        "handle_status": "unhandled",
                        "operate_detail": {"user": "deploy"},
                    },
                ]},
            },
        ))

        # IAM users: one without MFA, one stale, one compliant
        result.events.append(RawEventData(
            source="huawei", source_type=SourceType.CLOUD, provider="huawei",
            event_type="huawei_iam_users",
            raw_data={
                "project_id": "acme-huawei-proj-01",
                "region": "cn-north-4",
                "response": {"users": [
                    {
                        "name": "alice.chen",
                        "id": "hw-uid-001",
                        "enabled": True,
                        "mfa_device": {"serial_number": "hw-mfa-001"},
                        "pwd_status": True,
                        "last_login_time": (NOW - timedelta(hours=2)).isoformat() + "Z",
                    },
                    {
                        "name": "svc-cicd",
                        "id": "hw-uid-002",
                        "enabled": True,
                        "mfa_device": None,
                        "pwd_status": True,
                        "last_login_time": (NOW - timedelta(days=1)).isoformat() + "Z",
                    },
                    {
                        "name": "dave.thompson",
                        "id": "hw-uid-003",
                        "enabled": False,
                        "mfa_device": None,
                        "pwd_status": False,
                        "last_login_time": (NOW - timedelta(days=180)).isoformat() + "Z",
                    },
                ]},
            },
        ))

        # CTS events: one error trace, one normal (skipped)
        result.events.append(RawEventData(
            source="huawei", source_type=SourceType.CLOUD, provider="huawei",
            event_type="huawei_cts_events",
            raw_data={
                "project_id": "acme-huawei-proj-01",
                "region": "cn-north-4",
                "response": {"traces": [
                    {
                        "trace_name": "deleteSecurityGroup",
                        "trace_status": "error",
                        "service_type": "VPC",
                        "resource_type": "security_group",
                        "resource_name": "acme-prod-sg",
                        "resource_id": "sg-hw-acme-001",
                        "user": {"name": "bob.martinez", "id": "hw-uid-004"},
                        "trace_id": "trace-hw-001",
                        "record_time": NOW.isoformat(),
                        "request": {"security_group_id": "sg-hw-acme-001"},
                        "code": "403",
                    },
                    {
                        "trace_name": "listInstances",
                        "trace_status": "normal",
                        "service_type": "ECS",
                        "resource_type": "instance",
                        "resource_name": "",
                        "resource_id": "",
                        "user": {"name": "alice.chen"},
                        "trace_id": "trace-hw-002",
                        "record_time": NOW.isoformat(),
                        "request": {},
                        "code": "200",
                    },
                ]},
            },
        ))

        # Security groups: one open SSH, one restricted
        result.events.append(RawEventData(
            source="huawei", source_type=SourceType.CLOUD, provider="huawei",
            event_type="huawei_security_groups",
            raw_data={
                "project_id": "acme-huawei-proj-01",
                "region": "cn-north-4",
                "response": {"security_groups": [
                    {
                        "name": "acme-bastion-sg",
                        "id": "sg-hw-bastion-001",
                        "security_group_rules": [
                            {
                                "direction": "ingress",
                                "remote_ip_prefix": "0.0.0.0/0",
                                "protocol": "tcp",
                                "port_range_min": 22,
                                "port_range_max": 22,
                            },
                        ],
                    },
                    {
                        "name": "acme-app-sg",
                        "id": "sg-hw-app-001",
                        "security_group_rules": [
                            {
                                "direction": "ingress",
                                "remote_ip_prefix": "10.0.0.0/8",
                                "protocol": "tcp",
                                "port_range_min": 443,
                                "port_range_max": 443,
                            },
                        ],
                    },
                ]},
            },
        ))

        # KMS keys: one enabled without rotation, one disabled
        result.events.append(RawEventData(
            source="huawei", source_type=SourceType.CLOUD, provider="huawei",
            event_type="huawei_kms_keys",
            raw_data={
                "project_id": "acme-huawei-proj-01",
                "region": "cn-north-4",
                "response": {
                    "keys": ["kms-hw-001", "kms-hw-002"],
                    "key_details": [
                        {
                            "key_id": "kms-hw-001",
                            "key_alias": "acme-prod-data-key",
                            "key_state": "2",
                            "key_type": "AES_256",
                            "creation_date": "2024-03-01T00:00:00Z",
                            "rotation_enabled": False,
                            "key_rotation_interval": 0,
                        },
                        {
                            "key_id": "kms-hw-002",
                            "key_alias": "acme-legacy-key",
                            "key_state": "3",
                            "key_type": "AES_256",
                            "creation_date": "2022-06-01T00:00:00Z",
                            "rotation_enabled": False,
                            "key_rotation_interval": 0,
                        },
                    ],
                },
            },
        ))

        # OBS buckets: one with public ACL, one compliant
        result.events.append(RawEventData(
            source="huawei", source_type=SourceType.CLOUD, provider="huawei",
            event_type="huawei_obs_buckets",
            raw_data={
                "project_id": "acme-huawei-proj-01",
                "region": "cn-north-4",
                "response": {"buckets": [
                    {
                        "name": "acme-public-assets",
                        "location": "cn-north-4",
                        "creation_date": "2023-05-10T00:00:00Z",
                        "acl": {
                            "grants": [
                                {
                                    "grantee": {"uri": "http://acs.amazonaws.com/groups/global/AllUsers", "type": "Group"},
                                    "permission": "READ",
                                },
                            ],
                        },
                        "versioning": "Suspended",
                        "logging_enabled": False,
                    },
                    {
                        "name": "acme-prod-backups",
                        "location": "cn-north-4",
                        "creation_date": "2023-01-15T00:00:00Z",
                        "acl": {
                            "grants": [
                                {
                                    "grantee": {"uri": "", "type": "CanonicalUser", "id": "acme-owner-id"},
                                    "permission": "FULL_CONTROL",
                                },
                            ],
                        },
                        "versioning": "Enabled",
                        "logging_enabled": True,
                    },
                ]},
            },
        ))

        result.complete()
        return result


class DemoIBMCloudConnector(BaseConnector):
    """Simulates IBM Cloud collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="ibm_cloud", source_type=SourceType.CLOUD, provider="ibm_cloud",
        )

        # Security findings: one high vulnerability, one misconfiguration
        result.events.append(RawEventData(
            source="ibm_cloud", source_type=SourceType.CLOUD, provider="ibm_cloud",
            event_type="ibm_security_findings",
            raw_data={
                "account_id": "acme-ibm-account-001",
                "region": "us-south",
                "response": {"occurrences": [
                    {
                        "kind": "FINDING",
                        "finding": {
                            "severity": "HIGH",
                            "next_steps": [{"title": "Rotate exposed credentials"}],
                        },
                        "note_name": "providers/security-advisor/notes/exposed-credentials",
                        "resource_url": "crn:v1:bluemix:public:cloud-object-storage:us-south:a/acme-ibm-account-001:acme-cos-instance/bucket:acme-data-lake",
                        "context": {"resource_type": "cloud-object-storage"},
                        "remediation": "Rotate the exposed API keys and restrict bucket access",
                    },
                    {
                        "kind": "CONFIG",
                        "finding": {
                            "severity": "MEDIUM",
                            "next_steps": [{"title": "Enable encryption at rest"}],
                        },
                        "note_name": "providers/security-advisor/notes/misconfiguration-encryption",
                        "resource_url": "crn:v1:bluemix:public:databases-for-postgresql:us-south:a/acme-ibm-account-001:acme-pg-instance",
                        "context": {"resource_type": "databases-for-postgresql"},
                        "remediation": "Enable encryption at rest for the database instance",
                    },
                ]},
            },
        ))

        # IAM users: one with MFA disabled, one active
        result.events.append(RawEventData(
            source="ibm_cloud", source_type=SourceType.CLOUD, provider="ibm_cloud",
            event_type="ibm_iam_users",
            raw_data={
                "account_id": "acme-ibm-account-001",
                "region": "global",
                "response": {"resources": [
                    {
                        "iam_id": "IBMid-acme001",
                        "id": "uid-ibm-001",
                        "email": "alice.chen@acme.com",
                        "user_id": "alice.chen@acme.com",
                        "state": "ACTIVE",
                        "settings": {"mfa": True},
                    },
                    {
                        "iam_id": "IBMid-acme002",
                        "id": "uid-ibm-002",
                        "email": "svc-pipeline@acme.com",
                        "user_id": "svc-pipeline@acme.com",
                        "state": "ACTIVE",
                        "settings": {"mfa": False},
                    },
                    {
                        "iam_id": "IBMid-acme003",
                        "id": "uid-ibm-003",
                        "email": "dave.thompson@acme.com",
                        "user_id": "dave.thompson@acme.com",
                        "state": "DISABLED_CLASSIC_INFRASTRUCTURE",
                        "settings": {"mfa": False},
                    },
                ]},
            },
        ))

        # IAM groups: inventory
        result.events.append(RawEventData(
            source="ibm_cloud", source_type=SourceType.CLOUD, provider="ibm_cloud",
            event_type="ibm_iam_groups",
            raw_data={
                "account_id": "acme-ibm-account-001",
                "region": "global",
                "response": {"groups": [
                    {
                        "id": "grp-ibm-admins",
                        "name": "acme-cloud-admins",
                        "description": "Cloud platform administrators",
                        "membership_count": 3,
                        "is_federated": True,
                        "created_at": "2023-06-15T00:00:00Z",
                    },
                    {
                        "id": "grp-ibm-devs",
                        "name": "acme-developers",
                        "description": "Application development team",
                        "membership_count": 12,
                        "is_federated": True,
                        "created_at": "2023-06-15T00:00:00Z",
                    },
                ]},
            },
        ))

        # Activity events: one error, one warning
        result.events.append(RawEventData(
            source="ibm_cloud", source_type=SourceType.CLOUD, provider="ibm_cloud",
            event_type="ibm_activity_events",
            raw_data={
                "account_id": "acme-ibm-account-001",
                "region": "us-south",
                "response": {"events": [
                    {
                        "action": "iam-identity.serviceid-apikey.create",
                        "level": "warning",
                        "outcome": "success",
                        "target": {
                            "id": "crn:v1:bluemix:public:iam-identity::a/acme-ibm-account-001::serviceid:ServiceId-acme-deploy",
                            "typeURI": "iam-identity/serviceid-apikey",
                            "name": "acme-deploy-key",
                        },
                        "initiator": {"name": "bob.martinez@acme.com", "type": "user"},
                        "message": "API key created for service ID",
                        "eventTime": NOW.isoformat(),
                    },
                    {
                        "action": "iam-groups.member.delete",
                        "level": "error",
                        "outcome": "failure",
                        "target": {
                            "id": "grp-ibm-admins",
                            "typeURI": "iam-groups/member",
                            "name": "acme-cloud-admins",
                        },
                        "initiator": {"name": "svc-pipeline@acme.com", "type": "service"},
                        "message": "Insufficient permissions to remove member from group",
                        "eventTime": (NOW - timedelta(hours=2)).isoformat(),
                    },
                ]},
            },
        ))

        # Key Protect: one active, one extractable (risky)
        result.events.append(RawEventData(
            source="ibm_cloud", source_type=SourceType.CLOUD, provider="ibm_cloud",
            event_type="ibm_key_protect",
            raw_data={
                "account_id": "acme-ibm-account-001",
                "region": "us-south",
                "response": {"resources": [
                    {
                        "id": "kp-acme-prod-001",
                        "name": "acme-prod-root-key",
                        "state": 2,
                        "extractable": False,
                        "algorithmType": "AES",
                        "createdBy": "alice.chen@acme.com",
                        "creationDate": "2024-01-10T00:00:00Z",
                        "lastRotateDate": (NOW - timedelta(days=45)).isoformat() + "Z",
                    },
                    {
                        "id": "kp-acme-legacy-001",
                        "name": "acme-legacy-export-key",
                        "state": 2,
                        "extractable": True,
                        "algorithmType": "AES",
                        "createdBy": "dave.thompson@acme.com",
                        "creationDate": "2022-09-01T00:00:00Z",
                        "lastRotateDate": "",
                    },
                ]},
            },
        ))

        # Security groups: one open, one restricted
        result.events.append(RawEventData(
            source="ibm_cloud", source_type=SourceType.CLOUD, provider="ibm_cloud",
            event_type="ibm_security_groups",
            raw_data={
                "account_id": "acme-ibm-account-001",
                "region": "us-south",
                "response": {"security_groups": [
                    {
                        "id": "sg-ibm-legacy-001",
                        "name": "acme-legacy-sg",
                        "rules": [
                            {
                                "direction": "inbound",
                                "remote": {"cidr_block": "0.0.0.0/0"},
                                "protocol": "tcp",
                                "port_min": 0,
                                "port_max": 65535,
                            },
                        ],
                    },
                    {
                        "id": "sg-ibm-prod-001",
                        "name": "acme-prod-sg",
                        "rules": [
                            {
                                "direction": "inbound",
                                "remote": {"cidr_block": "10.240.0.0/16"},
                                "protocol": "tcp",
                                "port_min": 443,
                                "port_max": 443,
                            },
                        ],
                    },
                ]},
            },
        ))

        # Compliance profiles: one failed control, one passed
        result.events.append(RawEventData(
            source="ibm_cloud", source_type=SourceType.CLOUD, provider="ibm_cloud",
            event_type="ibm_compliance_profiles",
            raw_data={
                "account_id": "acme-ibm-account-001",
                "region": "global",
                "response": {"profiles": [
                    {
                        "id": "profile-ibm-fs-001",
                        "name": "IBM Cloud Framework for Financial Services",
                        "controls": [
                            {
                                "id": "SC-7",
                                "control_name": "Boundary Protection",
                                "status": "fail",
                                "severity": "high",
                                "assessment": {"description": "Network segmentation not enforced"},
                                "remediation": "Implement VPC network ACLs to restrict cross-zone traffic",
                            },
                            {
                                "id": "AC-2",
                                "control_name": "Account Management",
                                "status": "pass",
                                "severity": "medium",
                                "assessment": {"description": "All user accounts reviewed within 90 days"},
                                "remediation": "",
                            },
                            {
                                "id": "IA-5",
                                "control_name": "Authenticator Management",
                                "status": "failed",
                                "severity": "medium",
                                "assessment": {"description": "Service IDs using long-lived API keys without rotation"},
                                "remediation": "Enable automatic API key rotation for all service IDs",
                            },
                        ],
                    },
                ]},
            },
        ))

        result.complete()
        return result


class DemoOVHConnector(BaseConnector):
    """Simulates OVHcloud collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="ovh", source_type=SourceType.CLOUD, provider="ovh",
        )

        # Projects: list of IDs
        result.events.append(RawEventData(
            source="ovh", source_type=SourceType.CLOUD, provider="ovh",
            event_type="ovh_projects",
            raw_data={
                "service_name": "acme-ovh-001",
                "response": [
                    "proj-acme-prod-eu-001",
                    "proj-acme-staging-eu-001",
                ],
            },
        ))

        # Instances: one active, one in error state
        result.events.append(RawEventData(
            source="ovh", source_type=SourceType.CLOUD, provider="ovh",
            event_type="ovh_instances",
            raw_data={
                "service_name": "acme-ovh-001",
                "response": [
                    {
                        "id": "inst-ovh-prod-001",
                        "name": "acme-prod-web-eu-01",
                        "status": "ACTIVE",
                        "region": "GRA11",
                    },
                    {
                        "id": "inst-ovh-staging-001",
                        "name": "acme-staging-worker-eu-01",
                        "status": "ERROR",
                        "region": "SBG5",
                    },
                    {
                        "id": "inst-ovh-dev-001",
                        "name": "acme-dev-test-eu-01",
                        "status": "SHUTOFF",
                        "region": "GRA11",
                    },
                ],
            },
        ))

        # Cloud users: one admin, one standard
        result.events.append(RawEventData(
            source="ovh", source_type=SourceType.CLOUD, provider="ovh",
            event_type="ovh_cloud_users",
            raw_data={
                "service_name": "acme-ovh-001",
                "response": [
                    {
                        "id": 10001,
                        "username": "acme-admin-eu",
                        "description": "Platform admin",
                        "status": "ok",
                        "roles": [{"name": "administrator"}, {"name": "objectstore_operator"}],
                    },
                    {
                        "id": 10002,
                        "username": "acme-deploy-eu",
                        "description": "Deployment service",
                        "status": "ok",
                        "roles": [{"name": "compute_operator"}],
                    },
                ],
            },
        ))

        # Networks: inventory
        result.events.append(RawEventData(
            source="ovh", source_type=SourceType.CLOUD, provider="ovh",
            event_type="ovh_networks",
            raw_data={
                "service_name": "acme-ovh-001",
                "response": [
                    {
                        "id": "net-ovh-prod-001",
                        "name": "acme-prod-vlan",
                        "status": "ACTIVE",
                        "vlanId": 100,
                        "regions": [{"region": "GRA11", "status": "ACTIVE"}],
                    },
                ],
            },
        ))

        # Storage: one public container, one private
        result.events.append(RawEventData(
            source="ovh", source_type=SourceType.CLOUD, provider="ovh",
            event_type="ovh_storage",
            raw_data={
                "service_name": "acme-ovh-001",
                "response": [
                    {
                        "name": "acme-public-cdn",
                        "region": "GRA",
                        "storedObjects": 1247,
                        "storedBytes": 5368709120,
                        "public": True,
                    },
                    {
                        "name": "acme-prod-backups",
                        "region": "SBG",
                        "storedObjects": 89,
                        "storedBytes": 107374182400,
                        "public": False,
                    },
                ],
            },
        ))

        # Kubernetes: one outdated version, one current
        result.events.append(RawEventData(
            source="ovh", source_type=SourceType.CLOUD, provider="ovh",
            event_type="ovh_kubernetes",
            raw_data={
                "service_name": "acme-ovh-001",
                "response": [
                    {
                        "id": "k8s-ovh-prod-001",
                        "name": "acme-prod-mks",
                        "version": "1.30.2",
                        "region": "GRA9",
                        "status": "READY",
                        "updatePolicy": {"updateType": "ALWAYS_UPDATE"},
                    },
                    {
                        "id": "k8s-ovh-legacy-001",
                        "name": "acme-legacy-mks",
                        "version": "1.26.4",
                        "region": "SBG5",
                        "status": "READY",
                        "updatePolicy": {"updateType": "MANUAL"},
                    },
                ],
            },
        ))

        # Certificates: one expired, one valid, one bare service name
        result.events.append(RawEventData(
            source="ovh", source_type=SourceType.CLOUD, provider="ovh",
            event_type="ovh_certificates",
            raw_data={
                "service_name": "acme-ovh-001",
                "response": [
                    {
                        "serviceName": "cert-acme-prod-001",
                        "cn": "acme-corp.eu",
                        "expireDate": (NOW - timedelta(days=15)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    },
                    {
                        "serviceName": "cert-acme-api-001",
                        "cn": "api.acme-corp.eu",
                        "expireDate": (NOW + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    },
                    "cert-acme-internal-001",
                ],
            },
        ))

        result.complete()
        return result


class DemoOCIConnector(BaseConnector):
    """Simulates Oracle Cloud Infrastructure collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="oci", source_type=SourceType.CLOUD, provider="oci",
        )

        # Cloud Guard problems: one critical misconfiguration, one activity alert
        result.events.append(RawEventData(
            source="oci", source_type=SourceType.CLOUD, provider="oci",
            event_type="oci_cloud_guard_problems",
            raw_data={
                "tenancy_id": "ocid1.tenancy.oc1..acme-tenancy-001",
                "region": "us-ashburn-1",
                "response": {"problems": [
                    {
                        "id": "cg-prob-001",
                        "riskLevel": "CRITICAL",
                        "detectorId": "OCI_CONFIGURATION_DETECTOR",
                        "detectorRuleId": "BUCKET_IS_PUBLIC",
                        "lifecycleState": "ACTIVE",
                        "resourceId": "ocid1.bucket.oc1..acme-public-uploads",
                        "resourceType": "Bucket",
                        "resourceName": "acme-public-uploads",
                        "labels": ["security", "storage"],
                        "recommendation": "Remove public access from the bucket",
                        "targetId": "ocid1.target.oc1..acme-target-001",
                        "compartmentId": "ocid1.compartment.oc1..acme-prod",
                    },
                    {
                        "id": "cg-prob-002",
                        "riskLevel": "HIGH",
                        "detectorId": "ACTIVITY_DETECTOR",
                        "detectorRuleId": "SUSPICIOUS_ADMIN_ACTIVITY",
                        "lifecycleState": "ACTIVE",
                        "resourceId": "ocid1.user.oc1..acme-bob",
                        "resourceType": "User",
                        "resourceName": "bob.martinez@acme.com",
                        "labels": ["iam"],
                        "recommendation": "Review admin activity logs",
                        "targetId": "ocid1.target.oc1..acme-target-001",
                        "compartmentId": "ocid1.compartment.oc1..acme-prod",
                    },
                ]},
            },
        ))

        # IAM users: one without MFA, one stale, one compliant
        result.events.append(RawEventData(
            source="oci", source_type=SourceType.CLOUD, provider="oci",
            event_type="oci_iam_users",
            raw_data={
                "tenancy_id": "ocid1.tenancy.oc1..acme-tenancy-001",
                "region": "us-ashburn-1",
                "response": {"users": [
                    {
                        "name": "alice.chen@acme.com",
                        "id": "ocid1.user.oc1..acme-alice",
                        "lifecycleState": "ACTIVE",
                        "isMfaActivated": True,
                        "lastSuccessfulLoginTime": (NOW - timedelta(hours=3)).isoformat() + "Z",
                        "timeCreated": "2023-06-01T00:00:00Z",
                        "email": "alice.chen@acme.com",
                        "capabilities": {"canUseConsolePassword": True},
                    },
                    {
                        "name": "svc-terraform",
                        "id": "ocid1.user.oc1..acme-svc-tf",
                        "lifecycleState": "ACTIVE",
                        "isMfaActivated": False,
                        "lastSuccessfulLoginTime": (NOW - timedelta(days=1)).isoformat() + "Z",
                        "timeCreated": "2024-01-10T00:00:00Z",
                        "email": "",
                        "capabilities": {"canUseApiKeys": True},
                    },
                    {
                        "name": "carol.park@acme.com",
                        "id": "ocid1.user.oc1..acme-carol",
                        "lifecycleState": "ACTIVE",
                        "isMfaActivated": True,
                        "lastSuccessfulLoginTime": (NOW - timedelta(days=120)).isoformat() + "Z",
                        "timeCreated": "2023-03-15T00:00:00Z",
                        "email": "carol.park@acme.com",
                        "capabilities": {"canUseConsolePassword": True},
                    },
                ]},
            },
        ))

        # IAM groups: inventory
        result.events.append(RawEventData(
            source="oci", source_type=SourceType.CLOUD, provider="oci",
            event_type="oci_iam_groups",
            raw_data={
                "tenancy_id": "ocid1.tenancy.oc1..acme-tenancy-001",
                "region": "us-ashburn-1",
                "response": {"groups": [
                    {
                        "name": "acme-cloud-admins",
                        "id": "ocid1.group.oc1..acme-admins",
                        "description": "Cloud infrastructure administrators",
                        "lifecycleState": "ACTIVE",
                        "timeCreated": "2023-06-01T00:00:00Z",
                        "compartmentId": "ocid1.tenancy.oc1..acme-tenancy-001",
                    },
                ]},
            },
        ))

        # Audit events: one 403, one 500
        result.events.append(RawEventData(
            source="oci", source_type=SourceType.CLOUD, provider="oci",
            event_type="oci_audit_events",
            raw_data={
                "tenancy_id": "ocid1.tenancy.oc1..acme-tenancy-001",
                "region": "us-ashburn-1",
                "response": {"audit_events": [
                    {
                        "eventType": "com.oraclecloud.identitycontrolplane.UpdatePolicy",
                        "data": {
                            "eventName": "UpdatePolicy",
                            "identity": {"principalName": "bob.martinez@acme.com"},
                            "resourceId": "ocid1.policy.oc1..acme-admin-policy",
                            "response": {"status": "403", "message": "Not authorized"},
                            "request": {"action": "UpdatePolicy"},
                        },
                        "eventTime": NOW.isoformat(),
                        "source": "identitycontrolplane",
                    },
                    {
                        "eventType": "com.oraclecloud.computeapi.LaunchInstance",
                        "data": {
                            "eventName": "LaunchInstance",
                            "identity": {"principalName": "svc-terraform"},
                            "resourceId": "ocid1.instance.oc1..acme-new-inst",
                            "response": {"status": "500", "message": "Internal server error"},
                            "request": {"action": "LaunchInstance"},
                        },
                        "eventTime": (NOW - timedelta(hours=1)).isoformat(),
                        "source": "computeapi",
                    },
                ]},
            },
        ))

        # Vulnerabilities: one critical CVSS, one medium
        result.events.append(RawEventData(
            source="oci", source_type=SourceType.CLOUD, provider="oci",
            event_type="oci_vulnerabilities",
            raw_data={
                "tenancy_id": "ocid1.tenancy.oc1..acme-tenancy-001",
                "region": "us-ashburn-1",
                "response": {"vulnerabilities": [
                    {
                        "vulnerabilityId": "CVE-2024-21762",
                        "name": "FortiOS Out-of-Bound Write",
                        "hostId": "ocid1.instance.oc1..acme-prod-fw-01",
                        "cvssScore": 9.8,
                        "severity": "CRITICAL",
                        "state": "OPEN",
                        "description": "A out-of-bounds write in FortiOS allows remote code execution",
                        "cveReference": "https://nvd.nist.gov/vuln/detail/CVE-2024-21762",
                        "packageName": "fortios",
                        "packageVersion": "7.2.3",
                        "fixVersion": "7.2.7",
                    },
                    {
                        "vulnerabilityId": "CVE-2024-3400",
                        "name": "PAN-OS Command Injection",
                        "hostId": "ocid1.instance.oc1..acme-prod-app-01",
                        "cvssScore": 5.5,
                        "severity": "MEDIUM",
                        "state": "OPEN",
                        "description": "Command injection vulnerability in GlobalProtect",
                        "cveReference": "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
                        "packageName": "panos",
                        "packageVersion": "10.2.5",
                        "fixVersion": "10.2.9",
                    },
                ]},
            },
        ))

        # Security lists: one open all protocols, one restricted
        result.events.append(RawEventData(
            source="oci", source_type=SourceType.CLOUD, provider="oci",
            event_type="oci_security_lists",
            raw_data={
                "tenancy_id": "ocid1.tenancy.oc1..acme-tenancy-001",
                "region": "us-ashburn-1",
                "response": {"security_lists": [
                    {
                        "displayName": "acme-legacy-seclist",
                        "id": "ocid1.securitylist.oc1..acme-legacy-001",
                        "vcnId": "ocid1.vcn.oc1..acme-prod-vcn",
                        "lifecycleState": "AVAILABLE",
                        "ingressSecurityRules": [
                            {
                                "source": "0.0.0.0/0",
                                "protocol": "all",
                            },
                        ],
                        "egressSecurityRules": [{"destination": "0.0.0.0/0", "protocol": "all"}],
                    },
                    {
                        "displayName": "acme-prod-seclist",
                        "id": "ocid1.securitylist.oc1..acme-prod-001",
                        "vcnId": "ocid1.vcn.oc1..acme-prod-vcn",
                        "lifecycleState": "AVAILABLE",
                        "ingressSecurityRules": [
                            {
                                "source": "10.0.0.0/16",
                                "protocol": "6",
                                "tcpOptions": {"destinationPortRange": {"min": 443, "max": 443}},
                            },
                        ],
                        "egressSecurityRules": [],
                    },
                ]},
            },
        ))

        # Vaults: one DEFAULT type, one VIRTUAL_PRIVATE pending deletion
        result.events.append(RawEventData(
            source="oci", source_type=SourceType.CLOUD, provider="oci",
            event_type="oci_vaults",
            raw_data={
                "tenancy_id": "ocid1.tenancy.oc1..acme-tenancy-001",
                "region": "us-ashburn-1",
                "response": {"vaults": [
                    {
                        "displayName": "acme-prod-vault",
                        "id": "ocid1.vault.oc1..acme-prod-001",
                        "vaultType": "VIRTUAL_PRIVATE",
                        "lifecycleState": "ACTIVE",
                        "cryptoEndpoint": "https://acme-prod-001-crypto.kms.us-ashburn-1.oraclecloud.com",
                        "managementEndpoint": "https://acme-prod-001-mgmt.kms.us-ashburn-1.oraclecloud.com",
                        "timeCreated": "2023-09-01T00:00:00Z",
                        "compartmentId": "ocid1.compartment.oc1..acme-prod",
                    },
                    {
                        "displayName": "acme-legacy-vault",
                        "id": "ocid1.vault.oc1..acme-legacy-001",
                        "vaultType": "DEFAULT",
                        "lifecycleState": "PENDING_DELETION",
                        "cryptoEndpoint": "",
                        "managementEndpoint": "",
                        "timeCreated": "2022-03-15T00:00:00Z",
                        "compartmentId": "ocid1.compartment.oc1..acme-legacy",
                    },
                ]},
            },
        ))

        # Bastions: inventory
        result.events.append(RawEventData(
            source="oci", source_type=SourceType.CLOUD, provider="oci",
            event_type="oci_bastions",
            raw_data={
                "tenancy_id": "ocid1.tenancy.oc1..acme-tenancy-001",
                "region": "us-ashburn-1",
                "response": {"bastions": [
                    {
                        "name": "acme-prod-bastion",
                        "displayName": "acme-prod-bastion",
                        "id": "ocid1.bastion.oc1..acme-prod-001",
                        "bastionType": "STANDARD",
                        "lifecycleState": "ACTIVE",
                        "targetSubnetId": "ocid1.subnet.oc1..acme-prod-private",
                        "targetVcnId": "ocid1.vcn.oc1..acme-prod-vcn",
                        "clientCidrBlockAllowList": ["10.0.0.0/8"],
                        "maxSessionTtlInSeconds": 10800,
                        "timeCreated": "2024-02-01T00:00:00Z",
                        "compartmentId": "ocid1.compartment.oc1..acme-prod",
                    },
                ]},
            },
        ))

        result.complete()
        return result


class DemoCloudflareConnector(BaseConnector):
    """Simulates Cloudflare collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="cloudflare", source_type=SourceType.CLOUD, provider="cloudflare",
        )

        # WAF rules: one active block, one disabled
        result.events.append(RawEventData(
            source="cloudflare", source_type=SourceType.CLOUD, provider="cloudflare",
            event_type="cf_waf_rules",
            raw_data={
                "zone_id": "zone-acme-prod-001",
                "rules": [
                    {
                        "id": "waf-rule-001",
                        "mode": "block",
                        "configuration": {"target": "ip", "value": "198.51.100.0/24"},
                        "notes": "Known malicious range",
                    },
                    {
                        "id": "waf-rule-002",
                        "mode": "disabled",
                        "configuration": {"target": "country", "value": "XX"},
                        "notes": "Temporarily disabled for testing",
                    },
                ],
            },
        ))

        # DNS records: one proxied, one unproxied A record, one external CNAME
        result.events.append(RawEventData(
            source="cloudflare", source_type=SourceType.CLOUD, provider="cloudflare",
            event_type="cf_dns_records",
            raw_data={
                "zone_id": "zone-acme-prod-001",
                "records": [
                    {
                        "id": "dns-rec-001",
                        "type": "A",
                        "name": "acme-corp.com",
                        "content": "203.0.113.10",
                        "proxied": True,
                        "ttl": 1,
                    },
                    {
                        "id": "dns-rec-002",
                        "type": "A",
                        "name": "vpn.acme-corp.com",
                        "content": "203.0.113.20",
                        "proxied": False,
                        "ttl": 300,
                    },
                    {
                        "id": "dns-rec-003",
                        "type": "CNAME",
                        "name": "status.acme-corp.com",
                        "content": "acme-corp.statuspage.io",
                        "proxied": False,
                        "ttl": 300,
                    },
                    {
                        "id": "dns-rec-004",
                        "type": "MX",
                        "name": "acme-corp.com",
                        "content": "mail.acme-corp.com",
                        "proxied": False,
                        "ttl": 3600,
                    },
                ],
            },
        ))

        # Access apps: one with long session, one compliant
        result.events.append(RawEventData(
            source="cloudflare", source_type=SourceType.CLOUD, provider="cloudflare",
            event_type="cf_access_apps",
            raw_data={
                "account_id": "cf-acme-account-001",
                "apps": [
                    {
                        "id": "access-app-001",
                        "name": "Acme Internal Dashboard",
                        "type": "self_hosted",
                        "domain": "dashboard.acme-corp.com",
                        "session_duration": "720h",
                        "purpose_justification_required": False,
                        "allowed_idps": ["idp-okta-001"],
                    },
                    {
                        "id": "access-app-002",
                        "name": "Acme Admin Panel",
                        "type": "self_hosted",
                        "domain": "admin.acme-corp.com",
                        "session_duration": "8h",
                        "purpose_justification_required": True,
                        "allowed_idps": ["idp-okta-001"],
                    },
                ],
            },
        ))

        # Gateway rules: some enabled, some disabled
        result.events.append(RawEventData(
            source="cloudflare", source_type=SourceType.CLOUD, provider="cloudflare",
            event_type="cf_gateway_rules",
            raw_data={
                "account_id": "cf-acme-account-001",
                "rules": [
                    {
                        "id": "gw-rule-001",
                        "name": "Block malware domains",
                        "enabled": True,
                        "action": "block",
                        "traffic": "dns",
                        "filters": ["security_threats"],
                    },
                    {
                        "id": "gw-rule-002",
                        "name": "Block social media",
                        "enabled": False,
                        "action": "block",
                        "traffic": "dns",
                        "filters": ["content_categories"],
                    },
                    {
                        "id": "gw-rule-003",
                        "name": "Allow corporate SaaS",
                        "enabled": True,
                        "action": "allow",
                        "traffic": "http",
                        "filters": ["application"],
                    },
                ],
            },
        ))

        # SSL settings: flexible mode (insecure), TLS 1.0 min, no HTTPS enforcement
        result.events.append(RawEventData(
            source="cloudflare", source_type=SourceType.CLOUD, provider="cloudflare",
            event_type="cf_ssl_settings",
            raw_data={
                "zone_id": "zone-acme-staging-001",
                "ssl": {"value": "flexible"},
                "min_tls_version": {"value": "1.0"},
                "always_use_https": {"value": "off"},
            },
        ))

        # Page Shield: one clean script, one malicious
        result.events.append(RawEventData(
            source="cloudflare", source_type=SourceType.CLOUD, provider="cloudflare",
            event_type="cf_page_shield",
            raw_data={
                "zone_id": "zone-acme-prod-001",
                "scripts": [
                    {
                        "id": "ps-script-001",
                        "url": "https://cdn.acme-corp.com/js/app.min.js",
                        "host": "acme-corp.com",
                        "malicious": False,
                        "js_integrity_score": 95,
                        "fetched_at": NOW.isoformat(),
                        "first_seen_at": (NOW - timedelta(days=90)).isoformat(),
                        "last_seen_at": NOW.isoformat(),
                    },
                    {
                        "id": "ps-script-002",
                        "url": "https://cdn.suspicious-analytics.xyz/tracker.js",
                        "host": "acme-corp.com",
                        "malicious": True,
                        "js_integrity_score": 12,
                        "fetched_at": NOW.isoformat(),
                        "first_seen_at": (NOW - timedelta(days=2)).isoformat(),
                        "last_seen_at": NOW.isoformat(),
                    },
                ],
            },
        ))

        # Audit logs: one sensitive action, one non-sensitive
        result.events.append(RawEventData(
            source="cloudflare", source_type=SourceType.CLOUD, provider="cloudflare",
            event_type="cf_audit_logs",
            raw_data={
                "account_id": "cf-acme-account-001",
                "logs": [
                    {
                        "id": "audit-log-001",
                        "action": {"type": "api_key_created"},
                        "actor": {"email": "bob.martinez@acme.com", "type": "user"},
                        "when": NOW.isoformat(),
                        "resource": {"type": "api_key", "id": "apikey-new-001"},
                        "metadata": {"key_name": "deploy-pipeline-key"},
                    },
                    {
                        "id": "audit-log-002",
                        "action": {"type": "dns_record_created"},
                        "actor": {"email": "alice.chen@acme.com", "type": "user"},
                        "when": (NOW - timedelta(hours=4)).isoformat(),
                        "resource": {"type": "dns_record", "id": "dns-rec-005"},
                        "metadata": {"record_name": "test.acme-corp.com"},
                    },
                    {
                        "id": "audit-log-003",
                        "action": {"type": "page_view"},
                        "actor": {"email": "alice.chen@acme.com", "type": "user"},
                        "when": (NOW - timedelta(hours=5)).isoformat(),
                        "resource": {"type": "zone", "id": "zone-acme-prod-001"},
                        "metadata": {},
                    },
                ],
            },
        ))

        result.complete()
        return result


# --- Endpoint, SIEM & Container Demo Connectors ---


class DemoDefenderConnector(BaseConnector):
    """Simulates Microsoft Defender for Endpoint collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="defender",
            source_type=SourceType.EDR,
            provider="defender",
        )

        # Machines: mix of healthy, high-risk, and not-onboarded
        result.events.append(RawEventData(
            source="defender", source_type=SourceType.EDR, provider="defender",
            event_type="defender_machines",
            raw_data={
                "records": [
                    {
                        "id": "mde-machine-001",
                        "computerDnsName": "ws-finance-01.acme.local",
                        "machineName": "ws-finance-01",
                        "osPlatform": "Windows",
                        "osVersion": "10.0.22631",
                        "riskScore": "Low",
                        "exposureLevel": "Low",
                        "healthStatus": "Active",
                        "onboardingStatus": "Onboarded",
                    },
                    {
                        "id": "mde-machine-002",
                        "computerDnsName": "srv-db-01.acme.local",
                        "machineName": "srv-db-01",
                        "osPlatform": "Windows",
                        "osVersion": "10.0.20348",
                        "riskScore": "High",
                        "exposureLevel": "High",
                        "healthStatus": "Active",
                        "onboardingStatus": "Onboarded",
                    },
                    {
                        "id": "mde-machine-003",
                        "computerDnsName": "ws-marketing-02.acme.local",
                        "machineName": "ws-marketing-02",
                        "osPlatform": "Windows",
                        "osVersion": "10.0.19045",
                        "riskScore": "Medium",
                        "exposureLevel": "Medium",
                        "healthStatus": "Inactive",
                        "onboardingStatus": "Onboarded",
                    },
                    {
                        "id": "mde-machine-004",
                        "computerDnsName": "ws-contractor-05.acme.local",
                        "machineName": "ws-contractor-05",
                        "osPlatform": "Windows",
                        "osVersion": "10.0.22631",
                        "riskScore": "None",
                        "exposureLevel": "None",
                        "healthStatus": "Unknown",
                        "onboardingStatus": "CanBeOnboarded",
                    },
                ],
            },
        ))

        # Alerts: active threats across endpoints
        result.events.append(RawEventData(
            source="defender", source_type=SourceType.EDR, provider="defender",
            event_type="defender_alerts",
            raw_data={
                "records": [
                    {
                        "id": "mde-alert-001",
                        "title": "Suspicious PowerShell download cradle",
                        "severity": "High",
                        "status": "New",
                        "category": "Execution",
                        "machineId": "mde-machine-002",
                        "computerDnsName": "srv-db-01.acme.local",
                        "description": "A PowerShell process executed an encoded download command targeting an external IP.",
                        "recommendedAction": "Isolate the machine and investigate the PowerShell command history.",
                    },
                    {
                        "id": "mde-alert-002",
                        "title": "Ransomware behavior detected",
                        "severity": "Critical",
                        "status": "InProgress",
                        "category": "Ransomware",
                        "machineId": "mde-machine-002",
                        "computerDnsName": "srv-db-01.acme.local",
                        "description": "File encryption activity detected across multiple directories.",
                        "recommendedAction": "Immediately isolate the device and begin incident response.",
                    },
                    {
                        "id": "mde-alert-003",
                        "title": "Unusual login from Tor exit node",
                        "severity": "Medium",
                        "status": "New",
                        "category": "InitialAccess",
                        "machineId": "mde-machine-001",
                        "computerDnsName": "ws-finance-01.acme.local",
                        "description": "Interactive login detected from a known Tor exit node IP.",
                        "recommendedAction": "Verify the login with the user and reset credentials if unauthorized.",
                    },
                    {
                        "id": "mde-alert-004",
                        "title": "PUA detected: crypto miner",
                        "severity": "Low",
                        "status": "Resolved",
                        "category": "UnwantedSoftware",
                        "machineId": "mde-machine-003",
                        "computerDnsName": "ws-marketing-02.acme.local",
                        "description": "Potentially unwanted crypto mining software was detected and blocked.",
                        "recommendedAction": "Scan the device and remove the application.",
                    },
                ],
            },
        ))

        # Vulnerabilities: mix of severity
        result.events.append(RawEventData(
            source="defender", source_type=SourceType.EDR, provider="defender",
            event_type="defender_vulnerabilities",
            raw_data={
                "records": [
                    {
                        "id": "mde-vuln-001",
                        "cveId": "CVE-2024-38063",
                        "name": "Windows TCP/IP Remote Code Execution",
                        "severity": "Critical",
                        "exposedMachines": 3,
                        "publishedOn": "2024-08-13",
                        "description": "Remote code execution via specially crafted IPv6 packets.",
                        "cvssV3": 9.8,
                    },
                    {
                        "id": "mde-vuln-002",
                        "cveId": "CVE-2024-30080",
                        "name": "MSMQ Remote Code Execution",
                        "severity": "High",
                        "exposedMachines": 1,
                        "publishedOn": "2024-06-11",
                        "description": "Remote code execution via MSMQ service.",
                        "cvssV3": 8.1,
                    },
                    {
                        "id": "mde-vuln-003",
                        "cveId": "CVE-2024-21338",
                        "name": "Windows Kernel Elevation of Privilege",
                        "severity": "Medium",
                        "exposedMachines": 2,
                        "publishedOn": "2024-02-13",
                        "description": "Local privilege escalation via kernel driver vulnerability.",
                        "cvssV3": 7.0,
                    },
                ],
            },
        ))

        # Recommendations: security hardening
        result.events.append(RawEventData(
            source="defender", source_type=SourceType.EDR, provider="defender",
            event_type="defender_recommendations",
            raw_data={
                "records": [
                    {
                        "id": "mde-rec-001",
                        "recommendationName": "Enable Attack Surface Reduction rules",
                        "severityScore": "High",
                        "status": "Active",
                        "exposedMachinesCount": 4,
                        "recommendationCategory": "EndpointProtection",
                        "remediationType": "ConfigurationChange",
                        "vendor": "Microsoft",
                        "productName": "Windows Defender",
                    },
                    {
                        "id": "mde-rec-002",
                        "recommendationName": "Update Microsoft Edge to latest version",
                        "severityScore": "Medium",
                        "status": "Active",
                        "exposedMachinesCount": 2,
                        "recommendationCategory": "Application",
                        "remediationType": "Update",
                        "vendor": "Microsoft",
                        "productName": "Edge",
                    },
                    {
                        "id": "mde-rec-003",
                        "recommendationName": "Enable controlled folder access",
                        "severityScore": "Informational",
                        "status": "Active",
                        "exposedMachinesCount": 3,
                        "recommendationCategory": "EndpointProtection",
                        "remediationType": "ConfigurationChange",
                        "vendor": "Microsoft",
                        "productName": "Windows Defender",
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoSentinelOneConnector(BaseConnector):
    """Simulates SentinelOne EDR collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="sentinelone",
            source_type=SourceType.EDR,
            provider="sentinelone",
        )

        # Threats: malicious, suspicious, and mitigated
        result.events.append(RawEventData(
            source="sentinelone", source_type=SourceType.EDR, provider="sentinelone",
            event_type="s1_threats",
            raw_data={
                "records": [
                    {
                        "id": "s1-threat-001",
                        "classification": "Malware",
                        "confidenceLevel": "malicious",
                        "agentRealtimeInfo": {
                            "agentComputerName": "ws-eng-01.acme.local",
                            "agentId": "s1-agent-001",
                            "agentOsName": "Windows 11",
                        },
                        "threatInfo": {
                            "threatName": "Trojan.GenericKD.47839201",
                            "mitigationStatus": "active",
                            "filePath": "C:\\Users\\alice\\Downloads\\invoice.exe",
                            "engines": ["SentinelOne Cloud", "On-Write Static AI"],
                        },
                    },
                    {
                        "id": "s1-threat-002",
                        "classification": "PUP",
                        "confidenceLevel": "suspicious",
                        "agentRealtimeInfo": {
                            "agentComputerName": "ws-sales-03.acme.local",
                            "agentId": "s1-agent-003",
                            "agentOsName": "macOS",
                        },
                        "threatInfo": {
                            "threatName": "PUP.Optional.BrowserAssistant",
                            "mitigationStatus": "mitigated",
                            "filePath": "/Applications/BrowserHelper.app",
                            "engines": ["Behavioral AI"],
                        },
                    },
                    {
                        "id": "s1-threat-003",
                        "classification": "Ransomware",
                        "confidenceLevel": "malicious",
                        "agentDetectionInfo": {
                            "agentComputerName": "srv-file-01.acme.local",
                            "agentId": "s1-agent-005",
                            "agentOsName": "Windows Server 2022",
                        },
                        "threatInfo": {
                            "threatName": "Ransom.LockBit.Gen",
                            "mitigationStatus": "active",
                            "filePath": "C:\\Windows\\Temp\\svchost_update.exe",
                            "engines": ["SentinelOne Cloud", "Behavioral AI", "On-Write Static AI"],
                        },
                    },
                ],
            },
        ))

        # Agents: healthy, outdated, infected, disconnected
        result.events.append(RawEventData(
            source="sentinelone", source_type=SourceType.EDR, provider="sentinelone",
            event_type="s1_agents",
            raw_data={
                "records": [
                    {
                        "id": "s1-agent-001",
                        "computerName": "ws-eng-01.acme.local",
                        "osName": "Windows 11",
                        "osRevision": "23H2",
                        "agentVersion": "23.4.2.15",
                        "isActive": True,
                        "isUpToDate": True,
                        "infected": False,
                        "networkStatus": "connected",
                        "scanStatus": "finished",
                        "activeThreats": 1,
                    },
                    {
                        "id": "s1-agent-002",
                        "computerName": "ws-hr-02.acme.local",
                        "osName": "macOS",
                        "osRevision": "14.3",
                        "agentVersion": "23.4.2.15",
                        "isActive": True,
                        "isUpToDate": True,
                        "infected": False,
                        "networkStatus": "connected",
                        "scanStatus": "finished",
                        "activeThreats": 0,
                    },
                    {
                        "id": "s1-agent-003",
                        "computerName": "ws-sales-03.acme.local",
                        "osName": "macOS",
                        "osRevision": "13.6",
                        "agentVersion": "23.2.1.10",
                        "isActive": True,
                        "isUpToDate": False,
                        "infected": False,
                        "networkStatus": "connected",
                        "scanStatus": "finished",
                        "activeThreats": 0,
                    },
                    {
                        "id": "s1-agent-004",
                        "computerName": "ws-exec-01.acme.local",
                        "osName": "Windows 11",
                        "osRevision": "22H2",
                        "agentVersion": "23.4.2.15",
                        "isActive": False,
                        "isUpToDate": True,
                        "infected": False,
                        "networkStatus": "disconnected",
                        "scanStatus": "none",
                        "activeThreats": 0,
                    },
                    {
                        "id": "s1-agent-005",
                        "computerName": "srv-file-01.acme.local",
                        "osName": "Windows Server 2022",
                        "osRevision": "21H2",
                        "agentVersion": "23.4.2.15",
                        "isActive": True,
                        "isUpToDate": True,
                        "infected": True,
                        "networkStatus": "connected",
                        "scanStatus": "started",
                        "activeThreats": 2,
                    },
                ],
            },
        ))

        # Applications: inventory with a high-risk app
        result.events.append(RawEventData(
            source="sentinelone", source_type=SourceType.EDR, provider="sentinelone",
            event_type="s1_applications",
            raw_data={
                "total": 4,
                "records": [
                    {
                        "name": "Google Chrome",
                        "version": "121.0.6167.85",
                        "publisher": "Google LLC",
                        "riskLevel": "Low",
                        "agentComputerName": "ws-eng-01.acme.local",
                        "agentId": "s1-agent-001",
                    },
                    {
                        "name": "PuTTY",
                        "version": "0.74",
                        "publisher": "Simon Tatham",
                        "riskLevel": "High",
                        "agentComputerName": "ws-sales-03.acme.local",
                        "agentId": "s1-agent-003",
                    },
                    {
                        "name": "7-Zip",
                        "version": "23.01",
                        "publisher": "Igor Pavlov",
                        "riskLevel": "None",
                        "agentComputerName": "ws-hr-02.acme.local",
                        "agentId": "s1-agent-002",
                    },
                    {
                        "name": "TeamViewer",
                        "version": "15.30.3",
                        "publisher": "TeamViewer GmbH",
                        "riskLevel": "Critical",
                        "agentComputerName": "ws-exec-01.acme.local",
                        "agentId": "s1-agent-004",
                    },
                ],
            },
        ))

        # Policies: one strong, one with weak settings
        result.events.append(RawEventData(
            source="sentinelone", source_type=SourceType.EDR, provider="sentinelone",
            event_type="s1_policies",
            raw_data={
                "records": [
                    {
                        "id": "s1-policy-001",
                        "name": "Acme Production Servers",
                        "isDefault": False,
                        "scope": "site",
                        "antiTamperingEnabled": True,
                        "engines": {"onWrite": True},
                    },
                    {
                        "id": "s1-policy-002",
                        "name": "Acme Default Workstations",
                        "isDefault": True,
                        "scope": "global",
                        "antiTamperingEnabled": True,
                        "engines": {"onWrite": True},
                    },
                    {
                        "id": "s1-policy-003",
                        "name": "Acme Contractor Endpoints",
                        "isDefault": False,
                        "scope": "group",
                        "antiTamperingEnabled": False,
                        "engines": {"onWrite": False},
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoIntuneConnector(BaseConnector):
    """Simulates Microsoft Intune MDM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="intune",
            source_type=SourceType.MDM,
            provider="intune",
        )

        # Devices: compliant, non-compliant, unencrypted, outdated OS
        result.events.append(RawEventData(
            source="intune", source_type=SourceType.MDM, provider="intune",
            event_type="intune_devices",
            raw_data={
                "records": [
                    {
                        "id": "intune-dev-001",
                        "deviceName": "ACME-WS-ALICE",
                        "operatingSystem": "Windows",
                        "osVersion": "10.0.22631",
                        "complianceState": "compliant",
                        "isEncrypted": True,
                        "model": "Surface Laptop 5",
                        "manufacturer": "Microsoft",
                        "userPrincipalName": "alice.chen@acme.com",
                        "lastSyncDateTime": (NOW - timedelta(hours=2)).isoformat(),
                        "managementAgent": "mdm",
                    },
                    {
                        "id": "intune-dev-002",
                        "deviceName": "ACME-WS-BOB",
                        "operatingSystem": "macOS",
                        "osVersion": "14.3",
                        "complianceState": "compliant",
                        "isEncrypted": True,
                        "model": "MacBook Pro 14",
                        "manufacturer": "Apple",
                        "userPrincipalName": "bob.martinez@acme.com",
                        "lastSyncDateTime": (NOW - timedelta(hours=1)).isoformat(),
                        "managementAgent": "mdm",
                    },
                    {
                        "id": "intune-dev-003",
                        "deviceName": "ACME-WS-CAROL",
                        "operatingSystem": "Windows",
                        "osVersion": "10.0.19045",
                        "complianceState": "noncompliant",
                        "isEncrypted": False,
                        "model": "ThinkPad T480",
                        "manufacturer": "Lenovo",
                        "userPrincipalName": "carol.park@acme.com",
                        "lastSyncDateTime": (NOW - timedelta(days=7)).isoformat(),
                        "managementAgent": "mdm",
                    },
                    {
                        "id": "intune-dev-004",
                        "deviceName": "ACME-MB-DAVE",
                        "operatingSystem": "macOS",
                        "osVersion": "12.7",
                        "complianceState": "noncompliant",
                        "isEncrypted": True,
                        "model": "MacBook Air M1",
                        "manufacturer": "Apple",
                        "userPrincipalName": "dave.thompson@acme.com",
                        "lastSyncDateTime": (NOW - timedelta(days=14)).isoformat(),
                        "managementAgent": "mdm",
                    },
                    {
                        "id": "intune-dev-005",
                        "deviceName": "ACME-PHONE-EVE",
                        "operatingSystem": "iOS",
                        "osVersion": "17.3",
                        "complianceState": "compliant",
                        "isEncrypted": True,
                        "model": "iPhone 15",
                        "manufacturer": "Apple",
                        "userPrincipalName": "eve.nakamura@acme.com",
                        "lastSyncDateTime": (NOW - timedelta(hours=6)).isoformat(),
                        "managementAgent": "mdm",
                    },
                    {
                        "id": "intune-dev-006",
                        "deviceName": "ACME-WS-INTERN",
                        "operatingSystem": "Windows",
                        "osVersion": "6.3.9600",
                        "complianceState": "error",
                        "isEncrypted": False,
                        "model": "OptiPlex 3020",
                        "manufacturer": "Dell",
                        "userPrincipalName": "intern.temp@acme.com",
                        "lastSyncDateTime": (NOW - timedelta(days=30)).isoformat(),
                        "managementAgent": "mdm",
                    },
                ],
            },
        ))

        # Compliance policies
        result.events.append(RawEventData(
            source="intune", source_type=SourceType.MDM, provider="intune",
            event_type="intune_compliance_policies",
            raw_data={
                "records": [
                    {
                        "id": "intune-pol-001",
                        "displayName": "Acme Windows Compliance Baseline",
                        "description": "Requires encryption, minimum OS version, and password complexity.",
                        "createdDateTime": (NOW - timedelta(days=180)).isoformat(),
                        "lastModifiedDateTime": (NOW - timedelta(days=15)).isoformat(),
                    },
                    {
                        "id": "intune-pol-002",
                        "displayName": "Acme macOS Compliance Baseline",
                        "description": "Requires FileVault, minimum macOS 13, and screen lock.",
                        "createdDateTime": (NOW - timedelta(days=180)).isoformat(),
                        "lastModifiedDateTime": (NOW - timedelta(days=30)).isoformat(),
                    },
                    {
                        "id": "intune-pol-003",
                        "displayName": "Acme Mobile Device Policy",
                        "description": "Requires device encryption and passcode on iOS and Android.",
                        "createdDateTime": (NOW - timedelta(days=120)).isoformat(),
                        "lastModifiedDateTime": (NOW - timedelta(days=60)).isoformat(),
                    },
                ],
            },
        ))

        # Compliance states: per-device policy evaluation
        result.events.append(RawEventData(
            source="intune", source_type=SourceType.MDM, provider="intune",
            event_type="intune_compliance_states",
            raw_data={
                "records": [
                    {
                        "id": "state-001",
                        "deviceId": "intune-dev-001",
                        "displayName": "BitLocker Encryption",
                        "state": "compliant",
                        "policyName": "Acme Windows Compliance Baseline",
                        "userPrincipalName": "alice.chen@acme.com",
                    },
                    {
                        "id": "state-002",
                        "deviceId": "intune-dev-003",
                        "displayName": "BitLocker Encryption",
                        "state": "noncompliant",
                        "policyName": "Acme Windows Compliance Baseline",
                        "userPrincipalName": "carol.park@acme.com",
                    },
                    {
                        "id": "state-003",
                        "deviceId": "intune-dev-003",
                        "displayName": "Minimum OS Version",
                        "state": "noncompliant",
                        "policyName": "Acme Windows Compliance Baseline",
                        "userPrincipalName": "carol.park@acme.com",
                    },
                    {
                        "id": "state-004",
                        "deviceId": "intune-dev-004",
                        "managedDeviceId": "intune-dev-004",
                        "settingName": "Minimum OS Version",
                        "complianceState": "noncompliant",
                        "displayName": "Acme macOS Compliance Baseline",
                        "userPrincipalName": "dave.thompson@acme.com",
                    },
                    {
                        "id": "state-005",
                        "deviceId": "intune-dev-006",
                        "displayName": "Device Encryption",
                        "state": "error",
                        "policyName": "Acme Windows Compliance Baseline",
                        "userPrincipalName": "intern.temp@acme.com",
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoSentinelConnector(BaseConnector):
    """Simulates Microsoft Sentinel SIEM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="sentinel",
            source_type=SourceType.SIEM,
            provider="sentinel",
        )

        # Incidents: various severities and states
        result.events.append(RawEventData(
            source="sentinel", source_type=SourceType.SIEM, provider="sentinel",
            event_type="sentinel_incidents",
            raw_data={
                "subscription_id": "acme-sub-001",
                "response": [
                    {
                        "name": "sentinel-inc-001",
                        "id": "/subscriptions/acme-sub-001/resourceGroups/acme-siem/providers/Microsoft.SecurityInsights/incidents/sentinel-inc-001",
                        "properties": {
                            "title": "Multi-stage attack: credential theft followed by lateral movement",
                            "severity": "Critical",
                            "status": "Active",
                            "owner": {"assignedTo": "bob.martinez@acme.com", "email": "bob.martinez@acme.com"},
                            "relatedAnalyticRuleIds": ["rule-001", "rule-003"],
                            "additionalData": {"alertsCount": 5},
                            "createdTimeUtc": (NOW - timedelta(hours=4)).isoformat(),
                            "lastModifiedTimeUtc": (NOW - timedelta(minutes=30)).isoformat(),
                            "classification": "",
                            "labels": [{"labelName": "critical"}, {"labelName": "IR-active"}],
                        },
                    },
                    {
                        "name": "sentinel-inc-002",
                        "id": "/subscriptions/acme-sub-001/resourceGroups/acme-siem/providers/Microsoft.SecurityInsights/incidents/sentinel-inc-002",
                        "properties": {
                            "title": "Anomalous sign-in from unfamiliar location",
                            "severity": "Medium",
                            "status": "New",
                            "owner": {"assignedTo": "", "email": ""},
                            "relatedAnalyticRuleIds": ["rule-002"],
                            "additionalData": {"alertsCount": 1},
                            "createdTimeUtc": (NOW - timedelta(hours=1)).isoformat(),
                            "lastModifiedTimeUtc": (NOW - timedelta(hours=1)).isoformat(),
                            "classification": "",
                            "labels": [],
                        },
                    },
                    {
                        "name": "sentinel-inc-003",
                        "id": "/subscriptions/acme-sub-001/resourceGroups/acme-siem/providers/Microsoft.SecurityInsights/incidents/sentinel-inc-003",
                        "properties": {
                            "title": "Brute force SSH attempts detected",
                            "severity": "Low",
                            "status": "Closed",
                            "owner": {"assignedTo": "alice.chen@acme.com", "email": "alice.chen@acme.com"},
                            "relatedAnalyticRuleIds": ["rule-004"],
                            "additionalData": {"alertsCount": 42},
                            "createdTimeUtc": (NOW - timedelta(days=2)).isoformat(),
                            "lastModifiedTimeUtc": (NOW - timedelta(days=1)).isoformat(),
                            "classification": "BenignPositive",
                            "labels": [{"labelName": "auto-closed"}],
                        },
                    },
                ],
            },
        ))

        # Analytics rules: mix of enabled and disabled
        result.events.append(RawEventData(
            source="sentinel", source_type=SourceType.SIEM, provider="sentinel",
            event_type="sentinel_analytics_rules",
            raw_data={
                "subscription_id": "acme-sub-001",
                "response": [
                    {
                        "name": "rule-001",
                        "id": "/subscriptions/acme-sub-001/providers/Microsoft.SecurityInsights/alertRules/rule-001",
                        "kind": "Scheduled",
                        "properties": {
                            "displayName": "Credential Dumping via LSASS",
                            "enabled": True,
                            "severity": "High",
                            "tactics": ["CredentialAccess"],
                            "techniques": ["T1003"],
                        },
                    },
                    {
                        "name": "rule-002",
                        "id": "/subscriptions/acme-sub-001/providers/Microsoft.SecurityInsights/alertRules/rule-002",
                        "kind": "Scheduled",
                        "properties": {
                            "displayName": "Anomalous Sign-In Activity",
                            "enabled": True,
                            "severity": "Medium",
                            "tactics": ["InitialAccess"],
                            "techniques": ["T1078"],
                        },
                    },
                    {
                        "name": "rule-003",
                        "id": "/subscriptions/acme-sub-001/providers/Microsoft.SecurityInsights/alertRules/rule-003",
                        "kind": "Scheduled",
                        "properties": {
                            "displayName": "Lateral Movement via RDP",
                            "enabled": True,
                            "severity": "High",
                            "tactics": ["LateralMovement"],
                            "techniques": ["T1021"],
                        },
                    },
                    {
                        "name": "rule-004",
                        "id": "/subscriptions/acme-sub-001/providers/Microsoft.SecurityInsights/alertRules/rule-004",
                        "kind": "Scheduled",
                        "properties": {
                            "displayName": "SSH Brute Force Detection",
                            "enabled": True,
                            "severity": "Low",
                            "tactics": ["InitialAccess"],
                            "techniques": ["T1110"],
                        },
                    },
                    {
                        "name": "rule-005",
                        "id": "/subscriptions/acme-sub-001/providers/Microsoft.SecurityInsights/alertRules/rule-005",
                        "kind": "Scheduled",
                        "properties": {
                            "displayName": "DNS Tunneling Detection",
                            "enabled": False,
                            "severity": "Medium",
                            "tactics": ["Exfiltration"],
                            "techniques": ["T1048"],
                        },
                    },
                ],
            },
        ))

        # Hunting queries
        result.events.append(RawEventData(
            source="sentinel", source_type=SourceType.SIEM, provider="sentinel",
            event_type="sentinel_hunting_queries",
            raw_data={
                "subscription_id": "acme-sub-001",
                "response": [
                    {"name": "hunt-001", "properties": {"displayName": "Suspicious Process Creation Chains"}},
                    {"name": "hunt-002", "properties": {"displayName": "Anomalous PowerShell Usage"}},
                    {"name": "hunt-003", "properties": {"displayName": "Rare External Connections"}},
                ],
            },
        ))

        # Data connectors
        result.events.append(RawEventData(
            source="sentinel", source_type=SourceType.SIEM, provider="sentinel",
            event_type="sentinel_data_connectors",
            raw_data={
                "subscription_id": "acme-sub-001",
                "response": [
                    {
                        "name": "dc-001",
                        "id": "/subscriptions/acme-sub-001/providers/Microsoft.SecurityInsights/dataConnectors/dc-001",
                        "kind": "AzureActiveDirectory",
                        "properties": {"connectorUiConfig": {"title": "Azure Active Directory"}},
                    },
                    {
                        "name": "dc-002",
                        "id": "/subscriptions/acme-sub-001/providers/Microsoft.SecurityInsights/dataConnectors/dc-002",
                        "kind": "MicrosoftDefenderAdvancedThreatProtection",
                        "properties": {"connectorUiConfig": {"title": "Microsoft Defender for Endpoint"}},
                    },
                    {
                        "name": "dc-003",
                        "id": "/subscriptions/acme-sub-001/providers/Microsoft.SecurityInsights/dataConnectors/dc-003",
                        "kind": "Syslog",
                        "properties": {"connectorUiConfig": {"title": "Linux Syslog"}},
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoSplunkConnector(BaseConnector):
    """Simulates Splunk Enterprise Security SIEM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="splunk",
            source_type=SourceType.SIEM,
            provider="splunk",
        )

        # Notable events: various urgencies
        result.events.append(RawEventData(
            source="splunk", source_type=SourceType.SIEM, provider="splunk",
            event_type="splunk_notable_events",
            raw_data={
                "response": [
                    {
                        "result": {
                            "event_id": "splunk-notable-001",
                            "search_name": "Excessive Failed Logins",
                            "urgency": "high",
                            "status_label": "New",
                            "owner": "unassigned",
                            "security_domain": "access",
                            "src": "10.0.1.55",
                            "dest": "srv-dc-01.acme.local",
                            "user": "admin",
                            "rule_description": "More than 20 failed login attempts in 5 minutes from a single source.",
                            "_time": (NOW - timedelta(hours=2)).isoformat(),
                        },
                    },
                    {
                        "result": {
                            "event_id": "splunk-notable-002",
                            "search_name": "Data Exfiltration Over DNS",
                            "urgency": "critical",
                            "status_label": "In Progress",
                            "owner": "bob.martinez",
                            "security_domain": "network",
                            "src": "ws-eng-01.acme.local",
                            "dest": "suspicious-dns.example.com",
                            "user": "alice.chen",
                            "rule_description": "High volume of DNS TXT record queries to an unusual domain.",
                            "_time": (NOW - timedelta(hours=1)).isoformat(),
                        },
                    },
                    {
                        "result": {
                            "event_id": "splunk-notable-003",
                            "rule_name": "Unauthorized Service Account Usage",
                            "urgency": "medium",
                            "status": "New",
                            "owner": "unassigned",
                            "security_domain": "identity",
                            "src": "10.0.2.100",
                            "dest": "srv-api-02.acme.local",
                            "user": "svc-deploy",
                            "description": "Service account svc-deploy used interactively from a workstation.",
                            "_time": (NOW - timedelta(hours=6)).isoformat(),
                        },
                    },
                    {
                        "result": {
                            "event_id": "splunk-notable-004",
                            "search_name": "Endpoint Antivirus Disabled",
                            "urgency": "low",
                            "status_label": "Closed",
                            "owner": "alice.chen",
                            "security_domain": "endpoint",
                            "src": "ws-marketing-02.acme.local",
                            "dest": "ws-marketing-02.acme.local",
                            "user": "carol.park",
                            "rule_description": "Endpoint protection was disabled on a managed device.",
                            "_time": (NOW - timedelta(days=1)).isoformat(),
                        },
                    },
                ],
            },
        ))

        # Saved searches
        result.events.append(RawEventData(
            source="splunk", source_type=SourceType.SIEM, provider="splunk",
            event_type="splunk_saved_searches",
            raw_data={
                "response": [
                    {"name": "Failed Login Summary"},
                    {"name": "Privileged Account Activity"},
                    {"name": "Firewall Deny Report"},
                    {"name": "Malware Detection Summary"},
                    {"name": "VPN Connection Anomalies"},
                ],
            },
        ))

        # Correlation rules: enabled and disabled
        result.events.append(RawEventData(
            source="splunk", source_type=SourceType.SIEM, provider="splunk",
            event_type="splunk_correlation_rules",
            raw_data={
                "response": [
                    {
                        "name": "Excessive Failed Logins",
                        "id": "/servicesNS/admin/SplunkEnterpriseSecuritySuite/saved/searches/Excessive%20Failed%20Logins",
                        "content": {
                            "disabled": "0",
                            "action.correlationsearch.label": "High",
                            "description": "Detects brute force login attempts.",
                        },
                    },
                    {
                        "name": "Data Exfiltration Over DNS",
                        "id": "/servicesNS/admin/SplunkEnterpriseSecuritySuite/saved/searches/Data%20Exfiltration%20Over%20DNS",
                        "content": {
                            "disabled": "0",
                            "action.correlationsearch.label": "Critical",
                            "description": "Detects DNS-based data exfiltration.",
                        },
                    },
                    {
                        "name": "Unauthorized Service Account Usage",
                        "id": "/servicesNS/admin/SplunkEnterpriseSecuritySuite/saved/searches/Unauthorized%20Service%20Account",
                        "content": {
                            "disabled": "0",
                            "action.correlationsearch.label": "Medium",
                            "description": "Detects interactive service account usage.",
                        },
                    },
                    {
                        "name": "Suspicious Process Hollowing",
                        "id": "/servicesNS/admin/SplunkEnterpriseSecuritySuite/saved/searches/Suspicious%20Process%20Hollowing",
                        "content": {
                            "disabled": "1",
                            "action.correlationsearch.label": "High",
                            "description": "Detects process hollowing techniques.",
                        },
                    },
                    {
                        "name": "Anomalous Cloud API Activity",
                        "id": "/servicesNS/admin/SplunkEnterpriseSecuritySuite/saved/searches/Anomalous%20Cloud%20API",
                        "content": {
                            "disabled": "1",
                            "action.correlationsearch.label": "Medium",
                            "description": "Detects unusual cloud API call patterns.",
                        },
                    },
                ],
            },
        ))

        # Index health
        result.events.append(RawEventData(
            source="splunk", source_type=SourceType.SIEM, provider="splunk",
            event_type="splunk_index_health",
            raw_data={
                "response": [
                    {
                        "name": "main",
                        "id": "/services/data/indexes/main",
                        "content": {
                            "disabled": "0",
                            "totalEventCount": "15482903",
                            "currentDBSizeMB": "12400",
                            "maxTotalDataSizeMB": "500000",
                        },
                    },
                    {
                        "name": "security",
                        "id": "/services/data/indexes/security",
                        "content": {
                            "disabled": "0",
                            "totalEventCount": "8291034",
                            "currentDBSizeMB": "6800",
                            "maxTotalDataSizeMB": "250000",
                        },
                    },
                    {
                        "name": "network",
                        "id": "/services/data/indexes/network",
                        "content": {
                            "disabled": "0",
                            "totalEventCount": "42938102",
                            "currentDBSizeMB": "34200",
                            "maxTotalDataSizeMB": "500000",
                        },
                    },
                    {
                        "name": "deprecated_audit",
                        "id": "/services/data/indexes/deprecated_audit",
                        "content": {
                            "disabled": "1",
                            "totalEventCount": "0",
                            "currentDBSizeMB": "0",
                            "maxTotalDataSizeMB": "100000",
                        },
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoElasticConnector(BaseConnector):
    """Simulates Elastic Security SIEM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="elastic",
            source_type=SourceType.SIEM,
            provider="elastic",
        )

        # Security alerts: nested _source.kibana.alert format
        result.events.append(RawEventData(
            source="elastic", source_type=SourceType.SIEM, provider="elastic",
            event_type="elastic_security_alerts",
            raw_data={
                "response": {
                    "hits": {
                        "hits": [
                            {
                                "_id": "elastic-alert-001",
                                "_source": {
                                    "@timestamp": (NOW - timedelta(hours=3)).isoformat(),
                                    "kibana.alert": {
                                        "severity": "critical",
                                        "rule": {"name": "Mimikatz Activity Detected", "id": "erule-001"},
                                        "workflow_status": "open",
                                        "risk_score": 95,
                                    },
                                    "host": {"name": "srv-dc-01.acme.local"},
                                    "user": {"name": "admin"},
                                    "threat": [{"tactic": {"name": "Credential Access"}}],
                                },
                            },
                            {
                                "_id": "elastic-alert-002",
                                "_source": {
                                    "@timestamp": (NOW - timedelta(hours=1)).isoformat(),
                                    "kibana.alert": {
                                        "severity": "high",
                                        "rule": {"name": "Suspicious DLL Side-Loading", "id": "erule-002"},
                                        "workflow_status": "acknowledged",
                                        "risk_score": 78,
                                    },
                                    "host": {"name": "ws-eng-01.acme.local"},
                                    "user": {"name": "alice.chen"},
                                    "threat": [{"tactic": {"name": "Defense Evasion"}}],
                                },
                            },
                            {
                                "_id": "elastic-alert-003",
                                "_source": {
                                    "@timestamp": (NOW - timedelta(hours=8)).isoformat(),
                                    "kibana.alert.severity": "medium",
                                    "kibana.alert.rule.name": "Unusual Network Connection",
                                    "kibana.alert.rule.id": "erule-003",
                                    "kibana.alert.workflow_status": "open",
                                    "kibana.alert.risk_score": 52,
                                    "host": {"name": "ws-sales-03.acme.local"},
                                    "user": {"name": "carol.park"},
                                    "threat": [{"tactic": {"name": "Command and Control"}}],
                                },
                            },
                            {
                                "_id": "elastic-alert-004",
                                "_source": {
                                    "@timestamp": (NOW - timedelta(days=1)).isoformat(),
                                    "kibana.alert": {
                                        "severity": "low",
                                        "rule": {"name": "Potentially Unwanted Program", "id": "erule-004"},
                                        "workflow_status": "closed",
                                        "risk_score": 21,
                                    },
                                    "host": {"name": "ws-marketing-02.acme.local"},
                                    "user": {"name": "dave.thompson"},
                                    "threat": [],
                                },
                            },
                        ],
                    },
                },
            },
        ))

        # Detection rules: mix of enabled and disabled
        result.events.append(RawEventData(
            source="elastic", source_type=SourceType.SIEM, provider="elastic",
            event_type="elastic_detection_rules",
            raw_data={
                "response": {
                    "data": [
                        {
                            "id": "erule-001",
                            "name": "Mimikatz Activity Detected",
                            "enabled": True,
                            "severity": "critical",
                            "type": "eql",
                            "risk_score": 95,
                            "tags": ["Windows", "Credential Access", "T1003"],
                            "threat": [{"framework": "MITRE ATT&CK", "tactic": {"name": "Credential Access"}}],
                            "interval": "5m",
                            "updated_at": (NOW - timedelta(days=7)).isoformat(),
                        },
                        {
                            "id": "erule-002",
                            "name": "Suspicious DLL Side-Loading",
                            "enabled": True,
                            "severity": "high",
                            "type": "eql",
                            "risk_score": 78,
                            "tags": ["Windows", "Defense Evasion", "T1574"],
                            "threat": [{"framework": "MITRE ATT&CK", "tactic": {"name": "Defense Evasion"}}],
                            "interval": "5m",
                            "updated_at": (NOW - timedelta(days=14)).isoformat(),
                        },
                        {
                            "id": "erule-003",
                            "name": "Unusual Network Connection",
                            "enabled": True,
                            "severity": "medium",
                            "type": "query",
                            "risk_score": 52,
                            "tags": ["Network", "C2"],
                            "threat": [],
                            "interval": "15m",
                            "updated_at": (NOW - timedelta(days=30)).isoformat(),
                        },
                        {
                            "id": "erule-004",
                            "name": "Potentially Unwanted Program",
                            "enabled": True,
                            "severity": "low",
                            "type": "query",
                            "risk_score": 21,
                            "tags": ["Endpoint"],
                            "threat": [],
                            "interval": "1h",
                            "updated_at": (NOW - timedelta(days=60)).isoformat(),
                        },
                        {
                            "id": "erule-005",
                            "name": "Kernel Module Removal",
                            "enabled": False,
                            "severity": "high",
                            "type": "eql",
                            "risk_score": 73,
                            "tags": ["Linux", "Defense Evasion"],
                            "threat": [{"framework": "MITRE ATT&CK", "tactic": {"name": "Defense Evasion"}}],
                            "interval": "5m",
                            "updated_at": (NOW - timedelta(days=90)).isoformat(),
                        },
                        {
                            "id": "erule-006",
                            "name": "Deprecated: Windows Logon Script",
                            "enabled": False,
                            "severity": "medium",
                            "type": "query",
                            "risk_score": 47,
                            "tags": ["Windows", "Deprecated"],
                            "threat": [],
                            "interval": "1h",
                            "updated_at": (NOW - timedelta(days=180)).isoformat(),
                        },
                    ],
                },
            },
        ))

        # Agent status: some offline and in error
        result.events.append(RawEventData(
            source="elastic", source_type=SourceType.SIEM, provider="elastic",
            event_type="elastic_agent_status",
            raw_data={
                "response": {
                    "results": {
                        "online": 42,
                        "offline": 3,
                        "error": 1,
                        "updating": 2,
                        "inactive": 0,
                        "total": 48,
                    },
                },
            },
        ))

        result.complete()
        return result


class DemoKubernetesConnector(BaseConnector):
    """Simulates Kubernetes cluster security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="kubernetes",
            source_type=SourceType.CLOUD,
            provider="kubernetes",
        )

        # Namespaces: including the risky default namespace
        result.events.append(RawEventData(
            source="kubernetes", source_type=SourceType.CLOUD, provider="kubernetes",
            event_type="k8s_namespaces",
            raw_data={
                "api_url": "https://k8s.acme.internal:6443",
                "response": [
                    {
                        "metadata": {"name": "default", "uid": "ns-uid-001", "labels": {}, "annotations": {}},
                        "status": {"phase": "Active"},
                    },
                    {
                        "metadata": {"name": "acme-prod", "uid": "ns-uid-002", "labels": {"env": "production"}, "annotations": {}},
                        "status": {"phase": "Active"},
                    },
                    {
                        "metadata": {"name": "acme-staging", "uid": "ns-uid-003", "labels": {"env": "staging"}, "annotations": {}},
                        "status": {"phase": "Active"},
                    },
                    {
                        "metadata": {"name": "monitoring", "uid": "ns-uid-004", "labels": {"app": "prometheus"}, "annotations": {}},
                        "status": {"phase": "Active"},
                    },
                    {
                        "metadata": {"name": "kube-system", "uid": "ns-uid-005", "labels": {}, "annotations": {}},
                        "status": {"phase": "Active"},
                    },
                ],
            },
        ))

        # Network policies: some namespaces covered, triggers coverage check
        result.events.append(RawEventData(
            source="kubernetes", source_type=SourceType.CLOUD, provider="kubernetes",
            event_type="k8s_network_policies",
            raw_data={
                "api_url": "https://k8s.acme.internal:6443",
                "response": [
                    {
                        "metadata": {"name": "deny-all-ingress", "namespace": "acme-prod", "uid": "np-uid-001"},
                        "spec": {"podSelector": {}, "policyTypes": ["Ingress"]},
                    },
                    {
                        "metadata": {"name": "allow-api-ingress", "namespace": "acme-prod", "uid": "np-uid-002"},
                        "spec": {
                            "podSelector": {"matchLabels": {"app": "api"}},
                            "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"env": "production"}}}]}],
                            "policyTypes": ["Ingress"],
                        },
                    },
                    {
                        "metadata": {"name": "deny-all-ingress", "namespace": "monitoring", "uid": "np-uid-003"},
                        "spec": {"podSelector": {}, "policyTypes": ["Ingress"]},
                    },
                ],
            },
        ))

        # RBAC bindings: normal, cluster-admin, and anonymous
        result.events.append(RawEventData(
            source="kubernetes", source_type=SourceType.CLOUD, provider="kubernetes",
            event_type="k8s_rbac_bindings",
            raw_data={
                "api_url": "https://k8s.acme.internal:6443",
                "response": [
                    {
                        "metadata": {"name": "acme-dev-binding", "uid": "rb-uid-001"},
                        "roleRef": {"kind": "ClusterRole", "name": "edit", "apiGroup": "rbac.authorization.k8s.io"},
                        "subjects": [{"kind": "Group", "name": "acme-developers", "apiGroup": "rbac.authorization.k8s.io"}],
                    },
                    {
                        "metadata": {"name": "acme-ops-admin", "uid": "rb-uid-002"},
                        "roleRef": {"kind": "ClusterRole", "name": "cluster-admin", "apiGroup": "rbac.authorization.k8s.io"},
                        "subjects": [{"kind": "User", "name": "bob.martinez@acme.com", "apiGroup": "rbac.authorization.k8s.io"}],
                    },
                    {
                        "metadata": {"name": "legacy-anonymous-read", "uid": "rb-uid-003"},
                        "roleRef": {"kind": "ClusterRole", "name": "view", "apiGroup": "rbac.authorization.k8s.io"},
                        "subjects": [{"kind": "User", "name": "system:anonymous", "apiGroup": "rbac.authorization.k8s.io"}],
                    },
                    {
                        "metadata": {"name": "monitoring-reader", "uid": "rb-uid-004"},
                        "roleRef": {"kind": "Role", "name": "monitoring-read", "apiGroup": "rbac.authorization.k8s.io"},
                        "subjects": [{"kind": "ServiceAccount", "name": "prometheus", "namespace": "monitoring"}],
                    },
                ],
            },
        ))

        # Admission controls: one webhook configured
        result.events.append(RawEventData(
            source="kubernetes", source_type=SourceType.CLOUD, provider="kubernetes",
            event_type="k8s_admission_controls",
            raw_data={
                "api_url": "https://k8s.acme.internal:6443",
                "response": [
                    {
                        "metadata": {"name": "gatekeeper-validating-webhook", "uid": "wh-uid-001"},
                        "webhooks": [
                            {"name": "validation.gatekeeper.sh"},
                            {"name": "check-ignore-label.gatekeeper.sh"},
                        ],
                    },
                ],
            },
        ))

        # Running pods: compliant, privileged, root, no limits
        result.events.append(RawEventData(
            source="kubernetes", source_type=SourceType.CLOUD, provider="kubernetes",
            event_type="k8s_running_pods",
            raw_data={
                "api_url": "https://k8s.acme.internal:6443",
                "response": [
                    {
                        "metadata": {"name": "api-server-7b8c9d-xk2lp", "namespace": "acme-prod", "uid": "pod-uid-001"},
                        "spec": {
                            "nodeName": "node-prod-01",
                            "serviceAccountName": "api-sa",
                            "hostNetwork": False,
                            "hostPID": False,
                            "containers": [
                                {
                                    "name": "api",
                                    "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "privileged": False},
                                    "resources": {"limits": {"cpu": "500m", "memory": "512Mi"}},
                                },
                            ],
                        },
                    },
                    {
                        "metadata": {"name": "worker-processor-5f6a7b-mn3op", "namespace": "acme-prod", "uid": "pod-uid-002"},
                        "spec": {
                            "nodeName": "node-prod-02",
                            "serviceAccountName": "worker-sa",
                            "hostNetwork": False,
                            "hostPID": False,
                            "containers": [
                                {
                                    "name": "worker",
                                    "securityContext": {"runAsNonRoot": True, "runAsUser": 1000},
                                    "resources": {},
                                },
                            ],
                        },
                    },
                    {
                        "metadata": {"name": "debug-pod-legacy", "namespace": "acme-staging", "uid": "pod-uid-003"},
                        "spec": {
                            "nodeName": "node-staging-01",
                            "serviceAccountName": "default",
                            "hostNetwork": True,
                            "hostPID": True,
                            "containers": [
                                {
                                    "name": "debug",
                                    "securityContext": {"privileged": True},
                                    "resources": {},
                                },
                            ],
                        },
                    },
                    {
                        "metadata": {"name": "prometheus-0", "namespace": "monitoring", "uid": "pod-uid-004"},
                        "spec": {
                            "nodeName": "node-prod-01",
                            "serviceAccountName": "prometheus",
                            "hostNetwork": False,
                            "hostPID": False,
                            "containers": [
                                {
                                    "name": "prometheus",
                                    "securityContext": {"runAsUser": 0},
                                    "resources": {"limits": {"cpu": "2000m", "memory": "4Gi"}},
                                },
                            ],
                        },
                    },
                ],
            },
        ))

        # Deployments: various replica counts, including single-replica in non-system ns
        result.events.append(RawEventData(
            source="kubernetes", source_type=SourceType.CLOUD, provider="kubernetes",
            event_type="k8s_deployments",
            raw_data={
                "api_url": "https://k8s.acme.internal:6443",
                "response": [
                    {
                        "metadata": {"name": "api-server", "namespace": "acme-prod", "uid": "deploy-uid-001"},
                        "spec": {"replicas": 3, "strategy": {"type": "RollingUpdate"}},
                        "status": {"readyReplicas": 3, "availableReplicas": 3},
                    },
                    {
                        "metadata": {"name": "worker-processor", "namespace": "acme-prod", "uid": "deploy-uid-002"},
                        "spec": {"replicas": 2, "strategy": {"type": "RollingUpdate"}},
                        "status": {"readyReplicas": 2, "availableReplicas": 2},
                    },
                    {
                        "metadata": {"name": "staging-app", "namespace": "acme-staging", "uid": "deploy-uid-003"},
                        "spec": {"replicas": 1, "strategy": {"type": "Recreate"}},
                        "status": {"readyReplicas": 1, "availableReplicas": 1},
                    },
                    {
                        "metadata": {"name": "redis-cache", "namespace": "acme-prod", "uid": "deploy-uid-004"},
                        "spec": {"replicas": 1, "strategy": {"type": "RollingUpdate"}},
                        "status": {"readyReplicas": 1, "availableReplicas": 1},
                    },
                    {
                        "metadata": {"name": "coredns", "namespace": "kube-system", "uid": "deploy-uid-005"},
                        "spec": {"replicas": 1, "strategy": {"type": "RollingUpdate"}},
                        "status": {"readyReplicas": 1, "availableReplicas": 1},
                    },
                ],
            },
        ))

        result.complete()
        return result


# --- Scanner, ITSM, Code Security & Other Demo Connectors ---


class DemoTenableConnector(BaseConnector):
    """Simulates Tenable.io collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="tenable",
            source_type=SourceType.SCANNER,
            provider="tenable",
        )

        # vuln_export — critical and medium vulns
        result.events.append(RawEventData(
            source="tenable", source_type=SourceType.SCANNER, provider="tenable",
            event_type="vuln_export",
            raw_data={
                "vulnerabilities": [
                    {
                        "plugin_id": "97041",
                        "severity_id": 4,
                        "state": "open",
                        "plugin": {
                            "name": "OpenSSL Buffer Overflow",
                            "cve": ["CVE-2024-0567"],
                            "cvss_base_score": 7.5,
                            "cvss3_base_score": 9.8,
                        },
                        "asset": {
                            "uuid": "a1b2c3d4-e5f6-7890-abcd-ef0123456789",
                            "ipv4": "10.10.1.25",
                            "hostname": "acme-web-prod-01",
                            "fqdn": "acme-web-prod-01.acmecorp.internal",
                        },
                        "port": {"protocol": "tcp", "port": 443},
                        "first_found": (NOW - timedelta(days=14)).isoformat(),
                        "last_found": NOW.isoformat(),
                        "output": "OpenSSL 1.1.1t detected, vulnerable to buffer overflow.",
                    },
                    {
                        "plugin_id": "11219",
                        "severity_id": 2,
                        "state": "open",
                        "plugin": {
                            "name": "Apache HTTP Server Outdated Version",
                            "cve": [],
                            "cvss_base_score": 4.3,
                            "cvss3_base_score": 5.3,
                        },
                        "asset": {
                            "uuid": "b2c3d4e5-f6a7-8901-bcde-f01234567890",
                            "ipv4": "10.10.2.40",
                            "hostname": "acme-api-staging-01",
                        },
                        "port": {"protocol": "tcp", "port": 80},
                        "first_found": (NOW - timedelta(days=30)).isoformat(),
                        "last_found": NOW.isoformat(),
                        "output": "Apache HTTP Server 2.4.49 is outdated.",
                    },
                ],
            },
        ))

        # compliance_audits — one pass, one fail, one warning
        result.events.append(RawEventData(
            source="tenable", source_type=SourceType.SCANNER, provider="tenable",
            event_type="compliance_audits",
            raw_data={
                "audits": [
                    {
                        "check_name": "Ensure SSH root login is disabled",
                        "status": "PASSED",
                        "asset": {"uuid": "a1b2c3d4-e5f6-7890-abcd-ef0123456789", "hostname": "acme-web-prod-01"},
                        "reference": "CIS_Linux_Benchmark_v2.0.0:5.2.10",
                        "benchmark": "CIS Ubuntu Linux 22.04 LTS Benchmark",
                        "audit_file": "CIS_Ubuntu_22.04_v2.0.0_L1.audit",
                    },
                    {
                        "check_name": "Ensure password expiration is 365 days or less",
                        "status": "FAILED",
                        "asset": {"uuid": "b2c3d4e5-f6a7-8901-bcde-f01234567890", "hostname": "acme-api-staging-01"},
                        "reference": "CIS_Linux_Benchmark_v2.0.0:5.5.1.1",
                        "solution": "Set PASS_MAX_DAYS to 365 in /etc/login.defs",
                        "benchmark": "CIS Ubuntu Linux 22.04 LTS Benchmark",
                        "audit_file": "CIS_Ubuntu_22.04_v2.0.0_L1.audit",
                    },
                    {
                        "check_name": "Ensure journald is configured to send logs to rsyslog",
                        "status": "WARNING",
                        "asset": {"uuid": "a1b2c3d4-e5f6-7890-abcd-ef0123456789", "hostname": "acme-web-prod-01"},
                        "reference": "CIS_Linux_Benchmark_v2.0.0:4.2.2.1",
                        "benchmark": "CIS Ubuntu Linux 22.04 LTS Benchmark",
                    },
                ],
            },
        ))

        # asset_export
        result.events.append(RawEventData(
            source="tenable", source_type=SourceType.SCANNER, provider="tenable",
            event_type="asset_export",
            raw_data={
                "assets": [
                    {
                        "id": "a1b2c3d4-e5f6-7890-abcd-ef0123456789",
                        "hostname": "acme-web-prod-01",
                        "fqdn": "acme-web-prod-01.acmecorp.internal",
                        "ipv4": ["10.10.1.25"],
                        "ipv6": [],
                        "operating_system": ["Ubuntu 22.04.3 LTS"],
                        "mac_address": ["00:1A:2B:3C:4D:5E"],
                        "agent_uuid": "agent-001",
                        "last_seen": NOW.isoformat(),
                        "sources": [{"name": "NESSUS_AGENT", "first_seen": (NOW - timedelta(days=90)).isoformat()}],
                    },
                ],
            },
        ))

        # agent_status — one online, one offline
        result.events.append(RawEventData(
            source="tenable", source_type=SourceType.SCANNER, provider="tenable",
            event_type="agent_status",
            raw_data={
                "agents": [
                    {
                        "id": "agent-001",
                        "name": "acme-web-prod-01",
                        "status": "online",
                        "platform": "linux",
                        "ip": "10.10.1.25",
                        "last_connect": NOW.isoformat(),
                        "plugin_feed_id": "202603190000",
                        "core_version": "10.6.1",
                    },
                    {
                        "id": "agent-002",
                        "name": "acme-legacy-db-01",
                        "status": "offline",
                        "platform": "linux",
                        "ip": "10.10.3.10",
                        "last_connect": (NOW - timedelta(days=7)).isoformat(),
                        "plugin_feed_id": "202603120000",
                        "core_version": "10.5.0",
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoQualysConnector(BaseConnector):
    """Simulates Qualys VMDR collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="qualys",
            source_type=SourceType.SCANNER,
            provider="qualys",
        )

        # host_detections
        result.events.append(RawEventData(
            source="qualys", source_type=SourceType.SCANNER, provider="qualys",
            event_type="host_detections",
            raw_data={
                "detections": {
                    "RESPONSE": {
                        "HOST_LIST": {
                            "HOST": [
                                {
                                    "IP": "10.20.1.50",
                                    "ID": "qhost-101",
                                    "DNS": "acme-erp-prod-01.acmecorp.internal",
                                    "DETECTION_LIST": {
                                        "DETECTION": [
                                            {
                                                "QID": "38739",
                                                "SEVERITY": "5",
                                                "TITLE": "SSL/TLS Use of Weak RC4 Cipher",
                                                "CVE_ID": "CVE-2013-2566",
                                                "TYPE": "Vuln",
                                                "STATUS": "Active",
                                                "RESULTS": "RC4 cipher detected on port 443",
                                                "FIRST_FOUND_DATETIME": (NOW - timedelta(days=60)).isoformat(),
                                                "LAST_FOUND_DATETIME": NOW.isoformat(),
                                            },
                                            {
                                                "QID": "86002",
                                                "SEVERITY": "2",
                                                "TITLE": "HTTP Server Type and Version",
                                                "CVE_ID": "",
                                                "TYPE": "Info",
                                                "STATUS": "Active",
                                                "RESULTS": "nginx/1.24.0",
                                                "FIRST_FOUND_DATETIME": (NOW - timedelta(days=90)).isoformat(),
                                                "LAST_FOUND_DATETIME": NOW.isoformat(),
                                            },
                                        ],
                                    },
                                },
                            ],
                        },
                    },
                },
            },
        ))

        # compliance_posture
        result.events.append(RawEventData(
            source="qualys", source_type=SourceType.SCANNER, provider="qualys",
            event_type="compliance_posture",
            raw_data={
                "posture": {
                    "RESPONSE": {
                        "COMPLIANCE_POSTURE": {
                            "ENTRY": [
                                {
                                    "CONTROL_ID": "CIS-4.1.1",
                                    "CONTROL_TITLE": "Ensure auditing is enabled",
                                    "STATUS": "PASSED",
                                    "CRITICALITY": "SERIOUS",
                                    "POLICY": "CIS Benchmark Linux L1",
                                    "TECHNOLOGY": "Linux",
                                    "HOST_ID": "qhost-101",
                                    "HOST_IP": "10.20.1.50",
                                },
                                {
                                    "CONTROL_ID": "CIS-5.3.1",
                                    "CONTROL_TITLE": "Ensure password creation requirements are configured",
                                    "STATUS": "FAILED",
                                    "CRITICALITY": "CRITICAL",
                                    "POLICY": "CIS Benchmark Linux L1",
                                    "TECHNOLOGY": "Linux",
                                    "RATIONALE": "Password complexity not enforced.",
                                    "REMEDIATION": "Configure pam_pwquality with minlen=14.",
                                    "HOST_ID": "qhost-101",
                                    "HOST_IP": "10.20.1.50",
                                },
                            ],
                        },
                    },
                },
            },
        ))

        # asset_inventory
        result.events.append(RawEventData(
            source="qualys", source_type=SourceType.SCANNER, provider="qualys",
            event_type="asset_inventory",
            raw_data={
                "hosts": {
                    "RESPONSE": {
                        "HOST_LIST": {
                            "HOST": [
                                {
                                    "ID": "qhost-101",
                                    "IP": "10.20.1.50",
                                    "DNS": "acme-erp-prod-01.acmecorp.internal",
                                    "OS": "Red Hat Enterprise Linux 9.2",
                                    "LAST_SCAN_DATETIME": NOW.isoformat(),
                                    "TRACKING_METHOD": "AGENT",
                                    "TAGS": "production,erp,pci-scope",
                                },
                            ],
                        },
                    },
                },
            },
        ))

        # knowledge_base
        result.events.append(RawEventData(
            source="qualys", source_type=SourceType.SCANNER, provider="qualys",
            event_type="knowledge_base",
            raw_data={
                "knowledge_base": {
                    "RESPONSE": {
                        "VULN_LIST": {
                            "VULN": [
                                {
                                    "QID": "38739",
                                    "TITLE": "SSL/TLS Use of Weak RC4 Cipher",
                                    "VULN_TYPE": "Vulnerability",
                                    "SEVERITY_LEVEL": "5",
                                    "CVE_LIST": "CVE-2013-2566",
                                    "DIAGNOSIS": "The remote host supports RC4 ciphers.",
                                    "SOLUTION": "Disable RC4 ciphers in TLS configuration.",
                                    "CONSEQUENCE": "An attacker may recover plaintext.",
                                },
                            ],
                        },
                    },
                },
            },
        ))

        result.complete()
        return result


class DemoWizConnector(BaseConnector):
    """Simulates Wiz cloud security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="wiz",
            source_type=SourceType.SCANNER,
            provider="wiz",
        )

        # wiz_issues — toxic combo, config issue, vuln issue
        result.events.append(RawEventData(
            source="wiz", source_type=SourceType.SCANNER, provider="wiz",
            event_type="wiz_issues",
            raw_data={
                "issues": [
                    {
                        "id": "wiz-issue-001",
                        "title": "Publicly exposed VM with critical vulnerabilities",
                        "severity": "CRITICAL",
                        "type": "TOXIC_COMBINATION",
                        "status": "OPEN",
                        "entity": {
                            "id": "vm-acme-payments-01",
                            "type": "VIRTUAL_MACHINE",
                            "name": "acme-payments-prod-01",
                        },
                        "sourceRule": {"id": "wiz-rule-tc-001", "name": "Public VM with Critical CVEs"},
                        "projects": [{"name": "Acme Payments"}],
                        "createdAt": (NOW - timedelta(days=3)).isoformat(),
                        "dueAt": (NOW + timedelta(days=4)).isoformat(),
                    },
                    {
                        "id": "wiz-issue-002",
                        "title": "S3 bucket allows public read access",
                        "severity": "HIGH",
                        "type": "CLOUD_CONFIGURATION",
                        "status": "OPEN",
                        "entity": {
                            "id": "s3-acme-reports",
                            "type": "BUCKET",
                            "name": "acme-financial-reports",
                        },
                        "sourceRule": {"id": "wiz-rule-cfg-010", "name": "S3 Public Access"},
                        "projects": [{"name": "Acme Finance"}],
                        "createdAt": (NOW - timedelta(days=10)).isoformat(),
                    },
                    {
                        "id": "wiz-issue-003",
                        "title": "Log4j CVE-2021-44228 detected",
                        "severity": "CRITICAL",
                        "type": "VULNERABILITY",
                        "status": "IN_PROGRESS",
                        "entity": {
                            "id": "container-acme-search",
                            "type": "CONTAINER_IMAGE",
                            "name": "acme-search-service:2.3.1",
                        },
                        "sourceRule": {"id": "wiz-rule-vuln-001", "name": "Critical CVE Detected"},
                        "projects": [{"name": "Acme Platform"}],
                        "createdAt": (NOW - timedelta(days=20)).isoformat(),
                    },
                ],
            },
        ))

        # wiz_config_findings
        result.events.append(RawEventData(
            source="wiz", source_type=SourceType.SCANNER, provider="wiz",
            event_type="wiz_config_findings",
            raw_data={
                "findings": [
                    {
                        "id": "wiz-cfg-001",
                        "title": "RDS instance not encrypted at rest",
                        "severity": "HIGH",
                        "result": "FAIL",
                        "status": "OPEN",
                        "rule": {
                            "id": "wiz-rule-rds-enc",
                            "name": "RDS Encryption at Rest",
                            "description": "All RDS instances must have encryption at rest enabled.",
                            "remediationInstructions": "Enable encryption via AWS console or modify-db-instance.",
                        },
                        "resource": {
                            "id": "rds-acme-orders",
                            "type": "RDS_INSTANCE",
                            "name": "acme-orders-prod",
                            "nativeType": "aws_rds_db_instance",
                            "region": "us-east-1",
                            "subscription": {"id": "912345678012", "name": "acme-production"},
                        },
                        "analyzedAt": NOW.isoformat(),
                    },
                ],
            },
        ))

        # wiz_vuln_findings
        result.events.append(RawEventData(
            source="wiz", source_type=SourceType.SCANNER, provider="wiz",
            event_type="wiz_vuln_findings",
            raw_data={
                "findings": [
                    {
                        "id": "wiz-vuln-001",
                        "name": "CVE-2024-3094",
                        "detailedName": "xz-utils backdoor (CVE-2024-3094)",
                        "severity": "CRITICAL",
                        "CVEDescription": "Malicious code in xz-utils 5.6.0/5.6.1 allowing SSH bypass.",
                        "CVSSScore": 10.0,
                        "hasExploit": True,
                        "hasCISAKEVExploit": True,
                        "version": "5.6.0",
                        "fixedVersion": "5.6.1.2",
                        "vendorSeverity": "CRITICAL",
                        "status": "OPEN",
                        "firstDetectedAt": (NOW - timedelta(days=5)).isoformat(),
                        "lastDetectedAt": NOW.isoformat(),
                        "vulnerableAsset": {
                            "id": "vm-acme-build-01",
                            "type": "VIRTUAL_MACHINE",
                            "name": "acme-build-server-01",
                            "region": "us-east-1",
                            "subscription": {"id": "912345678012", "name": "acme-production"},
                        },
                    },
                ],
            },
        ))

        # wiz_graph
        result.events.append(RawEventData(
            source="wiz", source_type=SourceType.SCANNER, provider="wiz",
            event_type="wiz_graph",
            raw_data={
                "graph": [
                    {
                        "entities": [
                            {
                                "id": "vm-acme-payments-01",
                                "type": "VIRTUAL_MACHINE",
                                "name": "acme-payments-prod-01",
                                "properties": {"publiclyExposed": True, "os": "Ubuntu 22.04"},
                            },
                            {
                                "id": "rds-acme-orders",
                                "type": "RDS_INSTANCE",
                                "name": "acme-orders-prod",
                                "properties": {"encrypted": False, "engine": "postgres"},
                            },
                        ],
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoPrismaConnector(BaseConnector):
    """Simulates Prisma Cloud CSPM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="prisma",
            source_type=SourceType.CSPM,
            provider="prisma",
        )

        # prisma_alerts — CONFIG and IAM policy types
        result.events.append(RawEventData(
            source="prisma", source_type=SourceType.CSPM, provider="prisma",
            event_type="prisma_alerts",
            raw_data={
                "alerts": [
                    {
                        "id": "P-ALERT-001",
                        "status": "open",
                        "alertTime": NOW.isoformat(),
                        "policy": {
                            "policyId": "prisma-pol-s3pub",
                            "name": "S3 Bucket Has Public Access Enabled",
                            "policyType": "CONFIG",
                            "severity": "high",
                            "description": "S3 bucket allows public access.",
                            "recommendation": "Enable S3 Block Public Access settings.",
                            "complianceMetadata": [{"standardName": "CIS AWS", "requirementId": "2.1.5"}],
                        },
                        "resource": {
                            "id": "acme-customer-uploads",
                            "rrn": "rrn:aws:s3:us-east-1:912345678012:acme-customer-uploads",
                            "name": "acme-customer-uploads",
                            "resourceType": "aws_s3_bucket",
                            "region": "us-east-1",
                            "account": "Acme Production",
                            "accountId": "912345678012",
                            "cloudType": "aws",
                        },
                        "riskDetail": {"riskScore": {"score": 78}},
                    },
                    {
                        "id": "P-ALERT-002",
                        "status": "open",
                        "alertTime": NOW.isoformat(),
                        "policy": {
                            "policyId": "prisma-pol-iam-admin",
                            "name": "IAM User Has Inline Admin Policy",
                            "policyType": "IAM",
                            "severity": "critical",
                            "description": "IAM user has an inline policy with full admin access.",
                            "recommendation": "Remove inline admin policy and use managed roles.",
                        },
                        "resource": {
                            "id": "AIDA1234567890EXAMPLE",
                            "rrn": "rrn:aws:iam::912345678012:user/carol.nguyen",
                            "name": "carol.nguyen",
                            "resourceType": "aws_iam_user",
                            "region": "global",
                            "account": "Acme Production",
                            "accountId": "912345678012",
                            "cloudType": "aws",
                        },
                        "riskDetail": {"riskScore": {"score": 95}},
                    },
                ],
            },
        ))

        # prisma_compliance — complianceSummaries path
        result.events.append(RawEventData(
            source="prisma", source_type=SourceType.CSPM, provider="prisma",
            event_type="prisma_compliance",
            raw_data={
                "compliance": {
                    "complianceSummaries": [
                        {
                            "id": "cis-aws-1.5",
                            "name": "CIS AWS Foundations Benchmark v1.5",
                            "passedResources": 187,
                            "failedResources": 23,
                        },
                        {
                            "id": "nist-800-53",
                            "name": "NIST 800-53 Rev 5",
                            "passedResources": 312,
                            "failedResources": 0,
                        },
                    ],
                },
            },
        ))

        # prisma_assets — groupedAggregates path
        result.events.append(RawEventData(
            source="prisma", source_type=SourceType.CSPM, provider="prisma",
            event_type="prisma_assets",
            raw_data={
                "inventory": {
                    "groupedAggregates": [
                        {
                            "cloudTypeName": "AWS",
                            "serviceName": "Amazon S3",
                            "totalResources": 45,
                            "passedResources": 40,
                            "failedResources": 5,
                            "highSeverityFailedResources": 2,
                            "mediumSeverityFailedResources": 3,
                            "lowSeverityFailedResources": 0,
                        },
                        {
                            "cloudTypeName": "AWS",
                            "serviceName": "Amazon EC2",
                            "totalResources": 120,
                            "passedResources": 115,
                            "failedResources": 5,
                            "highSeverityFailedResources": 1,
                            "mediumSeverityFailedResources": 4,
                            "lowSeverityFailedResources": 0,
                        },
                    ],
                },
            },
        ))

        # prisma_policies
        result.events.append(RawEventData(
            source="prisma", source_type=SourceType.CSPM, provider="prisma",
            event_type="prisma_policies",
            raw_data={
                "policies": [
                    {
                        "policyId": "prisma-pol-s3pub",
                        "name": "S3 Bucket Has Public Access Enabled",
                        "policyType": "config",
                        "severity": "high",
                        "enabled": True,
                        "cloudType": "aws",
                        "description": "Detects S3 buckets with public access.",
                        "rule": {"type": "Config"},
                        "complianceMetadata": [{"standardName": "CIS AWS"}],
                    },
                    {
                        "policyId": "prisma-pol-disabled-example",
                        "name": "EC2 Instance Metadata v1 Enabled",
                        "policyType": "config",
                        "severity": "medium",
                        "enabled": False,
                        "cloudType": "aws",
                        "description": "IMDSv1 allows SSRF exploitation.",
                        "rule": {"type": "Config"},
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoServiceNowConnector(BaseConnector):
    """Simulates ServiceNow ITSM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="servicenow",
            source_type=SourceType.ITSM,
            provider="servicenow",
        )

        # snow_change_requests — approved with backout, unapproved, missing backout
        result.events.append(RawEventData(
            source="servicenow", source_type=SourceType.ITSM, provider="servicenow",
            event_type="snow_change_requests",
            raw_data={
                "instance": "acmecorp.service-now.com",
                "response": [
                    {
                        "sys_id": "chg-001",
                        "number": "CHG0012345",
                        "approval": "approved",
                        "type": "standard",
                        "backout_plan": "Revert deployment via Terraform rollback to previous state file.",
                        "short_description": "Deploy v2.4.1 of payment service to production",
                    },
                    {
                        "sys_id": "chg-002",
                        "number": "CHG0012346",
                        "approval": "requested",
                        "type": "normal",
                        "backout_plan": "",
                        "short_description": "Migrate database to Aurora PostgreSQL 15",
                    },
                    {
                        "sys_id": "chg-003",
                        "number": "CHG0012347",
                        "approval": "not requested",
                        "type": "emergency",
                        "backout_plan": "Restore from latest RDS snapshot.",
                        "short_description": "Hotfix CVE-2024-3094 on build servers",
                    },
                ],
            },
        ))

        # snow_incidents — resolved, open past SLA, open within SLA
        result.events.append(RawEventData(
            source="servicenow", source_type=SourceType.ITSM, provider="servicenow",
            event_type="snow_incidents",
            raw_data={
                "instance": "acmecorp.service-now.com",
                "response": [
                    {
                        "sys_id": "inc-001",
                        "number": "INC0078901",
                        "state": "7",
                        "priority": "2",
                        "short_description": "Production API latency spike",
                        "sla_due": (NOW - timedelta(days=1)).isoformat(),
                    },
                    {
                        "sys_id": "inc-002",
                        "number": "INC0078902",
                        "state": "2",
                        "priority": "1",
                        "short_description": "Payment processing outage for EU customers",
                        "sla_due": (NOW - timedelta(hours=6)).isoformat(),
                    },
                    {
                        "sys_id": "inc-003",
                        "number": "INC0078903",
                        "state": "1",
                        "priority": "3",
                        "short_description": "SSO login intermittent failures",
                        "sla_due": (NOW + timedelta(hours=12)).isoformat(),
                    },
                ],
            },
        ))

        # snow_problems — open with root cause, open without root cause
        result.events.append(RawEventData(
            source="servicenow", source_type=SourceType.ITSM, provider="servicenow",
            event_type="snow_problems",
            raw_data={
                "instance": "acmecorp.service-now.com",
                "response": [
                    {
                        "sys_id": "prb-001",
                        "number": "PRB0005678",
                        "state": "2",
                        "cause_notes": "Memory leak in payment-service container caused OOM kills.",
                        "short_description": "Recurring API gateway 502 errors",
                    },
                    {
                        "sys_id": "prb-002",
                        "number": "PRB0005679",
                        "state": "1",
                        "cause_notes": "",
                        "short_description": "Intermittent database connection pool exhaustion",
                    },
                ],
            },
        ))

        # snow_knowledge_articles — recent and stale
        result.events.append(RawEventData(
            source="servicenow", source_type=SourceType.ITSM, provider="servicenow",
            event_type="snow_knowledge_articles",
            raw_data={
                "instance": "acmecorp.service-now.com",
                "response": [
                    {
                        "sys_id": "kb-001",
                        "number": "KB0010234",
                        "short_description": "Acme Corp Incident Response Runbook",
                        "sys_updated_on": (NOW - timedelta(days=45)).isoformat(),
                    },
                    {
                        "sys_id": "kb-002",
                        "number": "KB0010235",
                        "short_description": "VPN Configuration Guide for Remote Employees",
                        "sys_updated_on": (NOW - timedelta(days=400)).isoformat(),
                    },
                ],
            },
        ))

        # snow_risks — compliant and non-compliant
        result.events.append(RawEventData(
            source="servicenow", source_type=SourceType.ITSM, provider="servicenow",
            event_type="snow_risks",
            raw_data={
                "instance": "acmecorp.service-now.com",
                "response": [
                    {
                        "sys_id": "risk-001",
                        "number": "RISK0002345",
                        "short_description": "Third-party vendor data exposure risk",
                        "acceptance_owner": "david.park@acmecorp.com",
                        "expiry": (NOW + timedelta(days=90)).isoformat(),
                    },
                    {
                        "sys_id": "risk-002",
                        "number": "RISK0002346",
                        "short_description": "Legacy ERP system end-of-life risk",
                        "acceptance_owner": "",
                        "expiry": "",
                    },
                ],
            },
        ))

        # snow_policies — current review and expired review
        result.events.append(RawEventData(
            source="servicenow", source_type=SourceType.ITSM, provider="servicenow",
            event_type="snow_policies",
            raw_data={
                "instance": "acmecorp.service-now.com",
                "response": [
                    {
                        "sys_id": "pol-001",
                        "number": "POL0000456",
                        "short_description": "Acme Corp Acceptable Use Policy",
                        "review_date": (NOW + timedelta(days=60)).isoformat(),
                    },
                    {
                        "sys_id": "pol-002",
                        "number": "POL0000457",
                        "short_description": "Acme Corp Data Classification Policy",
                        "review_date": (NOW - timedelta(days=120)).isoformat(),
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoOneTrustConnector(BaseConnector):
    """Simulates OneTrust GRC collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="onetrust",
            source_type=SourceType.GRC,
            provider="onetrust",
        )

        # onetrust_assessments — completed assessment + incomplete PIA
        result.events.append(RawEventData(
            source="onetrust", source_type=SourceType.GRC, provider="onetrust",
            event_type="onetrust_assessments",
            raw_data={
                "response": [
                    {
                        "assessmentId": "ot-assess-001",
                        "name": "Acme Customer Data Platform Risk Assessment",
                        "status": "Complete",
                        "type": "Risk Assessment",
                        "createdDt": (NOW - timedelta(days=90)).isoformat(),
                        "orgGroup": {"name": "Acme Engineering"},
                    },
                    {
                        "assessmentId": "ot-assess-002",
                        "name": "Acme Marketing Analytics PIA",
                        "status": "In Progress",
                        "type": "PIA",
                        "createdDt": (NOW - timedelta(days=45)).isoformat(),
                        "orgGroup": {"name": "Acme Marketing"},
                    },
                    {
                        "assessmentId": "ot-assess-003",
                        "name": "EU Customer Profiling DPIA",
                        "status": "Draft",
                        "type": "DPIA",
                        "createdDt": (NOW - timedelta(days=30)).isoformat(),
                        "orgGroup": {"name": "Acme Legal"},
                    },
                ],
            },
        ))

        # onetrust_data_maps
        result.events.append(RawEventData(
            source="onetrust", source_type=SourceType.GRC, provider="onetrust",
            event_type="onetrust_data_maps",
            raw_data={
                "response": [
                    {
                        "id": "dm-001",
                        "name": "Acme Customer PII Data Flow",
                        "description": "Maps PII flow from web forms through processing to storage.",
                        "orgGroup": {"name": "Acme Engineering"},
                    },
                    {
                        "id": "dm-002",
                        "name": "Acme HR Employee Records",
                        "description": "Employee data lifecycle from onboarding through offboarding.",
                        "orgGroup": {"name": "Acme HR"},
                    },
                ],
            },
        ))

        # onetrust_dsar_requests — one completed, one overdue
        result.events.append(RawEventData(
            source="onetrust", source_type=SourceType.GRC, provider="onetrust",
            event_type="onetrust_dsar_requests",
            raw_data={
                "response": [
                    {
                        "requestId": "dsar-001",
                        "subjectName": "Jane Doe",
                        "status": "Completed",
                        "type": "Access Request",
                        "createdDate": (NOW - timedelta(days=15)).isoformat(),
                        "deadline": (NOW + timedelta(days=15)).isoformat(),
                    },
                    {
                        "requestId": "dsar-002",
                        "subjectName": "John Smith",
                        "status": "Open",
                        "type": "Deletion Request",
                        "createdDate": (NOW - timedelta(days=45)).isoformat(),
                        "deadline": (NOW - timedelta(days=15)).isoformat(),
                    },
                ],
            },
        ))

        # onetrust_consent_records
        result.events.append(RawEventData(
            source="onetrust", source_type=SourceType.GRC, provider="onetrust",
            event_type="onetrust_consent_records",
            raw_data={
                "response": [
                    {
                        "consentReceiptId": "consent-001",
                        "purpose": "Marketing Communications",
                        "status": "Active",
                        "collectionPoint": "acmecorp.com/newsletter",
                    },
                    {
                        "consentReceiptId": "consent-002",
                        "purpose": "Analytics and Performance",
                        "status": "Withdrawn",
                        "collectionPoint": "acmecorp.com/cookie-banner",
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoMLflowConnector(BaseConnector):
    """Simulates MLflow model registry collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="mlflow",
            source_type=SourceType.CUSTOM,
            provider="mlflow",
        )

        # mlflow_registered_models — one with description, one without
        result.events.append(RawEventData(
            source="mlflow", source_type=SourceType.CUSTOM, provider="mlflow",
            event_type="mlflow_registered_models",
            raw_data={
                "response": [
                    {
                        "name": "acme-fraud-detection",
                        "description": "XGBoost model for real-time payment fraud detection. Trained on 2024 Q4 data.",
                        "creation_timestamp": (NOW - timedelta(days=120)).isoformat(),
                        "last_updated_timestamp": (NOW - timedelta(days=5)).isoformat(),
                        "tags": [{"key": "team", "value": "fraud-ops"}, {"key": "pii", "value": "true"}],
                    },
                    {
                        "name": "acme-churn-predictor",
                        "description": "",
                        "creation_timestamp": (NOW - timedelta(days=60)).isoformat(),
                        "last_updated_timestamp": (NOW - timedelta(days=30)).isoformat(),
                        "tags": [{"key": "team", "value": "growth"}],
                    },
                ],
            },
        ))

        # mlflow_experiments
        result.events.append(RawEventData(
            source="mlflow", source_type=SourceType.CUSTOM, provider="mlflow",
            event_type="mlflow_experiments",
            raw_data={
                "response": [
                    {
                        "experiment_id": "exp-101",
                        "name": "fraud-detection-v3-tuning",
                        "lifecycle_stage": "active",
                        "artifact_location": "s3://acme-ml-artifacts/fraud-detection-v3",
                        "creation_time": (NOW - timedelta(days=30)).isoformat(),
                    },
                    {
                        "experiment_id": "exp-102",
                        "name": "churn-predictor-baseline",
                        "lifecycle_stage": "active",
                        "artifact_location": "s3://acme-ml-artifacts/churn-predictor",
                        "creation_time": (NOW - timedelta(days=60)).isoformat(),
                    },
                ],
            },
        ))

        # mlflow_model_versions — production with desc, production without desc
        result.events.append(RawEventData(
            source="mlflow", source_type=SourceType.CUSTOM, provider="mlflow",
            event_type="mlflow_model_versions",
            raw_data={
                "response": [
                    {
                        "name": "acme-fraud-detection",
                        "version": "3",
                        "current_stage": "Production",
                        "description": "V3: Improved precision on cross-border transactions. AUC=0.97.",
                        "status": "READY",
                        "creation_timestamp": (NOW - timedelta(days=5)).isoformat(),
                        "run_id": "run-abc123",
                    },
                    {
                        "name": "acme-churn-predictor",
                        "version": "1",
                        "current_stage": "Production",
                        "description": "",
                        "status": "READY",
                        "creation_timestamp": (NOW - timedelta(days=30)).isoformat(),
                        "run_id": "run-def456",
                    },
                    {
                        "name": "acme-fraud-detection",
                        "version": "2",
                        "current_stage": "Archived",
                        "description": "V2: Baseline XGBoost model.",
                        "status": "READY",
                        "creation_timestamp": (NOW - timedelta(days=60)).isoformat(),
                        "run_id": "run-ghi789",
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoSnykConnector(BaseConnector):
    """Simulates Snyk code security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="snyk",
            source_type=SourceType.CODE,
            provider="snyk",
        )

        # snyk_projects — recently tested and stale
        result.events.append(RawEventData(
            source="snyk", source_type=SourceType.CODE, provider="snyk",
            event_type="snyk_projects",
            raw_data={
                "org_id": "acme-org-001",
                "response": [
                    {
                        "id": "snyk-proj-001",
                        "attributes": {
                            "name": "acmecorp/payment-service:package.json",
                            "type": "npm",
                            "last_tested_date": (NOW - timedelta(hours=2)).isoformat(),
                            "origin": "github",
                            "status": "active",
                        },
                    },
                    {
                        "id": "snyk-proj-002",
                        "attributes": {
                            "name": "acmecorp/legacy-auth:requirements.txt",
                            "type": "pip",
                            "last_tested_date": (NOW - timedelta(days=14)).isoformat(),
                            "origin": "github",
                            "status": "active",
                        },
                    },
                ],
            },
        ))

        # snyk_issues — critical with fix, high without fix
        result.events.append(RawEventData(
            source="snyk", source_type=SourceType.CODE, provider="snyk",
            event_type="snyk_issues",
            raw_data={
                "org_id": "acme-org-001",
                "response": [
                    {
                        "id": "snyk-issue-001",
                        "attributes": {
                            "title": "Prototype Pollution in lodash",
                            "effective_severity_level": "critical",
                            "problems": [{"id": "CVE-2020-28500", "source": "CVE"}],
                            "cvss_score": 9.1,
                            "package_name": "lodash",
                            "package_version": "4.17.15",
                            "is_fixable": True,
                            "fix_versions": ["4.17.21"],
                            "exploit_maturity": "proof-of-concept",
                            "language": "javascript",
                            "coordinates": [{"project_name": "acmecorp/payment-service"}],
                        },
                    },
                    {
                        "id": "snyk-issue-002",
                        "attributes": {
                            "title": "Improper Input Validation in Django",
                            "effective_severity_level": "high",
                            "problems": [{"id": "CVE-2024-27351", "source": "CVE"}],
                            "cvss_score": 7.5,
                            "package_name": "django",
                            "package_version": "4.2.9",
                            "is_fixable": False,
                            "fix_versions": [],
                            "exploit_maturity": "no-known-exploit",
                            "language": "python",
                            "coordinates": [{"project_name": "acmecorp/legacy-auth"}],
                        },
                    },
                ],
            },
        ))

        # snyk_audit_logs — alert and non-alert events
        result.events.append(RawEventData(
            source="snyk", source_type=SourceType.CODE, provider="snyk",
            event_type="snyk_audit_logs",
            raw_data={
                "org_id": "acme-org-001",
                "response": [
                    {
                        "id": "audit-evt-001",
                        "event": "org.project.ignore.create",
                        "userId": "user-001",
                        "userEmail": "carol.nguyen@acmecorp.com",
                        "created": NOW.isoformat(),
                    },
                    {
                        "id": "audit-evt-002",
                        "event": "org.project.test",
                        "userId": "user-002",
                        "userEmail": "bob.martinez@acmecorp.com",
                        "created": NOW.isoformat(),
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoGitHubConnector(BaseConnector):
    """Simulates GitHub code security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="github",
            source_type=SourceType.CODE,
            provider="github",
        )

        # github_repos — private and public
        result.events.append(RawEventData(
            source="github", source_type=SourceType.CODE, provider="github",
            event_type="github_repos",
            raw_data={
                "org": "acmecorp",
                "response": [
                    {
                        "id": 100001,
                        "full_name": "acmecorp/payment-service",
                        "visibility": "private",
                        "private": True,
                        "default_branch": "main",
                        "archived": False,
                        "fork": False,
                        "has_vulnerability_alerts_enabled": True,
                        "language": "TypeScript",
                    },
                    {
                        "id": 100002,
                        "full_name": "acmecorp/docs-public",
                        "visibility": "public",
                        "private": False,
                        "default_branch": "main",
                        "archived": False,
                        "fork": False,
                        "has_vulnerability_alerts_enabled": False,
                        "language": "Markdown",
                    },
                ],
            },
        ))

        # github_branch_protections — protected, unprotected, missing reviews
        result.events.append(RawEventData(
            source="github", source_type=SourceType.CODE, provider="github",
            event_type="github_branch_protections",
            raw_data={
                "org": "acmecorp",
                "response": [
                    {
                        "_repo": "acmecorp/payment-service",
                        "_branch": "main",
                        "_unprotected": False,
                        "required_pull_request_reviews": {
                            "required_approving_review_count": 2,
                            "dismiss_stale_reviews": True,
                        },
                        "required_status_checks": {
                            "strict": True,
                            "contexts": ["ci/build", "ci/test"],
                        },
                        "enforce_admins": {"enabled": True},
                        "required_signatures": {"enabled": True},
                    },
                    {
                        "_repo": "acmecorp/legacy-auth",
                        "_branch": "main",
                        "_unprotected": True,
                    },
                    {
                        "_repo": "acmecorp/docs-public",
                        "_branch": "main",
                        "_unprotected": False,
                        "required_pull_request_reviews": None,
                        "required_status_checks": None,
                        "enforce_admins": {"enabled": False},
                        "required_signatures": {"enabled": False},
                    },
                ],
            },
        ))

        # github_audit_log — sensitive and normal actions
        result.events.append(RawEventData(
            source="github", source_type=SourceType.CODE, provider="github",
            event_type="github_audit_log",
            raw_data={
                "org": "acmecorp",
                "response": [
                    {
                        "_document_id": "gh-audit-001",
                        "action": "repo.change_visibility",
                        "actor": "carol.nguyen",
                        "created_at": NOW.isoformat(),
                        "repo": "acmecorp/internal-tools",
                        "org": "acmecorp",
                    },
                    {
                        "_document_id": "gh-audit-002",
                        "action": "repo.create",
                        "actor": "bob.martinez",
                        "created_at": NOW.isoformat(),
                        "repo": "acmecorp/new-microservice",
                        "org": "acmecorp",
                    },
                ],
            },
        ))

        # github_dependabot_alerts
        result.events.append(RawEventData(
            source="github", source_type=SourceType.CODE, provider="github",
            event_type="github_dependabot_alerts",
            raw_data={
                "org": "acmecorp",
                "response": [
                    {
                        "number": 42,
                        "repository": {"full_name": "acmecorp/payment-service"},
                        "security_advisory": {
                            "severity": "critical",
                            "cve_id": "CVE-2024-4067",
                            "summary": "Regular expression denial of service in micromatch",
                            "ghsa_id": "GHSA-952p-6rrq-rcjv",
                            "cvss": {"score": 9.8},
                        },
                        "dependency": {
                            "package": {"name": "micromatch", "ecosystem": "npm"},
                            "manifest_path": "package-lock.json",
                        },
                    },
                ],
            },
        ))

        # github_secret_scanning_alerts
        result.events.append(RawEventData(
            source="github", source_type=SourceType.CODE, provider="github",
            event_type="github_secret_scanning_alerts",
            raw_data={
                "org": "acmecorp",
                "response": [
                    {
                        "number": 7,
                        "repository": {"full_name": "acmecorp/legacy-auth"},
                        "secret_type_display_name": "AWS Access Key ID",
                        "secret_type": "aws_access_key_id",
                        "state": "open",
                        "created_at": (NOW - timedelta(days=2)).isoformat(),
                        "html_url": "https://github.com/acmecorp/legacy-auth/security/secret-scanning/7",
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoProofpointConnector(BaseConnector):
    """Simulates Proofpoint TAP collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="proofpoint",
            source_type=SourceType.EMAIL,
            provider="proofpoint",
        )

        # proofpoint_blocked_messages
        result.events.append(RawEventData(
            source="proofpoint", source_type=SourceType.EMAIL, provider="proofpoint",
            event_type="proofpoint_blocked_messages",
            raw_data={
                "response": [
                    {"subject": "Urgent: Verify your account credentials immediately"},
                    {"subject": "Invoice #INV-29831 - Payment Required"},
                    {"subject": "Re: Q4 Financial Report - Action Needed"},
                ],
            },
        ))

        # proofpoint_delivered_threats — high score and low score
        result.events.append(RawEventData(
            source="proofpoint", source_type=SourceType.EMAIL, provider="proofpoint",
            event_type="proofpoint_delivered_threats",
            raw_data={
                "response": [
                    {
                        "GUID": "pp-msg-001",
                        "subject": "Urgent wire transfer request from CEO",
                        "sender": "ceo-impersonator@evil-domain.com",
                        "recipient": "finance-team@acmecorp.com",
                        "threatsInfoMap": {
                            "url": {
                                "threatScore": 92,
                                "classification": "phishing",
                            },
                        },
                    },
                    {
                        "GUID": "pp-msg-002",
                        "subject": "Your package delivery notification",
                        "sender": "noreply@tracking-service.net",
                        "recipient": "alice.chen@acmecorp.com",
                        "threatsInfoMap": {
                            "attachment": {
                                "threatScore": 45,
                                "classification": "malware",
                            },
                        },
                    },
                ],
            },
        ))

        # proofpoint_clicks_blocked
        result.events.append(RawEventData(
            source="proofpoint", source_type=SourceType.EMAIL, provider="proofpoint",
            event_type="proofpoint_clicks_blocked",
            raw_data={
                "response": [
                    {
                        "GUID": "pp-click-001",
                        "url": "https://evil-domain.com/credential-harvest/login.html",
                        "sender": "support@fake-saas.com",
                        "recipient": "david.park@acmecorp.com",
                        "clickTime": NOW.isoformat(),
                        "threatStatus": "active",
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoPurviewConnector(BaseConnector):
    """Simulates Microsoft Purview DLP collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="purview",
            source_type=SourceType.DLP,
            provider="purview",
        )

        # purview_dlp_alerts — high and low severity
        result.events.append(RawEventData(
            source="purview", source_type=SourceType.DLP, provider="purview",
            event_type="purview_dlp_alerts",
            raw_data={
                "records": [
                    {
                        "id": "purview-alert-001",
                        "title": "Credit card numbers shared via Teams",
                        "severity": "high",
                        "status": "new",
                        "category": "DataLossPrevention",
                        "description": "User shared message containing 4 credit card numbers in Teams channel.",
                        "createdDateTime": NOW.isoformat(),
                        "serviceSource": "Microsoft Teams",
                    },
                    {
                        "id": "purview-alert-002",
                        "title": "SSN pattern detected in SharePoint document",
                        "severity": "medium",
                        "status": "inProgress",
                        "category": "DataLossPrevention",
                        "description": "Document uploaded to SharePoint contains SSN patterns.",
                        "createdDateTime": (NOW - timedelta(hours=3)).isoformat(),
                        "serviceSource": "SharePoint Online",
                    },
                ],
            },
        ))

        # purview_sensitivity_labels
        result.events.append(RawEventData(
            source="purview", source_type=SourceType.DLP, provider="purview",
            event_type="purview_sensitivity_labels",
            raw_data={
                "records": [
                    {
                        "id": "label-001",
                        "name": "Acme Confidential",
                        "description": "For internal confidential business data.",
                        "isActive": True,
                        "tooltip": "Apply to documents containing confidential business information.",
                    },
                    {
                        "id": "label-002",
                        "name": "Acme Public",
                        "description": "For publicly shareable content.",
                        "isActive": True,
                        "tooltip": "Safe for external distribution.",
                    },
                ],
            },
        ))

        # purview_dlp_policies — enabled and disabled
        result.events.append(RawEventData(
            source="purview", source_type=SourceType.DLP, provider="purview",
            event_type="purview_dlp_policies",
            raw_data={
                "records": [
                    {
                        "id": "dlp-pol-001",
                        "name": "PCI-DSS Credit Card Protection",
                        "description": "Blocks sharing of credit card numbers outside organization.",
                        "isEnabled": True,
                    },
                    {
                        "id": "dlp-pol-002",
                        "name": "HIPAA PHI Protection",
                        "description": "Prevents sharing of protected health information.",
                        "isEnabled": False,
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoVeeamConnector(BaseConnector):
    """Simulates Veeam backup infrastructure collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="veeam",
            source_type=SourceType.BACKUP,
            provider="veeam",
        )

        # veeam_backup_jobs — enabled and disabled
        result.events.append(RawEventData(
            source="veeam", source_type=SourceType.BACKUP, provider="veeam",
            event_type="veeam_backup_jobs",
            raw_data={
                "records": [
                    {
                        "id": "veeam-job-001",
                        "name": "Acme Production DB Daily Backup",
                        "type": "Backup",
                        "isDisabled": False,
                        "scheduleEnabled": True,
                        "description": "Daily backup of production PostgreSQL databases.",
                    },
                    {
                        "id": "veeam-job-002",
                        "name": "Acme Legacy ERP Backup",
                        "type": "Backup",
                        "isDisabled": True,
                        "scheduleEnabled": False,
                        "description": "Weekly backup of legacy ERP system.",
                    },
                ],
            },
        ))

        # veeam_backup_sessions — success, failure, and old success for RPO
        result.events.append(RawEventData(
            source="veeam", source_type=SourceType.BACKUP, provider="veeam",
            event_type="veeam_backup_sessions",
            raw_data={
                "records": [
                    {
                        "id": "session-001",
                        "name": "Acme Production DB Daily Backup",
                        "jobId": "veeam-job-001",
                        "result": "Success",
                        "endTime": (NOW - timedelta(hours=6)).isoformat(),
                        "type": "Backup",
                    },
                    {
                        "id": "session-002",
                        "name": "Acme Legacy ERP Backup",
                        "jobId": "veeam-job-002",
                        "result": "Failed",
                        "endTime": (NOW - timedelta(hours=2)).isoformat(),
                        "type": "Backup",
                    },
                    {
                        "id": "session-003",
                        "name": "Acme Staging Backup",
                        "jobId": "veeam-job-003",
                        "result": "Success",
                        "endTime": (NOW - timedelta(hours=36)).isoformat(),
                        "type": "Backup",
                    },
                ],
            },
        ))

        # veeam_restore_points — one recent, one old (triggers no-recent finding)
        result.events.append(RawEventData(
            source="veeam", source_type=SourceType.BACKUP, provider="veeam",
            event_type="veeam_restore_points",
            raw_data={
                "records": [
                    {
                        "id": "rp-001",
                        "name": "acme-prod-db",
                        "creationTime": (NOW - timedelta(hours=6)).isoformat(),
                        "backupId": "veeam-job-001",
                    },
                    {
                        "id": "rp-002",
                        "name": "acme-legacy-erp",
                        "creationTime": (NOW - timedelta(days=7)).isoformat(),
                        "backupId": "veeam-job-002",
                    },
                ],
            },
        ))

        result.complete()
        return result


class DemoVerkadaConnector(BaseConnector):
    """Simulates Verkada physical security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="verkada",
            source_type=SourceType.PHYSICAL,
            provider="verkada",
        )

        # verkada_access_events — during hours and after hours (3 AM)
        result.events.append(RawEventData(
            source="verkada", source_type=SourceType.PHYSICAL, provider="verkada",
            event_type="verkada_access_events",
            raw_data={
                "response": [
                    {
                        "event_id": "vk-evt-001",
                        "user_name": "Alice Chen",
                        "door_name": "Acme HQ Main Entrance",
                        "event_time": NOW.replace(hour=9, minute=15).isoformat(),
                        "event_type": "access_granted",
                    },
                    {
                        "event_id": "vk-evt-002",
                        "user_name": "Bob Martinez",
                        "door_name": "Acme HQ Server Room",
                        "event_time": NOW.replace(hour=3, minute=42).isoformat(),
                        "event_type": "access_granted",
                    },
                    {
                        "event_id": "vk-evt-003",
                        "user_name": "Carol Nguyen",
                        "door_name": "Acme HQ Main Entrance",
                        "event_time": NOW.replace(hour=8, minute=30).isoformat(),
                        "event_type": "access_granted",
                    },
                ],
            },
        ))

        # verkada_doors — locked and unlocked
        result.events.append(RawEventData(
            source="verkada", source_type=SourceType.PHYSICAL, provider="verkada",
            event_type="verkada_doors",
            raw_data={
                "response": {
                    "doors": [
                        {
                            "door_id": "door-001",
                            "name": "Acme HQ Main Entrance",
                            "lock_status": "locked",
                            "site": "Acme HQ - San Francisco",
                        },
                        {
                            "door_id": "door-002",
                            "name": "Acme HQ Server Room",
                            "lock_status": "locked",
                            "site": "Acme HQ - San Francisco",
                        },
                        {
                            "door_id": "door-003",
                            "name": "Acme Warehouse Loading Dock",
                            "lock_status": "unlocked",
                            "site": "Acme Warehouse - Oakland",
                        },
                    ],
                },
            },
        ))

        # verkada_users
        result.events.append(RawEventData(
            source="verkada", source_type=SourceType.PHYSICAL, provider="verkada",
            event_type="verkada_users",
            raw_data={
                "response": {
                    "card_holders": [
                        {
                            "user_id": "vk-user-001",
                            "full_name": "Alice Chen",
                            "email": "alice.chen@acmecorp.com",
                            "department": "Engineering",
                            "active": True,
                        },
                        {
                            "user_id": "vk-user-002",
                            "full_name": "Bob Martinez",
                            "email": "bob.martinez@acmecorp.com",
                            "department": "DevOps",
                            "active": True,
                        },
                        {
                            "user_id": "vk-user-003",
                            "full_name": "Eve Former",
                            "email": "eve.former@acmecorp.com",
                            "department": "Sales",
                            "active": False,
                        },
                    ],
                },
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
    connectors.register("entra_id", DemoEntraIDConnector)
    connectors.register("cyberark", DemoCyberArkConnector)
    connectors.register("sailpoint", DemoSailPointConnector)
    connectors.register("vault", DemoVaultConnector)
    # Cloud providers
    connectors.register("azure", DemoAzureConnector)
    connectors.register("gcp", DemoGCPConnector)
    connectors.register("digitalocean", DemoDigitalOceanConnector)
    connectors.register("alibaba", DemoAlibabaConnector)
    connectors.register("huawei", DemoHuaweiConnector)
    connectors.register("ibm_cloud", DemoIBMCloudConnector)
    connectors.register("ovh", DemoOVHConnector)
    connectors.register("oci", DemoOCIConnector)
    connectors.register("cloudflare", DemoCloudflareConnector)
    connectors.register("kubernetes", DemoKubernetesConnector)
    # Endpoint & SIEM
    connectors.register("defender", DemoDefenderConnector)
    connectors.register("sentinelone", DemoSentinelOneConnector)
    connectors.register("intune", DemoIntuneConnector)
    connectors.register("sentinel", DemoSentinelConnector)
    connectors.register("splunk", DemoSplunkConnector)
    connectors.register("elastic", DemoElasticConnector)
    # Scanners & CSPM
    connectors.register("tenable", DemoTenableConnector)
    connectors.register("qualys", DemoQualysConnector)
    connectors.register("wiz", DemoWizConnector)
    connectors.register("prisma", DemoPrismaConnector)
    # ITSM & GRC
    connectors.register("servicenow", DemoServiceNowConnector)
    connectors.register("onetrust", DemoOneTrustConnector)
    connectors.register("mlflow", DemoMLflowConnector)
    # Code security
    connectors.register("snyk", DemoSnykConnector)
    connectors.register("github", DemoGitHubConnector)
    # Email, DLP, Backup, Physical
    connectors.register("proofpoint", DemoProofpointConnector)
    connectors.register("purview", DemoPurviewConnector)
    connectors.register("veeam", DemoVeeamConnector)
    connectors.register("verkada", DemoVerkadaConnector)

    # Create all connector instances
    _connector_configs = [
        ("demo-aws", SourceType.CLOUD, "aws"),
        ("demo-okta", SourceType.IAM, "okta"),
        ("demo-crowdstrike", SourceType.EDR, "crowdstrike"),
        ("demo-workday", SourceType.HRIS, "workday"),
        ("demo-knowbe4", SourceType.TRAINING, "knowbe4"),
        ("demo-securityscorecard", SourceType.GRC, "securityscorecard"),
        ("demo-confluence", SourceType.GRC, "confluence"),
        ("demo-entra-id", SourceType.IAM, "entra_id"),
        ("demo-cyberark", SourceType.IAM, "cyberark"),
        ("demo-sailpoint", SourceType.IAM, "sailpoint"),
        ("demo-vault", SourceType.IAM, "vault"),
        ("demo-azure", SourceType.CLOUD, "azure"),
        ("demo-gcp", SourceType.CLOUD, "gcp"),
        ("demo-digitalocean", SourceType.CLOUD, "digitalocean"),
        ("demo-alibaba", SourceType.CLOUD, "alibaba"),
        ("demo-huawei", SourceType.CLOUD, "huawei"),
        ("demo-ibm-cloud", SourceType.CLOUD, "ibm_cloud"),
        ("demo-ovh", SourceType.CLOUD, "ovh"),
        ("demo-oci", SourceType.CLOUD, "oci"),
        ("demo-cloudflare", SourceType.CLOUD, "cloudflare"),
        ("demo-kubernetes", SourceType.CLOUD, "kubernetes"),
        ("demo-defender", SourceType.EDR, "defender"),
        ("demo-sentinelone", SourceType.EDR, "sentinelone"),
        ("demo-intune", SourceType.MDM, "intune"),
        ("demo-sentinel", SourceType.SIEM, "sentinel"),
        ("demo-splunk", SourceType.SIEM, "splunk"),
        ("demo-elastic", SourceType.SIEM, "elastic"),
        ("demo-tenable", SourceType.SCANNER, "tenable"),
        ("demo-qualys", SourceType.SCANNER, "qualys"),
        ("demo-wiz", SourceType.SCANNER, "wiz"),
        ("demo-prisma", SourceType.CSPM, "prisma"),
        ("demo-servicenow", SourceType.ITSM, "servicenow"),
        ("demo-onetrust", SourceType.GRC, "onetrust"),
        ("demo-mlflow", SourceType.CUSTOM, "mlflow"),
        ("demo-snyk", SourceType.CODE, "snyk"),
        ("demo-github", SourceType.CODE, "github"),
        ("demo-proofpoint", SourceType.EMAIL, "proofpoint"),
        ("demo-purview", SourceType.DLP, "purview"),
        ("demo-veeam", SourceType.BACKUP, "veeam"),
        ("demo-verkada", SourceType.PHYSICAL, "verkada"),
    ]
    for name, stype, provider in _connector_configs:
        connectors.create(ConnectorConfig(name=name, source_type=stype, provider=provider))

    normalizers = NormalizerRegistry()
    # Register all normalizers (order matters — specific before generic)
    normalizers.register(AWSNormalizer())
    normalizers.register(AzureNormalizer())
    normalizers.register(GCPNormalizer())
    normalizers.register(OktaNormalizer())
    normalizers.register(CrowdStrikeNormalizer())
    normalizers.register(WorkdayNormalizer())
    normalizers.register(KnowBe4Normalizer())
    normalizers.register(SecurityScorecardNormalizer())
    normalizers.register(ConfluenceNormalizer())
    normalizers.register(EntraIDNormalizer())
    normalizers.register(CyberArkNormalizer())
    normalizers.register(SailPointNormalizer())
    normalizers.register(VaultNormalizer())
    normalizers.register(DigitalOceanNormalizer())
    normalizers.register(AlibabaNormalizer())
    normalizers.register(HuaweiNormalizer())
    normalizers.register(IBMCloudNormalizer())
    normalizers.register(OVHNormalizer())
    normalizers.register(OCINormalizer())
    normalizers.register(CloudflareNormalizer())
    normalizers.register(KubernetesNormalizer())
    normalizers.register(DefenderNormalizer())
    normalizers.register(SentinelOneNormalizer())
    normalizers.register(IntuneNormalizer())
    normalizers.register(SentinelNormalizer())
    normalizers.register(SplunkNormalizer())
    normalizers.register(ElasticNormalizer())
    normalizers.register(TenableNormalizer())
    normalizers.register(QualysNormalizer())
    normalizers.register(WizNormalizer())
    normalizers.register(PrismaNormalizer())
    normalizers.register(ServiceNowNormalizer())
    normalizers.register(OneTrustNormalizer())
    normalizers.register(MLflowNormalizer())
    normalizers.register(SnykNormalizer())
    normalizers.register(GitHubNormalizer())
    normalizers.register(ProofpointNormalizer())
    normalizers.register(PurviewNormalizer())
    normalizers.register(VeeamNormalizer())
    normalizers.register(VerkadaNormalizer())
    normalizers.register(GenericNormalizer())  # Generic must be last (fallback)

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
