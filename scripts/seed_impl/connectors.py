"""Mock demo connector classes (in-memory) for pipeline integration tests."""

import random
import sys
from datetime import timedelta
from pathlib import Path

# Ensure warlock package is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.seed_impl.helpers import *
from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
)


class DemoAWSConnector(BaseConnector):
    """Simulates an AWS collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="aws",
            source_type=SourceType.CLOUD,
            provider="aws",
        )

        # IAM credential report: root with access keys, user without MFA
        result.events.append(
            RawEventData(
                source="aws",
                source_type=SourceType.CLOUD,
                provider="aws",
                event_type="iam_credential_report",
                raw_data={
                    "service": "iam",
                    "method": "get_credential_report",
                    "region": "us-east-1",
                    "account_id": "912345678012",
                    "response": {
                        "Content": (
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
                        )
                    },
                },
            )
        )

        # Security groups: open SSH, open RDP, and a properly restricted one
        result.events.append(
            RawEventData(
                source="aws",
                source_type=SourceType.CLOUD,
                provider="aws",
                event_type="ec2_security_groups",
                raw_data={
                    "service": "ec2",
                    "method": "describe_security_groups",
                    "region": "us-east-1",
                    "account_id": "912345678012",
                    "response": {
                        "SecurityGroups": [
                            {
                                "GroupId": "sg-0a1b2c3d4e5f",
                                "GroupName": "web-bastion",
                                "IpPermissions": [
                                    {
                                        "FromPort": 22,
                                        "ToPort": 22,
                                        "IpProtocol": "tcp",
                                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                    }
                                ],
                            },
                            {
                                "GroupId": "sg-1f2e3d4c5b6a",
                                "GroupName": "legacy-windows",
                                "IpPermissions": [
                                    {
                                        "FromPort": 3389,
                                        "ToPort": 3389,
                                        "IpProtocol": "tcp",
                                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                    }
                                ],
                            },
                            {
                                "GroupId": "sg-9z8y7x6w5v4u",
                                "GroupName": "api-internal",
                                "IpPermissions": [
                                    {
                                        "FromPort": 443,
                                        "ToPort": 443,
                                        "IpProtocol": "tcp",
                                        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                                    }
                                ],
                            },
                        ]
                    },
                },
            )
        )

        # GuardDuty enabled
        result.events.append(
            RawEventData(
                source="aws",
                source_type=SourceType.CLOUD,
                provider="aws",
                event_type="guardduty_detectors",
                raw_data={
                    "service": "guardduty",
                    "method": "list_detectors",
                    "region": "us-east-1",
                    "account_id": "912345678012",
                    "response": {"DetectorIds": ["d-abc123def456"]},
                },
            )
        )

        # CloudTrail: single-region only (misconfiguration)
        result.events.append(
            RawEventData(
                source="aws",
                source_type=SourceType.CLOUD,
                provider="aws",
                event_type="cloudtrail_trails",
                raw_data={
                    "service": "cloudtrail",
                    "method": "describe_trails",
                    "region": "us-east-1",
                    "account_id": "912345678012",
                    "response": {
                        "trailList": [
                            {
                                "Name": "prod-trail",
                                "TrailARN": "arn:aws:cloudtrail:us-east-1:912345678012:trail/prod-trail",
                                "IsMultiRegionTrail": False,
                                "LogFileValidationEnabled": True,
                            }
                        ]
                    },
                },
            )
        )

        # SecurityHub enabled
        result.events.append(
            RawEventData(
                source="aws",
                source_type=SourceType.CLOUD,
                provider="aws",
                event_type="securityhub_hub",
                raw_data={
                    "service": "securityhub",
                    "method": "describe_hub",
                    "region": "us-east-1",
                    "account_id": "912345678012",
                    "response": {
                        "HubArn": "arn:aws:securityhub:us-east-1:912345678012:hub/default",
                    },
                },
            )
        )

        # Password policy: weak (no symbols, short min length, no expiration)
        result.events.append(
            RawEventData(
                source="aws",
                source_type=SourceType.CLOUD,
                provider="aws",
                event_type="iam_password_policy",
                raw_data={
                    "service": "iam",
                    "method": "get_account_password_policy",
                    "region": "us-east-1",
                    "account_id": "912345678012",
                    "response": {
                        "PasswordPolicy": {
                            "MinimumPasswordLength": 8,
                            "RequireSymbols": False,
                            "RequireNumbers": True,
                            "RequireUppercaseCharacters": True,
                            "RequireLowercaseCharacters": True,
                            "MaxPasswordAge": 0,
                        }
                    },
                },
            )
        )

        # Config recorder enabled
        result.events.append(
            RawEventData(
                source="aws",
                source_type=SourceType.CLOUD,
                provider="aws",
                event_type="config_recorders",
                raw_data={
                    "service": "config",
                    "method": "describe_configuration_recorders",
                    "region": "us-east-1",
                    "account_id": "912345678012",
                    "response": {
                        "ConfigurationRecorders": [
                            {
                                "name": "default",
                                "recordingGroup": {"allSupported": True},
                            }
                        ]
                    },
                },
            )
        )

        # S3 buckets: one public, one encrypted
        result.events.append(
            RawEventData(
                source="aws",
                source_type=SourceType.CLOUD,
                provider="aws",
                event_type="s3_buckets",
                raw_data={
                    "service": "s3",
                    "method": "list_buckets",
                    "region": "us-east-1",
                    "account_id": "912345678012",
                    "response": {
                        "Buckets": [
                            {"Name": "acme-public-assets", "CreationDate": "2023-01-15"},
                            {"Name": "acme-prod-data", "CreationDate": "2022-06-01"},
                            {"Name": "acme-logs", "CreationDate": "2022-06-01"},
                        ]
                    },
                },
            )
        )

        # RDS instances: encrypted production database
        result.events.append(
            RawEventData(
                source="aws",
                source_type=SourceType.CLOUD,
                provider="aws",
                event_type="rds_instances",
                raw_data={
                    "service": "rds",
                    "method": "describe_db_instances",
                    "region": "us-east-1",
                    "account_id": "912345678012",
                    "response": {
                        "DBInstances": [
                            {
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
                            }
                        ]
                    },
                },
            )
        )

        # Redshift clusters: encrypted but no automated snapshots
        result.events.append(
            RawEventData(
                source="aws",
                source_type=SourceType.CLOUD,
                provider="aws",
                event_type="redshift_clusters",
                raw_data={
                    "service": "redshift",
                    "method": "describe_clusters",
                    "region": "us-east-1",
                    "account_id": "912345678012",
                    "response": {
                        "Clusters": [
                            {
                                "ClusterIdentifier": "analytics-warehouse",
                                "ClusterNamespaceArn": "arn:aws:redshift:us-east-1:912345678012:namespace/analytics-warehouse",
                                "NodeType": "ra3.xlplus",
                                "NumberOfNodes": 2,
                                "Encrypted": True,
                                "AutomatedSnapshotRetentionPeriod": 0,
                                "ClusterStatus": "available",
                                "PubliclyAccessible": False,
                            }
                        ]
                    },
                },
            )
        )

        # --- Rich data: cloud instances, security groups, storage, IAM ---
        _aws_instances = _instances_filter_cloud(RICH_DATA["cloud_instances"], "aws")
        for batch_start in range(0, len(_aws_instances), 50):
            batch = _aws_instances[batch_start : batch_start + 50]
            result.events.append(
                RawEventData(
                    source="aws",
                    source_type=SourceType.CLOUD,
                    provider="aws",
                    event_type="ec2_instances",
                    raw_data={
                        "service": "ec2",
                        "method": "describe_instances",
                        "region": "us-east-1",
                        "account_id": "912345678012",
                        "response": {"Reservations": [{"Instances": batch}]},
                    },
                )
            )
        _aws_sgs = _sg_filter_cloud(RICH_DATA["security_groups"], "aws")
        result.events.append(
            RawEventData(
                source="aws",
                source_type=SourceType.CLOUD,
                provider="aws",
                event_type="ec2_security_groups",
                raw_data={
                    "service": "ec2",
                    "method": "describe_security_groups",
                    "region": "us-east-1",
                    "account_id": "912345678012",
                    "response": {"SecurityGroups": _aws_sgs},
                },
            )
        )
        _aws_buckets = _buckets_filter_cloud(RICH_DATA["storage_buckets"], "aws")
        result.events.append(
            RawEventData(
                source="aws",
                source_type=SourceType.CLOUD,
                provider="aws",
                event_type="s3_buckets",
                raw_data={
                    "service": "s3",
                    "method": "list_buckets",
                    "region": "us-east-1",
                    "account_id": "912345678012",
                    "response": {
                        "Buckets": [
                            {"Name": b["name"], "CreationDate": b["created_at"]}
                            for b in _aws_buckets
                        ]
                    },
                },
            )
        )

        result.complete()
        return result


class DemoOktaConnector(BaseConnector):
    """Simulates Okta IAM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="okta",
            source_type=SourceType.IAM,
            provider="okta",
        )

        # Users: rich data slice (users 0:30)
        result.events.append(
            RawEventData(
                source="okta",
                source_type=SourceType.IAM,
                provider="okta",
                event_type="okta_users",
                raw_data={
                    "domain": "acme.okta.com",
                    "response": _users_as_okta(RICH_DATA["users"][0:40]),
                },
            )
        )

        # System log: rich auth logs slice (0:150)
        result.events.append(
            RawEventData(
                source="okta",
                source_type=SourceType.IAM,
                provider="okta",
                event_type="okta_system_log",
                raw_data={
                    "domain": "acme.okta.com",
                    "response": _auth_logs_as_okta(RICH_DATA["auth_logs"][0:250]),
                },
            )
        )

        # Policies: weak password policy
        result.events.append(
            RawEventData(
                source="okta",
                source_type=SourceType.IAM,
                provider="okta",
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
            )
        )

        # MFA factors: one user missing MFA
        result.events.append(
            RawEventData(
                source="okta",
                source_type=SourceType.IAM,
                provider="okta",
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
            )
        )

        result.complete()
        return result


class DemoCrowdStrikeConnector(BaseConnector):
    """Simulates CrowdStrike Falcon EDR collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="crowdstrike",
            source_type=SourceType.EDR,
            provider="crowdstrike",
        )

        # Detections: malware + suspicious activity
        result.events.append(
            RawEventData(
                source="crowdstrike",
                source_type=SourceType.EDR,
                provider="crowdstrike",
                event_type="falcon_detection_details",
                raw_data={
                    "detections": [
                        {
                            "detection_id": "ldt:abc123:1001",
                            "status": "new",
                            "max_severity": 5,
                            "behaviors": [
                                {
                                    "tactic": "Execution",
                                    "technique": "PowerShell",
                                    "description": "Suspicious PowerShell execution with encoded command",
                                }
                            ],
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
                            "behaviors": [
                                {
                                    "tactic": "Credential Access",
                                    "technique": "LSASS Memory",
                                    "description": "Credential dumping via LSASS memory access",
                                }
                            ],
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
                            "behaviors": [
                                {
                                    "tactic": "Defense Evasion",
                                    "technique": "Masquerading",
                                    "description": "Process masquerading as legitimate system binary",
                                }
                            ],
                            "device": {
                                "device_id": "dev-003",
                                "hostname": "ws-dev-05",
                                "platform_name": "macOS",
                            },
                        },
                    ],
                },
            )
        )

        # Spotlight vulnerabilities
        result.events.append(
            RawEventData(
                source="crowdstrike",
                source_type=SourceType.EDR,
                provider="crowdstrike",
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
            )
        )

        # Device compliance
        result.events.append(
            RawEventData(
                source="crowdstrike",
                source_type=SourceType.EDR,
                provider="crowdstrike",
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
            )
        )

        # Zero Trust assessments
        result.events.append(
            RawEventData(
                source="crowdstrike",
                source_type=SourceType.EDR,
                provider="crowdstrike",
                event_type="falcon_zero_trust",
                raw_data={
                    "assessments": [
                        {"aid": "dev-001", "overall": 85},
                        {"aid": "dev-002", "overall": 92},
                        {"aid": "dev-007", "overall": 35},
                    ],
                },
            )
        )

        # --- Rich data: endpoints + vulnerabilities ---
        _cs_endpoints = RICH_DATA["endpoints_edr"][0:50]
        result.events.append(
            RawEventData(
                source="crowdstrike",
                source_type=SourceType.EDR,
                provider="crowdstrike",
                event_type="falcon_device_details",
                raw_data={"devices": _endpoints_as_crowdstrike(_cs_endpoints)},
            )
        )
        _cs_vulns = RICH_DATA["vulnerabilities"][0:400]
        result.events.append(
            RawEventData(
                source="crowdstrike",
                source_type=SourceType.EDR,
                provider="crowdstrike",
                event_type="falcon_vulnerabilities",
                raw_data={"vulnerabilities": _vulns_as_crowdstrike(_cs_vulns)},
            )
        )

        result.complete()
        return result


class DemoWorkdayConnector(BaseConnector):
    """Simulates Workday HRIS collection with employee data."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="workday",
            source_type=SourceType.HRIS,
            provider="workday",
        )

        # 8 employees matching the Acme Corp story
        result.events.append(
            RawEventData(
                source="workday",
                source_type=SourceType.HRIS,
                provider="workday",
                event_type="workday_employees",
                raw_data={
                    "tenant": "acme-prod",
                    "response": [
                        {
                            "id": "WD-001",
                            "descriptor": "Alice Chen",
                            "status": "Active",
                            "hireDate": "2022-03-15",
                            "department": "Engineering",
                            "manager": "frank.torres@acme.com",
                        },
                        {
                            "id": "WD-002",
                            "descriptor": "Bob Martinez",
                            "status": "Active",
                            "hireDate": "2021-08-01",
                            "department": "DevOps",
                            "manager": "frank.torres@acme.com",
                        },
                        {
                            "id": "WD-003",
                            "descriptor": "Carol Park",
                            "status": "Active",
                            "hireDate": "2020-01-10",
                            "department": "Finance",
                            "manager": "hassan.ali@acme.com",
                        },
                        {
                            "id": "WD-004",
                            "descriptor": "Dave Thompson",
                            "status": "Terminated",
                            "hireDate": "2023-06-01",
                            "department": "Sales",
                            "manager": "hassan.ali@acme.com",
                            "terminationDate": (NOW - timedelta(days=30)).isoformat(),
                        },
                        {
                            "id": "WD-005",
                            "descriptor": "Eve Nakamura",
                            "status": "Active",
                            "hireDate": (NOW - timedelta(days=14)).strftime("%Y-%m-%d"),
                            "department": "Security",
                            "manager": "grace.kim@acme.com",
                        },
                        {
                            "id": "WD-006",
                            "descriptor": "Frank Torres",
                            "status": "Active",
                            "hireDate": "2019-11-20",
                            "department": "Engineering",
                            "manager": "hassan.ali@acme.com",
                        },
                        {
                            "id": "WD-007",
                            "descriptor": "Grace Kim",
                            "status": "Active",
                            "hireDate": (NOW - timedelta(days=7)).strftime("%Y-%m-%d"),
                            "department": "Legal",
                            "manager": "hassan.ali@acme.com",
                        },
                        {
                            "id": "WD-008",
                            "descriptor": "Hassan Ali",
                            "status": "Active",
                            "hireDate": "2021-04-15",
                            "department": "Product",
                            "manager": "",
                        },
                    ],
                },
            )
        )

        # Background checks: Eve in_progress, Grace pending, rest completed
        result.events.append(
            RawEventData(
                source="workday",
                source_type=SourceType.HRIS,
                provider="workday",
                event_type="workday_background_checks",
                raw_data={
                    "tenant": "acme-prod",
                    "response": [
                        {
                            "worker_id": "WD-001",
                            "worker_name": "Alice Chen",
                            "background_check": {
                                "status": "completed",
                                "completed_date": "2022-03-10",
                            },
                        },
                        {
                            "worker_id": "WD-002",
                            "worker_name": "Bob Martinez",
                            "background_check": {
                                "status": "completed",
                                "completed_date": "2021-07-25",
                            },
                        },
                        {
                            "worker_id": "WD-003",
                            "worker_name": "Carol Park",
                            "background_check": {
                                "status": "completed",
                                "completed_date": "2019-12-20",
                            },
                        },
                        {
                            "worker_id": "WD-004",
                            "worker_name": "Dave Thompson",
                            "background_check": {
                                "status": "completed",
                                "completed_date": "2023-05-20",
                            },
                        },
                        {
                            "worker_id": "WD-005",
                            "worker_name": "Eve Nakamura",
                            "background_check": {
                                "status": "in_progress",
                                "submitted_date": (NOW - timedelta(days=10)).strftime("%Y-%m-%d"),
                            },
                        },
                        {
                            "worker_id": "WD-006",
                            "worker_name": "Frank Torres",
                            "background_check": {
                                "status": "completed",
                                "completed_date": "2019-11-01",
                            },
                        },
                        {
                            "worker_id": "WD-007",
                            "worker_name": "Grace Kim",
                            "background_check": {
                                "status": "pending",
                                "submitted_date": (NOW - timedelta(days=3)).strftime("%Y-%m-%d"),
                            },
                        },
                        {
                            "worker_id": "WD-008",
                            "worker_name": "Hassan Ali",
                            "background_check": {
                                "status": "completed",
                                "completed_date": "2021-04-01",
                            },
                        },
                    ],
                },
            )
        )

        # Agreements: Eve missing NDA, Grace missing both, rest signed
        result.events.append(
            RawEventData(
                source="workday",
                source_type=SourceType.HRIS,
                provider="workday",
                event_type="workday_agreements",
                raw_data={
                    "tenant": "acme-prod",
                    "response": [
                        {
                            "worker_id": "WD-001",
                            "worker_name": "Alice Chen",
                            "employment_agreement_signed": True,
                            "nda_signed": True,
                        },
                        {
                            "worker_id": "WD-002",
                            "worker_name": "Bob Martinez",
                            "employment_agreement_signed": True,
                            "nda_signed": True,
                        },
                        {
                            "worker_id": "WD-003",
                            "worker_name": "Carol Park",
                            "employment_agreement_signed": True,
                            "nda_signed": True,
                        },
                        {
                            "worker_id": "WD-004",
                            "worker_name": "Dave Thompson",
                            "employment_agreement_signed": True,
                            "nda_signed": True,
                        },
                        {
                            "worker_id": "WD-005",
                            "worker_name": "Eve Nakamura",
                            "employment_agreement_signed": True,
                            "nda_signed": False,
                        },
                        {
                            "worker_id": "WD-006",
                            "worker_name": "Frank Torres",
                            "employment_agreement_signed": True,
                            "nda_signed": True,
                        },
                        {
                            "worker_id": "WD-007",
                            "worker_name": "Grace Kim",
                            "employment_agreement_signed": False,
                            "nda_signed": False,
                        },
                        {
                            "worker_id": "WD-008",
                            "worker_name": "Hassan Ali",
                            "employment_agreement_signed": True,
                            "nda_signed": True,
                        },
                    ],
                },
            )
        )

        # --- Rich data: employees ---
        _wd_employees = RICH_DATA["employees"][0:125]
        result.events.append(
            RawEventData(
                source="workday",
                source_type=SourceType.HRIS,
                provider="workday",
                event_type="workday_employees",
                raw_data={
                    "tenant": "acme-prod",
                    "response": _employees_as_workday(_wd_employees),
                },
            )
        )

        result.complete()
        return result


class DemoKnowBe4Connector(BaseConnector):
    """Simulates KnowBe4 security awareness training collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="knowbe4",
            source_type=SourceType.TRAINING,
            provider="knowbe4",
        )

        # Training enrollments: Alice overdue 30d, Carol overdue 60d, Grace overdue 15d,
        # Eve in_progress, Bob/Dave/Frank/Hassan completed
        result.events.append(
            RawEventData(
                source="knowbe4",
                source_type=SourceType.TRAINING,
                provider="knowbe4",
                event_type="kb4_training_enrollments",
                raw_data={
                    "region": "US",
                    "response": [
                        {
                            "enrollment_id": "enr-001",
                            "user_name": "Alice Chen",
                            "user": {"name": "Alice Chen"},
                            "module_name": "Security Awareness 2025",
                            "status": "not_started",
                            "due_date": (NOW - timedelta(days=30)).isoformat(),
                        },
                        {
                            "enrollment_id": "enr-002",
                            "user_name": "Bob Martinez",
                            "user": {"name": "Bob Martinez"},
                            "module_name": "Security Awareness 2025",
                            "status": "completed",
                            "due_date": (NOW + timedelta(days=30)).isoformat(),
                            "completion_date": (NOW - timedelta(days=10)).isoformat(),
                        },
                        {
                            "enrollment_id": "enr-003",
                            "user_name": "Carol Park",
                            "user": {"name": "Carol Park"},
                            "module_name": "Security Awareness 2025",
                            "status": "not_started",
                            "due_date": (NOW - timedelta(days=60)).isoformat(),
                        },
                        {
                            "enrollment_id": "enr-004",
                            "user_name": "Dave Thompson",
                            "user": {"name": "Dave Thompson"},
                            "module_name": "Security Awareness 2025",
                            "status": "completed",
                            "due_date": (NOW - timedelta(days=90)).isoformat(),
                            "completion_date": (NOW - timedelta(days=100)).isoformat(),
                        },
                        {
                            "enrollment_id": "enr-005",
                            "user_name": "Eve Nakamura",
                            "user": {"name": "Eve Nakamura"},
                            "module_name": "New Hire Security Onboarding",
                            "status": "in_progress",
                            "due_date": (NOW + timedelta(days=14)).isoformat(),
                        },
                        {
                            "enrollment_id": "enr-006",
                            "user_name": "Frank Torres",
                            "user": {"name": "Frank Torres"},
                            "module_name": "Security Awareness 2025",
                            "status": "completed",
                            "due_date": (NOW + timedelta(days=30)).isoformat(),
                            "completion_date": (NOW - timedelta(days=20)).isoformat(),
                        },
                        {
                            "enrollment_id": "enr-007",
                            "user_name": "Grace Kim",
                            "user": {"name": "Grace Kim"},
                            "module_name": "New Hire Onboarding",
                            "status": "not_started",
                            "due_date": (NOW - timedelta(days=15)).isoformat(),
                        },
                        {
                            "enrollment_id": "enr-008",
                            "user_name": "Hassan Ali",
                            "user": {"name": "Hassan Ali"},
                            "module_name": "Security Awareness 2025",
                            "status": "completed",
                            "due_date": (NOW + timedelta(days=30)).isoformat(),
                            "completion_date": (NOW - timedelta(days=15)).isoformat(),
                        },
                    ],
                },
            )
        )

        # Phishing results: 1 test, 6 recipients, Carol and Grace clicked
        result.events.append(
            RawEventData(
                source="knowbe4",
                source_type=SourceType.TRAINING,
                provider="knowbe4",
                event_type="kb4_phishing_results",
                raw_data={
                    "region": "US",
                    "response": [
                        {
                            "pst_id": "pst-001",
                            "name": "Q1 2025 Phishing Test",
                            "recipients": [
                                {
                                    "recipient_id": "rec-001",
                                    "email": "alice.chen@acme.com",
                                    "user": {"name": "Alice Chen"},
                                    "clicked_link": False,
                                    "opened_email": True,
                                    "reported": True,
                                },
                                {
                                    "recipient_id": "rec-002",
                                    "email": "bob.martinez@acme.com",
                                    "user": {"name": "Bob Martinez"},
                                    "clicked_link": False,
                                    "opened_email": True,
                                    "reported": True,
                                },
                                {
                                    "recipient_id": "rec-003",
                                    "email": "carol.park@acme.com",
                                    "user": {"name": "Carol Park"},
                                    "clicked_link": True,
                                    "opened_email": True,
                                    "reported": False,
                                },
                                {
                                    "recipient_id": "rec-004",
                                    "email": "dave.thompson@acme.com",
                                    "user": {"name": "Dave Thompson"},
                                    "clicked_link": False,
                                    "opened_email": True,
                                    "reported": False,
                                },
                                {
                                    "recipient_id": "rec-005",
                                    "email": "grace.kim@acme.com",
                                    "user": {"name": "Grace Kim"},
                                    "clicked_link": True,
                                    "opened_email": True,
                                    "reported": False,
                                },
                                {
                                    "recipient_id": "rec-006",
                                    "email": "hassan.ali@acme.com",
                                    "user": {"name": "Hassan Ali"},
                                    "clicked_link": False,
                                    "opened_email": False,
                                    "reported": True,
                                },
                            ],
                        }
                    ],
                },
            )
        )

        # Training campaigns: 2 campaigns with completion rates
        result.events.append(
            RawEventData(
                source="knowbe4",
                source_type=SourceType.TRAINING,
                provider="knowbe4",
                event_type="kb4_training_campaigns",
                raw_data={
                    "region": "US",
                    "response": [
                        {
                            "campaign_id": "camp-001",
                            "name": "Security Awareness 2025",
                            "status": "in_progress",
                            "completion_percentage": 50,
                            "start_date": (NOW - timedelta(days=60)).isoformat(),
                            "end_date": (NOW + timedelta(days=30)).isoformat(),
                        },
                        {
                            "campaign_id": "camp-002",
                            "name": "New Hire Onboarding",
                            "status": "in_progress",
                            "completion_percentage": 0,
                            "start_date": (NOW - timedelta(days=14)).isoformat(),
                            "end_date": (NOW + timedelta(days=14)).isoformat(),
                        },
                    ],
                },
            )
        )

        # --- Rich data: training records ---
        _kb4_records = RICH_DATA["training_records"][0:125]
        result.events.append(
            RawEventData(
                source="knowbe4",
                source_type=SourceType.TRAINING,
                provider="knowbe4",
                event_type="kb4_training_enrollments",
                raw_data={
                    "region": "US",
                    "response": _training_as_knowbe4(_kb4_records),
                },
            )
        )

        result.complete()
        return result


class DemoSecurityScorecardConnector(BaseConnector):
    """Simulates SecurityScorecard vendor risk collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="securityscorecard",
            source_type=SourceType.GRC,
            provider="securityscorecard",
        )

        # 5 vendors with varying scores
        result.events.append(
            RawEventData(
                source="securityscorecard",
                source_type=SourceType.GRC,
                provider="securityscorecard",
                event_type="ssc_companies",
                raw_data={
                    "response": [
                        {
                            "domain": "stripe.com",
                            "name": "Stripe",
                            "score": 92,
                            "grade": "A",
                            "industry": "Financial Services",
                            "size": "large",
                            "last_score_change": (NOW - timedelta(days=7)).isoformat(),
                        },
                        {
                            "domain": "datadoghq.com",
                            "name": "Datadog",
                            "score": 88,
                            "grade": "A",
                            "industry": "Technology",
                            "size": "large",
                            "last_score_change": (NOW - timedelta(days=14)).isoformat(),
                        },
                        {
                            "domain": "acmestaffing.example.com",
                            "name": "Acme Staffing Co",
                            "score": 58,
                            "grade": "D",
                            "industry": "Staffing",
                            "size": "small",
                            "last_score_change": (NOW - timedelta(days=3)).isoformat(),
                        },
                        {
                            "domain": "cloudbackuppro.example.com",
                            "name": "CloudBackup Pro",
                            "score": 45,
                            "grade": "F",
                            "industry": "Technology",
                            "size": "small",
                            "last_score_change": (NOW - timedelta(days=1)).isoformat(),
                        },
                        {
                            "domain": "quickdocs.example.com",
                            "name": "QuickDocs",
                            "score": 72,
                            "grade": "C",
                            "industry": "SaaS",
                            "size": "medium",
                            "last_score_change": (NOW - timedelta(days=10)).isoformat(),
                        },
                    ],
                },
            )
        )

        # Risk factors per vendor (4 each)
        result.events.append(
            RawEventData(
                source="securityscorecard",
                source_type=SourceType.GRC,
                provider="securityscorecard",
                event_type="ssc_factors",
                raw_data={
                    "response": [
                        {
                            "domain": "stripe.com",
                            "factors": [
                                {
                                    "name": "Network Security",
                                    "grade": "A",
                                    "score": 95,
                                    "issue_count": 0,
                                },
                                {
                                    "name": "Patching Cadence",
                                    "grade": "A",
                                    "score": 90,
                                    "issue_count": 0,
                                },
                                {
                                    "name": "Endpoint Security",
                                    "grade": "A",
                                    "score": 92,
                                    "issue_count": 0,
                                },
                                {"name": "DNS Health", "grade": "A", "score": 94, "issue_count": 0},
                            ],
                        },
                        {
                            "domain": "datadoghq.com",
                            "factors": [
                                {
                                    "name": "Network Security",
                                    "grade": "A",
                                    "score": 90,
                                    "issue_count": 0,
                                },
                                {
                                    "name": "Patching Cadence",
                                    "grade": "B",
                                    "score": 82,
                                    "issue_count": 1,
                                },
                                {
                                    "name": "Endpoint Security",
                                    "grade": "A",
                                    "score": 91,
                                    "issue_count": 0,
                                },
                                {"name": "DNS Health", "grade": "A", "score": 88, "issue_count": 0},
                            ],
                        },
                        {
                            "domain": "acmestaffing.example.com",
                            "factors": [
                                {
                                    "name": "Network Security",
                                    "grade": "D",
                                    "score": 55,
                                    "issue_count": 3,
                                },
                                {
                                    "name": "Patching Cadence",
                                    "grade": "D",
                                    "score": 50,
                                    "issue_count": 4,
                                },
                                {
                                    "name": "Endpoint Security",
                                    "grade": "C",
                                    "score": 65,
                                    "issue_count": 2,
                                },
                                {"name": "DNS Health", "grade": "D", "score": 58, "issue_count": 2},
                            ],
                        },
                        {
                            "domain": "cloudbackuppro.example.com",
                            "factors": [
                                {
                                    "name": "Network Security",
                                    "grade": "F",
                                    "score": 35,
                                    "issue_count": 5,
                                },
                                {
                                    "name": "Patching Cadence",
                                    "grade": "F",
                                    "score": 40,
                                    "issue_count": 6,
                                },
                                {
                                    "name": "Endpoint Security",
                                    "grade": "D",
                                    "score": 52,
                                    "issue_count": 3,
                                },
                                {"name": "DNS Health", "grade": "F", "score": 38, "issue_count": 4},
                            ],
                        },
                        {
                            "domain": "quickdocs.example.com",
                            "factors": [
                                {
                                    "name": "Network Security",
                                    "grade": "C",
                                    "score": 70,
                                    "issue_count": 2,
                                },
                                {
                                    "name": "Patching Cadence",
                                    "grade": "B",
                                    "score": 78,
                                    "issue_count": 1,
                                },
                                {
                                    "name": "Endpoint Security",
                                    "grade": "C",
                                    "score": 72,
                                    "issue_count": 1,
                                },
                                {"name": "DNS Health", "grade": "C", "score": 68, "issue_count": 2},
                            ],
                        },
                    ],
                },
            )
        )

        # Issues for the bad vendors
        result.events.append(
            RawEventData(
                source="securityscorecard",
                source_type=SourceType.GRC,
                provider="securityscorecard",
                event_type="ssc_issues",
                raw_data={
                    "response": [
                        {
                            "_domain": "acmestaffing.example.com",
                            "type": "tlscert_expired",
                            "severity": "high",
                            "count": 2,
                            "first_seen_time": (NOW - timedelta(days=45)).isoformat(),
                            "last_seen_time": NOW.isoformat(),
                        },
                        {
                            "_domain": "acmestaffing.example.com",
                            "type": "open_port_25",
                            "severity": "medium",
                            "count": 1,
                            "first_seen_time": (NOW - timedelta(days=90)).isoformat(),
                            "last_seen_time": NOW.isoformat(),
                        },
                        {
                            "_domain": "cloudbackuppro.example.com",
                            "type": "tlscert_no_revocation",
                            "severity": "critical",
                            "count": 3,
                            "first_seen_time": (NOW - timedelta(days=60)).isoformat(),
                            "last_seen_time": NOW.isoformat(),
                        },
                        {
                            "_domain": "cloudbackuppro.example.com",
                            "type": "cve_detected",
                            "severity": "critical",
                            "count": 5,
                            "first_seen_time": (NOW - timedelta(days=30)).isoformat(),
                            "last_seen_time": NOW.isoformat(),
                        },
                        {
                            "_domain": "cloudbackuppro.example.com",
                            "type": "spf_record_missing",
                            "severity": "high",
                            "count": 1,
                            "first_seen_time": (NOW - timedelta(days=120)).isoformat(),
                            "last_seen_time": NOW.isoformat(),
                        },
                        {
                            "_domain": "quickdocs.example.com",
                            "type": "hsts_missing",
                            "severity": "medium",
                            "count": 1,
                            "first_seen_time": (NOW - timedelta(days=15)).isoformat(),
                            "last_seen_time": NOW.isoformat(),
                        },
                    ],
                },
            )
        )

        # --- Rich data: vendor assessments ---
        _ssc_vendors = RICH_DATA["vendor_assessments"][0:30]
        result.events.append(
            RawEventData(
                source="securityscorecard",
                source_type=SourceType.GRC,
                provider="securityscorecard",
                event_type="ssc_companies",
                raw_data={
                    "portfolio_id": "acme-portfolio",
                    "response": _vendors_as_securityscorecard(_ssc_vendors),
                },
            )
        )

        result.complete()
        return result


class DemoConfluenceConnector(BaseConnector):
    """Simulates Confluence policy document collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="confluence",
            source_type=SourceType.GRC,
            provider="confluence",
        )

        # 7 policy documents in the SEC space
        result.events.append(
            RawEventData(
                source="confluence",
                source_type=SourceType.GRC,
                provider="confluence",
                event_type="confluence_pages",
                raw_data={
                    "space_key": "SEC",
                    "pages": [
                        {
                            "id": "page-101",
                            "title": "Access Control Policy",
                            "status": "current",
                            "authorId": "usr-ciso-01",
                            "version": {"createdAt": (NOW - timedelta(days=45)).isoformat()},
                        },
                        {
                            "id": "page-102",
                            "title": "Incident Response Plan",
                            "status": "current",
                            "authorId": "usr-ciso-01",
                            "version": {"createdAt": (NOW - timedelta(days=30)).isoformat()},
                        },
                        {
                            "id": "page-103",
                            "title": "Change Management Policy",
                            "status": "current",
                            "authorId": "usr-itsec-02",
                            "version": {"createdAt": (NOW - timedelta(days=90)).isoformat()},
                        },
                        {
                            "id": "page-104",
                            "title": "Data Classification Standard",
                            "status": "current",
                            "authorId": "usr-itsec-02",
                            "version": {"createdAt": (NOW - timedelta(days=120)).isoformat()},
                        },
                        {
                            "id": "page-105",
                            "title": "Business Continuity Plan",
                            "status": "current",
                            "authorId": "usr-ciso-01",
                            "version": {"createdAt": (NOW - timedelta(days=200)).isoformat()},
                        },
                        {
                            "id": "page-106",
                            "title": "Encryption and Key Management Policy",
                            "status": "current",
                            "authorId": "usr-itsec-02",
                            "version": {"createdAt": (NOW - timedelta(days=60)).isoformat()},
                        },
                        {
                            "id": "page-107",
                            "title": "Acceptable Use Policy",
                            "status": "current",
                            "authorId": "usr-hr-01",
                            "version": {"createdAt": (NOW - timedelta(days=150)).isoformat()},
                        },
                    ],
                },
            )
        )

        # --- Rich data: policy documents ---
        _conf_policies = RICH_DATA["policy_documents"][0:20]
        result.events.append(
            RawEventData(
                source="confluence",
                source_type=SourceType.GRC,
                provider="confluence",
                event_type="confluence_pages",
                raw_data={
                    "space_key": "SEC",
                    "response": {"results": _policies_as_confluence(_conf_policies)},
                },
            )
        )

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
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="entra_id",
            source_type=SourceType.IAM,
            provider="entra_id",
        )

        # Users: mix of active, stale, disabled, never-signed-in
        result.events.append(
            RawEventData(
                source="entra_id",
                source_type=SourceType.IAM,
                provider="entra_id",
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
            )
        )

        # Risky users: bob high, carol medium
        result.events.append(
            RawEventData(
                source="entra_id",
                source_type=SourceType.IAM,
                provider="entra_id",
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
            )
        )

        # Sign-ins: failed sign-in, risky sign-in, CA-blocked sign-in, success
        result.events.append(
            RawEventData(
                source="entra_id",
                source_type=SourceType.IAM,
                provider="entra_id",
                event_type="entra_sign_ins",
                raw_data={
                    "tenant_id": "acme-tenant-001",
                    "response": [
                        {
                            "userId": "entra-u-002",
                            "userPrincipalName": "bob.martinez@acme.onmicrosoft.com",
                            "status": {
                                "errorCode": 50126,
                                "failureReason": "Invalid username or password",
                            },
                            "riskLevelDuringSignIn": "high",
                            "conditionalAccessStatus": "notApplied",
                            "ipAddress": "198.51.100.42",
                            "location": {"city": "Moscow", "countryOrRegion": "RU"},
                        },
                        {
                            "userId": "entra-u-003",
                            "userPrincipalName": "carol.park@acme.onmicrosoft.com",
                            "status": {
                                "errorCode": 53003,
                                "failureReason": "Blocked by Conditional Access",
                            },
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
            )
        )

        # Directory audits: privilege change + normal activity
        result.events.append(
            RawEventData(
                source="entra_id",
                source_type=SourceType.IAM,
                provider="entra_id",
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
                                {
                                    "displayName": "eve.nakamura@acme.onmicrosoft.com",
                                    "type": "User",
                                },
                            ],
                        },
                    ],
                },
            )
        )

        # Conditional access policies: enabled, disabled, and report-only
        result.events.append(
            RawEventData(
                source="entra_id",
                source_type=SourceType.IAM,
                provider="entra_id",
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
            )
        )

        # Service principals: one overprivileged, one clean
        result.events.append(
            RawEventData(
                source="entra_id",
                source_type=SourceType.IAM,
                provider="entra_id",
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
            )
        )

        # App registrations
        result.events.append(
            RawEventData(
                source="entra_id",
                source_type=SourceType.IAM,
                provider="entra_id",
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
            )
        )

        # --- Rich data: users ---
        _entra_users = RICH_DATA["users"][30:60]
        result.events.append(
            RawEventData(
                source="entra_id",
                source_type=SourceType.IAM,
                provider="microsoft",
                event_type="entra_users",
                raw_data={
                    "tenant_id": "acme-tenant-001",
                    "response": _users_as_entra(_entra_users),
                },
            )
        )

        result.complete()
        return result


class DemoCyberArkConnector(BaseConnector):
    """Simulates CyberArk collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="cyberark",
            source_type=SourceType.IAM,
            provider="cyberark",
        )

        # Accounts: compliant, overdue rotation, auto-mgmt disabled, unused
        result.events.append(
            RawEventData(
                source="cyberark",
                source_type=SourceType.IAM,
                provider="cyberark",
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
            )
        )

        # Safes: one with members, one empty
        result.events.append(
            RawEventData(
                source="cyberark",
                source_type=SourceType.IAM,
                provider="cyberark",
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
            )
        )

        # Platforms: active and inactive
        result.events.append(
            RawEventData(
                source="cyberark",
                source_type=SourceType.IAM,
                provider="cyberark",
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
            )
        )

        # Session recordings
        result.events.append(
            RawEventData(
                source="cyberark",
                source_type=SourceType.IAM,
                provider="cyberark",
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
            )
        )

        # Password compliance: reuse same accounts for summary view
        result.events.append(
            RawEventData(
                source="cyberark",
                source_type=SourceType.IAM,
                provider="cyberark",
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
            )
        )

        # --- Rich data: privileged accounts ---
        _ca_users = RICH_DATA["users"][60:80]
        result.events.append(
            RawEventData(
                source="cyberark",
                source_type=SourceType.IAM,
                provider="cyberark",
                event_type="cyberark_accounts",
                raw_data={
                    "vault": "acme-vault",
                    "response": _users_as_cyberark(_ca_users),
                },
            )
        )

        result.complete()
        return result


class DemoSailPointConnector(BaseConnector):
    """Simulates SailPoint collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="sailpoint",
            source_type=SourceType.IAM,
            provider="sailpoint",
        )

        # Identities: active, inactive, excessive entitlements
        result.events.append(
            RawEventData(
                source="sailpoint",
                source_type=SourceType.IAM,
                provider="sailpoint",
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
            )
        )

        # Certifications: completed, overdue, low-completion, not started
        result.events.append(
            RawEventData(
                source="sailpoint",
                source_type=SourceType.IAM,
                provider="sailpoint",
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
            )
        )

        # Roles
        result.events.append(
            RawEventData(
                source="sailpoint",
                source_type=SourceType.IAM,
                provider="sailpoint",
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
            )
        )

        # Entitlements: privileged with owner, privileged without owner, normal
        result.events.append(
            RawEventData(
                source="sailpoint",
                source_type=SourceType.IAM,
                provider="sailpoint",
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
            )
        )

        # Accounts: correlated, orphan, disabled-with-identity
        result.events.append(
            RawEventData(
                source="sailpoint",
                source_type=SourceType.IAM,
                provider="sailpoint",
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
            )
        )

        # --- Rich data: identities ---
        _sp_users = RICH_DATA["users"][80:110]
        result.events.append(
            RawEventData(
                source="sailpoint",
                source_type=SourceType.IAM,
                provider="sailpoint",
                event_type="sailpoint_identities",
                raw_data={
                    "org": "acme",
                    "response": _users_as_sailpoint(_sp_users),
                },
            )
        )

        result.complete()
        return result


class DemoVaultConnector(BaseConnector):
    """Simulates Vault collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="vault",
            source_type=SourceType.IAM,
            provider="vault",
        )

        # Secret engines: KV with no max TTL, PKI with max TTL, system/identity
        result.events.append(
            RawEventData(
                source="vault",
                source_type=SourceType.IAM,
                provider="vault",
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
            )
        )

        # Auth methods: token only (no MFA-capable method)
        result.events.append(
            RawEventData(
                source="vault",
                source_type=SourceType.IAM,
                provider="vault",
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
            )
        )

        # Policies: default, root, and custom
        result.events.append(
            RawEventData(
                source="vault",
                source_type=SourceType.IAM,
                provider="vault",
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
            )
        )

        # Audit devices: file-based audit logging enabled
        result.events.append(
            RawEventData(
                source="vault",
                source_type=SourceType.IAM,
                provider="vault",
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
            )
        )

        # Seal status: unsealed, healthy, HA configured
        result.events.append(
            RawEventData(
                source="vault",
                source_type=SourceType.IAM,
                provider="vault",
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
            )
        )

        # Health: active node
        result.events.append(
            RawEventData(
                source="vault",
                source_type=SourceType.IAM,
                provider="vault",
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
            )
        )

        # --- Rich data: IaC misconfigs as vault audit events ---
        _vault_iac = RICH_DATA["iac_misconfigs"][0:30]
        result.events.append(
            RawEventData(
                source="vault",
                source_type=SourceType.IAM,
                provider="hashicorp",
                event_type="vault_audit_devices",
                raw_data={
                    "data": {
                        "file/": {
                            "type": "file",
                            "options": {"file_path": "/var/log/vault/audit.log"},
                        },
                        "syslog/": {"type": "syslog", "options": {}},
                    },
                },
            )
        )

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
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="azure",
            source_type=SourceType.CLOUD,
            provider="azure",
        )

        # Policy compliance: one compliant, one non-compliant with security group
        result.events.append(
            RawEventData(
                source="azure",
                source_type=SourceType.CLOUD,
                provider="azure",
                event_type="policy_compliance",
                raw_data={
                    "subscription_id": "sub-acme-prod-001",
                    "region": "eastus",
                    "response": {
                        "policy_states": [
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
                        ]
                    },
                },
            )
        )

        # Defender alerts: one high, one medium
        result.events.append(
            RawEventData(
                source="azure",
                source_type=SourceType.CLOUD,
                provider="azure",
                event_type="defender_alerts",
                raw_data={
                    "subscription_id": "sub-acme-prod-001",
                    "region": "eastus",
                    "response": {
                        "alerts": [
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
                        ]
                    },
                },
            )
        )

        # Entra sign-ins: risky sign-in and failed sign-in
        result.events.append(
            RawEventData(
                source="azure",
                source_type=SourceType.CLOUD,
                provider="azure",
                event_type="entra_sign_ins",
                raw_data={
                    "subscription_id": "sub-acme-prod-001",
                    "region": "eastus",
                    "response": {
                        "value": [
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
                                "status": {
                                    "errorCode": 50126,
                                    "failureReason": "Invalid username or password",
                                },
                                "conditionalAccessStatus": "notApplied",
                            },
                        ]
                    },
                },
            )
        )

        # Network security groups: one open SSH, one restricted
        result.events.append(
            RawEventData(
                source="azure",
                source_type=SourceType.CLOUD,
                provider="azure",
                event_type="network_security_groups",
                raw_data={
                    "subscription_id": "sub-acme-prod-001",
                    "region": "eastus",
                    "response": {
                        "network_security_groups": [
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
                        ]
                    },
                },
            )
        )

        # Key Vault: one compliant, one missing purge protection
        result.events.append(
            RawEventData(
                source="azure",
                source_type=SourceType.CLOUD,
                provider="azure",
                event_type="key_vault",
                raw_data={
                    "subscription_id": "sub-acme-prod-001",
                    "region": "eastus",
                    "response": {
                        "vaults": [
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
                        ]
                    },
                },
            )
        )

        # Storage accounts: one with public blob access, one compliant
        result.events.append(
            RawEventData(
                source="azure",
                source_type=SourceType.CLOUD,
                provider="azure",
                event_type="storage_accounts",
                raw_data={
                    "subscription_id": "sub-acme-prod-001",
                    "region": "eastus",
                    "response": {
                        "storage_accounts": [
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
                        ]
                    },
                },
            )
        )

        # Activity log: error-level operation
        result.events.append(
            RawEventData(
                source="azure",
                source_type=SourceType.CLOUD,
                provider="azure",
                event_type="activity_log",
                raw_data={
                    "subscription_id": "sub-acme-prod-001",
                    "region": "eastus",
                    "response": {
                        "activity_logs": [
                            {
                                "level": "Error",
                                "operation_name": {
                                    "value": "Microsoft.Authorization/roleAssignments/write"
                                },
                                "caller": "dave.thompson@acme.com",
                                "status": {"value": "Failed"},
                                "resource_id": "/subscriptions/sub-acme-prod-001/resourceGroups/acme-prod-rg",
                                "event_timestamp": NOW.isoformat(),
                            },
                            {
                                "level": "Warning",
                                "operation_name": {
                                    "value": "Microsoft.Compute/virtualMachines/delete"
                                },
                                "caller": "bob.martinez@acme.com",
                                "status": {"value": "Succeeded"},
                                "resource_id": "/subscriptions/sub-acme-prod-001/resourceGroups/acme-dev-rg/providers/Microsoft.Compute/virtualMachines/acme-test-vm",
                                "event_timestamp": (NOW - timedelta(hours=3)).isoformat(),
                            },
                        ]
                    },
                },
            )
        )

        # Monitor alerts: one Sev1
        result.events.append(
            RawEventData(
                source="azure",
                source_type=SourceType.CLOUD,
                provider="azure",
                event_type="monitor_alerts",
                raw_data={
                    "subscription_id": "sub-acme-prod-001",
                    "region": "eastus",
                    "response": {
                        "alerts": [
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
                        ]
                    },
                },
            )
        )

        # --- Rich data: Azure cloud instances, security groups, storage ---
        _az_instances = _instances_filter_cloud(RICH_DATA["cloud_instances"], "azure")
        for batch_start in range(0, len(_az_instances), 50):
            batch = _az_instances[batch_start : batch_start + 50]
            result.events.append(
                RawEventData(
                    source="azure",
                    source_type=SourceType.CLOUD,
                    provider="azure",
                    event_type="compute_instances",
                    raw_data={"value": batch},
                )
            )
        _az_sgs = _sg_filter_cloud(RICH_DATA["security_groups"], "azure")
        result.events.append(
            RawEventData(
                source="azure",
                source_type=SourceType.CLOUD,
                provider="azure",
                event_type="network_security_groups",
                raw_data={"value": _az_sgs},
            )
        )

        result.complete()
        return result


class DemoGCPConnector(BaseConnector):
    """Simulates GCP collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="gcp",
            source_type=SourceType.CLOUD,
            provider="gcp",
        )

        # SCC findings: one active misconfiguration, one active threat, one inactive
        result.events.append(
            RawEventData(
                source="gcp",
                source_type=SourceType.CLOUD,
                provider="gcp",
                event_type="scc_findings",
                raw_data={
                    "project_id": "acme-gcp-project-01",
                    "region": "us-central1",
                    "response": {
                        "findings": [
                            {
                                "category": "PUBLIC_BUCKET_ACL",
                                "severity": "HIGH",
                                "state": "ACTIVE",
                                "finding_class": "MISCONFIGURATION",
                                "resource_name": "//storage.googleapis.com/projects/acme-gcp-project-01/buckets/acme-public-uploads",
                                "source_properties": {
                                    "explanation": "Bucket has public ACL granting allUsers read access"
                                },
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
                        ]
                    },
                },
            )
        )

        # IAM policies: one risky owner binding, one safe viewer binding
        result.events.append(
            RawEventData(
                source="gcp",
                source_type=SourceType.CLOUD,
                provider="gcp",
                event_type="iam_policies",
                raw_data={
                    "project_id": "acme-gcp-project-01",
                    "region": "global",
                    "response": {
                        "bindings": [
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
                        ]
                    },
                },
            )
        )

        # Firewall rules: one open SSH, one restricted
        result.events.append(
            RawEventData(
                source="gcp",
                source_type=SourceType.CLOUD,
                provider="gcp",
                event_type="compute_firewall_rules",
                raw_data={
                    "project_id": "acme-gcp-project-01",
                    "region": "global",
                    "response": {
                        "firewall_rules": [
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
                        ]
                    },
                },
            )
        )

        # Storage buckets: one without versioning, one compliant
        result.events.append(
            RawEventData(
                source="gcp",
                source_type=SourceType.CLOUD,
                provider="gcp",
                event_type="storage_buckets",
                raw_data={
                    "project_id": "acme-gcp-project-01",
                    "region": "us-central1",
                    "response": {
                        "buckets": [
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
                        ]
                    },
                },
            )
        )

        # Audit logs: one error, one warning
        result.events.append(
            RawEventData(
                source="gcp",
                source_type=SourceType.CLOUD,
                provider="gcp",
                event_type="audit_logs",
                raw_data={
                    "project_id": "acme-gcp-project-01",
                    "region": "global",
                    "response": {
                        "log_entries": [
                            {
                                "severity": "ERROR",
                                "log_name": "projects/acme-gcp-project-01/logs/cloudaudit.googleapis.com%2Factivity",
                                "resource": {
                                    "type": "gce_instance",
                                    "labels": {
                                        "project_id": "acme-gcp-project-01",
                                        "instance_id": "i-acme-staging-03",
                                    },
                                },
                                "payload": {
                                    "methodName": "v1.compute.instances.delete",
                                    "status": {"code": 7, "message": "PERMISSION_DENIED"},
                                },
                                "timestamp": NOW.isoformat(),
                            },
                            {
                                "severity": "WARNING",
                                "log_name": "projects/acme-gcp-project-01/logs/cloudaudit.googleapis.com%2Fdata_access",
                                "resource": {
                                    "type": "bigquery_dataset",
                                    "labels": {
                                        "project_id": "acme-gcp-project-01",
                                        "dataset_id": "customer_analytics",
                                    },
                                },
                                "payload": {
                                    "methodName": "google.cloud.bigquery.v2.JobService.InsertJob"
                                },
                                "timestamp": (NOW - timedelta(hours=1)).isoformat(),
                            },
                        ]
                    },
                },
            )
        )

        # GKE clusters: one with legacy ABAC, one compliant
        result.events.append(
            RawEventData(
                source="gcp",
                source_type=SourceType.CLOUD,
                provider="gcp",
                event_type="gke_clusters",
                raw_data={
                    "project_id": "acme-gcp-project-01",
                    "region": "us-central1",
                    "response": {
                        "clusters": [
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
                        ]
                    },
                },
            )
        )

        # --- Rich data: GCP cloud instances, storage ---
        _gcp_instances = _instances_filter_cloud(RICH_DATA["cloud_instances"], "gcp")
        for batch_start in range(0, len(_gcp_instances), 50):
            batch = _gcp_instances[batch_start : batch_start + 50]
            result.events.append(
                RawEventData(
                    source="gcp",
                    source_type=SourceType.CLOUD,
                    provider="gcp",
                    event_type="compute_instances",
                    raw_data={"items": batch},
                )
            )
        _gcp_buckets = _buckets_filter_cloud(RICH_DATA["storage_buckets"], "gcp")
        result.events.append(
            RawEventData(
                source="gcp",
                source_type=SourceType.CLOUD,
                provider="gcp",
                event_type="storage_buckets",
                raw_data={"items": _gcp_buckets},
            )
        )

        result.complete()
        return result


class DemoDigitalOceanConnector(BaseConnector):
    """Simulates DigitalOcean collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="digitalocean",
            source_type=SourceType.CLOUD,
            provider="digitalocean",
        )

        # Firewalls: one open SSH, one restricted
        result.events.append(
            RawEventData(
                source="digitalocean",
                source_type=SourceType.CLOUD,
                provider="digitalocean",
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
            )
        )

        # Droplets: one public without backups, one compliant
        result.events.append(
            RawEventData(
                source="digitalocean",
                source_type=SourceType.CLOUD,
                provider="digitalocean",
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
                            "networks": {
                                "v4": [
                                    {"type": "public", "ip_address": "198.51.100.20"},
                                    {"type": "private", "ip_address": "10.132.0.5"},
                                ]
                            },
                            "backup_ids": [55001],
                            "features": ["backups", "monitoring"],
                            "region": {"slug": "nyc1"},
                        },
                    ],
                },
            )
        )

        # Spaces: inventory
        result.events.append(
            RawEventData(
                source="digitalocean",
                source_type=SourceType.CLOUD,
                provider="digitalocean",
                event_type="do_spaces",
                raw_data={
                    "response": [
                        {"name": "acme-cdn-assets", "region": {"slug": "nyc3"}},
                        {"name": "acme-backup-archives", "region": {"slug": "sfo3"}},
                    ],
                },
            )
        )

        # Databases: one publicly accessible, one compliant
        result.events.append(
            RawEventData(
                source="digitalocean",
                source_type=SourceType.CLOUD,
                provider="digitalocean",
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
            )
        )

        # Kubernetes: one without auto_upgrade, one compliant
        result.events.append(
            RawEventData(
                source="digitalocean",
                source_type=SourceType.CLOUD,
                provider="digitalocean",
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
            )
        )

        # Load Balancers: one without HTTPS redirect
        result.events.append(
            RawEventData(
                source="digitalocean",
                source_type=SourceType.CLOUD,
                provider="digitalocean",
                event_type="do_load_balancers",
                raw_data={
                    "response": [
                        {
                            "id": "lb-acme-web-001",
                            "name": "acme-web-lb",
                            "redirect_http_to_https": False,
                            "sticky_sessions": {"type": "none"},
                            "forwarding_rules": [
                                {
                                    "entry_protocol": "http",
                                    "entry_port": 80,
                                    "target_protocol": "http",
                                    "target_port": 80,
                                },
                                {
                                    "entry_protocol": "https",
                                    "entry_port": 443,
                                    "target_protocol": "http",
                                    "target_port": 80,
                                },
                            ],
                            "droplet_ids": [301003, 301004],
                            "region": {"slug": "nyc1"},
                        },
                    ],
                },
            )
        )

        # Domains: inventory
        result.events.append(
            RawEventData(
                source="digitalocean",
                source_type=SourceType.CLOUD,
                provider="digitalocean",
                event_type="do_domains",
                raw_data={
                    "response": [
                        {"name": "acme-corp.io", "ttl": 1800, "zone_file": "$ORIGIN acme-corp.io."},
                        {
                            "name": "acme-internal.dev",
                            "ttl": 300,
                            "zone_file": "$ORIGIN acme-internal.dev.",
                        },
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoAlibabaConnector(BaseConnector):
    """Simulates Alibaba Cloud collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="alibaba",
            source_type=SourceType.CLOUD,
            provider="alibaba",
        )

        # Security Center alerts
        result.events.append(
            RawEventData(
                source="alibaba",
                source_type=SourceType.CLOUD,
                provider="alibaba",
                event_type="ali_security_alerts",
                raw_data={
                    "region": "cn-hangzhou",
                    "response": {
                        "alerts": [
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
                        ]
                    },
                },
            )
        )

        # RAM users: one without MFA, one stale, one compliant
        result.events.append(
            RawEventData(
                source="alibaba",
                source_type=SourceType.CLOUD,
                provider="alibaba",
                event_type="ali_ram_users",
                raw_data={
                    "region": "cn-hangzhou",
                    "response": {
                        "users": [
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
                        ]
                    },
                },
            )
        )

        # ActionTrail: privilege escalation event and error event
        result.events.append(
            RawEventData(
                source="alibaba",
                source_type=SourceType.CLOUD,
                provider="alibaba",
                event_type="ali_actiontrail_events",
                raw_data={
                    "region": "cn-hangzhou",
                    "response": {
                        "events": [
                            {
                                "eventName": "AttachPolicyToUser",
                                "eventSource": "ram.aliyuncs.com",
                                "eventTime": NOW.isoformat(),
                                "errorCode": "",
                                "errorMessage": "",
                                "userIdentity": {
                                    "principalId": "ram-uid-003",
                                    "userName": "bob.martinez",
                                },
                                "sourceIpAddress": "203.0.113.50",
                                "userAgent": "aliyun-sdk-go/1.0",
                                "requestParameters": {
                                    "PolicyName": "AdministratorAccess",
                                    "UserName": "svc-deploy",
                                },
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
                                "userIdentity": {
                                    "principalId": "ram-uid-002",
                                    "userName": "svc-deploy",
                                },
                                "sourceIpAddress": "172.16.0.10",
                                "userAgent": "aliyun-sdk-python/3.0",
                                "requestParameters": {},
                                "resourceId": "",
                                "resourceType": "ecs:Instance",
                                "accountId": "acme-alibaba-001",
                            },
                        ]
                    },
                },
            )
        )

        # Security groups: one open all ports, one restricted
        result.events.append(
            RawEventData(
                source="alibaba",
                source_type=SourceType.CLOUD,
                provider="alibaba",
                event_type="ali_security_groups",
                raw_data={
                    "region": "cn-hangzhou",
                    "response": {
                        "security_groups": [
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
                        ]
                    },
                },
            )
        )

        # KMS keys: one with rotation disabled, one pending deletion
        result.events.append(
            RawEventData(
                source="alibaba",
                source_type=SourceType.CLOUD,
                provider="alibaba",
                event_type="ali_kms_keys",
                raw_data={
                    "region": "cn-hangzhou",
                    "response": {
                        "keys": [
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
                        ]
                    },
                },
            )
        )

        # Config compliance: one non-compliant, one compliant
        result.events.append(
            RawEventData(
                source="alibaba",
                source_type=SourceType.CLOUD,
                provider="alibaba",
                event_type="ali_config_compliance",
                raw_data={
                    "region": "cn-hangzhou",
                    "response": {
                        "results": [
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
                        ]
                    },
                },
            )
        )

        # OSS buckets: one public-read-write, one encrypted and private
        result.events.append(
            RawEventData(
                source="alibaba",
                source_type=SourceType.CLOUD,
                provider="alibaba",
                event_type="ali_oss_buckets",
                raw_data={
                    "region": "cn-hangzhou",
                    "response": {
                        "buckets": [
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
                        ]
                    },
                },
            )
        )

        result.complete()
        return result


class DemoHuaweiConnector(BaseConnector):
    """Simulates Huawei Cloud collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="huawei",
            source_type=SourceType.CLOUD,
            provider="huawei",
        )

        # HSS events: one critical, one low
        result.events.append(
            RawEventData(
                source="huawei",
                source_type=SourceType.CLOUD,
                provider="huawei",
                event_type="huawei_hss_events",
                raw_data={
                    "project_id": "acme-huawei-proj-01",
                    "region": "cn-north-4",
                    "response": {
                        "events": [
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
                        ]
                    },
                },
            )
        )

        # IAM users: one without MFA, one stale, one compliant
        result.events.append(
            RawEventData(
                source="huawei",
                source_type=SourceType.CLOUD,
                provider="huawei",
                event_type="huawei_iam_users",
                raw_data={
                    "project_id": "acme-huawei-proj-01",
                    "region": "cn-north-4",
                    "response": {
                        "users": [
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
                        ]
                    },
                },
            )
        )

        # CTS events: one error trace, one normal (skipped)
        result.events.append(
            RawEventData(
                source="huawei",
                source_type=SourceType.CLOUD,
                provider="huawei",
                event_type="huawei_cts_events",
                raw_data={
                    "project_id": "acme-huawei-proj-01",
                    "region": "cn-north-4",
                    "response": {
                        "traces": [
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
                        ]
                    },
                },
            )
        )

        # Security groups: one open SSH, one restricted
        result.events.append(
            RawEventData(
                source="huawei",
                source_type=SourceType.CLOUD,
                provider="huawei",
                event_type="huawei_security_groups",
                raw_data={
                    "project_id": "acme-huawei-proj-01",
                    "region": "cn-north-4",
                    "response": {
                        "security_groups": [
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
                        ]
                    },
                },
            )
        )

        # KMS keys: one enabled without rotation, one disabled
        result.events.append(
            RawEventData(
                source="huawei",
                source_type=SourceType.CLOUD,
                provider="huawei",
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
            )
        )

        # OBS buckets: one with public ACL, one compliant
        result.events.append(
            RawEventData(
                source="huawei",
                source_type=SourceType.CLOUD,
                provider="huawei",
                event_type="huawei_obs_buckets",
                raw_data={
                    "project_id": "acme-huawei-proj-01",
                    "region": "cn-north-4",
                    "response": {
                        "buckets": [
                            {
                                "name": "acme-public-assets",
                                "location": "cn-north-4",
                                "creation_date": "2023-05-10T00:00:00Z",
                                "acl": {
                                    "grants": [
                                        {
                                            "grantee": {
                                                "uri": "http://acs.amazonaws.com/groups/global/AllUsers",
                                                "type": "Group",
                                            },
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
                                            "grantee": {
                                                "uri": "",
                                                "type": "CanonicalUser",
                                                "id": "acme-owner-id",
                                            },
                                            "permission": "FULL_CONTROL",
                                        },
                                    ],
                                },
                                "versioning": "Enabled",
                                "logging_enabled": True,
                            },
                        ]
                    },
                },
            )
        )

        result.complete()
        return result


class DemoIBMCloudConnector(BaseConnector):
    """Simulates IBM Cloud collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="ibm_cloud",
            source_type=SourceType.CLOUD,
            provider="ibm_cloud",
        )

        # Security findings: one high vulnerability, one misconfiguration
        result.events.append(
            RawEventData(
                source="ibm_cloud",
                source_type=SourceType.CLOUD,
                provider="ibm_cloud",
                event_type="ibm_security_findings",
                raw_data={
                    "account_id": "acme-ibm-account-001",
                    "region": "us-south",
                    "response": {
                        "occurrences": [
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
                        ]
                    },
                },
            )
        )

        # IAM users: one with MFA disabled, one active
        result.events.append(
            RawEventData(
                source="ibm_cloud",
                source_type=SourceType.CLOUD,
                provider="ibm_cloud",
                event_type="ibm_iam_users",
                raw_data={
                    "account_id": "acme-ibm-account-001",
                    "region": "global",
                    "response": {
                        "resources": [
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
                        ]
                    },
                },
            )
        )

        # IAM groups: inventory
        result.events.append(
            RawEventData(
                source="ibm_cloud",
                source_type=SourceType.CLOUD,
                provider="ibm_cloud",
                event_type="ibm_iam_groups",
                raw_data={
                    "account_id": "acme-ibm-account-001",
                    "region": "global",
                    "response": {
                        "groups": [
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
                        ]
                    },
                },
            )
        )

        # Activity events: one error, one warning
        result.events.append(
            RawEventData(
                source="ibm_cloud",
                source_type=SourceType.CLOUD,
                provider="ibm_cloud",
                event_type="ibm_activity_events",
                raw_data={
                    "account_id": "acme-ibm-account-001",
                    "region": "us-south",
                    "response": {
                        "events": [
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
                        ]
                    },
                },
            )
        )

        # Key Protect: one active, one extractable (risky)
        result.events.append(
            RawEventData(
                source="ibm_cloud",
                source_type=SourceType.CLOUD,
                provider="ibm_cloud",
                event_type="ibm_key_protect",
                raw_data={
                    "account_id": "acme-ibm-account-001",
                    "region": "us-south",
                    "response": {
                        "resources": [
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
                        ]
                    },
                },
            )
        )

        # Security groups: one open, one restricted
        result.events.append(
            RawEventData(
                source="ibm_cloud",
                source_type=SourceType.CLOUD,
                provider="ibm_cloud",
                event_type="ibm_security_groups",
                raw_data={
                    "account_id": "acme-ibm-account-001",
                    "region": "us-south",
                    "response": {
                        "security_groups": [
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
                        ]
                    },
                },
            )
        )

        # Compliance profiles: one failed control, one passed
        result.events.append(
            RawEventData(
                source="ibm_cloud",
                source_type=SourceType.CLOUD,
                provider="ibm_cloud",
                event_type="ibm_compliance_profiles",
                raw_data={
                    "account_id": "acme-ibm-account-001",
                    "region": "global",
                    "response": {
                        "profiles": [
                            {
                                "id": "profile-ibm-fs-001",
                                "name": "IBM Cloud Framework for Financial Services",
                                "controls": [
                                    {
                                        "id": "SC-7",
                                        "control_name": "Boundary Protection",
                                        "status": "fail",
                                        "severity": "high",
                                        "assessment": {
                                            "description": "Network segmentation not enforced"
                                        },
                                        "remediation": "Implement VPC network ACLs to restrict cross-zone traffic",
                                    },
                                    {
                                        "id": "AC-2",
                                        "control_name": "Account Management",
                                        "status": "pass",
                                        "severity": "medium",
                                        "assessment": {
                                            "description": "All user accounts reviewed within 90 days"
                                        },
                                        "remediation": "",
                                    },
                                    {
                                        "id": "IA-5",
                                        "control_name": "Authenticator Management",
                                        "status": "error",
                                        "severity": "medium",
                                        "assessment": {
                                            "description": "Service IDs using long-lived API keys without rotation"
                                        },
                                        "remediation": "Enable automatic API key rotation for all service IDs",
                                    },
                                ],
                            },
                        ]
                    },
                },
            )
        )

        result.complete()
        return result


class DemoOVHConnector(BaseConnector):
    """Simulates OVHcloud collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="ovh",
            source_type=SourceType.CLOUD,
            provider="ovh",
        )

        # Projects: list of IDs
        result.events.append(
            RawEventData(
                source="ovh",
                source_type=SourceType.CLOUD,
                provider="ovh",
                event_type="ovh_projects",
                raw_data={
                    "service_name": "acme-ovh-001",
                    "response": [
                        "proj-acme-prod-eu-001",
                        "proj-acme-staging-eu-001",
                    ],
                },
            )
        )

        # Instances: one active, one in error state
        result.events.append(
            RawEventData(
                source="ovh",
                source_type=SourceType.CLOUD,
                provider="ovh",
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
            )
        )

        # Cloud users: one admin, one standard
        result.events.append(
            RawEventData(
                source="ovh",
                source_type=SourceType.CLOUD,
                provider="ovh",
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
            )
        )

        # Networks: inventory
        result.events.append(
            RawEventData(
                source="ovh",
                source_type=SourceType.CLOUD,
                provider="ovh",
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
            )
        )

        # Storage: one public container, one private
        result.events.append(
            RawEventData(
                source="ovh",
                source_type=SourceType.CLOUD,
                provider="ovh",
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
            )
        )

        # Kubernetes: one outdated version, one current
        result.events.append(
            RawEventData(
                source="ovh",
                source_type=SourceType.CLOUD,
                provider="ovh",
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
            )
        )

        # Certificates: one expired, one valid, one bare service name
        result.events.append(
            RawEventData(
                source="ovh",
                source_type=SourceType.CLOUD,
                provider="ovh",
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
                            "expireDate": (NOW + timedelta(days=365)).strftime(
                                "%Y-%m-%dT%H:%M:%SZ"
                            ),
                        },
                        "cert-acme-internal-001",
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoOCIConnector(BaseConnector):
    """Simulates Oracle Cloud Infrastructure collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="oci",
            source_type=SourceType.CLOUD,
            provider="oci",
        )

        # Cloud Guard problems: one critical misconfiguration, one activity alert
        result.events.append(
            RawEventData(
                source="oci",
                source_type=SourceType.CLOUD,
                provider="oci",
                event_type="oci_cloud_guard_problems",
                raw_data={
                    "tenancy_id": "ocid1.tenancy.oc1..acme-tenancy-001",
                    "region": "us-ashburn-1",
                    "response": {
                        "problems": [
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
                        ]
                    },
                },
            )
        )

        # IAM users: one without MFA, one stale, one compliant
        result.events.append(
            RawEventData(
                source="oci",
                source_type=SourceType.CLOUD,
                provider="oci",
                event_type="oci_iam_users",
                raw_data={
                    "tenancy_id": "ocid1.tenancy.oc1..acme-tenancy-001",
                    "region": "us-ashburn-1",
                    "response": {
                        "users": [
                            {
                                "name": "alice.chen@acme.com",
                                "id": "ocid1.user.oc1..acme-alice",
                                "lifecycleState": "ACTIVE",
                                "isMfaActivated": True,
                                "lastSuccessfulLoginTime": (NOW - timedelta(hours=3)).isoformat()
                                + "Z",
                                "timeCreated": "2023-06-01T00:00:00Z",
                                "email": "alice.chen@acme.com",
                                "capabilities": {"canUseConsolePassword": True},
                            },
                            {
                                "name": "svc-terraform",
                                "id": "ocid1.user.oc1..acme-svc-tf",
                                "lifecycleState": "ACTIVE",
                                "isMfaActivated": False,
                                "lastSuccessfulLoginTime": (NOW - timedelta(days=1)).isoformat()
                                + "Z",
                                "timeCreated": "2024-01-10T00:00:00Z",
                                "email": "",
                                "capabilities": {"canUseApiKeys": True},
                            },
                            {
                                "name": "carol.park@acme.com",
                                "id": "ocid1.user.oc1..acme-carol",
                                "lifecycleState": "ACTIVE",
                                "isMfaActivated": True,
                                "lastSuccessfulLoginTime": (NOW - timedelta(days=120)).isoformat()
                                + "Z",
                                "timeCreated": "2023-03-15T00:00:00Z",
                                "email": "carol.park@acme.com",
                                "capabilities": {"canUseConsolePassword": True},
                            },
                        ]
                    },
                },
            )
        )

        # IAM groups: inventory
        result.events.append(
            RawEventData(
                source="oci",
                source_type=SourceType.CLOUD,
                provider="oci",
                event_type="oci_iam_groups",
                raw_data={
                    "tenancy_id": "ocid1.tenancy.oc1..acme-tenancy-001",
                    "region": "us-ashburn-1",
                    "response": {
                        "groups": [
                            {
                                "name": "acme-cloud-admins",
                                "id": "ocid1.group.oc1..acme-admins",
                                "description": "Cloud infrastructure administrators",
                                "lifecycleState": "ACTIVE",
                                "timeCreated": "2023-06-01T00:00:00Z",
                                "compartmentId": "ocid1.tenancy.oc1..acme-tenancy-001",
                            },
                        ]
                    },
                },
            )
        )

        # Audit events: one 403, one 500
        result.events.append(
            RawEventData(
                source="oci",
                source_type=SourceType.CLOUD,
                provider="oci",
                event_type="oci_audit_events",
                raw_data={
                    "tenancy_id": "ocid1.tenancy.oc1..acme-tenancy-001",
                    "region": "us-ashburn-1",
                    "response": {
                        "audit_events": [
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
                                    "response": {
                                        "status": "500",
                                        "message": "Internal server error",
                                    },
                                    "request": {"action": "LaunchInstance"},
                                },
                                "eventTime": (NOW - timedelta(hours=1)).isoformat(),
                                "source": "computeapi",
                            },
                        ]
                    },
                },
            )
        )

        # Vulnerabilities: one critical CVSS, one medium
        result.events.append(
            RawEventData(
                source="oci",
                source_type=SourceType.CLOUD,
                provider="oci",
                event_type="oci_vulnerabilities",
                raw_data={
                    "tenancy_id": "ocid1.tenancy.oc1..acme-tenancy-001",
                    "region": "us-ashburn-1",
                    "response": {
                        "vulnerabilities": [
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
                        ]
                    },
                },
            )
        )

        # Security lists: one open all protocols, one restricted
        result.events.append(
            RawEventData(
                source="oci",
                source_type=SourceType.CLOUD,
                provider="oci",
                event_type="oci_security_lists",
                raw_data={
                    "tenancy_id": "ocid1.tenancy.oc1..acme-tenancy-001",
                    "region": "us-ashburn-1",
                    "response": {
                        "security_lists": [
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
                                "egressSecurityRules": [
                                    {"destination": "0.0.0.0/0", "protocol": "all"}
                                ],
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
                                        "tcpOptions": {
                                            "destinationPortRange": {"min": 443, "max": 443}
                                        },
                                    },
                                ],
                                "egressSecurityRules": [],
                            },
                        ]
                    },
                },
            )
        )

        # Vaults: one DEFAULT type, one VIRTUAL_PRIVATE pending deletion
        result.events.append(
            RawEventData(
                source="oci",
                source_type=SourceType.CLOUD,
                provider="oci",
                event_type="oci_vaults",
                raw_data={
                    "tenancy_id": "ocid1.tenancy.oc1..acme-tenancy-001",
                    "region": "us-ashburn-1",
                    "response": {
                        "vaults": [
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
                        ]
                    },
                },
            )
        )

        # Bastions: inventory
        result.events.append(
            RawEventData(
                source="oci",
                source_type=SourceType.CLOUD,
                provider="oci",
                event_type="oci_bastions",
                raw_data={
                    "tenancy_id": "ocid1.tenancy.oc1..acme-tenancy-001",
                    "region": "us-ashburn-1",
                    "response": {
                        "bastions": [
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
                        ]
                    },
                },
            )
        )

        result.complete()
        return result


class DemoCloudflareConnector(BaseConnector):
    """Simulates Cloudflare collection with realistic findings."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="cloudflare",
            source_type=SourceType.CLOUD,
            provider="cloudflare",
        )

        # WAF rules: one active block, one disabled
        result.events.append(
            RawEventData(
                source="cloudflare",
                source_type=SourceType.CLOUD,
                provider="cloudflare",
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
            )
        )

        # DNS records: one proxied, one unproxied A record, one external CNAME
        result.events.append(
            RawEventData(
                source="cloudflare",
                source_type=SourceType.CLOUD,
                provider="cloudflare",
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
            )
        )

        # Access apps: one with long session, one compliant
        result.events.append(
            RawEventData(
                source="cloudflare",
                source_type=SourceType.CLOUD,
                provider="cloudflare",
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
            )
        )

        # Gateway rules: some enabled, some disabled
        result.events.append(
            RawEventData(
                source="cloudflare",
                source_type=SourceType.CLOUD,
                provider="cloudflare",
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
            )
        )

        # SSL settings: flexible mode (insecure), TLS 1.0 min, no HTTPS enforcement
        result.events.append(
            RawEventData(
                source="cloudflare",
                source_type=SourceType.CLOUD,
                provider="cloudflare",
                event_type="cf_ssl_settings",
                raw_data={
                    "zone_id": "zone-acme-staging-001",
                    "ssl": {"value": "flexible"},
                    "min_tls_version": {"value": "1.0"},
                    "always_use_https": {"value": "off"},
                },
            )
        )

        # Page Shield: one clean script, one malicious
        result.events.append(
            RawEventData(
                source="cloudflare",
                source_type=SourceType.CLOUD,
                provider="cloudflare",
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
            )
        )

        # Audit logs: one sensitive action, one non-sensitive
        result.events.append(
            RawEventData(
                source="cloudflare",
                source_type=SourceType.CLOUD,
                provider="cloudflare",
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
            )
        )

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
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="defender",
            source_type=SourceType.EDR,
            provider="defender",
        )

        # Machines: mix of healthy, high-risk, and not-onboarded
        result.events.append(
            RawEventData(
                source="defender",
                source_type=SourceType.EDR,
                provider="defender",
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
            )
        )

        # Alerts: active threats across endpoints
        result.events.append(
            RawEventData(
                source="defender",
                source_type=SourceType.EDR,
                provider="defender",
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
            )
        )

        # Vulnerabilities: mix of severity
        result.events.append(
            RawEventData(
                source="defender",
                source_type=SourceType.EDR,
                provider="defender",
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
            )
        )

        # Recommendations: security hardening
        result.events.append(
            RawEventData(
                source="defender",
                source_type=SourceType.EDR,
                provider="defender",
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
            )
        )

        # --- Rich data: endpoints + alerts ---
        _def_endpoints = RICH_DATA["endpoints_edr"][50:100]
        result.events.append(
            RawEventData(
                source="defender",
                source_type=SourceType.EDR,
                provider="microsoft",
                event_type="defender_machines",
                raw_data={"value": _endpoints_as_defender(_def_endpoints)},
            )
        )
        _def_alerts = RICH_DATA["security_alerts"][0:120]
        result.events.append(
            RawEventData(
                source="defender",
                source_type=SourceType.EDR,
                provider="microsoft",
                event_type="defender_alerts",
                raw_data={
                    "value": [
                        {
                            "id": a["alert_id"],
                            "title": a["title"],
                            "severity": a["severity"].capitalize(),
                            "status": "Resolved" if a["status"] == "resolved" else "New",
                            "investigationState": "Running"
                            if a["status"] == "investigating"
                            else "Queued",
                            "createdDateTime": a["detected_at"],
                            "machineId": a["affected_host"],
                        }
                        for a in _def_alerts
                    ]
                },
            )
        )
        _def_vulns = RICH_DATA["vulnerabilities"][400:650]
        result.events.append(
            RawEventData(
                source="defender",
                source_type=SourceType.EDR,
                provider="microsoft",
                event_type="defender_vulnerabilities",
                raw_data={
                    "value": [
                        {
                            "id": v["cve_id"],
                            "name": v["title"],
                            "severity": v["severity"].capitalize(),
                            "cvssV3": v["cvss_score"],
                            "exposedMachines": random.randint(1, 20),
                            "publishedOn": v["first_seen"],
                        }
                        for v in _def_vulns
                    ]
                },
            )
        )

        result.complete()
        return result


class DemoSentinelOneConnector(BaseConnector):
    """Simulates SentinelOne EDR collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="sentinelone",
            source_type=SourceType.EDR,
            provider="sentinelone",
        )

        # Threats: malicious, suspicious, and mitigated
        result.events.append(
            RawEventData(
                source="sentinelone",
                source_type=SourceType.EDR,
                provider="sentinelone",
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
                                "engines": [
                                    "SentinelOne Cloud",
                                    "Behavioral AI",
                                    "On-Write Static AI",
                                ],
                            },
                        },
                    ],
                },
            )
        )

        # Agents: healthy, outdated, infected, disconnected
        result.events.append(
            RawEventData(
                source="sentinelone",
                source_type=SourceType.EDR,
                provider="sentinelone",
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
            )
        )

        # Applications: inventory with a high-risk app
        result.events.append(
            RawEventData(
                source="sentinelone",
                source_type=SourceType.EDR,
                provider="sentinelone",
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
            )
        )

        # Policies: one strong, one with weak settings
        result.events.append(
            RawEventData(
                source="sentinelone",
                source_type=SourceType.EDR,
                provider="sentinelone",
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
            )
        )

        # --- Rich data: endpoints ---
        _s1_agents = RICH_DATA["endpoints_edr"][100:150]
        result.events.append(
            RawEventData(
                source="sentinelone",
                source_type=SourceType.EDR,
                provider="sentinelone",
                event_type="s1_agents",
                raw_data={"data": _endpoints_as_sentinelone(_s1_agents)},
            )
        )

        result.complete()
        return result


class DemoIntuneConnector(BaseConnector):
    """Simulates Microsoft Intune MDM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="intune",
            source_type=SourceType.MDM,
            provider="intune",
        )

        # Devices: compliant, non-compliant, unencrypted, outdated OS
        result.events.append(
            RawEventData(
                source="intune",
                source_type=SourceType.MDM,
                provider="intune",
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
            )
        )

        # Compliance policies
        result.events.append(
            RawEventData(
                source="intune",
                source_type=SourceType.MDM,
                provider="intune",
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
            )
        )

        # Compliance states: per-device policy evaluation
        result.events.append(
            RawEventData(
                source="intune",
                source_type=SourceType.MDM,
                provider="intune",
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
            )
        )

        # --- Rich data: devices ---
        _intune_devices = RICH_DATA["devices"][0:100]
        result.events.append(
            RawEventData(
                source="intune",
                source_type=SourceType.MDM,
                provider="microsoft",
                event_type="intune_devices",
                raw_data={"value": _devices_as_intune(_intune_devices)},
            )
        )

        result.complete()
        return result


class DemoSentinelConnector(BaseConnector):
    """Simulates Microsoft Sentinel SIEM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="sentinel",
            source_type=SourceType.SIEM,
            provider="sentinel",
        )

        # Incidents: various severities and states
        result.events.append(
            RawEventData(
                source="sentinel",
                source_type=SourceType.SIEM,
                provider="sentinel",
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
                                "owner": {
                                    "assignedTo": "bob.martinez@acme.com",
                                    "email": "bob.martinez@acme.com",
                                },
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
                                "owner": {
                                    "assignedTo": "alice.chen@acme.com",
                                    "email": "alice.chen@acme.com",
                                },
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
            )
        )

        # Analytics rules: mix of enabled and disabled
        result.events.append(
            RawEventData(
                source="sentinel",
                source_type=SourceType.SIEM,
                provider="sentinel",
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
            )
        )

        # Hunting queries
        result.events.append(
            RawEventData(
                source="sentinel",
                source_type=SourceType.SIEM,
                provider="sentinel",
                event_type="sentinel_hunting_queries",
                raw_data={
                    "subscription_id": "acme-sub-001",
                    "response": [
                        {
                            "name": "hunt-001",
                            "properties": {"displayName": "Suspicious Process Creation Chains"},
                        },
                        {
                            "name": "hunt-002",
                            "properties": {"displayName": "Anomalous PowerShell Usage"},
                        },
                        {
                            "name": "hunt-003",
                            "properties": {"displayName": "Rare External Connections"},
                        },
                    ],
                },
            )
        )

        # Data connectors
        result.events.append(
            RawEventData(
                source="sentinel",
                source_type=SourceType.SIEM,
                provider="sentinel",
                event_type="sentinel_data_connectors",
                raw_data={
                    "subscription_id": "acme-sub-001",
                    "response": [
                        {
                            "name": "dc-001",
                            "id": "/subscriptions/acme-sub-001/providers/Microsoft.SecurityInsights/dataConnectors/dc-001",
                            "kind": "AzureActiveDirectory",
                            "properties": {
                                "connectorUiConfig": {"title": "Azure Active Directory"}
                            },
                        },
                        {
                            "name": "dc-002",
                            "id": "/subscriptions/acme-sub-001/providers/Microsoft.SecurityInsights/dataConnectors/dc-002",
                            "kind": "MicrosoftDefenderAdvancedThreatProtection",
                            "properties": {
                                "connectorUiConfig": {"title": "Microsoft Defender for Endpoint"}
                            },
                        },
                        {
                            "name": "dc-003",
                            "id": "/subscriptions/acme-sub-001/providers/Microsoft.SecurityInsights/dataConnectors/dc-003",
                            "kind": "Syslog",
                            "properties": {"connectorUiConfig": {"title": "Linux Syslog"}},
                        },
                    ],
                },
            )
        )

        # --- Rich data: security alerts as incidents ---
        _sen_alerts = RICH_DATA["security_alerts"][120:280]
        result.events.append(
            RawEventData(
                source="sentinel",
                source_type=SourceType.SIEM,
                provider="microsoft",
                event_type="sentinel_incidents",
                raw_data={"value": _alerts_as_sentinel(_sen_alerts)},
            )
        )

        result.complete()
        return result


class DemoSplunkConnector(BaseConnector):
    """Simulates Splunk Enterprise Security SIEM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="splunk",
            source_type=SourceType.SIEM,
            provider="splunk",
        )

        # Notable events: various urgencies
        result.events.append(
            RawEventData(
                source="splunk",
                source_type=SourceType.SIEM,
                provider="splunk",
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
            )
        )

        # Saved searches
        result.events.append(
            RawEventData(
                source="splunk",
                source_type=SourceType.SIEM,
                provider="splunk",
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
            )
        )

        # Correlation rules: enabled and disabled
        result.events.append(
            RawEventData(
                source="splunk",
                source_type=SourceType.SIEM,
                provider="splunk",
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
            )
        )

        # Index health
        result.events.append(
            RawEventData(
                source="splunk",
                source_type=SourceType.SIEM,
                provider="splunk",
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
            )
        )

        # --- Rich data: security alerts as notable events ---
        _splunk_alerts = RICH_DATA["security_alerts"][280:440]
        result.events.append(
            RawEventData(
                source="splunk",
                source_type=SourceType.SIEM,
                provider="splunk",
                event_type="splunk_notable_events",
                raw_data={"results": _alerts_as_splunk(_splunk_alerts)},
            )
        )

        result.complete()
        return result


class DemoElasticConnector(BaseConnector):
    """Simulates Elastic Security SIEM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="elastic",
            source_type=SourceType.SIEM,
            provider="elastic",
        )

        # Security alerts: nested _source.kibana.alert format
        result.events.append(
            RawEventData(
                source="elastic",
                source_type=SourceType.SIEM,
                provider="elastic",
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
                                            "rule": {
                                                "name": "Mimikatz Activity Detected",
                                                "id": "erule-001",
                                            },
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
                                            "rule": {
                                                "name": "Suspicious DLL Side-Loading",
                                                "id": "erule-002",
                                            },
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
                                            "rule": {
                                                "name": "Potentially Unwanted Program",
                                                "id": "erule-004",
                                            },
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
            )
        )

        # Detection rules: mix of enabled and disabled
        result.events.append(
            RawEventData(
                source="elastic",
                source_type=SourceType.SIEM,
                provider="elastic",
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
                                "threat": [
                                    {
                                        "framework": "MITRE ATT&CK",
                                        "tactic": {"name": "Credential Access"},
                                    }
                                ],
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
                                "threat": [
                                    {
                                        "framework": "MITRE ATT&CK",
                                        "tactic": {"name": "Defense Evasion"},
                                    }
                                ],
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
                                "threat": [
                                    {
                                        "framework": "MITRE ATT&CK",
                                        "tactic": {"name": "Defense Evasion"},
                                    }
                                ],
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
            )
        )

        # Agent status: some offline and in error
        result.events.append(
            RawEventData(
                source="elastic",
                source_type=SourceType.SIEM,
                provider="elastic",
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
            )
        )

        # --- Rich data: security alerts ---
        _elastic_alerts = RICH_DATA["security_alerts"][440:600]
        result.events.append(
            RawEventData(
                source="elastic",
                source_type=SourceType.SIEM,
                provider="elastic",
                event_type="elastic_security_alerts",
                raw_data={
                    "hits": {"hits": [{"_source": a} for a in _alerts_as_elastic(_elastic_alerts)]}
                },
            )
        )

        result.complete()
        return result


class DemoKubernetesConnector(BaseConnector):
    """Simulates Kubernetes cluster security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="kubernetes",
            source_type=SourceType.CLOUD,
            provider="kubernetes",
        )

        # Namespaces: including the risky default namespace
        result.events.append(
            RawEventData(
                source="kubernetes",
                source_type=SourceType.CLOUD,
                provider="kubernetes",
                event_type="k8s_namespaces",
                raw_data={
                    "api_url": "https://k8s.acme.internal:6443",
                    "response": [
                        {
                            "metadata": {
                                "name": "default",
                                "uid": "ns-uid-001",
                                "labels": {},
                                "annotations": {},
                            },
                            "status": {"phase": "Active"},
                        },
                        {
                            "metadata": {
                                "name": "acme-prod",
                                "uid": "ns-uid-002",
                                "labels": {"env": "production"},
                                "annotations": {},
                            },
                            "status": {"phase": "Active"},
                        },
                        {
                            "metadata": {
                                "name": "acme-staging",
                                "uid": "ns-uid-003",
                                "labels": {"env": "staging"},
                                "annotations": {},
                            },
                            "status": {"phase": "Active"},
                        },
                        {
                            "metadata": {
                                "name": "monitoring",
                                "uid": "ns-uid-004",
                                "labels": {"app": "prometheus"},
                                "annotations": {},
                            },
                            "status": {"phase": "Active"},
                        },
                        {
                            "metadata": {
                                "name": "kube-system",
                                "uid": "ns-uid-005",
                                "labels": {},
                                "annotations": {},
                            },
                            "status": {"phase": "Active"},
                        },
                    ],
                },
            )
        )

        # Network policies: some namespaces covered, triggers coverage check
        result.events.append(
            RawEventData(
                source="kubernetes",
                source_type=SourceType.CLOUD,
                provider="kubernetes",
                event_type="k8s_network_policies",
                raw_data={
                    "api_url": "https://k8s.acme.internal:6443",
                    "response": [
                        {
                            "metadata": {
                                "name": "deny-all-ingress",
                                "namespace": "acme-prod",
                                "uid": "np-uid-001",
                            },
                            "spec": {"podSelector": {}, "policyTypes": ["Ingress"]},
                        },
                        {
                            "metadata": {
                                "name": "allow-api-ingress",
                                "namespace": "acme-prod",
                                "uid": "np-uid-002",
                            },
                            "spec": {
                                "podSelector": {"matchLabels": {"app": "api"}},
                                "ingress": [
                                    {
                                        "from": [
                                            {
                                                "namespaceSelector": {
                                                    "matchLabels": {"env": "production"}
                                                }
                                            }
                                        ]
                                    }
                                ],
                                "policyTypes": ["Ingress"],
                            },
                        },
                        {
                            "metadata": {
                                "name": "deny-all-ingress",
                                "namespace": "monitoring",
                                "uid": "np-uid-003",
                            },
                            "spec": {"podSelector": {}, "policyTypes": ["Ingress"]},
                        },
                    ],
                },
            )
        )

        # RBAC bindings: normal, cluster-admin, and anonymous
        result.events.append(
            RawEventData(
                source="kubernetes",
                source_type=SourceType.CLOUD,
                provider="kubernetes",
                event_type="k8s_rbac_bindings",
                raw_data={
                    "api_url": "https://k8s.acme.internal:6443",
                    "response": [
                        {
                            "metadata": {"name": "acme-dev-binding", "uid": "rb-uid-001"},
                            "roleRef": {
                                "kind": "ClusterRole",
                                "name": "edit",
                                "apiGroup": "rbac.authorization.k8s.io",
                            },
                            "subjects": [
                                {
                                    "kind": "Group",
                                    "name": "acme-developers",
                                    "apiGroup": "rbac.authorization.k8s.io",
                                }
                            ],
                        },
                        {
                            "metadata": {"name": "acme-ops-admin", "uid": "rb-uid-002"},
                            "roleRef": {
                                "kind": "ClusterRole",
                                "name": "cluster-admin",
                                "apiGroup": "rbac.authorization.k8s.io",
                            },
                            "subjects": [
                                {
                                    "kind": "User",
                                    "name": "bob.martinez@acme.com",
                                    "apiGroup": "rbac.authorization.k8s.io",
                                }
                            ],
                        },
                        {
                            "metadata": {"name": "legacy-anonymous-read", "uid": "rb-uid-003"},
                            "roleRef": {
                                "kind": "ClusterRole",
                                "name": "view",
                                "apiGroup": "rbac.authorization.k8s.io",
                            },
                            "subjects": [
                                {
                                    "kind": "User",
                                    "name": "system:anonymous",
                                    "apiGroup": "rbac.authorization.k8s.io",
                                }
                            ],
                        },
                        {
                            "metadata": {"name": "monitoring-reader", "uid": "rb-uid-004"},
                            "roleRef": {
                                "kind": "Role",
                                "name": "monitoring-read",
                                "apiGroup": "rbac.authorization.k8s.io",
                            },
                            "subjects": [
                                {
                                    "kind": "ServiceAccount",
                                    "name": "prometheus",
                                    "namespace": "monitoring",
                                }
                            ],
                        },
                    ],
                },
            )
        )

        # Admission controls: one webhook configured
        result.events.append(
            RawEventData(
                source="kubernetes",
                source_type=SourceType.CLOUD,
                provider="kubernetes",
                event_type="k8s_admission_controls",
                raw_data={
                    "api_url": "https://k8s.acme.internal:6443",
                    "response": [
                        {
                            "metadata": {
                                "name": "gatekeeper-validating-webhook",
                                "uid": "wh-uid-001",
                            },
                            "webhooks": [
                                {"name": "validation.gatekeeper.sh"},
                                {"name": "check-ignore-label.gatekeeper.sh"},
                            ],
                        },
                    ],
                },
            )
        )

        # Running pods: compliant, privileged, root, no limits
        result.events.append(
            RawEventData(
                source="kubernetes",
                source_type=SourceType.CLOUD,
                provider="kubernetes",
                event_type="k8s_running_pods",
                raw_data={
                    "api_url": "https://k8s.acme.internal:6443",
                    "response": [
                        {
                            "metadata": {
                                "name": "api-server-7b8c9d-xk2lp",
                                "namespace": "acme-prod",
                                "uid": "pod-uid-001",
                            },
                            "spec": {
                                "nodeName": "node-prod-01",
                                "serviceAccountName": "api-sa",
                                "hostNetwork": False,
                                "hostPID": False,
                                "containers": [
                                    {
                                        "name": "api",
                                        "securityContext": {
                                            "runAsNonRoot": True,
                                            "runAsUser": 1000,
                                            "privileged": False,
                                        },
                                        "resources": {"limits": {"cpu": "500m", "memory": "512Mi"}},
                                    },
                                ],
                            },
                        },
                        {
                            "metadata": {
                                "name": "worker-processor-5f6a7b-mn3op",
                                "namespace": "acme-prod",
                                "uid": "pod-uid-002",
                            },
                            "spec": {
                                "nodeName": "node-prod-02",
                                "serviceAccountName": "worker-sa",
                                "hostNetwork": False,
                                "hostPID": False,
                                "containers": [
                                    {
                                        "name": "worker",
                                        "securityContext": {
                                            "runAsNonRoot": True,
                                            "runAsUser": 1000,
                                        },
                                        "resources": {},
                                    },
                                ],
                            },
                        },
                        {
                            "metadata": {
                                "name": "debug-pod-legacy",
                                "namespace": "acme-staging",
                                "uid": "pod-uid-003",
                            },
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
                            "metadata": {
                                "name": "prometheus-0",
                                "namespace": "monitoring",
                                "uid": "pod-uid-004",
                            },
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
            )
        )

        # Deployments: various replica counts, including single-replica in non-system ns
        result.events.append(
            RawEventData(
                source="kubernetes",
                source_type=SourceType.CLOUD,
                provider="kubernetes",
                event_type="k8s_deployments",
                raw_data={
                    "api_url": "https://k8s.acme.internal:6443",
                    "response": [
                        {
                            "metadata": {
                                "name": "api-server",
                                "namespace": "acme-prod",
                                "uid": "deploy-uid-001",
                            },
                            "spec": {"replicas": 3, "strategy": {"type": "RollingUpdate"}},
                            "status": {"readyReplicas": 3, "availableReplicas": 3},
                        },
                        {
                            "metadata": {
                                "name": "worker-processor",
                                "namespace": "acme-prod",
                                "uid": "deploy-uid-002",
                            },
                            "spec": {"replicas": 2, "strategy": {"type": "RollingUpdate"}},
                            "status": {"readyReplicas": 2, "availableReplicas": 2},
                        },
                        {
                            "metadata": {
                                "name": "staging-app",
                                "namespace": "acme-staging",
                                "uid": "deploy-uid-003",
                            },
                            "spec": {"replicas": 1, "strategy": {"type": "Recreate"}},
                            "status": {"readyReplicas": 1, "availableReplicas": 1},
                        },
                        {
                            "metadata": {
                                "name": "redis-cache",
                                "namespace": "acme-prod",
                                "uid": "deploy-uid-004",
                            },
                            "spec": {"replicas": 1, "strategy": {"type": "RollingUpdate"}},
                            "status": {"readyReplicas": 1, "availableReplicas": 1},
                        },
                        {
                            "metadata": {
                                "name": "coredns",
                                "namespace": "kube-system",
                                "uid": "deploy-uid-005",
                            },
                            "spec": {"replicas": 1, "strategy": {"type": "RollingUpdate"}},
                            "status": {"readyReplicas": 1, "availableReplicas": 1},
                        },
                    ],
                },
            )
        )

        # --- Rich data: container images ---
        _k8s_images = RICH_DATA["container_images"][75:150]
        result.events.append(
            RawEventData(
                source="kubernetes",
                source_type=SourceType.CLOUD,
                provider="kubernetes",
                event_type="k8s_running_pods",
                raw_data={
                    "items": [
                        {
                            "metadata": {
                                "name": f"pod-{img['repository'].split('/')[-1]}-{i}",
                                "namespace": random.choice(
                                    ["default", "production", "staging", "monitoring"]
                                ),
                                "labels": {"app": img["repository"].split("/")[-1]},
                            },
                            "spec": {
                                "containers": [
                                    {
                                        "name": img["repository"].split("/")[-1],
                                        "image": f"{img['repository']}:{img['tag']}",
                                        "securityContext": {
                                            "runAsNonRoot": random.random() > 0.15,
                                            "readOnlyRootFilesystem": random.random() > 0.3,
                                        },
                                    }
                                ]
                            },
                            "status": {"phase": "Running"},
                        }
                        for i, img in enumerate(_k8s_images)
                    ],
                },
            )
        )

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
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="tenable",
            source_type=SourceType.SCANNER,
            provider="tenable",
        )

        # vuln_export — critical and medium vulns
        result.events.append(
            RawEventData(
                source="tenable",
                source_type=SourceType.SCANNER,
                provider="tenable",
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
            )
        )

        # compliance_audits — one pass, one fail, one warning
        result.events.append(
            RawEventData(
                source="tenable",
                source_type=SourceType.SCANNER,
                provider="tenable",
                event_type="compliance_audits",
                raw_data={
                    "audits": [
                        {
                            "check_name": "Ensure SSH root login is disabled",
                            "status": "PASSED",
                            "asset": {
                                "uuid": "a1b2c3d4-e5f6-7890-abcd-ef0123456789",
                                "hostname": "acme-web-prod-01",
                            },
                            "reference": "CIS_Linux_Benchmark_v2.0.0:5.2.10",
                            "benchmark": "CIS Ubuntu Linux 22.04 LTS Benchmark",
                            "audit_file": "CIS_Ubuntu_22.04_v2.0.0_L1.audit",
                        },
                        {
                            "check_name": "Ensure password expiration is 365 days or less",
                            "status": "FAILED",
                            "asset": {
                                "uuid": "b2c3d4e5-f6a7-8901-bcde-f01234567890",
                                "hostname": "acme-api-staging-01",
                            },
                            "reference": "CIS_Linux_Benchmark_v2.0.0:5.5.1.1",
                            "solution": "Set PASS_MAX_DAYS to 365 in /etc/login.defs",
                            "benchmark": "CIS Ubuntu Linux 22.04 LTS Benchmark",
                            "audit_file": "CIS_Ubuntu_22.04_v2.0.0_L1.audit",
                        },
                        {
                            "check_name": "Ensure journald is configured to send logs to rsyslog",
                            "status": "WARNING",
                            "asset": {
                                "uuid": "a1b2c3d4-e5f6-7890-abcd-ef0123456789",
                                "hostname": "acme-web-prod-01",
                            },
                            "reference": "CIS_Linux_Benchmark_v2.0.0:4.2.2.1",
                            "benchmark": "CIS Ubuntu Linux 22.04 LTS Benchmark",
                        },
                    ],
                },
            )
        )

        # asset_export
        result.events.append(
            RawEventData(
                source="tenable",
                source_type=SourceType.SCANNER,
                provider="tenable",
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
                            "sources": [
                                {
                                    "name": "NESSUS_AGENT",
                                    "first_seen": (NOW - timedelta(days=90)).isoformat(),
                                }
                            ],
                        },
                    ],
                },
            )
        )

        # agent_status — one online, one offline
        result.events.append(
            RawEventData(
                source="tenable",
                source_type=SourceType.SCANNER,
                provider="tenable",
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
            )
        )

        # --- Rich data: vulnerabilities ---
        _ten_vulns = RICH_DATA["vulnerabilities"][650:1100]
        result.events.append(
            RawEventData(
                source="tenable",
                source_type=SourceType.SCANNER,
                provider="tenable",
                event_type="vuln_export",
                raw_data={"vulnerabilities": _vulns_as_tenable(_ten_vulns)},
            )
        )

        result.complete()
        return result


class DemoQualysConnector(BaseConnector):
    """Simulates Qualys VMDR collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="qualys",
            source_type=SourceType.SCANNER,
            provider="qualys",
        )

        # host_detections
        result.events.append(
            RawEventData(
                source="qualys",
                source_type=SourceType.SCANNER,
                provider="qualys",
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
                                                    "FIRST_FOUND_DATETIME": (
                                                        NOW - timedelta(days=60)
                                                    ).isoformat(),
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
                                                    "FIRST_FOUND_DATETIME": (
                                                        NOW - timedelta(days=90)
                                                    ).isoformat(),
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
            )
        )

        # compliance_posture
        result.events.append(
            RawEventData(
                source="qualys",
                source_type=SourceType.SCANNER,
                provider="qualys",
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
            )
        )

        # asset_inventory
        result.events.append(
            RawEventData(
                source="qualys",
                source_type=SourceType.SCANNER,
                provider="qualys",
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
            )
        )

        # knowledge_base
        result.events.append(
            RawEventData(
                source="qualys",
                source_type=SourceType.SCANNER,
                provider="qualys",
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
            )
        )

        # --- Rich data: vulnerabilities ---
        _qual_vulns = RICH_DATA["vulnerabilities"][1100:1500]
        result.events.append(
            RawEventData(
                source="qualys",
                source_type=SourceType.SCANNER,
                provider="qualys",
                event_type="host_detections",
                raw_data={
                    "HOST_LIST_VM_DETECTION_OUTPUT": {
                        "RESPONSE": {"HOST_LIST": {"HOST": _vulns_as_qualys(_qual_vulns)}}
                    }
                },
            )
        )

        result.complete()
        return result


class DemoWizConnector(BaseConnector):
    """Simulates Wiz cloud security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="wiz",
            source_type=SourceType.SCANNER,
            provider="wiz",
        )

        # wiz_issues — toxic combo, config issue, vuln issue
        result.events.append(
            RawEventData(
                source="wiz",
                source_type=SourceType.SCANNER,
                provider="wiz",
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
                            "sourceRule": {
                                "id": "wiz-rule-tc-001",
                                "name": "Public VM with Critical CVEs",
                            },
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
                            "sourceRule": {
                                "id": "wiz-rule-vuln-001",
                                "name": "Critical CVE Detected",
                            },
                            "projects": [{"name": "Acme Platform"}],
                            "createdAt": (NOW - timedelta(days=20)).isoformat(),
                        },
                    ],
                },
            )
        )

        # wiz_config_findings
        result.events.append(
            RawEventData(
                source="wiz",
                source_type=SourceType.SCANNER,
                provider="wiz",
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
            )
        )

        # wiz_vuln_findings
        result.events.append(
            RawEventData(
                source="wiz",
                source_type=SourceType.SCANNER,
                provider="wiz",
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
            )
        )

        # wiz_graph
        result.events.append(
            RawEventData(
                source="wiz",
                source_type=SourceType.SCANNER,
                provider="wiz",
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
            )
        )

        # --- Rich data: vulnerabilities as issues ---
        _wiz_vulns = RICH_DATA["vulnerabilities"][1500:1900]
        result.events.append(
            RawEventData(
                source="wiz",
                source_type=SourceType.SCANNER,
                provider="wiz",
                event_type="wiz_issues",
                raw_data={"issues": _vulns_as_wiz(_wiz_vulns)},
            )
        )

        result.complete()
        return result


class DemoPrismaConnector(BaseConnector):
    """Simulates Prisma Cloud CSPM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="prisma",
            source_type=SourceType.CSPM,
            provider="prisma",
        )

        # prisma_alerts — CONFIG and IAM policy types
        result.events.append(
            RawEventData(
                source="prisma",
                source_type=SourceType.CSPM,
                provider="prisma",
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
                                "complianceMetadata": [
                                    {"standardName": "CIS AWS", "requirementId": "2.1.5"}
                                ],
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
            )
        )

        # prisma_compliance — complianceSummaries path
        result.events.append(
            RawEventData(
                source="prisma",
                source_type=SourceType.CSPM,
                provider="prisma",
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
            )
        )

        # prisma_assets — groupedAggregates path
        result.events.append(
            RawEventData(
                source="prisma",
                source_type=SourceType.CSPM,
                provider="prisma",
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
            )
        )

        # prisma_policies
        result.events.append(
            RawEventData(
                source="prisma",
                source_type=SourceType.CSPM,
                provider="prisma",
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
            )
        )

        # --- Rich data: cloud instances as assets ---
        _prisma_assets = RICH_DATA["cloud_instances"][0:50]
        result.events.append(
            RawEventData(
                source="prisma",
                source_type=SourceType.CSPM,
                provider="prisma",
                event_type="prisma_assets",
                raw_data={
                    "data": [
                        {
                            "id": a["instance_id"],
                            "name": a["name"],
                            "cloudType": a["cloud"],
                            "regionId": a["region"],
                            "resourceType": "Instance",
                            "accountId": "acme-account",
                        }
                        for a in _prisma_assets
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoServiceNowConnector(BaseConnector):
    """Simulates ServiceNow ITSM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="servicenow",
            source_type=SourceType.ITSM,
            provider="servicenow",
        )

        # snow_change_requests — approved with backout, unapproved, missing backout
        result.events.append(
            RawEventData(
                source="servicenow",
                source_type=SourceType.ITSM,
                provider="servicenow",
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
            )
        )

        # snow_incidents — resolved, open past SLA, open within SLA
        result.events.append(
            RawEventData(
                source="servicenow",
                source_type=SourceType.ITSM,
                provider="servicenow",
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
            )
        )

        # snow_problems — open with root cause, open without root cause
        result.events.append(
            RawEventData(
                source="servicenow",
                source_type=SourceType.ITSM,
                provider="servicenow",
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
            )
        )

        # snow_knowledge_articles — recent and stale
        result.events.append(
            RawEventData(
                source="servicenow",
                source_type=SourceType.ITSM,
                provider="servicenow",
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
            )
        )

        # snow_risks — compliant and non-compliant
        result.events.append(
            RawEventData(
                source="servicenow",
                source_type=SourceType.ITSM,
                provider="servicenow",
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
            )
        )

        # snow_policies — current review and expired review
        result.events.append(
            RawEventData(
                source="servicenow",
                source_type=SourceType.ITSM,
                provider="servicenow",
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
            )
        )

        # --- Rich data: policy documents as ServiceNow records ---
        _snow_policies = RICH_DATA["policy_documents"][20:40]
        result.events.append(
            RawEventData(
                source="servicenow",
                source_type=SourceType.ITSM,
                provider="servicenow",
                event_type="snow_policies",
                raw_data={"result": _policies_as_servicenow(_snow_policies)},
            )
        )

        result.complete()
        return result


class DemoOneTrustConnector(BaseConnector):
    """Simulates OneTrust GRC collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="onetrust",
            source_type=SourceType.GRC,
            provider="onetrust",
        )

        # onetrust_assessments — completed assessment + incomplete PIA
        result.events.append(
            RawEventData(
                source="onetrust",
                source_type=SourceType.GRC,
                provider="onetrust",
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
            )
        )

        # onetrust_data_maps
        result.events.append(
            RawEventData(
                source="onetrust",
                source_type=SourceType.GRC,
                provider="onetrust",
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
            )
        )

        # onetrust_dsar_requests — one completed, one overdue
        result.events.append(
            RawEventData(
                source="onetrust",
                source_type=SourceType.GRC,
                provider="onetrust",
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
            )
        )

        # onetrust_consent_records
        result.events.append(
            RawEventData(
                source="onetrust",
                source_type=SourceType.GRC,
                provider="onetrust",
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
            )
        )

        # --- Rich data: policy documents as assessments ---
        _ot_policies = RICH_DATA["policy_documents"][0:20]
        result.events.append(
            RawEventData(
                source="onetrust",
                source_type=SourceType.GRC,
                provider="onetrust",
                event_type="onetrust_assessments",
                raw_data={"data": _policies_as_onetrust(_ot_policies)},
            )
        )

        result.complete()
        return result


class DemoMLflowConnector(BaseConnector):
    """Simulates MLflow model registry collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="mlflow",
            source_type=SourceType.CUSTOM,
            provider="mlflow",
        )

        # mlflow_registered_models — one with description, one without
        result.events.append(
            RawEventData(
                source="mlflow",
                source_type=SourceType.CUSTOM,
                provider="mlflow",
                event_type="mlflow_registered_models",
                raw_data={
                    "response": [
                        {
                            "name": "acme-fraud-detection",
                            "description": "XGBoost model for real-time payment fraud detection. Trained on 2024 Q4 data.",
                            "creation_timestamp": (NOW - timedelta(days=120)).isoformat(),
                            "last_updated_timestamp": (NOW - timedelta(days=5)).isoformat(),
                            "tags": [
                                {"key": "team", "value": "fraud-ops"},
                                {"key": "pii", "value": "true"},
                            ],
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
            )
        )

        # mlflow_experiments
        result.events.append(
            RawEventData(
                source="mlflow",
                source_type=SourceType.CUSTOM,
                provider="mlflow",
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
            )
        )

        # mlflow_model_versions — production with desc, production without desc
        result.events.append(
            RawEventData(
                source="mlflow",
                source_type=SourceType.CUSTOM,
                provider="mlflow",
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
            )
        )

        result.complete()
        return result


class DemoSnykConnector(BaseConnector):
    """Simulates Snyk code security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="snyk",
            source_type=SourceType.CODE,
            provider="snyk",
        )

        # snyk_projects — recently tested and stale
        result.events.append(
            RawEventData(
                source="snyk",
                source_type=SourceType.CODE,
                provider="snyk",
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
            )
        )

        # snyk_issues — critical with fix, high without fix
        result.events.append(
            RawEventData(
                source="snyk",
                source_type=SourceType.CODE,
                provider="snyk",
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
            )
        )

        # snyk_audit_logs — alert and non-alert events
        result.events.append(
            RawEventData(
                source="snyk",
                source_type=SourceType.CODE,
                provider="snyk",
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
            )
        )

        # --- Rich data: code findings ---
        _snyk_findings = RICH_DATA["code_findings"][0:120]
        result.events.append(
            RawEventData(
                source="snyk",
                source_type=SourceType.CODE,
                provider="snyk",
                event_type="snyk_issues",
                raw_data={
                    "org_id": "acme-org-001",
                    "response": _code_findings_as_snyk(_snyk_findings),
                },
            )
        )

        result.complete()
        return result


class DemoGitHubConnector(BaseConnector):
    """Simulates GitHub code security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="github",
            source_type=SourceType.CODE,
            provider="github",
        )

        # github_repos — private and public
        result.events.append(
            RawEventData(
                source="github",
                source_type=SourceType.CODE,
                provider="github",
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
            )
        )

        # github_branch_protections — protected, unprotected, missing reviews
        result.events.append(
            RawEventData(
                source="github",
                source_type=SourceType.CODE,
                provider="github",
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
            )
        )

        # github_audit_log — sensitive and normal actions
        result.events.append(
            RawEventData(
                source="github",
                source_type=SourceType.CODE,
                provider="github",
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
            )
        )

        # github_dependabot_alerts
        result.events.append(
            RawEventData(
                source="github",
                source_type=SourceType.CODE,
                provider="github",
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
            )
        )

        # github_secret_scanning_alerts
        result.events.append(
            RawEventData(
                source="github",
                source_type=SourceType.CODE,
                provider="github",
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
            )
        )

        # --- Rich data: code findings as dependabot alerts ---
        _gh_findings = RICH_DATA["code_findings"][120:240]
        result.events.append(
            RawEventData(
                source="github",
                source_type=SourceType.CODE,
                provider="github",
                event_type="github_dependabot_alerts",
                raw_data={
                    "org": "acmecorp",
                    "response": _code_findings_as_github_dependabot(_gh_findings),
                },
            )
        )

        result.complete()
        return result


class DemoProofpointConnector(BaseConnector):
    """Simulates Proofpoint TAP collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="proofpoint",
            source_type=SourceType.EMAIL,
            provider="proofpoint",
        )

        # proofpoint_blocked_messages
        result.events.append(
            RawEventData(
                source="proofpoint",
                source_type=SourceType.EMAIL,
                provider="proofpoint",
                event_type="proofpoint_blocked_messages",
                raw_data={
                    "response": [
                        {"subject": "Urgent: Verify your account credentials immediately"},
                        {"subject": "Invoice #INV-29831 - Payment Required"},
                        {"subject": "Re: Q4 Financial Report - Action Needed"},
                    ],
                },
            )
        )

        # proofpoint_delivered_threats — high score and low score
        result.events.append(
            RawEventData(
                source="proofpoint",
                source_type=SourceType.EMAIL,
                provider="proofpoint",
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
            )
        )

        # proofpoint_clicks_blocked
        result.events.append(
            RawEventData(
                source="proofpoint",
                source_type=SourceType.EMAIL,
                provider="proofpoint",
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
            )
        )

        # --- Rich data: email events ---
        _pp_data = _email_as_proofpoint(RICH_DATA["email_events"][0:100])
        result.events.append(
            RawEventData(
                source="proofpoint",
                source_type=SourceType.EMAIL,
                provider="proofpoint",
                event_type="proofpoint_blocked_messages",
                raw_data={"response": _pp_data["blocked"][:50]},
            )
        )
        result.events.append(
            RawEventData(
                source="proofpoint",
                source_type=SourceType.EMAIL,
                provider="proofpoint",
                event_type="proofpoint_delivered_threats",
                raw_data={"response": _pp_data["delivered_threats"][:30]},
            )
        )

        result.complete()
        return result


class DemoPurviewConnector(BaseConnector):
    """Simulates Microsoft Purview DLP collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="purview",
            source_type=SourceType.DLP,
            provider="purview",
        )

        # purview_dlp_alerts — high and low severity
        result.events.append(
            RawEventData(
                source="purview",
                source_type=SourceType.DLP,
                provider="purview",
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
            )
        )

        # purview_sensitivity_labels
        result.events.append(
            RawEventData(
                source="purview",
                source_type=SourceType.DLP,
                provider="purview",
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
            )
        )

        # purview_dlp_policies — enabled and disabled
        result.events.append(
            RawEventData(
                source="purview",
                source_type=SourceType.DLP,
                provider="purview",
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
            )
        )

        # --- Rich data: DNS queries as DLP alerts ---
        _pv_alerts = _dns_as_purview(RICH_DATA["dns_queries"][0:80])
        result.events.append(
            RawEventData(
                source="purview",
                source_type=SourceType.DLP,
                provider="purview",
                event_type="purview_dlp_alerts",
                raw_data={"value": _pv_alerts},
            )
        )

        result.complete()
        return result


class DemoVeeamConnector(BaseConnector):
    """Simulates Veeam backup infrastructure collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="veeam",
            source_type=SourceType.BACKUP,
            provider="veeam",
        )

        # veeam_backup_jobs — enabled and disabled
        result.events.append(
            RawEventData(
                source="veeam",
                source_type=SourceType.BACKUP,
                provider="veeam",
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
            )
        )

        # veeam_backup_sessions — success, failure, and old success for RPO
        result.events.append(
            RawEventData(
                source="veeam",
                source_type=SourceType.BACKUP,
                provider="veeam",
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
            )
        )

        # veeam_restore_points — one recent, one old (triggers no-recent finding)
        result.events.append(
            RawEventData(
                source="veeam",
                source_type=SourceType.BACKUP,
                provider="veeam",
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
            )
        )

        # --- Rich data: security alerts as backup alerts ---
        _veeam_alerts = RICH_DATA["security_alerts"][900:950]
        result.events.append(
            RawEventData(
                source="veeam",
                source_type=SourceType.BACKUP,
                provider="veeam",
                event_type="veeam_sessions",
                raw_data={
                    "data": [
                        {
                            "id": a["alert_id"],
                            "name": f"Backup-{a['alert_id'][-6:]}",
                            "result": "Warning"
                            if a["severity"] in ("high", "critical")
                            else "Success",
                            "creationTime": a["detected_at"],
                            "endTime": a.get("resolved_at", a["detected_at"]),
                        }
                        for a in _veeam_alerts
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoVerkadaConnector(BaseConnector):
    """Simulates Verkada physical security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="verkada",
            source_type=SourceType.PHYSICAL,
            provider="verkada",
        )

        # verkada_access_events — during hours and after hours (3 AM)
        result.events.append(
            RawEventData(
                source="verkada",
                source_type=SourceType.PHYSICAL,
                provider="verkada",
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
            )
        )

        # verkada_doors — locked and unlocked
        result.events.append(
            RawEventData(
                source="verkada",
                source_type=SourceType.PHYSICAL,
                provider="verkada",
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
            )
        )

        # verkada_users
        result.events.append(
            RawEventData(
                source="verkada",
                source_type=SourceType.PHYSICAL,
                provider="verkada",
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
            )
        )

        result.complete()
        return result


class DemoPaloAltoConnector(BaseConnector):
    """Simulates Palo Alto Networks PAN-OS collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="palo_alto",
            source_type=SourceType.NETWORK,
            provider="palo_alto",
        )
        result.events.append(
            RawEventData(
                source="palo_alto",
                source_type=SourceType.NETWORK,
                provider="palo_alto",
                event_type="pan_security_rules",
                raw_data={
                    "rules": [
                        {
                            "name": "Allow-DNS",
                            "action": "allow",
                            "from": ["trust"],
                            "to": ["untrust"],
                            "source": ["any"],
                            "destination": ["any"],
                            "application": ["dns"],
                            "disabled": False,
                        },
                        {
                            "name": "Block-Crypto",
                            "action": "deny",
                            "from": ["any"],
                            "to": ["any"],
                            "source": ["any"],
                            "destination": ["any"],
                            "application": ["crypto-mining"],
                            "disabled": False,
                        },
                        {
                            "name": "Legacy-Permit-All",
                            "action": "allow",
                            "from": ["any"],
                            "to": ["any"],
                            "source": ["any"],
                            "destination": ["any"],
                            "application": ["any"],
                            "disabled": True,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="palo_alto",
                source_type=SourceType.NETWORK,
                provider="palo_alto",
                event_type="pan_threat_logs",
                raw_data={
                    "logs": [
                        {
                            "threat_id": "pan-t-001",
                            "type": "vulnerability",
                            "severity": "critical",
                            "src_ip": "10.0.1.50",
                            "dst_ip": "203.0.113.5",
                            "action": "alert",
                            "threat_name": "Apache Log4j RCE",
                            "category": "code-execution",
                        },
                    ]
                },
            )
        )

        # --- Rich data: DNS queries as threat logs ---
        _pa_dns = RICH_DATA["dns_queries"][80:160]
        result.events.append(
            RawEventData(
                source="palo_alto",
                source_type=SourceType.NETWORK,
                provider="palo_alto",
                event_type="pan_threat_logs",
                raw_data={
                    "logs": [
                        {
                            "threat_id": q["query_id"],
                            "type": q.get("threat_type", "url"),
                            "severity": "critical"
                            if q.get("threat_type") == "malware"
                            else "medium",
                            "src_ip": q["source_ip"],
                            "dst_ip": f"203.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
                            "action": "alert" if q["action"] == "allow" else "block",
                            "threat_name": q["domain"],
                            "category": q.get("threat_type", "unknown"),
                        }
                        for q in _pa_dns
                        if q["action"] == "block" or q.get("threat_type")
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoFortinetConnector(BaseConnector):
    """Simulates Fortinet FortiGate collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="fortinet",
            source_type=SourceType.NETWORK,
            provider="fortinet",
        )
        result.events.append(
            RawEventData(
                source="fortinet",
                source_type=SourceType.NETWORK,
                provider="fortinet",
                event_type="forti_firewall_policies",
                raw_data={
                    "results": [
                        {
                            "policyid": 1,
                            "name": "Web-Access",
                            "srcintf": [{"name": "internal"}],
                            "dstintf": [{"name": "wan1"}],
                            "srcaddr": [{"name": "all"}],
                            "dstaddr": [{"name": "all"}],
                            "action": "accept",
                            "status": "enable",
                            "logtraffic": "all",
                        },
                        {
                            "policyid": 2,
                            "name": "Disabled-Legacy",
                            "srcintf": [{"name": "internal"}],
                            "dstintf": [{"name": "wan1"}],
                            "srcaddr": [{"name": "all"}],
                            "dstaddr": [{"name": "all"}],
                            "action": "accept",
                            "status": "disable",
                            "logtraffic": "disable",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="fortinet",
                source_type=SourceType.NETWORK,
                provider="fortinet",
                event_type="forti_vpn_tunnels",
                raw_data={
                    "results": [
                        {
                            "name": "HQ-to-Branch",
                            "status": "up",
                            "incoming_bytes": 1024000,
                            "outgoing_bytes": 512000,
                            "cert_expiry": "2026-12-31",
                        },
                        {
                            "name": "Remote-Workers",
                            "status": "down",
                            "incoming_bytes": 0,
                            "outgoing_bytes": 0,
                            "cert_expiry": "2025-01-15",
                        },
                    ]
                },
            )
        )

        # --- Rich data: DNS queries as IPS logs ---
        _fort_dns = RICH_DATA["dns_queries"][160:240]
        result.events.append(
            RawEventData(
                source="fortinet",
                source_type=SourceType.NETWORK,
                provider="fortinet",
                event_type="forti_ips_logs",
                raw_data={
                    "results": [
                        {
                            "logid": q["query_id"],
                            "srcip": q["source_ip"],
                            "dstip": f"203.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
                            "action": q["action"],
                            "threat_name": q["domain"],
                            "severity": "critical" if q.get("threat_type") else "medium",
                        }
                        for q in _fort_dns
                        if q.get("threat_type")
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoZscalerConnector(BaseConnector):
    """Simulates Zscaler ZIA collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="zscaler",
            source_type=SourceType.NETWORK,
            provider="zscaler",
        )
        result.events.append(
            RawEventData(
                source="zscaler",
                source_type=SourceType.NETWORK,
                provider="zscaler",
                event_type="zscaler_web_policies",
                raw_data={
                    "policies": [
                        {
                            "id": 1,
                            "name": "Default Web Policy",
                            "state": "ENABLED",
                            "action": "ALLOW",
                            "protocols": ["SSL_RULE"],
                            "order": 1,
                        },
                        {
                            "id": 2,
                            "name": "Block-Malware-Sites",
                            "state": "ENABLED",
                            "action": "BLOCK",
                            "protocols": ["SSL_RULE"],
                            "order": 2,
                        },
                        {
                            "id": 3,
                            "name": "Legacy-Allow-All",
                            "state": "DISABLED",
                            "action": "ALLOW",
                            "protocols": ["ANY_RULE"],
                            "order": 99,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="zscaler",
                source_type=SourceType.NETWORK,
                provider="zscaler",
                event_type="zscaler_sandbox",
                raw_data={
                    "submissions": [
                        {
                            "md5": "abc123def456",
                            "verdict": "MALICIOUS",
                            "file_name": "invoice.exe",
                            "file_type": "PE",
                            "score": 95,
                            "category": "Trojan",
                        },
                    ]
                },
            )
        )

        # --- Rich data: DNS queries as web transactions ---
        _zs_dns = RICH_DATA["dns_queries"][240:320]
        result.events.append(
            RawEventData(
                source="zscaler",
                source_type=SourceType.NETWORK,
                provider="zscaler",
                event_type="zscaler_web_transactions",
                raw_data={"transactions": _dns_as_zscaler(_zs_dns)},
            )
        )

        result.complete()
        return result


class DemoJamfConnector(BaseConnector):
    """Simulates Jamf Pro MDM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="jamf",
            source_type=SourceType.MDM,
            provider="jamf",
        )
        result.events.append(
            RawEventData(
                source="jamf",
                source_type=SourceType.MDM,
                provider="jamf",
                event_type="jamf_devices",
                raw_data={
                    "devices": [
                        {
                            "id": 1001,
                            "general": {
                                "name": "ENG-MBP-001",
                                "serialNumber": "C02Z1234HKLM",
                                "managementStatus": {"enrolled": True},
                                "lastContactTime": NOW.isoformat(),
                            },
                            "hardware": {"serialNumber": "C02Z1234HKLM", "osVersion": "14.3"},
                            "operatingSystem": {"version": "14.3"},
                            "security": {"fileVault2Status": "ALL_ENCRYPTED"},
                        },
                        {
                            "id": 1002,
                            "general": {
                                "name": "SALES-MBP-042",
                                "serialNumber": "C02Y9876WXYZ",
                                "managementStatus": {"enrolled": True},
                                "lastContactTime": NOW.isoformat(),
                            },
                            "hardware": {"serialNumber": "C02Y9876WXYZ", "osVersion": "12.7.1"},
                            "operatingSystem": {"version": "12.7.1"},
                            "security": {"fileVault2Status": "NOT_ENCRYPTED"},
                        },
                        {
                            "id": 1003,
                            "general": {
                                "name": "EXEC-MBP-007",
                                "serialNumber": "C02X5555ABCD",
                                "managementStatus": {"enrolled": True},
                                "lastContactTime": (NOW - timedelta(days=14)).isoformat(),
                            },
                            "hardware": {"serialNumber": "C02X5555ABCD", "osVersion": "14.2"},
                            "operatingSystem": {"version": "14.2"},
                            "security": {"fileVault2Status": "ALL_ENCRYPTED"},
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="jamf",
                source_type=SourceType.MDM,
                provider="jamf",
                event_type="jamf_policies",
                raw_data={
                    "policies": [
                        {
                            "id": 501,
                            "name": "FileVault Enforcement",
                            "enabled": True,
                            "scope": {"all_computers": True},
                            "category": "Security",
                        },
                        {
                            "id": 502,
                            "name": "OS Update Nudge",
                            "enabled": True,
                            "scope": {"all_computers": True},
                            "category": "Maintenance",
                        },
                    ]
                },
            )
        )

        # --- Rich data: devices ---
        _jamf_devices = RICH_DATA["devices"][100:200]
        result.events.append(
            RawEventData(
                source="jamf",
                source_type=SourceType.MDM,
                provider="jamf",
                event_type="jamf_computers",
                raw_data={"computers": _devices_as_jamf(_jamf_devices)},
            )
        )

        result.complete()
        return result


class DemoDuoConnector(BaseConnector):
    """Simulates Duo Security MFA collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="duo",
            source_type=SourceType.IAM,
            provider="duo",
        )
        result.events.append(
            RawEventData(
                source="duo",
                source_type=SourceType.IAM,
                provider="duo",
                event_type="duo_users",
                raw_data={
                    "users": [
                        {
                            "user_id": "DUO-U001",
                            "username": "alice.chen",
                            "email": "alice.chen@acme.com",
                            "status": "active",
                            "is_enrolled": True,
                            "phones": [{"phone_id": "DP001"}],
                            "tokens": [],
                            "last_login": (NOW - timedelta(hours=2)).isoformat(),
                        },
                        {
                            "user_id": "DUO-U002",
                            "username": "bob.martinez",
                            "email": "bob.martinez@acme.com",
                            "status": "active",
                            "is_enrolled": False,
                            "phones": [],
                            "tokens": [],
                            "last_login": (NOW - timedelta(days=3)).isoformat(),
                        },
                        {
                            "user_id": "DUO-U003",
                            "username": "svc-legacy-app",
                            "email": "svc-legacy@acme.com",
                            "status": "bypass",
                            "is_enrolled": False,
                            "phones": [],
                            "tokens": [],
                            "last_login": (NOW - timedelta(days=30)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="duo",
                source_type=SourceType.IAM,
                provider="duo",
                event_type="duo_auth_logs",
                raw_data={
                    "logs": [
                        {
                            "txid": "tx-auth-001",
                            "result": "SUCCESS",
                            "reason": "user_approved",
                            "event_type": "authentication",
                            "factor": "push",
                            "user": {"name": "alice.chen"},
                            "access_device": {"ip": "10.0.1.50"},
                            "timestamp": int(NOW.timestamp()),
                        },
                        {
                            "txid": "tx-auth-002",
                            "result": "FRAUD",
                            "reason": "user_marked_fraud",
                            "event_type": "authentication",
                            "factor": "push",
                            "user": {"name": "bob.martinez"},
                            "access_device": {"ip": "198.51.100.44"},
                            "timestamp": int(NOW.timestamp()),
                        },
                    ]
                },
            )
        )

        # --- Rich data: users + auth logs ---
        _duo_users = RICH_DATA["users"][110:130]
        result.events.append(
            RawEventData(
                source="duo",
                source_type=SourceType.IAM,
                provider="duo",
                event_type="duo_users",
                raw_data={
                    "response": [
                        {
                            "user_id": u["user_id"],
                            "username": u["username"],
                            "email": u["email"],
                            "status": "active" if u["status"] == "active" else "disabled",
                            "is_enrolled": u["is_enrolled_mfa"],
                            "last_login": u["last_login"],
                        }
                        for u in _duo_users
                    ],
                },
            )
        )
        _duo_logs = RICH_DATA["auth_logs"][150:300]
        result.events.append(
            RawEventData(
                source="duo",
                source_type=SourceType.IAM,
                provider="duo",
                event_type="duo_auth_logs",
                raw_data={
                    "response": [
                        {
                            "txid": log["event_id"],
                            "user": {"name": log["username"]},
                            "result": "SUCCESS" if log["result"] == "success" else "FAILURE",
                            "reason": log.get("reason", ""),
                            "access_device": {"ip": log["ip_address"]},
                            "factor": log["factor"],
                            "timestamp": log["timestamp"],
                        }
                        for log in _duo_logs
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoOnePasswordConnector(BaseConnector):
    """Simulates 1Password Events API collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="onepassword",
            source_type=SourceType.IAM,
            provider="onepassword",
        )
        result.events.append(
            RawEventData(
                source="onepassword",
                source_type=SourceType.IAM,
                provider="onepassword",
                event_type="onepassword_signin_attempts",
                raw_data={
                    "items": [
                        {
                            "uuid": "op-signin-001",
                            "session_uuid": "sess-001",
                            "type": "credentials_ok",
                            "category": "success",
                            "target_user": {
                                "uuid": "user-001",
                                "email": "alice.chen@acme.com",
                                "name": "Alice Chen",
                            },
                            "client": {"app_name": "1Password for Mac", "ip": "10.0.1.50"},
                            "location": {"country": "US", "region": "California"},
                            "timestamp": NOW.isoformat(),
                        },
                        {
                            "uuid": "op-signin-002",
                            "session_uuid": "sess-002",
                            "type": "credentials_failed",
                            "category": "credentials_failed",
                            "target_user": {
                                "uuid": "user-002",
                                "email": "bob.martinez@acme.com",
                                "name": "Bob Martinez",
                            },
                            "client": {"app_name": "1Password for Web", "ip": "198.51.100.77"},
                            "location": {"country": "RU", "region": "Moscow"},
                            "timestamp": NOW.isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="onepassword",
                source_type=SourceType.IAM,
                provider="onepassword",
                event_type="onepassword_item_usage",
                raw_data={
                    "items": [
                        {
                            "uuid": "op-usage-001",
                            "user": {
                                "uuid": "user-001",
                                "email": "alice.chen@acme.com",
                                "name": "Alice Chen",
                            },
                            "item": {
                                "uuid": "item-001",
                                "title": "AWS Root Credentials",
                            },
                            "vault": {
                                "uuid": "vault-001",
                                "title": "Engineering",
                            },
                            "action": "fill",
                            "client": {"app_name": "1Password for Chrome"},
                            "timestamp": NOW.isoformat(),
                        },
                        {
                            "uuid": "op-usage-002",
                            "user": {
                                "uuid": "user-003",
                                "email": "charlie.wong@acme.com",
                                "name": "Charlie Wong",
                            },
                            "item": {
                                "uuid": "item-002",
                                "title": "Production Database",
                            },
                            "vault": {
                                "uuid": "vault-002",
                                "title": "Infrastructure",
                            },
                            "action": "reveal",
                            "client": {"app_name": "1Password for Web"},
                            "timestamp": NOW.isoformat(),
                        },
                        {
                            "uuid": "op-usage-003",
                            "user": {
                                "uuid": "user-003",
                                "email": "charlie.wong@acme.com",
                                "name": "Charlie Wong",
                            },
                            "item": {
                                "uuid": "item-003",
                                "title": "Stripe API Key",
                            },
                            "vault": {
                                "uuid": "vault-002",
                                "title": "Infrastructure",
                            },
                            "action": "export",
                            "client": {"app_name": "1Password for Web"},
                            "timestamp": NOW.isoformat(),
                        },
                    ]
                },
            )
        )

        # --- Rich data: users ---
        _op_users = RICH_DATA["users"][130:150]
        result.events.append(
            RawEventData(
                source="onepassword",
                source_type=SourceType.IAM,
                provider="onepassword",
                event_type="onepassword_users",
                raw_data={
                    "users": [
                        {
                            "uuid": u["user_id"],
                            "email": u["email"],
                            "name": f"{u['first_name']} {u['last_name']}",
                            "state": "A" if u["status"] == "active" else "S",
                            "type": "R",
                            "created_at": u["created_at"],
                        }
                        for u in _op_users
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoBitwardenConnector(BaseConnector):
    """Simulates Bitwarden organization collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="bitwarden",
            source_type=SourceType.IAM,
            provider="bitwarden",
        )
        result.events.append(
            RawEventData(
                source="bitwarden",
                source_type=SourceType.IAM,
                provider="bitwarden",
                event_type="bitwarden_members",
                raw_data={
                    "members": [
                        {
                            "id": "bw-m001",
                            "userId": "bw-u001",
                            "email": "alice.chen@acme.com",
                            "name": "Alice Chen",
                            "status": 2,
                            "type": 0,
                            "twoFactorEnabled": True,
                            "collections": [{"id": "col-001", "name": "Engineering"}],
                        },
                        {
                            "id": "bw-m002",
                            "userId": "bw-u002",
                            "email": "bob.martinez@acme.com",
                            "name": "Bob Martinez",
                            "status": 2,
                            "type": 1,
                            "twoFactorEnabled": False,
                            "collections": [{"id": "col-002", "name": "DevOps"}],
                        },
                        {
                            "id": "bw-m003",
                            "userId": "bw-u003",
                            "email": "former.employee@acme.com",
                            "name": "Former Employee",
                            "status": -1,
                            "type": 2,
                            "twoFactorEnabled": False,
                            "collections": [],
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="bitwarden",
                source_type=SourceType.IAM,
                provider="bitwarden",
                event_type="bitwarden_policies",
                raw_data={
                    "policies": [
                        {
                            "id": "pol-001",
                            "type": 0,
                            "enabled": True,
                            "data": {"minComplexity": 3, "minLength": 12},
                        },
                        {
                            "id": "pol-002",
                            "type": 1,
                            "enabled": False,
                            "data": {},
                        },
                    ]
                },
            )
        )

        # --- Rich data: users ---
        _bw_users = RICH_DATA["users"][150:170]
        result.events.append(
            RawEventData(
                source="bitwarden",
                source_type=SourceType.IAM,
                provider="bitwarden",
                event_type="bitwarden_members",
                raw_data={
                    "data": [
                        {
                            "id": u["user_id"],
                            "email": u["email"],
                            "name": f"{u['first_name']} {u['last_name']}",
                            "status": 2 if u["status"] == "active" else 0,
                            "type": 2,
                            "twoFactorEnabled": u["is_enrolled_mfa"],
                            "resetPasswordEnrolled": False,
                        }
                        for u in _bw_users
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoGuardDutyConnector(BaseConnector):
    """Simulates AWS GuardDuty findings collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="guardduty",
            source_type=SourceType.CLOUD,
            provider="guardduty",
        )
        result.events.append(
            RawEventData(
                source="guardduty",
                source_type=SourceType.CLOUD,
                provider="guardduty",
                event_type="guardduty_findings",
                raw_data={
                    "detector_id": "d-gd-demo-001",
                    "findings": [
                        {
                            "Id": "gd-finding-001",
                            "Type": "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
                            "Title": "Console login from unusual IP",
                            "Description": "An API call was invoked from an IP address that is included on a threat list.",
                            "Severity": 8.0,
                            "Confidence": 90,
                            "AccountId": "912345678012",
                            "Region": "us-east-1",
                            "Resource": {
                                "ResourceType": "AccessKey",
                                "AccessKeyDetails": {
                                    "AccessKeyId": "DEMO-KEY-00000000000",
                                    "UserName": "admin-user",
                                    "UserType": "IAMUser",
                                },
                            },
                            "Service": {
                                "ServiceName": "guardduty",
                                "Action": {"ActionType": "AWS_API_CALL"},
                                "Count": 3,
                            },
                            "CreatedAt": (NOW - timedelta(hours=2)).isoformat(),
                            "UpdatedAt": NOW.isoformat(),
                        },
                        {
                            "Id": "gd-finding-002",
                            "Type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
                            "Title": "EC2 instance querying cryptocurrency domain",
                            "Description": "EC2 instance i-0abc123def is querying a domain associated with Bitcoin.",
                            "Severity": 9.0,
                            "Confidence": 95,
                            "AccountId": "912345678012",
                            "Region": "us-east-1",
                            "Resource": {
                                "ResourceType": "Instance",
                                "InstanceDetails": {
                                    "InstanceId": "i-0abc123def",
                                    "InstanceType": "c5.4xlarge",
                                },
                            },
                            "Service": {
                                "ServiceName": "guardduty",
                                "Action": {"ActionType": "DNS_REQUEST"},
                                "Count": 142,
                            },
                            "CreatedAt": (NOW - timedelta(hours=1)).isoformat(),
                            "UpdatedAt": NOW.isoformat(),
                        },
                    ],
                },
            )
        )
        result.events.append(
            RawEventData(
                source="guardduty",
                source_type=SourceType.CLOUD,
                provider="guardduty",
                event_type="guardduty_detector_status",
                raw_data={
                    "detector_id": "d-gd-demo-001",
                    "detector": {
                        "Status": "ENABLED",
                        "CreatedAt": "2024-01-15T00:00:00Z",
                        "FindingPublishingFrequency": "FIFTEEN_MINUTES",
                        "DataSources": {
                            "CloudTrail": {"Status": "ENABLED"},
                            "DNSLogs": {"Status": "ENABLED"},
                            "FlowLogs": {"Status": "ENABLED"},
                            "S3Logs": {"Status": "ENABLED"},
                        },
                        "Features": [
                            {"Name": "EBS_MALWARE_PROTECTION", "Status": "ENABLED"},
                            {"Name": "LAMBDA_NETWORK_LOGS", "Status": "DISABLED"},
                        ],
                    },
                },
            )
        )

        # --- Rich data: security alerts ---
        _gd_alerts = RICH_DATA["security_alerts"][700:900]
        result.events.append(
            RawEventData(
                source="guardduty",
                source_type=SourceType.CLOUD,
                provider="aws",
                event_type="guardduty_findings",
                raw_data={
                    "findings": [
                        {
                            "id": a["alert_id"],
                            "type": f"Recon:{a['tactic']}",
                            "severity": {
                                "critical": 8.0,
                                "high": 7.0,
                                "medium": 5.0,
                                "low": 2.0,
                                "info": 1.0,
                            }.get(a["severity"], 5.0),
                            "title": a["title"],
                            "description": a["description"],
                            "resource": {"resourceType": "Instance"},
                            "service": {"action": {"actionType": "NETWORK_CONNECTION"}},
                            "createdAt": a["detected_at"],
                        }
                        for a in _gd_alerts
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoDatadogConnector(BaseConnector):
    """Simulates Datadog observability collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="datadog",
            source_type=SourceType.OBSERVABILITY,
            provider="datadog",
        )
        result.events.append(
            RawEventData(
                source="datadog",
                source_type=SourceType.OBSERVABILITY,
                provider="datadog",
                event_type="datadog_monitors",
                raw_data={
                    "monitors": [
                        {
                            "id": 10001,
                            "name": "High CPU on prod-api",
                            "type": "metric alert",
                            "overall_state": "OK",
                            "query": "avg(last_5m):avg:system.cpu.user{env:prod} > 90",
                            "tags": ["env:prod", "team:platform"],
                            "created": (NOW - timedelta(days=90)).isoformat(),
                        },
                        {
                            "id": 10002,
                            "name": "Error rate spike - payments",
                            "type": "metric alert",
                            "overall_state": "Alert",
                            "query": "avg(last_5m):sum:trace.http.request.errors{service:payments} > 50",
                            "tags": ["env:prod", "team:payments"],
                            "created": (NOW - timedelta(days=60)).isoformat(),
                        },
                        {
                            "id": 10003,
                            "name": "Disk usage warning",
                            "type": "metric alert",
                            "overall_state": "Warn",
                            "query": "avg(last_15m):avg:system.disk.in_use{env:prod} > 0.8",
                            "tags": ["env:prod", "team:infra"],
                            "created": (NOW - timedelta(days=30)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="datadog",
                source_type=SourceType.OBSERVABILITY,
                provider="datadog",
                event_type="datadog_slos",
                raw_data={
                    "slos": [
                        {
                            "id": "slo-001",
                            "name": "API Availability",
                            "type": "metric",
                            "target_threshold": 99.9,
                            "overall_status": [
                                {
                                    "status": "OK",
                                    "error_budget_remaining": 15.2,
                                    "timeframe": "7d",
                                    "target": 99.9,
                                }
                            ],
                            "tags": ["service:api", "tier:critical"],
                        },
                        {
                            "id": "slo-002",
                            "name": "Payment Latency P99",
                            "type": "metric",
                            "target_threshold": 99.5,
                            "overall_status": [
                                {
                                    "status": "BREACHED",
                                    "error_budget_remaining": -3.7,
                                    "timeframe": "7d",
                                    "target": 99.5,
                                }
                            ],
                            "tags": ["service:payments", "tier:critical"],
                        },
                    ]
                },
            )
        )

        # --- Rich data: security alerts as monitors ---
        _dd_alerts = RICH_DATA["security_alerts"][0:40]
        result.events.append(
            RawEventData(
                source="datadog",
                source_type=SourceType.OBSERVABILITY,
                provider="datadog",
                event_type="datadog_monitors",
                raw_data={
                    "monitors": [
                        {
                            "id": a["alert_id"],
                            "name": a["title"],
                            "type": "service check",
                            "overall_state": "Alert" if a["status"] == "new" else "OK",
                            "tags": [f"severity:{a['severity']}"],
                            "created": a["detected_at"],
                        }
                        for a in _dd_alerts
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoNewRelicConnector(BaseConnector):
    """Simulates New Relic observability collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="newrelic",
            source_type=SourceType.OBSERVABILITY,
            provider="newrelic",
        )
        result.events.append(
            RawEventData(
                source="newrelic",
                source_type=SourceType.OBSERVABILITY,
                provider="newrelic",
                event_type="newrelic_alerts",
                raw_data={
                    "violations": [
                        {
                            "id": 55001,
                            "condition_name": "High error rate",
                            "entity": {"name": "prod-api", "type": "APPLICATION"},
                            "priority": "CRITICAL",
                            "opened_at": int((NOW - timedelta(hours=1)).timestamp()),
                            "closed_at": None,
                            "duration": 3600,
                            "label": "Error rate > 5%",
                        },
                        {
                            "id": 55002,
                            "condition_name": "Apdex below threshold",
                            "entity": {"name": "web-frontend", "type": "APPLICATION"},
                            "priority": "WARNING",
                            "opened_at": int((NOW - timedelta(hours=3)).timestamp()),
                            "closed_at": None,
                            "duration": 10800,
                            "label": "Apdex < 0.7",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="newrelic",
                source_type=SourceType.OBSERVABILITY,
                provider="newrelic",
                event_type="newrelic_entities",
                raw_data={
                    "entities": [
                        {
                            "guid": "nr-entity-001",
                            "name": "prod-api",
                            "type": "APPLICATION",
                            "alertSeverity": "CRITICAL",
                            "reporting": True,
                            "domain": "APM",
                            "tags": [
                                {"key": "environment", "values": ["production"]},
                                {"key": "team", "values": ["platform"]},
                            ],
                        },
                        {
                            "guid": "nr-entity-002",
                            "name": "web-frontend",
                            "type": "APPLICATION",
                            "alertSeverity": "WARNING",
                            "reporting": True,
                            "domain": "APM",
                            "tags": [
                                {"key": "environment", "values": ["production"]},
                            ],
                        },
                        {
                            "guid": "nr-entity-003",
                            "name": "batch-processor",
                            "type": "APPLICATION",
                            "alertSeverity": "NOT_ALERTING",
                            "reporting": False,
                            "domain": "APM",
                            "tags": [
                                {"key": "environment", "values": ["production"]},
                            ],
                        },
                    ]
                },
            )
        )

        # --- Rich data: security alerts ---
        _nr_alerts = RICH_DATA["security_alerts"][40:80]
        result.events.append(
            RawEventData(
                source="newrelic",
                source_type=SourceType.OBSERVABILITY,
                provider="newrelic",
                event_type="newrelic_violations",
                raw_data={
                    "violations": [
                        {
                            "id": a["alert_id"],
                            "label": a["title"],
                            "priority": a["severity"],
                            "opened_at": a["detected_at"],
                            "closed_at": a.get("resolved_at"),
                            "entity": {"name": a["affected_host"]},
                        }
                        for a in _nr_alerts
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoCheckmarxConnector(BaseConnector):
    """Simulates Checkmarx SAST/SCA collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="checkmarx",
            source_type=SourceType.CODE,
            provider="checkmarx",
        )
        result.events.append(
            RawEventData(
                source="checkmarx",
                source_type=SourceType.CODE,
                provider="checkmarx",
                event_type="checkmarx_vulnerabilities",
                raw_data={
                    "vulnerabilities": [
                        {
                            "id": "cx-vuln-001",
                            "queryName": "SQL_Injection",
                            "severity": "Critical",
                            "state": "To Verify",
                            "status": "New",
                            "language": "Python",
                            "fileName": "app/api/users.py",
                            "line": 142,
                            "column": 28,
                            "description": "User input flows into SQL query without parameterization",
                            "categories": ["OWASP Top 10 2021: A03 - Injection"],
                            "cweId": 89,
                            "projectName": "acme-api",
                            "scanId": "scan-cx-001",
                        },
                        {
                            "id": "cx-vuln-002",
                            "queryName": "Reflected_XSS",
                            "severity": "High",
                            "state": "To Verify",
                            "status": "New",
                            "language": "JavaScript",
                            "fileName": "frontend/src/components/Search.jsx",
                            "line": 87,
                            "column": 15,
                            "description": "User input rendered without escaping in HTML context",
                            "categories": ["OWASP Top 10 2021: A03 - Injection"],
                            "cweId": 79,
                            "projectName": "acme-web",
                            "scanId": "scan-cx-002",
                        },
                    ]
                },
            )
        )

        # --- Rich data: code findings ---
        _cx_findings = RICH_DATA["code_findings"][240:400]
        result.events.append(
            RawEventData(
                source="checkmarx",
                source_type=SourceType.CODE,
                provider="checkmarx",
                event_type="checkmarx_results",
                raw_data={"results": _code_findings_as_checkmarx(_cx_findings)},
            )
        )

        result.complete()
        return result


class DemoSonarQubeConnector(BaseConnector):
    """Simulates SonarQube code quality collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="sonarqube",
            source_type=SourceType.CODE,
            provider="sonarqube",
        )
        result.events.append(
            RawEventData(
                source="sonarqube",
                source_type=SourceType.CODE,
                provider="sonarqube",
                event_type="sonarqube_projects",
                raw_data={
                    "projects": [
                        {
                            "key": "acme-api",
                            "name": "ACME API",
                            "qualifier": "TRK",
                            "lastAnalysisDate": NOW.isoformat(),
                            "measures": [
                                {"metric": "alert_status", "value": "OK"},
                                {"metric": "coverage", "value": "82.5"},
                                {"metric": "bugs", "value": "3"},
                                {"metric": "vulnerabilities", "value": "1"},
                            ],
                        },
                        {
                            "key": "acme-web",
                            "name": "ACME Web Frontend",
                            "qualifier": "TRK",
                            "lastAnalysisDate": NOW.isoformat(),
                            "measures": [
                                {"metric": "alert_status", "value": "ERROR"},
                                {"metric": "coverage", "value": "34.2"},
                                {"metric": "bugs", "value": "12"},
                                {"metric": "vulnerabilities", "value": "7"},
                            ],
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sonarqube",
                source_type=SourceType.CODE,
                provider="sonarqube",
                event_type="sonarqube_issues",
                raw_data={
                    "issues": [
                        {
                            "key": "sq-issue-001",
                            "rule": "python:S3649",
                            "severity": "BLOCKER",
                            "type": "VULNERABILITY",
                            "component": "acme-api:app/db/queries.py",
                            "line": 55,
                            "message": "Make sure that formatting this SQL query is safe.",
                            "status": "OPEN",
                            "effort": "30min",
                            "creationDate": (NOW - timedelta(days=5)).isoformat(),
                        },
                        {
                            "key": "sq-issue-002",
                            "rule": "javascript:S5131",
                            "severity": "CRITICAL",
                            "type": "VULNERABILITY",
                            "component": "acme-web:src/utils/render.js",
                            "line": 23,
                            "message": "Make sure disabling auto-escaping is safe here.",
                            "status": "OPEN",
                            "effort": "15min",
                            "creationDate": (NOW - timedelta(days=3)).isoformat(),
                        },
                    ]
                },
            )
        )

        # --- Rich data: code findings ---
        _sq_findings = RICH_DATA["code_findings"][400:560]
        result.events.append(
            RawEventData(
                source="sonarqube",
                source_type=SourceType.CODE,
                provider="sonarqube",
                event_type="sonarqube_issues",
                raw_data={"issues": _code_findings_as_sonarqube(_sq_findings)},
            )
        )

        result.complete()
        return result


class DemoAbnormalSecurityConnector(BaseConnector):
    """Simulates Abnormal Security email threat detection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="abnormal_security",
            source_type=SourceType.EMAIL,
            provider="abnormal_security",
        )
        result.events.append(
            RawEventData(
                source="abnormal_security",
                source_type=SourceType.EMAIL,
                provider="abnormal_security",
                event_type="abnormal_threats",
                raw_data={
                    "threats": [
                        {
                            "threatId": "abn-t001",
                            "abxMessageId": "msg-001",
                            "subject": "Urgent: Wire Transfer Required",
                            "fromAddress": "ceo-lookalike@acme-corp.net",
                            "toAddress": "cfo@acme.com",
                            "recipientAddress": "cfo@acme.com",
                            "attackType": "BEC",
                            "attackStrategy": "Impersonation: Executive",
                            "sentTime": NOW.isoformat(),
                            "receivedTime": NOW.isoformat(),
                            "remediationStatus": "Auto-Remediated",
                            "severity": "critical",
                            "isRead": False,
                            "attackVector": "Text",
                            "summaryInsights": [
                                "Sender domain is a lookalike of acme.com",
                                "Requests urgent wire transfer",
                            ],
                        },
                        {
                            "threatId": "abn-t002",
                            "abxMessageId": "msg-002",
                            "subject": "Your account has been compromised",
                            "fromAddress": "support@micros0ft-security.com",
                            "toAddress": "alice.chen@acme.com",
                            "recipientAddress": "alice.chen@acme.com",
                            "attackType": "Phishing: Credential",
                            "attackStrategy": "Brand Impersonation",
                            "sentTime": NOW.isoformat(),
                            "receivedTime": NOW.isoformat(),
                            "remediationStatus": "Auto-Remediated",
                            "severity": "high",
                            "isRead": False,
                            "attackVector": "Link",
                            "summaryInsights": [
                                "Impersonates Microsoft branding",
                                "Contains credential harvesting link",
                            ],
                        },
                        {
                            "threatId": "abn-t003",
                            "abxMessageId": "msg-003",
                            "subject": "Quarterly Board Presentation - CONFIDENTIAL",
                            "fromAddress": "exec-assistant@acme-partners.io",
                            "toAddress": "ceo@acme.com",
                            "recipientAddress": "ceo@acme.com",
                            "attackType": "BEC",
                            "attackStrategy": "Impersonation: Executive",
                            "sentTime": NOW.isoformat(),
                            "receivedTime": NOW.isoformat(),
                            "remediationStatus": "Pending",
                            "severity": "critical",
                            "isRead": True,
                            "attackVector": "Attachment",
                            "summaryInsights": [
                                "Targets C-suite executive",
                                "Contains suspicious attachment",
                            ],
                        },
                    ]
                },
            )
        )

        # --- Rich data: email events ---
        _abnormal_emails = RICH_DATA["email_events"][100:250]
        result.events.append(
            RawEventData(
                source="abnormal_security",
                source_type=SourceType.EMAIL,
                provider="abnormal_security",
                event_type="abnormal_threats",
                raw_data={"threats": _email_as_abnormal(_abnormal_emails)},
            )
        )

        result.complete()
        return result


class DemoNetskopeConnector(BaseConnector):
    """Simulates Netskope CASB/DLP collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="netskope",
            source_type=SourceType.DLP,
            provider="netskope",
        )
        result.events.append(
            RawEventData(
                source="netskope",
                source_type=SourceType.DLP,
                provider="netskope",
                event_type="netskope_alerts",
                raw_data={
                    "alerts": [
                        {
                            "alert_id": "nsk-alert-001",
                            "alert_name": "DLP: SSN detected in cloud upload",
                            "alert_type": "DLP",
                            "severity": "critical",
                            "user": "bob.martinez@acme.com",
                            "app": "Google Drive",
                            "object": "employee_data_export.xlsx",
                            "activity": "Upload",
                            "policy": "PII Protection Policy",
                            "dlp_profile": "US PII - Social Security Numbers",
                            "dlp_rule": "SSN Pattern Match",
                            "dlp_incident_id": "dlp-inc-001",
                            "file_size": 2048000,
                            "timestamp": int(NOW.timestamp()),
                            "action": "block",
                            "status": "open",
                        },
                        {
                            "alert_id": "nsk-alert-002",
                            "alert_name": "Compromised credential detected",
                            "alert_type": "Compromised Credential",
                            "severity": "high",
                            "user": "charlie.wong@acme.com",
                            "app": "Slack",
                            "object": "",
                            "activity": "Login",
                            "breach_id": "breach-2025-04",
                            "breach_date": (NOW - timedelta(days=15)).isoformat(),
                            "timestamp": int(NOW.timestamp()),
                            "action": "alert",
                            "status": "open",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="netskope",
                source_type=SourceType.DLP,
                provider="netskope",
                event_type="netskope_clients",
                raw_data={
                    "clients": [
                        {
                            "client_id": "nsk-client-001",
                            "host_info": {
                                "hostname": "ENG-MBP-001",
                                "os": "macOS 14.3",
                                "device_id": "dev-001",
                            },
                            "user": "alice.chen@acme.com",
                            "client_version": "117.0.2",
                            "status": "Connected",
                            "last_event_time": NOW.isoformat(),
                        },
                        {
                            "client_id": "nsk-client-002",
                            "host_info": {
                                "hostname": "SALES-WIN-042",
                                "os": "Windows 11",
                                "device_id": "dev-002",
                            },
                            "user": "dave.johnson@acme.com",
                            "client_version": "115.1.0",
                            "status": "Disconnected",
                            "last_event_time": (NOW - timedelta(days=7)).isoformat(),
                        },
                    ]
                },
            )
        )

        # --- Rich data: DNS queries as CASB alerts ---
        _ns_dns = RICH_DATA["dns_queries"][320:400]
        result.events.append(
            RawEventData(
                source="netskope",
                source_type=SourceType.DLP,
                provider="netskope",
                event_type="netskope_alerts",
                raw_data={"data": _dns_as_netskope(_ns_dns)},
            )
        )

        result.complete()
        return result


class DemoNessusConnector(BaseConnector):
    """Simulates Tenable Nessus vulnerability scanner collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="nessus",
            source_type=SourceType.SCANNER,
            provider="nessus",
        )
        result.events.append(
            RawEventData(
                source="nessus",
                source_type=SourceType.SCANNER,
                provider="nessus",
                event_type="nessus_scans",
                raw_data={
                    "scans": [
                        {
                            "id": 3001,
                            "name": "Weekly Infrastructure Scan",
                            "status": "completed",
                            "last_modification_date": int(NOW.timestamp()),
                            "creation_date": int((NOW - timedelta(days=90)).timestamp()),
                            "starttime": (NOW - timedelta(hours=4)).isoformat(),
                            "host_count": 128,
                            "info_count": 45,
                            "low_count": 12,
                            "medium_count": 8,
                            "high_count": 3,
                            "critical_count": 1,
                        },
                        {
                            "id": 3002,
                            "name": "PCI Quarterly Scan",
                            "status": "completed",
                            "last_modification_date": int((NOW - timedelta(days=40)).timestamp()),
                            "creation_date": int((NOW - timedelta(days=120)).timestamp()),
                            "starttime": (NOW - timedelta(days=40)).isoformat(),
                            "host_count": 64,
                            "info_count": 20,
                            "low_count": 5,
                            "medium_count": 2,
                            "high_count": 1,
                            "critical_count": 0,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="nessus",
                source_type=SourceType.SCANNER,
                provider="nessus",
                event_type="nessus_vulnerabilities",
                raw_data={
                    "vulnerabilities": [
                        {
                            "plugin_id": 97861,
                            "plugin_name": "OpenSSL < 3.0.13 Multiple Vulnerabilities",
                            "severity": 4,
                            "severity_text": "Critical",
                            "host_ip": "10.0.1.15",
                            "host_fqdn": "db-primary.internal.acme.com",
                            "port": 443,
                            "protocol": "tcp",
                            "cvss3_base_score": 9.8,
                            "cve": ["CVE-2024-0727"],
                            "exploit_available": True,
                            "exploit_code_maturity": "functional",
                            "solution": "Upgrade OpenSSL to 3.0.13 or later.",
                            "scan_id": 3001,
                        },
                        {
                            "plugin_id": 156032,
                            "plugin_name": "Apache HTTP Server < 2.4.58 RCE",
                            "severity": 4,
                            "severity_text": "Critical",
                            "host_ip": "10.0.2.30",
                            "host_fqdn": "web-legacy.internal.acme.com",
                            "port": 80,
                            "protocol": "tcp",
                            "cvss3_base_score": 9.1,
                            "cve": ["CVE-2023-44487"],
                            "exploit_available": False,
                            "exploit_code_maturity": "unproven",
                            "solution": "Upgrade Apache HTTP Server to 2.4.58 or later.",
                            "scan_id": 3001,
                        },
                    ]
                },
            )
        )

        # --- Rich data: vulnerabilities ---
        _nes_vulns = RICH_DATA["vulnerabilities"][1900:2200]
        result.events.append(
            RawEventData(
                source="nessus",
                source_type=SourceType.SCANNER,
                provider="nessus",
                event_type="nessus_scan_results",
                raw_data={"vulnerabilities": _vulns_as_nessus(_nes_vulns)},
            )
        )

        result.complete()
        return result


class DemoBambooHRConnector(BaseConnector):
    """Simulates BambooHR HRIS collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="bamboohr",
            source_type=SourceType.HRIS,
            provider="bamboohr",
        )
        result.events.append(
            RawEventData(
                source="bamboohr",
                source_type=SourceType.HRIS,
                provider="bamboohr",
                event_type="bamboohr_employees",
                raw_data={
                    "employees": [
                        {
                            "id": 7001,
                            "displayName": "Alice Chen",
                            "status": "Active",
                            "department": "Engineering",
                            "jobTitle": "Senior Engineer",
                            "hireDate": "2022-03-15",
                            "terminationDate": None,
                            "supervisor": "Diana Prince",
                            "supervisorId": "7010",
                            "workEmail": "alice.chen@acme.com",
                        },
                        {
                            "id": 7002,
                            "displayName": "John Smith",
                            "status": "Active",
                            "department": "Sales",
                            "jobTitle": "Account Executive",
                            "hireDate": "2021-06-01",
                            "terminationDate": "2026-02-28",
                            "supervisor": "Jane Doe",
                            "supervisorId": "7011",
                            "workEmail": "john.smith@acme.com",
                        },
                        {
                            "id": 7003,
                            "displayName": "Eve Adams",
                            "status": "Active",
                            "department": "Engineering",
                            "jobTitle": "Junior Developer",
                            "hireDate": "2025-11-01",
                            "terminationDate": None,
                            "supervisor": "",
                            "supervisorId": "",
                            "workEmail": "eve.adams@acme.com",
                        },
                        {
                            "id": 7004,
                            "displayName": "Bob Martinez",
                            "status": "Active",
                            "department": "DevOps",
                            "jobTitle": "DevOps Engineer",
                            "hireDate": "2023-08-15",
                            "terminationDate": None,
                            "supervisor": "Diana Prince",
                            "supervisorId": "7010",
                            "workEmail": "bob.martinez@acme.com",
                        },
                    ]
                },
            )
        )

        # --- Rich data: employees ---
        _bhr_employees = RICH_DATA["employees"][125:250]
        result.events.append(
            RawEventData(
                source="bamboohr",
                source_type=SourceType.HRIS,
                provider="bamboohr",
                event_type="bamboohr_employees",
                raw_data={"employees": _employees_as_bamboohr(_bhr_employees)},
            )
        )

        result.complete()
        return result


class DemoSophosConnector(BaseConnector):
    """Simulates Sophos Central EDR collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="sophos",
            source_type=SourceType.EDR,
            provider="sophos",
        )
        result.events.append(
            RawEventData(
                source="sophos",
                source_type=SourceType.EDR,
                provider="sophos",
                event_type="sophos_endpoints",
                raw_data={
                    "endpoints": [
                        {
                            "id": "soph-ep-001",
                            "hostname": "ENG-MBP-001",
                            "os": {"name": "macOS", "platform": "macOS", "majorVersion": 14},
                            "health": {"overall": "good", "threats": {"status": "good"}},
                            "tamperProtectionEnabled": True,
                            "associatedPerson": {"viaLogin": "alice.chen@acme.com"},
                            "lastSeenAt": NOW.isoformat(),
                            "ipv4Addresses": ["10.0.1.50"],
                        },
                        {
                            "id": "soph-ep-002",
                            "hostname": "SALES-WIN-042",
                            "os": {"name": "Windows 11", "platform": "windows", "majorVersion": 11},
                            "health": {"overall": "bad", "threats": {"status": "bad"}},
                            "tamperProtectionEnabled": True,
                            "associatedPerson": {"viaLogin": "dave.johnson@acme.com"},
                            "lastSeenAt": NOW.isoformat(),
                            "ipv4Addresses": ["10.0.2.88"],
                        },
                        {
                            "id": "soph-ep-003",
                            "hostname": "DEV-LNX-009",
                            "os": {"name": "Ubuntu 22.04", "platform": "linux", "majorVersion": 22},
                            "health": {"overall": "good", "threats": {"status": "good"}},
                            "tamperProtectionEnabled": False,
                            "associatedPerson": {"viaLogin": "eve.adams@acme.com"},
                            "lastSeenAt": (NOW - timedelta(days=3)).isoformat(),
                            "ipv4Addresses": ["10.0.3.15"],
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sophos",
                source_type=SourceType.EDR,
                provider="sophos",
                event_type="sophos_alerts",
                raw_data={
                    "alerts": [
                        {
                            "id": "soph-alert-001",
                            "description": "Malware detected: Trojan.GenericKD",
                            "severity": "high",
                            "category": "malware",
                            "managedAgent": {
                                "id": "soph-ep-002",
                                "type": "computer",
                            },
                            "person": {"id": "p-002"},
                            "type": "Event::Endpoint::Threat::Detected",
                            "groupKey": "threat-grp-001",
                            "product": "endpoint",
                            "raisedAt": (NOW - timedelta(hours=3)).isoformat(),
                            "allowedActions": ["clean", "authPUA"],
                            "status": "raised",
                        },
                    ]
                },
            )
        )

        # --- Rich data: endpoints ---
        _soph_endpoints = RICH_DATA["endpoints_edr"][150:200]
        result.events.append(
            RawEventData(
                source="sophos",
                source_type=SourceType.EDR,
                provider="sophos",
                event_type="sophos_endpoints",
                raw_data={"endpoints": _endpoints_as_sophos(_soph_endpoints)},
            )
        )

        result.complete()
        return result


class DemoJumpCloudConnector(BaseConnector):
    """Simulates JumpCloud IAM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="jumpcloud",
            source_type=SourceType.IAM,
            provider="jumpcloud",
        )
        result.events.append(
            RawEventData(
                source="jumpcloud",
                source_type=SourceType.IAM,
                provider="jumpcloud",
                event_type="jumpcloud_users",
                raw_data={
                    "users": [
                        {
                            "id": "jc-usr-001",
                            "username": "alice.chen",
                            "email": "alice.chen@acme.com",
                            "mfa_enabled": True,
                            "suspended": False,
                            "created": "2024-01-15T00:00:00Z",
                            "last_login": (NOW - timedelta(hours=2)).isoformat(),
                        },
                        {
                            "id": "jc-usr-002",
                            "username": "bob.martinez",
                            "email": "bob.martinez@acme.com",
                            "mfa_enabled": False,
                            "suspended": False,
                            "created": "2024-03-10T00:00:00Z",
                            "last_login": (NOW - timedelta(days=1)).isoformat(),
                        },
                        {
                            "id": "jc-usr-003",
                            "username": "carol.wang",
                            "email": "carol.wang@acme.com",
                            "mfa_enabled": True,
                            "suspended": True,
                            "created": "2023-11-20T00:00:00Z",
                            "last_login": (NOW - timedelta(days=90)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="jumpcloud",
                source_type=SourceType.IAM,
                provider="jumpcloud",
                event_type="jumpcloud_devices",
                raw_data={
                    "devices": [
                        {
                            "id": "jc-dev-001",
                            "hostname": "ENG-MBP-101",
                            "os": "macOS 14.3",
                            "disk_encryption": True,
                            "agent_version": "2.8.1",
                            "last_contact": NOW.isoformat(),
                        },
                        {
                            "id": "jc-dev-002",
                            "hostname": "SALES-WIN-055",
                            "os": "Windows 11",
                            "disk_encryption": False,
                            "agent_version": "2.7.0",
                            "last_contact": (NOW - timedelta(hours=6)).isoformat(),
                        },
                    ]
                },
            )
        )

        # --- Rich data: users ---
        _jc_users = RICH_DATA["users"][170:190]
        result.events.append(
            RawEventData(
                source="jumpcloud",
                source_type=SourceType.IAM,
                provider="jumpcloud",
                event_type="jumpcloud_users",
                raw_data={
                    "users": [
                        {
                            "id": u["user_id"],
                            "username": u["username"],
                            "email": u["email"],
                            "mfa_enabled": u["is_enrolled_mfa"],
                            "suspended": u["status"] != "active",
                            "created": u["created_at"],
                            "last_login": u["last_login"],
                        }
                        for u in _jc_users
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoAuth0Connector(BaseConnector):
    """Simulates Auth0 IAM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="auth0",
            source_type=SourceType.IAM,
            provider="auth0",
        )
        result.events.append(
            RawEventData(
                source="auth0",
                source_type=SourceType.IAM,
                provider="auth0",
                event_type="auth0_users",
                raw_data={
                    "users": [
                        {
                            "user_id": "auth0|usr-001",
                            "email": "alice.chen@acme.com",
                            "name": "Alice Chen",
                            "mfa_enrolled": True,
                            "blocked": False,
                            "last_login": (NOW - timedelta(hours=1)).isoformat(),
                            "logins_count": 342,
                        },
                        {
                            "user_id": "auth0|usr-002",
                            "email": "bob.martinez@acme.com",
                            "name": "Bob Martinez",
                            "mfa_enrolled": False,
                            "blocked": False,
                            "last_login": (NOW - timedelta(days=2)).isoformat(),
                            "logins_count": 87,
                        },
                        {
                            "user_id": "auth0|usr-003",
                            "email": "eve.malicious@external.com",
                            "name": "Eve Malicious",
                            "mfa_enrolled": False,
                            "blocked": True,
                            "last_login": (NOW - timedelta(days=30)).isoformat(),
                            "logins_count": 5,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="auth0",
                source_type=SourceType.IAM,
                provider="auth0",
                event_type="auth0_connections",
                raw_data={
                    "connections": [
                        {
                            "id": "con-001",
                            "name": "Username-Password-Authentication",
                            "strategy": "auth0",
                            "enabled_clients": ["app-web", "app-mobile"],
                        },
                        {
                            "id": "con-002",
                            "name": "google-oauth2",
                            "strategy": "google-oauth2",
                            "enabled_clients": ["app-web"],
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="auth0",
                source_type=SourceType.IAM,
                provider="auth0",
                event_type="auth0_logs",
                raw_data={
                    "logs": [
                        {
                            "log_id": "log-001",
                            "type": "s",
                            "description": "Successful login",
                            "user_id": "auth0|usr-001",
                            "ip": "203.0.113.42",
                            "date": (NOW - timedelta(hours=1)).isoformat(),
                        },
                        {
                            "log_id": "log-002",
                            "type": "f",
                            "description": "Failed login: wrong password",
                            "user_id": "auth0|usr-003",
                            "ip": "198.51.100.99",
                            "date": (NOW - timedelta(minutes=30)).isoformat(),
                        },
                    ]
                },
            )
        )

        # --- Rich data: users + auth logs ---
        _a0_users = RICH_DATA["users"][190:200]
        result.events.append(
            RawEventData(
                source="auth0",
                source_type=SourceType.IAM,
                provider="auth0",
                event_type="auth0_users",
                raw_data={
                    "users": [
                        {
                            "user_id": f"auth0|{u['user_id']}",
                            "email": u["email"],
                            "name": f"{u['first_name']} {u['last_name']}",
                            "mfa_enrolled": u["is_enrolled_mfa"],
                            "blocked": u["status"] != "active",
                            "last_login": u["last_login"],
                            "logins_count": random.randint(1, 500),
                        }
                        for u in _a0_users
                    ],
                },
            )
        )
        _a0_logs = RICH_DATA["auth_logs"][300:450]
        result.events.append(
            RawEventData(
                source="auth0",
                source_type=SourceType.IAM,
                provider="auth0",
                event_type="auth0_logs",
                raw_data={
                    "logs": [
                        {
                            "log_id": log["event_id"],
                            "type": "s" if log["result"] == "success" else "f",
                            "description": "Successful login"
                            if log["result"] == "success"
                            else f"Failed login: {log.get('reason', 'unknown')}",
                            "user_id": f"auth0|{log['event_id'][-8:]}",
                            "ip": log["ip_address"],
                            "date": log["timestamp"],
                        }
                        for log in _a0_logs
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoGitLabConnector(BaseConnector):
    """Simulates GitLab code security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="gitlab",
            source_type=SourceType.CODE,
            provider="gitlab",
        )
        result.events.append(
            RawEventData(
                source="gitlab",
                source_type=SourceType.CODE,
                provider="gitlab",
                event_type="gitlab_projects",
                raw_data={
                    "projects": [
                        {
                            "id": 101,
                            "name": "platform-api",
                            "visibility": "private",
                            "merge_requests_enabled": True,
                            "approvals_before_merge": 2,
                            "default_branch": "main",
                            "last_activity_at": NOW.isoformat(),
                        },
                        {
                            "id": 102,
                            "name": "public-docs",
                            "visibility": "public",
                            "merge_requests_enabled": True,
                            "approvals_before_merge": 1,
                            "default_branch": "main",
                            "last_activity_at": (NOW - timedelta(days=3)).isoformat(),
                        },
                        {
                            "id": 103,
                            "name": "data-pipeline",
                            "visibility": "internal",
                            "merge_requests_enabled": True,
                            "approvals_before_merge": 0,
                            "default_branch": "main",
                            "last_activity_at": (NOW - timedelta(hours=8)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="gitlab",
                source_type=SourceType.CODE,
                provider="gitlab",
                event_type="gitlab_vulnerabilities",
                raw_data={
                    "vulnerabilities": [
                        {
                            "id": "gl-vuln-001",
                            "title": "SQL Injection in user search endpoint",
                            "severity": "critical",
                            "state": "detected",
                            "project_id": 101,
                            "scanner": "sast",
                            "location": {"file": "src/api/users.py", "line": 142},
                            "detected_at": (NOW - timedelta(days=5)).isoformat(),
                        },
                        {
                            "id": "gl-vuln-002",
                            "title": "Outdated dependency with known CVE",
                            "severity": "high",
                            "state": "detected",
                            "project_id": 103,
                            "scanner": "dependency_scanning",
                            "location": {"file": "requirements.txt", "line": 15},
                            "detected_at": (NOW - timedelta(days=2)).isoformat(),
                        },
                    ]
                },
            )
        )

        # --- Rich data: code findings as vulnerabilities ---
        _gl_findings = RICH_DATA["code_findings"][560:720]
        result.events.append(
            RawEventData(
                source="gitlab",
                source_type=SourceType.CODE,
                provider="gitlab",
                event_type="gitlab_vulnerabilities",
                raw_data={
                    "vulnerabilities": [
                        {
                            "id": f["finding_id"],
                            "title": f["title"],
                            "severity": f["severity"],
                            "state": "detected" if f["status"] == "open" else "resolved",
                            "project_id": random.randint(100, 200),
                            "scanner": "sast",
                            "location": {
                                "file": f.get("file_path", "unknown"),
                                "line": f.get("line_number", 0),
                            },
                            "detected_at": f.get("detected_at", NOW.isoformat()),
                        }
                        for f in _gl_findings
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoJiraConnector(BaseConnector):
    """Simulates Jira ITSM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="jira",
            source_type=SourceType.ITSM,
            provider="jira",
        )
        result.events.append(
            RawEventData(
                source="jira",
                source_type=SourceType.ITSM,
                provider="jira",
                event_type="jira_security_bugs",
                raw_data={
                    "issues": [
                        {
                            "key": "SEC-101",
                            "summary": "XSS vulnerability in admin panel",
                            "priority": "Critical",
                            "status": "Open",
                            "assignee": "alice.chen@acme.com",
                            "created": (NOW - timedelta(days=14)).isoformat(),
                            "due_date": (NOW - timedelta(days=7)).isoformat(),
                            "labels": ["security", "vulnerability"],
                        },
                        {
                            "key": "SEC-102",
                            "summary": "Upgrade TLS to 1.3 on API gateway",
                            "priority": "High",
                            "status": "In Progress",
                            "assignee": "bob.martinez@acme.com",
                            "created": (NOW - timedelta(days=5)).isoformat(),
                            "due_date": (NOW + timedelta(days=10)).isoformat(),
                            "labels": ["security", "infrastructure"],
                        },
                        {
                            "key": "SEC-103",
                            "summary": "Implement CSP headers on web app",
                            "priority": "Medium",
                            "status": "To Do",
                            "assignee": None,
                            "created": (NOW - timedelta(days=2)).isoformat(),
                            "due_date": (NOW + timedelta(days=30)).isoformat(),
                            "labels": ["security", "hardening"],
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="jira",
                source_type=SourceType.ITSM,
                provider="jira",
                event_type="jira_sla_status",
                raw_data={
                    "sla_records": [
                        {
                            "issue_key": "SEC-101",
                            "sla_name": "Critical Bug Resolution",
                            "target_hours": 72,
                            "elapsed_hours": 336,
                            "breached": True,
                        },
                        {
                            "issue_key": "SEC-102",
                            "sla_name": "High Bug Resolution",
                            "target_hours": 168,
                            "elapsed_hours": 120,
                            "breached": False,
                        },
                    ]
                },
            )
        )

        # --- Rich data: incidents as security bugs ---
        _jira_incidents = RICH_DATA["incidents"][0:25]
        result.events.append(
            RawEventData(
                source="jira",
                source_type=SourceType.ITSM,
                provider="jira",
                event_type="jira_security_bugs",
                raw_data={
                    "issues": [
                        {
                            "key": f"SEC-{200 + i}",
                            "summary": inc["title"],
                            "priority": inc["severity"].capitalize(),
                            "status": "Open"
                            if inc["status"] in ("open", "investigating")
                            else "Done",
                            "assignee": inc.get("assignee_email", ""),
                            "created": inc["reported_at"],
                            "due_date": inc.get("contained_at", ""),
                            "labels": ["security", inc["type"]],
                        }
                        for i, inc in enumerate(_jira_incidents)
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoSlackConnector(BaseConnector):
    """Simulates Slack collaboration collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="slack",
            source_type=SourceType.COLLABORATION,
            provider="slack",
        )
        result.events.append(
            RawEventData(
                source="slack",
                source_type=SourceType.COLLABORATION,
                provider="slack",
                event_type="slack_workspace",
                raw_data={
                    "workspace": {
                        "id": "T0001ACME",
                        "name": "Acme Corp",
                        "domain": "acme-corp",
                        "two_factor_required": False,
                        "sso_enabled": True,
                        "message_retention_days": 365,
                        "file_retention_days": 365,
                    }
                },
            )
        )
        result.events.append(
            RawEventData(
                source="slack",
                source_type=SourceType.COLLABORATION,
                provider="slack",
                event_type="slack_users",
                raw_data={
                    "users": [
                        {
                            "id": "U001",
                            "name": "alice.chen",
                            "email": "alice.chen@acme.com",
                            "is_admin": True,
                            "is_owner": False,
                            "has_2fa": True,
                            "is_sso": True,
                            "status": "active",
                        },
                        {
                            "id": "U002",
                            "name": "bob.martinez",
                            "email": "bob.martinez@acme.com",
                            "is_admin": False,
                            "is_owner": False,
                            "has_2fa": True,
                            "is_sso": True,
                            "status": "active",
                        },
                        {
                            "id": "U003",
                            "name": "contractor.dave",
                            "email": "dave@external-vendor.com",
                            "is_admin": False,
                            "is_owner": False,
                            "has_2fa": False,
                            "is_sso": False,
                            "status": "active",
                        },
                    ]
                },
            )
        )

        # --- Rich data: users ---
        _slack_users = RICH_DATA["users"][0:30]
        result.events.append(
            RawEventData(
                source="slack",
                source_type=SourceType.COLLABORATION,
                provider="slack",
                event_type="slack_users",
                raw_data={
                    "members": [
                        {
                            "id": u["user_id"],
                            "name": u["username"],
                            "profile": {
                                "email": u["email"],
                                "real_name": f"{u['first_name']} {u['last_name']}",
                            },
                            "is_admin": random.random() < 0.1,
                            "is_owner": False,
                            "is_restricted": False,
                            "has_2fa": u["is_enrolled_mfa"],
                            "deleted": u["status"] != "active",
                        }
                        for u in _slack_users
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoGoogleWorkspaceConnector(BaseConnector):
    """Simulates Google Workspace collaboration collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="google_workspace",
            source_type=SourceType.COLLABORATION,
            provider="google",
        )
        result.events.append(
            RawEventData(
                source="google_workspace",
                source_type=SourceType.COLLABORATION,
                provider="google",
                event_type="gws_users",
                raw_data={
                    "users": [
                        {
                            "id": "gws-usr-001",
                            "primaryEmail": "alice.chen@acme.com",
                            "name": {"fullName": "Alice Chen"},
                            "isEnrolledIn2Sv": True,
                            "suspended": False,
                            "lastLoginTime": (NOW - timedelta(hours=3)).isoformat(),
                            "isAdmin": True,
                        },
                        {
                            "id": "gws-usr-002",
                            "primaryEmail": "bob.martinez@acme.com",
                            "name": {"fullName": "Bob Martinez"},
                            "isEnrolledIn2Sv": False,
                            "suspended": False,
                            "lastLoginTime": (NOW - timedelta(days=1)).isoformat(),
                            "isAdmin": False,
                        },
                        {
                            "id": "gws-usr-003",
                            "primaryEmail": "carol.wang@acme.com",
                            "name": {"fullName": "Carol Wang"},
                            "isEnrolledIn2Sv": True,
                            "suspended": True,
                            "lastLoginTime": (NOW - timedelta(days=60)).isoformat(),
                            "isAdmin": False,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="google_workspace",
                source_type=SourceType.COLLABORATION,
                provider="google",
                event_type="gws_admin_activity",
                raw_data={
                    "activities": [
                        {
                            "id": "gws-act-001",
                            "actor": {"email": "alice.chen@acme.com"},
                            "event_name": "CHANGE_APPLICATION_SETTING",
                            "parameters": {"name": "ENABLE_LESS_SECURE_APPS", "value": "true"},
                            "time": (NOW - timedelta(hours=12)).isoformat(),
                        },
                        {
                            "id": "gws-act-002",
                            "actor": {"email": "alice.chen@acme.com"},
                            "event_name": "ADD_GROUP_MEMBER",
                            "parameters": {
                                "group": "security-team@acme.com",
                                "member": "bob.martinez@acme.com",
                            },
                            "time": (NOW - timedelta(hours=6)).isoformat(),
                        },
                    ]
                },
            )
        )

        # --- Rich data: users + auth logs ---
        _gw_users = RICH_DATA["users"][30:60]
        result.events.append(
            RawEventData(
                source="google_workspace",
                source_type=SourceType.COLLABORATION,
                provider="google",
                event_type="gw_users",
                raw_data={
                    "users": [
                        {
                            "id": u["user_id"],
                            "primaryEmail": u["email"],
                            "name": {"fullName": f"{u['first_name']} {u['last_name']}"},
                            "suspended": u["status"] != "active",
                            "isAdmin": random.random() < 0.1,
                            "isEnrolledIn2Sv": u["is_enrolled_mfa"],
                            "lastLoginTime": u["last_login"],
                            "creationTime": u["created_at"],
                        }
                        for u in _gw_users
                    ],
                },
            )
        )
        _gw_logs = RICH_DATA["auth_logs"][450:600]
        result.events.append(
            RawEventData(
                source="google_workspace",
                source_type=SourceType.COLLABORATION,
                provider="google",
                event_type="gw_login_events",
                raw_data={
                    "items": [
                        {
                            "id": {"time": log["timestamp"]},
                            "actor": {"email": log["email"]},
                            "events": [
                                {
                                    "name": "login_success"
                                    if log["result"] == "success"
                                    else "login_failure",
                                    "parameters": [{"name": "login_type", "value": log["factor"]}],
                                }
                            ],
                            "ipAddress": log["ip_address"],
                        }
                        for log in _gw_logs
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoSemgrepConnector(BaseConnector):
    """Simulates Semgrep code security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="semgrep",
            source_type=SourceType.CODE,
            provider="semgrep",
        )
        result.events.append(
            RawEventData(
                source="semgrep",
                source_type=SourceType.CODE,
                provider="semgrep",
                event_type="semgrep_findings",
                raw_data={
                    "findings": [
                        {
                            "id": "sg-find-001",
                            "rule_id": "python.lang.security.audit.dangerous-subprocess-use",
                            "severity": "critical",
                            "message": "SQL injection via string concatenation in query builder",
                            "path": "src/db/queries.py",
                            "line": 88,
                            "repository": "acme/platform-api",
                            "state": "open",
                            "first_seen": (NOW - timedelta(days=10)).isoformat(),
                        },
                        {
                            "id": "sg-find-002",
                            "rule_id": "python.flask.security.xss.direct-use-of-jinja2",
                            "severity": "high",
                            "message": "Potential XSS via unescaped template variable",
                            "path": "src/web/templates.py",
                            "line": 34,
                            "repository": "acme/platform-api",
                            "state": "open",
                            "first_seen": (NOW - timedelta(days=7)).isoformat(),
                        },
                        {
                            "id": "sg-find-003",
                            "rule_id": "python.lang.best-practice.open-never-closed",
                            "severity": "medium",
                            "message": "File handle opened but never closed",
                            "path": "src/utils/export.py",
                            "line": 12,
                            "repository": "acme/data-pipeline",
                            "state": "open",
                            "first_seen": (NOW - timedelta(days=3)).isoformat(),
                        },
                    ]
                },
            )
        )

        # --- Rich data: code findings ---
        _sg_findings = RICH_DATA["code_findings"][720:880]
        result.events.append(
            RawEventData(
                source="semgrep",
                source_type=SourceType.CODE,
                provider="semgrep",
                event_type="semgrep_findings",
                raw_data={"findings": _code_findings_as_semgrep(_sg_findings)},
            )
        )

        result.complete()
        return result


class DemoTrivyConnector(BaseConnector):
    """Simulates Trivy vulnerability scanner collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="trivy",
            source_type=SourceType.SCANNER,
            provider="trivy",
        )
        result.events.append(
            RawEventData(
                source="trivy",
                source_type=SourceType.SCANNER,
                provider="trivy",
                event_type="trivy_container_vulns",
                raw_data={
                    "target": "acme/platform-api:latest",
                    "vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-29018",
                            "PkgName": "libcurl",
                            "InstalledVersion": "7.88.1",
                            "FixedVersion": "8.6.0",
                            "Severity": "CRITICAL",
                            "Title": "libcurl HSTS bypass via IDN",
                            "Description": "HTTP Strict Transport Security bypass in libcurl",
                        },
                        {
                            "VulnerabilityID": "CVE-2024-28849",
                            "PkgName": "follow-redirects",
                            "InstalledVersion": "1.15.3",
                            "FixedVersion": "1.15.6",
                            "Severity": "HIGH",
                            "Title": "Credential leak on cross-origin redirect",
                            "Description": "Authorization header leaked to third-party site on redirect",
                        },
                        {
                            "VulnerabilityID": "CVE-2024-22365",
                            "PkgName": "pam",
                            "InstalledVersion": "1.5.2",
                            "FixedVersion": "1.5.3",
                            "Severity": "MEDIUM",
                            "Title": "Linux-PAM denial of service",
                            "Description": "Local DoS via pam_namespace.so misconfiguration",
                        },
                    ],
                },
            )
        )
        result.events.append(
            RawEventData(
                source="trivy",
                source_type=SourceType.SCANNER,
                provider="trivy",
                event_type="trivy_iac_misconfigs",
                raw_data={
                    "misconfigurations": [
                        {
                            "ID": "AVD-AWS-0086",
                            "Title": "S3 bucket has public access enabled",
                            "Severity": "HIGH",
                            "Resource": "aws_s3_bucket.data_export",
                            "File": "terraform/s3.tf",
                            "Line": 15,
                        },
                        {
                            "ID": "AVD-AWS-0107",
                            "Title": "RDS instance not encrypted at rest",
                            "Severity": "HIGH",
                            "Resource": "aws_db_instance.main",
                            "File": "terraform/rds.tf",
                            "Line": 8,
                        },
                    ]
                },
            )
        )

        # --- Rich data: vulnerabilities ---
        _trivy_vulns = RICH_DATA["vulnerabilities"][2200:2600]
        result.events.append(
            RawEventData(
                source="trivy",
                source_type=SourceType.SCANNER,
                provider="trivy",
                event_type="trivy_results",
                raw_data={"Results": [{"Vulnerabilities": _vulns_as_trivy(_trivy_vulns)}]},
            )
        )

        result.complete()
        return result


class DemoGitGuardianConnector(BaseConnector):
    """Simulates GitGuardian code security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="gitguardian",
            source_type=SourceType.CODE,
            provider="gitguardian",
        )
        result.events.append(
            RawEventData(
                source="gitguardian",
                source_type=SourceType.CODE,
                provider="gitguardian",
                event_type="gitguardian_incidents",
                raw_data={
                    "incidents": [
                        {
                            "id": "gg-inc-001",
                            "date": (NOW - timedelta(days=2)).isoformat(),
                            "detector_name": "AWS Keys",
                            "status": "OPEN",
                            "severity": "critical",
                            "secret_hash": "a1b2c3d4e5f6",
                            "repository": "acme/infrastructure",
                            "file_path": "deploy/config.py",
                            "author": "bob.martinez@acme.com",
                            "validity": "valid",
                        },
                        {
                            "id": "gg-inc-002",
                            "date": (NOW - timedelta(days=15)).isoformat(),
                            "detector_name": "Slack Bot Token",
                            "status": "RESOLVED",
                            "severity": "high",
                            "secret_hash": "f6e5d4c3b2a1",
                            "repository": "acme/chatbot",
                            "file_path": "src/integrations/slack.py",
                            "author": "alice.chen@acme.com",
                            "validity": "revoked",
                        },
                    ]
                },
            )
        )

        # --- Rich data: code findings as secrets ---
        _gg_findings = RICH_DATA["code_findings"][880:1050]
        result.events.append(
            RawEventData(
                source="gitguardian",
                source_type=SourceType.CODE,
                provider="gitguardian",
                event_type="gitguardian_incidents",
                raw_data={"incidents": _code_findings_as_gitguardian(_gg_findings)},
            )
        )

        result.complete()
        return result


class DemoVeracodeConnector(BaseConnector):
    """Simulates Veracode code security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="veracode",
            source_type=SourceType.CODE,
            provider="veracode",
        )
        result.events.append(
            RawEventData(
                source="veracode",
                source_type=SourceType.CODE,
                provider="veracode",
                event_type="veracode_applications",
                raw_data={
                    "applications": [
                        {
                            "guid": "vc-app-001",
                            "profile": {"name": "Platform API"},
                            "policy_compliance_status": "PASS",
                            "last_scan_date": (NOW - timedelta(days=1)).isoformat(),
                            "business_criticality": "Very High",
                        },
                        {
                            "guid": "vc-app-002",
                            "profile": {"name": "Data Pipeline"},
                            "policy_compliance_status": "DID_NOT_PASS",
                            "last_scan_date": (NOW - timedelta(days=7)).isoformat(),
                            "business_criticality": "High",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="veracode",
                source_type=SourceType.CODE,
                provider="veracode",
                event_type="veracode_findings",
                raw_data={
                    "findings": [
                        {
                            "issue_id": "vc-find-001",
                            "scan_type": "STATIC",
                            "severity": 5,
                            "severity_label": "Very High",
                            "cwe_id": 89,
                            "cwe_name": "SQL Injection",
                            "file_path": "src/db/queries.py",
                            "line": 142,
                            "finding_status": "OPEN",
                            "app_guid": "vc-app-002",
                        },
                        {
                            "issue_id": "vc-find-002",
                            "scan_type": "DYNAMIC",
                            "severity": 3,
                            "severity_label": "Medium",
                            "cwe_id": 79,
                            "cwe_name": "Cross-site Scripting",
                            "file_path": "src/web/views.py",
                            "line": 55,
                            "finding_status": "OPEN",
                            "app_guid": "vc-app-001",
                        },
                    ]
                },
            )
        )

        # --- Rich data: code findings ---
        _vc_findings = RICH_DATA["code_findings"][1050:1200]
        result.events.append(
            RawEventData(
                source="veracode",
                source_type=SourceType.CODE,
                provider="veracode",
                event_type="veracode_findings",
                raw_data={"findings": _code_findings_as_veracode(_vc_findings)},
            )
        )

        result.complete()
        return result


class DemoTerraformCloudConnector(BaseConnector):
    """Simulates Terraform Cloud infrastructure collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="terraform_cloud",
            source_type=SourceType.INFRASTRUCTURE,
            provider="hashicorp",
        )
        result.events.append(
            RawEventData(
                source="terraform_cloud",
                source_type=SourceType.INFRASTRUCTURE,
                provider="hashicorp",
                event_type="tfc_workspaces",
                raw_data={
                    "workspaces": [
                        {
                            "id": "ws-prod-001",
                            "name": "production-infra",
                            "environment": "production",
                            "terraform_version": "1.7.3",
                            "auto_apply": False,
                            "resource_count": 142,
                            "current_run_status": "applied",
                            "drift_detected": False,
                            "updated_at": (NOW - timedelta(hours=4)).isoformat(),
                        },
                        {
                            "id": "ws-stg-001",
                            "name": "staging-infra",
                            "environment": "staging",
                            "terraform_version": "1.6.6",
                            "auto_apply": True,
                            "resource_count": 98,
                            "current_run_status": "planned",
                            "drift_detected": True,
                            "updated_at": (NOW - timedelta(days=2)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="terraform_cloud",
                source_type=SourceType.INFRASTRUCTURE,
                provider="hashicorp",
                event_type="tfc_policy_checks",
                raw_data={
                    "policy_checks": [
                        {
                            "id": "polchk-001",
                            "workspace_id": "ws-prod-001",
                            "result": "passed",
                            "policy_set": "security-policies",
                            "checked_at": (NOW - timedelta(hours=4)).isoformat(),
                        },
                        {
                            "id": "polchk-002",
                            "workspace_id": "ws-stg-001",
                            "result": "hard_failed",
                            "policy_set": "security-policies",
                            "failure_reason": "Sentinel policy 'no-public-s3' failed",
                            "checked_at": (NOW - timedelta(days=2)).isoformat(),
                        },
                    ]
                },
            )
        )

        # --- Rich data: terraform workspaces + IaC misconfigs ---
        _tf_ws = RICH_DATA["terraform_workspaces"][0:40]
        result.events.append(
            RawEventData(
                source="hashicorp",
                source_type=SourceType.INFRASTRUCTURE,
                provider="hashicorp",
                event_type="tfc_workspaces",
                raw_data={"data": _tf_ws},
            )
        )
        _tf_iac = RICH_DATA["iac_misconfigs"][0:75]
        result.events.append(
            RawEventData(
                source="hashicorp",
                source_type=SourceType.INFRASTRUCTURE,
                provider="hashicorp",
                event_type="tfc_policy_checks",
                raw_data={"data": _tf_iac},
            )
        )

        result.complete()
        return result


class DemoAquaConnector(BaseConnector):
    """Simulates Aqua container security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="aqua",
            source_type=SourceType.CONTAINER_SECURITY,
            provider="aqua",
        )
        result.events.append(
            RawEventData(
                source="aqua",
                source_type=SourceType.CONTAINER_SECURITY,
                provider="aqua",
                event_type="aqua_images",
                raw_data={
                    "images": [
                        {
                            "name": "acme/platform-api:v2.4.1",
                            "registry": "ecr",
                            "os": "debian:12",
                            "critical_vulns": 0,
                            "high_vulns": 2,
                            "compliant": True,
                            "scan_date": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "name": "acme/data-worker:v1.8.0",
                            "registry": "ecr",
                            "os": "alpine:3.18",
                            "critical_vulns": 3,
                            "high_vulns": 5,
                            "compliant": False,
                            "scan_date": (NOW - timedelta(hours=2)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="aqua",
                source_type=SourceType.CONTAINER_SECURITY,
                provider="aqua",
                event_type="aqua_compliance",
                raw_data={
                    "checks": [
                        {
                            "id": "CIS-DI-0001",
                            "title": "Ensure a user for the container has been created",
                            "status": "pass",
                            "benchmark": "CIS Docker Benchmark v1.6",
                            "image": "acme/platform-api:v2.4.1",
                        },
                        {
                            "id": "CIS-DI-0005",
                            "title": "Ensure Content Trust is enabled",
                            "status": "fail",
                            "benchmark": "CIS Docker Benchmark v1.6",
                            "image": "acme/data-worker:v1.8.0",
                        },
                    ]
                },
            )
        )

        # --- Rich data: container images ---
        _aqua_images = RICH_DATA["container_images"][0:75]
        result.events.append(
            RawEventData(
                source="aqua",
                source_type=SourceType.CONTAINER_SECURITY,
                provider="aqua",
                event_type="aqua_images",
                raw_data={"result": _aqua_images},
            )
        )

        result.complete()
        return result


class DemoKandjiConnector(BaseConnector):
    """Simulates Kandji MDM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="kandji",
            source_type=SourceType.MDM,
            provider="kandji",
        )
        result.events.append(
            RawEventData(
                source="kandji",
                source_type=SourceType.MDM,
                provider="kandji",
                event_type="kandji_devices",
                raw_data={
                    "devices": [
                        {
                            "device_id": "kj-dev-001",
                            "device_name": "ENG-MBP-201",
                            "model": "MacBook Pro 16-inch (M3 Max)",
                            "os_version": "14.3.1",
                            "serial_number": "C02ABC123DEF",
                            "filevault_enabled": True,
                            "firewall_enabled": True,
                            "user": "alice.chen@acme.com",
                            "last_check_in": NOW.isoformat(),
                        },
                        {
                            "device_id": "kj-dev-002",
                            "device_name": "SALES-MBP-042",
                            "model": "MacBook Air 13-inch (M2)",
                            "os_version": "14.3.1",
                            "serial_number": "C02DEF456GHI",
                            "filevault_enabled": False,
                            "firewall_enabled": True,
                            "user": "dave.johnson@acme.com",
                            "last_check_in": (NOW - timedelta(hours=12)).isoformat(),
                        },
                        {
                            "device_id": "kj-dev-003",
                            "device_name": "EXEC-MBP-001",
                            "model": "MacBook Pro 14-inch (M3 Pro)",
                            "os_version": "13.6.4",
                            "serial_number": "C02GHI789JKL",
                            "filevault_enabled": True,
                            "firewall_enabled": False,
                            "user": "ceo@acme.com",
                            "last_check_in": (NOW - timedelta(days=3)).isoformat(),
                        },
                    ]
                },
            )
        )

        # --- Rich data: devices ---
        _kandji_devices = RICH_DATA["devices"][200:300]
        result.events.append(
            RawEventData(
                source="kandji",
                source_type=SourceType.MDM,
                provider="kandji",
                event_type="kandji_devices",
                raw_data={"devices": _devices_as_kandji(_kandji_devices)},
            )
        )

        result.complete()
        return result


class DemoGrafanaConnector(BaseConnector):
    """Simulates Grafana observability collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="grafana",
            source_type=SourceType.OBSERVABILITY,
            provider="grafana",
        )
        result.events.append(
            RawEventData(
                source="grafana",
                source_type=SourceType.OBSERVABILITY,
                provider="grafana",
                event_type="grafana_alerts",
                raw_data={
                    "alerts": [
                        {
                            "id": "gf-alert-001",
                            "title": "High API latency (p99 > 2s)",
                            "state": "firing",
                            "severity": "warning",
                            "dashboard_uid": "api-perf-001",
                            "panel_id": 4,
                            "value": 2.8,
                            "started_at": (NOW - timedelta(hours=1)).isoformat(),
                        },
                        {
                            "id": "gf-alert-002",
                            "title": "Database connection pool exhaustion",
                            "state": "resolved",
                            "severity": "critical",
                            "dashboard_uid": "db-health-001",
                            "panel_id": 2,
                            "value": 0.15,
                            "started_at": (NOW - timedelta(hours=6)).isoformat(),
                            "resolved_at": (NOW - timedelta(hours=5)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="grafana",
                source_type=SourceType.OBSERVABILITY,
                provider="grafana",
                event_type="grafana_datasources",
                raw_data={
                    "datasources": [
                        {
                            "id": 1,
                            "name": "Prometheus",
                            "type": "prometheus",
                            "url": "http://prometheus:9090",
                            "access": "proxy",
                            "is_default": True,
                        },
                        {
                            "id": 2,
                            "name": "Loki",
                            "type": "loki",
                            "url": "http://loki:3100",
                            "access": "proxy",
                            "is_default": False,
                        },
                    ]
                },
            )
        )

        # --- Rich data: security alerts ---
        _graf_alerts = RICH_DATA["security_alerts"][80:120]
        result.events.append(
            RawEventData(
                source="grafana",
                source_type=SourceType.OBSERVABILITY,
                provider="grafana",
                event_type="grafana_alerts",
                raw_data={
                    "alerts": [
                        {
                            "id": a["alert_id"],
                            "labels": {"alertname": a["title"], "severity": a["severity"]},
                            "state": "firing" if a["status"] == "new" else "normal",
                            "activeAt": a["detected_at"],
                            "resolvedAt": a.get("resolved_at"),
                        }
                        for a in _graf_alerts
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoBitSightConnector(BaseConnector):
    """Simulates BitSight third-party risk collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="bitsight",
            source_type=SourceType.THIRD_PARTY_RISK,
            provider="bitsight",
        )
        result.events.append(
            RawEventData(
                source="bitsight",
                source_type=SourceType.THIRD_PARTY_RISK,
                provider="bitsight",
                event_type="bitsight_ratings",
                raw_data={
                    "company": {
                        "name": "Acme Corp",
                        "guid": "bs-comp-001",
                        "rating": 640,
                        "rating_date": NOW.strftime("%Y-%m-%d"),
                        "industry": "Technology",
                        "percentile": 45,
                    }
                },
            )
        )
        result.events.append(
            RawEventData(
                source="bitsight",
                source_type=SourceType.THIRD_PARTY_RISK,
                provider="bitsight",
                event_type="bitsight_risk_vectors",
                raw_data={
                    "risk_vectors": [
                        {
                            "name": "Patching Cadence",
                            "grade": "B",
                            "rating": 720,
                            "percentile": 65,
                            "details": "Most systems patched within 30 days",
                        },
                        {
                            "name": "Open Ports",
                            "grade": "D",
                            "rating": 480,
                            "percentile": 20,
                            "details": "12 unnecessary open ports detected on public-facing hosts",
                        },
                    ]
                },
            )
        )

        # --- Rich data: vendor assessments ---
        _bs_vendors = RICH_DATA["vendor_assessments"][30:60]
        result.events.append(
            RawEventData(
                source="bitsight",
                source_type=SourceType.THIRD_PARTY_RISK,
                provider="bitsight",
                event_type="bitsight_companies",
                raw_data={"companies": _vendors_as_bitsight(_bs_vendors)},
            )
        )

        result.complete()
        return result


class DemoGustoConnector(BaseConnector):
    """Simulates Gusto HR collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="gusto",
            source_type=SourceType.HRIS,
            provider="gusto",
        )
        result.events.append(
            RawEventData(
                source="gusto",
                source_type=SourceType.HRIS,
                provider="gusto",
                event_type="gusto_employees",
                raw_data={
                    "employees": [
                        {
                            "id": "gusto-emp-001",
                            "first_name": "Alice",
                            "last_name": "Chen",
                            "email": "alice.chen@acme.com",
                            "department": "Engineering",
                            "status": "active",
                            "hire_date": "2023-01-15",
                            "manager_id": "gusto-emp-010",
                        },
                        {
                            "id": "gusto-emp-002",
                            "first_name": "Bob",
                            "last_name": "Martinez",
                            "email": "bob.martinez@acme.com",
                            "department": "Engineering",
                            "status": "active",
                            "hire_date": "2023-06-01",
                            "manager_id": "gusto-emp-010",
                        },
                        {
                            "id": "gusto-emp-003",
                            "first_name": "Dave",
                            "last_name": "Johnson",
                            "email": "dave.johnson@acme.com",
                            "department": "Sales",
                            "status": "terminated",
                            "hire_date": "2022-03-10",
                            "termination_date": "2024-11-30",
                            "manager_id": "gusto-emp-011",
                        },
                    ]
                },
            )
        )

        # --- Rich data: employees ---
        _gusto_employees = RICH_DATA["employees"][250:375]
        result.events.append(
            RawEventData(
                source="gusto",
                source_type=SourceType.HRIS,
                provider="gusto",
                event_type="gusto_employees",
                raw_data={"employees": _employees_as_gusto(_gusto_employees)},
            )
        )

        result.complete()
        return result


class DemoRipplingConnector(BaseConnector):
    """Simulates Rippling HR collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="rippling",
            source_type=SourceType.HRIS,
            provider="rippling",
        )
        result.events.append(
            RawEventData(
                source="rippling",
                source_type=SourceType.HRIS,
                provider="rippling",
                event_type="rippling_employees",
                raw_data={
                    "employees": [
                        {
                            "id": "rpl-emp-001",
                            "name": "Alice Chen",
                            "email": "alice.chen@acme.com",
                            "department": "Engineering",
                            "employment_status": "ACTIVE",
                            "start_date": "2023-01-15",
                            "role": "Senior Engineer",
                        },
                        {
                            "id": "rpl-emp-002",
                            "name": "Bob Martinez",
                            "email": "bob.martinez@acme.com",
                            "department": "Engineering",
                            "employment_status": "ACTIVE",
                            "start_date": "2023-06-01",
                            "role": "DevOps Engineer",
                        },
                        {
                            "id": "rpl-emp-003",
                            "name": "Carol Wang",
                            "email": "carol.wang@acme.com",
                            "department": "Marketing",
                            "employment_status": "TERMINATED",
                            "start_date": "2022-08-15",
                            "end_date": "2024-10-31",
                            "role": "Marketing Manager",
                            "has_company_devices": True,
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="rippling",
                source_type=SourceType.HRIS,
                provider="rippling",
                event_type="rippling_devices",
                raw_data={
                    "devices": [
                        {
                            "id": "rpl-dev-001",
                            "device_name": "ENG-MBP-301",
                            "assigned_to": "rpl-emp-001",
                            "managed": True,
                            "os": "macOS 14.3",
                            "encryption_enabled": True,
                        },
                        {
                            "id": "rpl-dev-002",
                            "device_name": "MKT-MBP-050",
                            "assigned_to": "rpl-emp-003",
                            "managed": False,
                            "os": "macOS 13.6",
                            "encryption_enabled": True,
                        },
                    ]
                },
            )
        )

        # --- Rich data: employees ---
        _rip_employees = RICH_DATA["employees"][375:500]
        result.events.append(
            RawEventData(
                source="rippling",
                source_type=SourceType.HRIS,
                provider="rippling",
                event_type="rippling_employees",
                raw_data={"data": _employees_as_rippling(_rip_employees)},
            )
        )

        result.complete()
        return result


class DemoSageMakerConnector(BaseConnector):
    """Simulates AWS SageMaker AI/ML collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="sagemaker",
            source_type=SourceType.AI_ML,
            provider="aws",
        )
        result.events.append(
            RawEventData(
                source="sagemaker",
                source_type=SourceType.AI_ML,
                provider="aws",
                event_type="sagemaker_endpoints",
                raw_data={
                    "endpoints": [
                        {
                            "EndpointName": "fraud-detection-prod",
                            "EndpointStatus": "InService",
                            "KmsKeyId": "arn:aws:kms:us-east-1:912345678012:key/abc-123",
                            "CreationTime": "2024-06-01T00:00:00Z",
                            "LastModifiedTime": (NOW - timedelta(hours=12)).isoformat(),
                            "InstanceType": "ml.m5.xlarge",
                        },
                        {
                            "EndpointName": "recommendation-staging",
                            "EndpointStatus": "InService",
                            "KmsKeyId": None,
                            "CreationTime": "2024-09-15T00:00:00Z",
                            "LastModifiedTime": (NOW - timedelta(days=5)).isoformat(),
                            "InstanceType": "ml.m5.large",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sagemaker",
                source_type=SourceType.AI_ML,
                provider="aws",
                event_type="sagemaker_notebooks",
                raw_data={
                    "notebooks": [
                        {
                            "NotebookInstanceName": "ds-team-notebook-01",
                            "NotebookInstanceStatus": "InService",
                            "RootAccess": "Disabled",
                            "DirectInternetAccess": "Disabled",
                            "KmsKeyId": "arn:aws:kms:us-east-1:912345678012:key/def-456",
                            "VolumeSizeInGB": 50,
                        },
                        {
                            "NotebookInstanceName": "research-notebook-02",
                            "NotebookInstanceStatus": "InService",
                            "RootAccess": "Enabled",
                            "DirectInternetAccess": "Enabled",
                            "KmsKeyId": None,
                            "VolumeSizeInGB": 100,
                        },
                    ]
                },
            )
        )

        # --- Rich data: cloud instances (ML) + code findings ---
        _sm_instances = [i for i in RICH_DATA["cloud_instances"] if i["cloud"] == "aws"][:20]
        result.events.append(
            RawEventData(
                source="aws_sagemaker",
                source_type=SourceType.AI_ML,
                provider="aws",
                event_type="sagemaker_endpoints",
                raw_data={
                    "Endpoints": [
                        {
                            "EndpointName": f"ml-{i['name']}",
                            "EndpointStatus": i["state"].capitalize(),
                            "CreationTime": i["launched_at"],
                            "InstanceType": i["instance_type"],
                        }
                        for i in _sm_instances
                    ]
                },
            )
        )

        result.complete()
        return result


class DemoDatabricksConnector(BaseConnector):
    """Simulates Databricks data governance collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="databricks",
            source_type=SourceType.DATA_GOVERNANCE,
            provider="databricks",
        )
        result.events.append(
            RawEventData(
                source="databricks",
                source_type=SourceType.DATA_GOVERNANCE,
                provider="databricks",
                event_type="databricks_clusters",
                raw_data={
                    "clusters": [
                        {
                            "cluster_id": "db-clust-001",
                            "cluster_name": "production-etl",
                            "state": "RUNNING",
                            "spark_version": "14.3.x-scala2.12",
                            "node_type_id": "i3.xlarge",
                            "num_workers": 4,
                            "enable_elastic_disk": True,
                            "disk_encryption": True,
                            "creator_user_name": "alice.chen@acme.com",
                        },
                        {
                            "cluster_id": "db-clust-002",
                            "cluster_name": "dev-exploration",
                            "state": "RUNNING",
                            "spark_version": "13.3.x-scala2.12",
                            "node_type_id": "m5.large",
                            "num_workers": 2,
                            "enable_elastic_disk": False,
                            "disk_encryption": False,
                            "creator_user_name": "bob.martinez@acme.com",
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="databricks",
                source_type=SourceType.DATA_GOVERNANCE,
                provider="databricks",
                event_type="databricks_unity_catalog",
                raw_data={
                    "tables": [
                        {
                            "catalog_name": "main",
                            "schema_name": "finance",
                            "table_name": "transactions",
                            "table_type": "MANAGED",
                            "owner": "finance-team",
                            "has_acl": True,
                            "column_count": 15,
                            "row_count": 2500000,
                        },
                        {
                            "catalog_name": "main",
                            "schema_name": "raw",
                            "table_name": "user_events",
                            "table_type": "MANAGED",
                            "owner": "data-eng",
                            "has_acl": False,
                            "column_count": 22,
                            "row_count": 15000000,
                        },
                    ]
                },
            )
        )

        # --- Rich data: cloud instances + code findings ---
        _db_instances = [i for i in RICH_DATA["cloud_instances"] if i["cloud"] == "aws"][20:40]
        result.events.append(
            RawEventData(
                source="databricks",
                source_type=SourceType.DATA_GOVERNANCE,
                provider="databricks",
                event_type="databricks_clusters",
                raw_data={
                    "clusters": [
                        {
                            "cluster_id": i["instance_id"],
                            "cluster_name": f"db-{i['name']}",
                            "state": i["state"].upper(),
                            "spark_version": "14.3.x-scala2.12",
                            "node_type_id": i["instance_type"],
                            "start_time": i["launched_at"],
                        }
                        for i in _db_instances
                    ]
                },
            )
        )

        result.complete()
        return result


class DemoExchangeOnlineConnector(BaseConnector):
    """Simulates Exchange Online email security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        _ensure_rich_data()
        result = ConnectorResult(
            connector_name=self.name,
            source="exchange_online",
            source_type=SourceType.EMAIL_SECURITY,
            provider="microsoft",
        )
        result.events.append(
            RawEventData(
                source="exchange_online",
                source_type=SourceType.EMAIL_SECURITY,
                provider="microsoft",
                event_type="exchange_mail_flow_rules",
                raw_data={
                    "rules": [
                        {
                            "id": "exo-rule-001",
                            "name": "Encrypt PII Outbound",
                            "state": "Enabled",
                            "priority": 0,
                            "mode": "Enforce",
                            "conditions": ["SubjectContainsWords: SSN, PII, Confidential"],
                            "actions": ["ApplyRightsProtectionTemplate: Encrypt"],
                        },
                        {
                            "id": "exo-rule-002",
                            "name": "Allow External Forwarding for Execs",
                            "state": "Enabled",
                            "priority": 1,
                            "mode": "Enforce",
                            "conditions": ["FromMemberOf: exec-group@acme.com"],
                            "actions": ["RedirectMessageTo: exec-assistant@external-firm.com"],
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="exchange_online",
                source_type=SourceType.EMAIL_SECURITY,
                provider="microsoft",
                event_type="exchange_atp_policies",
                raw_data={
                    "atp_policies": [
                        {
                            "id": "atp-pol-001",
                            "name": "Default Safe Attachments Policy",
                            "enabled": True,
                            "action": "DynamicDelivery",
                            "safe_links_enabled": True,
                            "anti_phishing_enabled": True,
                            "impersonation_protection": True,
                            "applied_to": "all-users@acme.com",
                        }
                    ]
                },
            )
        )

        # --- Rich data: email events ---
        _exo_emails = RICH_DATA["email_events"][250:400]
        result.events.append(
            RawEventData(
                source="exchange_online",
                source_type=SourceType.EMAIL_SECURITY,
                provider="microsoft",
                event_type="exchange_message_trace",
                raw_data={
                    "value": [
                        {
                            "MessageId": e["message_id"],
                            "SenderAddress": e["from_address"],
                            "RecipientAddress": e["to_address"],
                            "Subject": e["subject"],
                            "Status": e["status"].capitalize(),
                            "Direction": e["direction"],
                        }
                        for e in _exo_emails
                    ],
                },
            )
        )

        result.complete()
        return result


class DemoJenkinsConnector(BaseConnector):
    """Simulates Jenkins CI/CD server collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="jenkins",
            source_type=SourceType.CI_CD,
            provider="jenkins",
        )
        result.events.append(
            RawEventData(
                source="jenkins",
                source_type=SourceType.CI_CD,
                provider="jenkins",
                event_type="jenkins_jobs",
                raw_data={
                    "jobs": [
                        {
                            "name": "backend-build",
                            "url": "https://jenkins.acme.com/job/backend-build/",
                            "color": "blue",
                            "last_build": {
                                "number": 1247,
                                "result": "SUCCESS",
                                "timestamp": int((NOW - timedelta(hours=1)).timestamp() * 1000),
                                "duration": 184000,
                            },
                        },
                        {
                            "name": "frontend-deploy",
                            "url": "https://jenkins.acme.com/job/frontend-deploy/",
                            "color": "blue",
                            "last_build": {
                                "number": 893,
                                "result": "SUCCESS",
                                "timestamp": int((NOW - timedelta(hours=3)).timestamp() * 1000),
                                "duration": 312000,
                            },
                        },
                        {
                            "name": "security-scan-sast",
                            "url": "https://jenkins.acme.com/job/security-scan-sast/",
                            "color": "red",
                            "last_build": {
                                "number": 456,
                                "result": "FAILURE",
                                "timestamp": int((NOW - timedelta(hours=2)).timestamp() * 1000),
                                "duration": 97000,
                                "failure_reason": "SAST scan found 3 critical vulnerabilities in auth module",
                            },
                        },
                        {
                            "name": "integration-tests",
                            "url": "https://jenkins.acme.com/job/integration-tests/",
                            "color": "yellow",
                            "last_build": {
                                "number": 2104,
                                "result": "UNSTABLE",
                                "timestamp": int((NOW - timedelta(minutes=45)).timestamp() * 1000),
                                "duration": 540000,
                                "test_report": {
                                    "total": 342,
                                    "passed": 338,
                                    "failed": 4,
                                    "skipped": 0,
                                },
                            },
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="jenkins",
                source_type=SourceType.CI_CD,
                provider="jenkins",
                event_type="jenkins_nodes",
                raw_data={
                    "computer": [
                        {
                            "displayName": "built-in",
                            "offline": False,
                            "temporarilyOffline": False,
                            "numExecutors": 2,
                            "idle": False,
                            "jnlpAgent": False,
                            "monitorData": {
                                "hudson.node_monitors.DiskSpaceMonitor": {"size": 53687091200}
                            },
                        },
                        {
                            "displayName": "build-agent-01",
                            "offline": False,
                            "temporarilyOffline": False,
                            "numExecutors": 4,
                            "idle": True,
                            "jnlpAgent": True,
                            "monitorData": {
                                "hudson.node_monitors.DiskSpaceMonitor": {"size": 107374182400}
                            },
                        },
                        {
                            "displayName": "build-agent-02",
                            "offline": True,
                            "temporarilyOffline": False,
                            "numExecutors": 4,
                            "idle": False,
                            "jnlpAgent": True,
                            "offlineCauseReason": "Connection lost — agent process terminated unexpectedly",
                            "monitorData": {},
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="jenkins",
                source_type=SourceType.CI_CD,
                provider="jenkins",
                event_type="jenkins_security",
                raw_data={
                    "useSecurity": True,
                    "crumbIssuer": {"crumbRequestField": "Jenkins-Crumb"},
                    "securityRealm": {
                        "type": "LDAPSecurityRealm",
                        "server": "ldap://ldap.acme.com:389",
                    },
                    "authorizationStrategy": {"type": "RoleBased"},
                    "slaveAgentPort": -1,
                    "markupFormatter": "EscapedMarkupFormatter",
                },
            )
        )
        result.complete()
        return result


class DemoGitHubActionsConnector(BaseConnector):
    """Simulates GitHub Actions CI/CD collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="github_actions",
            source_type=SourceType.CI_CD,
            provider="github",
        )
        result.events.append(
            RawEventData(
                source="github_actions",
                source_type=SourceType.CI_CD,
                provider="github",
                event_type="gha_workflow_runs",
                raw_data={
                    "total_count": 5,
                    "workflow_runs": [
                        {
                            "id": 9800001,
                            "name": "CI Pipeline",
                            "head_branch": "main",
                            "status": "completed",
                            "conclusion": "success",
                            "run_number": 1584,
                            "event": "push",
                            "created_at": (NOW - timedelta(hours=1)).isoformat(),
                            "updated_at": (NOW - timedelta(minutes=45)).isoformat(),
                            "run_attempt": 1,
                            "triggering_actor": {"login": "dev-alice"},
                        },
                        {
                            "id": 9800002,
                            "name": "CI Pipeline",
                            "head_branch": "feat/user-auth",
                            "status": "completed",
                            "conclusion": "success",
                            "run_number": 1583,
                            "event": "pull_request",
                            "created_at": (NOW - timedelta(hours=2)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=1, minutes=30)).isoformat(),
                            "run_attempt": 1,
                            "triggering_actor": {"login": "dev-bob"},
                        },
                        {
                            "id": 9800003,
                            "name": "Nightly Security Scan",
                            "head_branch": "main",
                            "status": "completed",
                            "conclusion": "success",
                            "run_number": 312,
                            "event": "schedule",
                            "created_at": (NOW - timedelta(hours=8)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=7)).isoformat(),
                            "run_attempt": 1,
                            "triggering_actor": {"login": "github-actions[bot]"},
                        },
                        {
                            "id": 9800004,
                            "name": "SAST / Dependency Audit",
                            "head_branch": "feat/payments-v2",
                            "status": "completed",
                            "conclusion": "failure",
                            "run_number": 87,
                            "event": "pull_request",
                            "created_at": (NOW - timedelta(hours=3)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=2, minutes=50)).isoformat(),
                            "run_attempt": 1,
                            "triggering_actor": {"login": "dev-carol"},
                            "failure_reason": "CodeQL found SQL injection in payments/checkout.py:142",
                        },
                        {
                            "id": 9800005,
                            "name": "Deploy Staging",
                            "head_branch": "release/2.4.0",
                            "status": "completed",
                            "conclusion": "cancelled",
                            "run_number": 45,
                            "event": "workflow_dispatch",
                            "created_at": (NOW - timedelta(hours=5)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=4, minutes=55)).isoformat(),
                            "run_attempt": 1,
                            "triggering_actor": {"login": "dev-dave"},
                        },
                    ],
                },
            )
        )
        result.events.append(
            RawEventData(
                source="github_actions",
                source_type=SourceType.CI_CD,
                provider="github",
                event_type="gha_code_scanning",
                raw_data={
                    "alerts": [
                        {
                            "number": 101,
                            "rule": {
                                "id": "py/sql-injection",
                                "severity": "error",
                                "description": "SQL Injection",
                            },
                            "state": "open",
                            "tool": {"name": "CodeQL"},
                            "most_recent_instance": {
                                "ref": "refs/heads/feat/payments-v2",
                                "location": {"path": "payments/checkout.py", "start_line": 142},
                                "message": {"text": "Unsanitized user input flows into SQL query"},
                                "classifications": ["security"],
                            },
                            "severity": "critical",
                            "created_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "number": 102,
                            "rule": {
                                "id": "js/xss",
                                "severity": "warning",
                                "description": "Cross-site Scripting",
                            },
                            "state": "open",
                            "tool": {"name": "CodeQL"},
                            "most_recent_instance": {
                                "ref": "refs/heads/main",
                                "location": {
                                    "path": "frontend/src/components/UserProfile.jsx",
                                    "start_line": 87,
                                },
                                "message": {
                                    "text": "User-controlled value rendered without escaping"
                                },
                                "classifications": ["security"],
                            },
                            "severity": "high",
                            "created_at": (NOW - timedelta(days=2)).isoformat(),
                        },
                        {
                            "number": 103,
                            "rule": {
                                "id": "py/insecure-hash",
                                "severity": "note",
                                "description": "Use of insecure hash algorithm",
                            },
                            "state": "open",
                            "tool": {"name": "CodeQL"},
                            "most_recent_instance": {
                                "ref": "refs/heads/main",
                                "location": {"path": "utils/legacy_auth.py", "start_line": 23},
                                "message": {"text": "MD5 hash used for password comparison"},
                                "classifications": ["security"],
                            },
                            "severity": "medium",
                            "created_at": (NOW - timedelta(days=14)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="github_actions",
                source_type=SourceType.CI_CD,
                provider="github",
                event_type="gha_runners",
                raw_data={
                    "total_count": 2,
                    "runners": [
                        {
                            "id": 55001,
                            "name": "github-hosted-ubuntu-latest",
                            "os": "Linux",
                            "status": "online",
                            "busy": False,
                            "labels": [{"name": "self-hosted"}, {"name": "Linux"}, {"name": "X64"}],
                        },
                        {
                            "id": 55002,
                            "name": "self-hosted-gpu-runner",
                            "os": "Linux",
                            "status": "offline",
                            "busy": False,
                            "labels": [{"name": "self-hosted"}, {"name": "Linux"}, {"name": "GPU"}],
                            "last_active_at": (NOW - timedelta(days=3)).isoformat(),
                        },
                    ],
                },
            )
        )
        result.complete()
        return result


class DemoGitLabCIConnector(BaseConnector):
    """Simulates GitLab CI/CD pipeline collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="gitlab_ci",
            source_type=SourceType.CI_CD,
            provider="gitlab",
        )
        result.events.append(
            RawEventData(
                source="gitlab_ci",
                source_type=SourceType.CI_CD,
                provider="gitlab",
                event_type="gitlab_ci_pipelines",
                raw_data={
                    "pipelines": [
                        {
                            "id": 720001,
                            "iid": 4501,
                            "project_id": 42,
                            "status": "success",
                            "ref": "main",
                            "sha": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                            "source": "push",
                            "created_at": (NOW - timedelta(hours=2)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=1, minutes=40)).isoformat(),
                            "duration": 1200,
                            "user": {"username": "gl-dev-alice"},
                            "stages": ["build", "test", "deploy"],
                        },
                        {
                            "id": 720002,
                            "iid": 4502,
                            "project_id": 42,
                            "status": "success",
                            "ref": "feat/api-v3",
                            "sha": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
                            "source": "merge_request_event",
                            "created_at": (NOW - timedelta(hours=4)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3, minutes=20)).isoformat(),
                            "duration": 2400,
                            "user": {"username": "gl-dev-bob"},
                            "stages": ["build", "test", "sast", "deploy"],
                        },
                        {
                            "id": 720003,
                            "iid": 4503,
                            "project_id": 42,
                            "status": "error",
                            "ref": "feat/data-export",
                            "sha": "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                            "source": "merge_request_event",
                            "created_at": (NOW - timedelta(hours=6)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=5, minutes=30)).isoformat(),
                            "duration": 480,
                            "user": {"username": "gl-dev-carol"},
                            "stages": ["build", "test", "sast"],
                            "failed_jobs": [
                                {
                                    "name": "sast-semgrep",
                                    "stage": "sast",
                                    "failure_reason": "SAST detected hardcoded credentials in config/database.yml",
                                }
                            ],
                        },
                        {
                            "id": 720004,
                            "iid": 4504,
                            "project_id": 42,
                            "status": "running",
                            "ref": "main",
                            "sha": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
                            "source": "schedule",
                            "created_at": (NOW - timedelta(minutes=15)).isoformat(),
                            "updated_at": (NOW - timedelta(minutes=5)).isoformat(),
                            "duration": None,
                            "user": {"username": "gl-bot"},
                            "stages": ["build", "test", "sast", "dast", "deploy"],
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="gitlab_ci",
                source_type=SourceType.CI_CD,
                provider="gitlab",
                event_type="gitlab_ci_variables",
                raw_data={
                    "variables": [
                        {
                            "key": "DEPLOY_TOKEN",
                            "variable_type": "env_var",
                            "protected": True,
                            "masked": True,
                            "environment_scope": "production",
                        },
                        {
                            "key": "STAGING_API_KEY",
                            "variable_type": "env_var",
                            "protected": True,
                            "masked": True,
                            "environment_scope": "staging",
                        },
                        {
                            "key": "DB_SECRET_PASSWORD",
                            "variable_type": "env_var",
                            "protected": False,
                            "masked": False,
                            "environment_scope": "*",
                        },
                    ]
                },
            )
        )
        result.complete()
        return result


class DemoCircleCIConnector(BaseConnector):
    """Simulates CircleCI pipeline collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="circleci",
            source_type=SourceType.CI_CD,
            provider="circleci",
        )
        result.events.append(
            RawEventData(
                source="circleci",
                source_type=SourceType.CI_CD,
                provider="circleci",
                event_type="circleci_pipelines",
                raw_data={
                    "items": [
                        {
                            "id": "cc-pipe-001",
                            "project_slug": "gh/acme-corp/backend-api",
                            "number": 2891,
                            "state": "created",
                            "status": "success",
                            "created_at": (NOW - timedelta(hours=1)).isoformat(),
                            "trigger": {"type": "webhook", "actor": {"login": "ci-dev-alice"}},
                            "vcs": {
                                "branch": "main",
                                "revision": "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
                            },
                        },
                        {
                            "id": "cc-pipe-002",
                            "project_slug": "gh/acme-corp/backend-api",
                            "number": 2890,
                            "state": "created",
                            "status": "success",
                            "created_at": (NOW - timedelta(hours=4)).isoformat(),
                            "trigger": {"type": "webhook", "actor": {"login": "ci-dev-bob"}},
                            "vcs": {
                                "branch": "feat/notifications",
                                "revision": "f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
                            },
                        },
                        {
                            "id": "cc-pipe-003",
                            "project_slug": "gh/acme-corp/frontend-app",
                            "number": 1204,
                            "state": "created",
                            "status": "error",
                            "created_at": (NOW - timedelta(hours=6)).isoformat(),
                            "trigger": {"type": "webhook", "actor": {"login": "ci-dev-carol"}},
                            "vcs": {
                                "branch": "feat/dashboard-v2",
                                "revision": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                            },
                            "errors": [
                                {
                                    "type": "config",
                                    "message": "Job 'deploy-prod' failed: exit code 1 — npm audit found 2 high severity vulnerabilities",
                                }
                            ],
                        },
                    ],
                    "next_page_token": None,
                },
            )
        )
        result.events.append(
            RawEventData(
                source="circleci",
                source_type=SourceType.CI_CD,
                provider="circleci",
                event_type="circleci_contexts",
                raw_data={
                    "items": [
                        {
                            "id": "ctx-001",
                            "name": "production-secrets",
                            "created_at": (NOW - timedelta(days=180)).isoformat(),
                            "environment_variables": [
                                {
                                    "variable": "AWS_ACCESS_KEY_ID",
                                    "created_at": (NOW - timedelta(days=30)).isoformat(),
                                },
                                {
                                    "variable": "AWS_SECRET_ACCESS_KEY",
                                    "created_at": (NOW - timedelta(days=30)).isoformat(),
                                },
                                {
                                    "variable": "DATABASE_URL",
                                    "created_at": (NOW - timedelta(days=60)).isoformat(),
                                },
                            ],
                        },
                        {
                            "id": "ctx-002",
                            "name": "staging-secrets",
                            "created_at": (NOW - timedelta(days=365)).isoformat(),
                            "environment_variables": [
                                {
                                    "variable": "STAGING_DB_URL",
                                    "created_at": (NOW - timedelta(days=400)).isoformat(),
                                },
                                {
                                    "variable": "LEGACY_API_TOKEN",
                                    "created_at": (NOW - timedelta(days=540)).isoformat(),
                                },
                            ],
                        },
                    ],
                    "next_page_token": None,
                },
            )
        )
        result.complete()
        return result


__all__ = [
    "DemoAWSConnector",
    "DemoAbnormalSecurityConnector",
    "DemoAlibabaConnector",
    "DemoAquaConnector",
    "DemoAuth0Connector",
    "DemoAzureConnector",
    "DemoBambooHRConnector",
    "DemoBitSightConnector",
    "DemoBitwardenConnector",
    "DemoCheckmarxConnector",
    "DemoCircleCIConnector",
    "DemoCloudflareConnector",
    "DemoConfluenceConnector",
    "DemoCrowdStrikeConnector",
    "DemoCyberArkConnector",
    "DemoDatabricksConnector",
    "DemoDatadogConnector",
    "DemoDefenderConnector",
    "DemoDigitalOceanConnector",
    "DemoDuoConnector",
    "DemoElasticConnector",
    "DemoEntraIDConnector",
    "DemoExchangeOnlineConnector",
    "DemoFortinetConnector",
    "DemoGCPConnector",
    "DemoGitGuardianConnector",
    "DemoGitHubActionsConnector",
    "DemoGitHubConnector",
    "DemoGitLabCIConnector",
    "DemoGitLabConnector",
    "DemoGoogleWorkspaceConnector",
    "DemoGrafanaConnector",
    "DemoGuardDutyConnector",
    "DemoGustoConnector",
    "DemoHuaweiConnector",
    "DemoIBMCloudConnector",
    "DemoIntuneConnector",
    "DemoJamfConnector",
    "DemoJenkinsConnector",
    "DemoJiraConnector",
    "DemoJumpCloudConnector",
    "DemoKandjiConnector",
    "DemoKnowBe4Connector",
    "DemoKubernetesConnector",
    "DemoMLflowConnector",
    "DemoNessusConnector",
    "DemoNetskopeConnector",
    "DemoNewRelicConnector",
    "DemoOCIConnector",
    "DemoOVHConnector",
    "DemoOktaConnector",
    "DemoOnePasswordConnector",
    "DemoOneTrustConnector",
    "DemoPaloAltoConnector",
    "DemoPrismaConnector",
    "DemoProofpointConnector",
    "DemoPurviewConnector",
    "DemoQualysConnector",
    "DemoRipplingConnector",
    "DemoSageMakerConnector",
    "DemoSailPointConnector",
    "DemoSecurityScorecardConnector",
    "DemoSemgrepConnector",
    "DemoSentinelConnector",
    "DemoSentinelOneConnector",
    "DemoServiceNowConnector",
    "DemoSlackConnector",
    "DemoSnykConnector",
    "DemoSonarQubeConnector",
    "DemoSophosConnector",
    "DemoSplunkConnector",
    "DemoTenableConnector",
    "DemoTerraformCloudConnector",
    "DemoTrivyConnector",
    "DemoVaultConnector",
    "DemoVeeamConnector",
    "DemoVeracodeConnector",
    "DemoVerkadaConnector",
    "DemoWizConnector",
    "DemoWorkdayConnector",
    "DemoZscalerConnector",
]
