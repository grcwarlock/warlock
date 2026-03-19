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
from warlock.db.models import Base, ControlMapping, ControlResult, Finding
from warlock.normalizers.aws import AWSNormalizer
from warlock.normalizers.base import NormalizerRegistry
from warlock.normalizers.crowdstrike import CrowdStrikeNormalizer
from warlock.normalizers.generic import GenericNormalizer
from warlock.normalizers.okta import OktaNormalizer
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    print("=" * 60)
    print("  Warlock Demo Seed")
    print("=" * 60)

    # 1. Init DB
    print("\n[1/4] Initializing database...")
    init_db()

    # 2. Build pipeline with real framework configs + assertions
    print("[2/4] Loading frameworks, assertions, and normalizers...")
    bus = EventBus()
    load_assertions()

    connectors = ConnectorRegistry()
    connectors.register("aws", DemoAWSConnector)
    connectors.register("okta", DemoOktaConnector)
    connectors.register("crowdstrike", DemoCrowdStrikeConnector)
    connectors.create(ConnectorConfig(
        name="demo-aws", source_type=SourceType.CLOUD, provider="aws",
    ))
    connectors.create(ConnectorConfig(
        name="demo-okta", source_type=SourceType.IAM, provider="okta",
    ))
    connectors.create(ConnectorConfig(
        name="demo-crowdstrike", source_type=SourceType.EDR, provider="crowdstrike",
    ))

    normalizers = NormalizerRegistry()
    normalizers.register(AWSNormalizer())
    normalizers.register(OktaNormalizer())
    normalizers.register(CrowdStrikeNormalizer())
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
    print("[3/4] Running pipeline (collect -> normalize -> map -> assess)...")
    with get_session() as session:
        stats = pipeline.run(session)

    # 4. Print results
    print("[4/4] Done!\n")
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

    print("\n" + "=" * 60)
    print("  Try these commands:")
    print("=" * 60)
    print("  warlock results                    # control results")
    print("  warlock results --status non_compliant")
    print("  warlock coverage                   # compliance summary")
    print("  warlock findings                   # all findings")
    print("  warlock sources                    # registered sources")
    print("  warlock issues-auto-create         # create issues from failures")
    print("  warlock issues                     # view issues")
    print("  warlock oscal                      # export OSCAL JSON")
    print("  warlock risk -f nist_800_53        # FAIR risk analysis")
    print("=" * 60)


if __name__ == "__main__":
    main()
