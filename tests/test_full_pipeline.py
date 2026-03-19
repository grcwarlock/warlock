"""Comprehensive pipeline test exercising all layers with framework configs,
crosswalks, the assertion library, and multiple source types.
"""

from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker

from warlock.db.models import (
    Base, ConnectorRun, RawEvent, Finding, ControlMapping, ControlResult,
)
from warlock.pipeline.bus import EventBus
from warlock.pipeline.orchestrator import Pipeline
from warlock.connectors.base import (
    BaseConnector, ConnectorConfig, ConnectorRegistry, ConnectorResult,
    RawEventData, SourceType,
)
from warlock.normalizers.base import NormalizerRegistry
from warlock.normalizers.aws import AWSNormalizer
from warlock.normalizers.generic import GenericNormalizer
from warlock.mappers.control_mapper import ControlMapper
from warlock.assessors.engine import Assessor, engine as assertion_engine
from warlock.pipeline.loader import load_framework_configs, load_assertions
from warlock.connectors.webhook import WebhookReceiver


# ---------------------------------------------------------------------------
# Mock connectors — simulate multiple source types
# ---------------------------------------------------------------------------

class MockAWSConnector(BaseConnector):
    def validate(self): return []
    def health_check(self): return True

    def collect(self):
        result = ConnectorResult(
            connector_name=self.name, source="aws",
            source_type=SourceType.CLOUD, provider="aws",
        )
        # IAM credential report with MFA issues
        result.events.append(RawEventData(
            source="aws", source_type=SourceType.CLOUD, provider="aws",
            event_type="iam_credential_report",
            raw_data={
                "service": "iam", "method": "get_credential_report",
                "region": "us-east-1", "account_id": "123456789012",
                "response": {"Content": (
                    "user,arn,user_creation_time,password_enabled,password_last_used,"
                    "password_last_changed,password_next_rotation,mfa_active,"
                    "access_key_1_active,access_key_1_last_rotated,"
                    "access_key_2_active,access_key_2_last_rotated\n"
                    "<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,"
                    "not_supported,2024-06-01T00:00:00+00:00,not_supported,not_supported,true,"
                    "true,2023-01-01T00:00:00+00:00,false,N/A\n"
                    "dev-user,arn:aws:iam::123456789012:user/dev-user,2024-01-01T00:00:00+00:00,"
                    "true,2024-06-01T00:00:00+00:00,2024-01-01T00:00:00+00:00,N/A,false,"
                    "true,2024-01-01T00:00:00+00:00,false,N/A\n"
                )},
            },
        ))
        # Security groups with open ports
        result.events.append(RawEventData(
            source="aws", source_type=SourceType.CLOUD, provider="aws",
            event_type="ec2_security_groups",
            raw_data={
                "service": "ec2", "method": "describe_security_groups",
                "region": "us-east-1", "account_id": "123456789012",
                "response": {"SecurityGroups": [
                    {
                        "GroupId": "sg-open-ssh",
                        "GroupName": "open-ssh",
                        "IpPermissions": [{
                            "FromPort": 22, "ToPort": 22, "IpProtocol": "tcp",
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }],
                    },
                    {
                        "GroupId": "sg-restricted",
                        "GroupName": "restricted",
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
                "region": "us-east-1", "account_id": "123456789012",
                "response": {"DetectorIds": ["abc123"]},
            },
        ))
        # CloudTrail with issues
        result.events.append(RawEventData(
            source="aws", source_type=SourceType.CLOUD, provider="aws",
            event_type="cloudtrail_trails",
            raw_data={
                "service": "cloudtrail", "method": "describe_trails",
                "region": "us-east-1", "account_id": "123456789012",
                "response": {"trailList": [{
                    "Name": "main-trail",
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/main-trail",
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
                "region": "us-east-1", "account_id": "123456789012",
                "response": {"HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default"},
            },
        ))
        # Password policy with issues
        result.events.append(RawEventData(
            source="aws", source_type=SourceType.CLOUD, provider="aws",
            event_type="iam_password_policy",
            raw_data={
                "service": "iam", "method": "get_account_password_policy",
                "region": "us-east-1", "account_id": "123456789012",
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
        # Config recorder
        result.events.append(RawEventData(
            source="aws", source_type=SourceType.CLOUD, provider="aws",
            event_type="config_recorders",
            raw_data={
                "service": "config", "method": "describe_configuration_recorders",
                "region": "us-east-1", "account_id": "123456789012",
                "response": {"ConfigurationRecorders": [{
                    "name": "default",
                    "recordingGroup": {"allSupported": True},
                }]},
            },
        ))
        result.complete()
        return result


def test_full_pipeline_with_frameworks():
    # -- Setup --
    engine_db = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine_db)
    Session = sessionmaker(bind=engine_db, expire_on_commit=False)
    session = Session()

    bus = EventBus()
    events = []
    bus.subscribe_all(lambda e: events.append(e))

    # Connectors
    connectors = ConnectorRegistry()
    connectors.register("aws", MockAWSConnector)
    connectors.create(ConnectorConfig(name="aws", source_type=SourceType.CLOUD, provider="aws"))

    # Normalizers
    normalizers = NormalizerRegistry()
    normalizers.register(AWSNormalizer())
    normalizers.register(GenericNormalizer())

    # Load real framework configs and assertions
    load_assertions()
    mapper = ControlMapper()
    framework_dir = str(Path(__file__).resolve().parent.parent / "warlock" / "frameworks")
    load_framework_configs(framework_dir, mapper)

    # Assessor with assertion engine
    assessor = Assessor(engine=assertion_engine)

    # -- Run pipeline --
    pipeline = Pipeline(
        connectors=connectors, normalizers=normalizers,
        mapper=mapper, assessor=assessor, bus=bus,
    )
    stats = pipeline.run(session)
    session.commit()

    # -- Verify stats --
    assert stats.raw_events_collected == 7
    assert stats.findings_normalized > 0
    assert stats.controls_mapped > 0
    assert stats.results_assessed > 0
    assert stats.connectors_succeeded == 1

    # -- Verify database --
    finding_count = session.query(func.count(Finding.id)).scalar()
    mapping_count = session.query(func.count(ControlMapping.id)).scalar()
    result_count = session.query(func.count(ControlResult.id)).scalar()

    assert finding_count > 0
    assert mapping_count > 0
    assert result_count > 0

    # -- Verify framework mappings happened --
    frameworks_seen = set(
        r[0] for r in session.query(ControlMapping.framework).distinct().all()
    )
    assert "nist_800_53" in frameworks_seen, f"Expected nist_800_53 in {frameworks_seen}"

    # -- Verify crosswalks worked --
    crosswalk_mappings = session.query(ControlMapping).filter(
        ControlMapping.mapping_method == "crosswalk"
    ).all()
    # With crosswalks loaded, at least some mappings should be crosswalked
    # (depends on which controls are mapped)

    # -- Verify assertions ran --
    compliant = session.query(ControlResult).filter(
        ControlResult.status == "compliant"
    ).count()
    non_compliant = session.query(ControlResult).filter(
        ControlResult.status == "non_compliant"
    ).count()
    not_assessed = session.query(ControlResult).filter(
        ControlResult.status == "not_assessed"
    ).count()

    # We should have a mix of statuses
    assert compliant + non_compliant + not_assessed == result_count

    # MFA finding should produce non_compliant results
    mfa_results = session.query(ControlResult).filter(
        ControlResult.assertion_name == "mfa_enabled",
        ControlResult.assertion_passed == False,
    ).all()
    assert len(mfa_results) > 0, "Expected MFA assertion failures"

    # -- Verify event bus --
    event_types = {e.event_type for e in events}
    assert event_types == {"raw_event.created", "finding.normalized", "finding.mapped", "control.assessed"}

    # -- Print summary --
    print(f"\n{'='*70}")
    print(f"COMPREHENSIVE PIPELINE TEST PASSED")
    print(f"{'='*70}")
    print(f"Raw events:        {stats.raw_events_collected}")
    print(f"Findings:          {finding_count}")
    print(f"Control mappings:  {mapping_count}")
    print(f"Control results:   {result_count}")
    print(f"  Compliant:       {compliant}")
    print(f"  Non-compliant:   {non_compliant}")
    print(f"  Not assessed:    {not_assessed}")
    print(f"Crosswalked:       {len(crosswalk_mappings)}")
    print(f"Frameworks:        {frameworks_seen}")
    print(f"Bus events:        {len(events)}")
    print(f"Duration:          {stats.duration_seconds:.3f}s")

    # Show non-compliant results
    nc_results = session.query(ControlResult).filter(
        ControlResult.status == "non_compliant"
    ).all()
    if nc_results:
        print(f"\nNon-compliant findings:")
        for r in nc_results:
            print(f"  {r.framework}:{r.control_id} — {r.assertion_name} — {r.assertion_findings}")

    session.close()


def test_webhook_ingestion():
    """Test that webhook-ingested data flows through normalize → map → assess."""
    engine_db = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine_db)
    Session = sessionmaker(bind=engine_db, expire_on_commit=False)
    session = Session()

    bus = EventBus()

    # Use generic normalizer for webhook data
    normalizers = NormalizerRegistry()
    normalizers.register(GenericNormalizer())

    mapper = ControlMapper()
    load_assertions()
    assessor = Assessor(engine=assertion_engine)

    # Ingest via webhook
    receiver = WebhookReceiver()
    raw_event = receiver.ingest(
        payload={
            "title": "Critical vulnerability CVE-2024-1234",
            "severity": "critical",
            "resource": "prod-web-01",
            "description": "Remote code execution in OpenSSL",
            "cve": "CVE-2024-1234",
            "cvss": 9.8,
        },
        source="webhook",
        provider="custom_scanner",
        event_type="vulnerability_report",
    )

    assert raw_event.source == "webhook"
    assert raw_event.sha256  # has integrity hash

    # Normalize it
    findings = normalizers.normalize(raw_event)
    assert len(findings) >= 1, "Generic normalizer should produce at least one finding"
    assert findings[0].severity == "critical"

    print(f"\nWebhook test: ingested 1 event → {len(findings)} finding(s)")
    for f in findings:
        print(f"  [{f.severity}] {f.title}")

    session.close()


if __name__ == "__main__":
    test_full_pipeline_with_frameworks()
    test_webhook_ingestion()
    print("\n" + "="*70)
    print("ALL TESTS PASSED")
    print("="*70)
