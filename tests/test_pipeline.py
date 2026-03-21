"""End-to-end pipeline test with mock AWS data.

Proves: Ingest → Normalize → Map → Assess flows through all 4 stages,
persists to all 5 tables, and publishes events on the bus.
"""


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from warlock.db.models import (
    Base,
    ConnectorRun,
    RawEvent,
    Finding,
    ControlMapping,
    ControlResult,
)
from warlock.pipeline.bus import EventBus
from warlock.pipeline.orchestrator import Pipeline
from warlock.connectors.base import (
    BaseConnector,
    ConnectorConfig,
    ConnectorRegistry,
    ConnectorResult,
    RawEventData,
    SourceType,
)
from warlock.normalizers.base import NormalizerRegistry
from warlock.mappers.control_mapper import ControlMapper, ExplicitRule, CrosswalkEdge
from warlock.assessors.engine import AssertionEngine, Assessor


# ---------------------------------------------------------------------------
# Mock connector — simulates AWS IAM credential report
# ---------------------------------------------------------------------------


class MockAWSConnector(BaseConnector):
    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self):
        result = ConnectorResult(
            connector_name=self.name,
            source="aws",
            source_type=SourceType.CLOUD,
            provider="aws",
        )
        # Simulate IAM credential report with one user missing MFA
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
                    "account_id": "123456789012",
                    "response": {
                        "Content": (
                            "user,arn,user_creation_time,password_enabled,password_last_used,"
                            "password_last_changed,password_next_rotation,mfa_active,"
                            "access_key_1_active,access_key_1_last_rotated,"
                            "access_key_2_active,access_key_2_last_rotated\n"
                            "admin-user,arn:aws:iam::123456789012:user/admin-user,"
                            "2024-01-01T00:00:00+00:00,true,2024-06-01T00:00:00+00:00,"
                            "2024-01-01T00:00:00+00:00,N/A,false,true,2024-01-01T00:00:00+00:00,"
                            "false,N/A\n"
                            "service-account,arn:aws:iam::123456789012:user/service-account,"
                            "2024-01-01T00:00:00+00:00,false,N/A,N/A,N/A,false,true,"
                            "2024-01-01T00:00:00+00:00,false,N/A\n"
                        )
                    },
                },
            )
        )
        # Simulate GuardDuty not enabled
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
                    "account_id": "123456789012",
                    "response": {"DetectorIds": []},
                },
            )
        )
        result.complete()
        return result


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


def test_full_pipeline():
    # -- Setup in-memory database --
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()

    # -- Event bus with tracking --
    bus = EventBus()
    events_received = []
    bus.subscribe_all(lambda e: events_received.append(e))

    # -- Connector registry --
    connectors = ConnectorRegistry()
    connectors.register("aws", MockAWSConnector)
    connectors.create(
        ConnectorConfig(
            name="mock-aws",
            source_type=SourceType.CLOUD,
            provider="aws",
        )
    )

    # -- Normalizer registry (use real AWS normalizer) --
    from warlock.normalizers.aws import AWSNormalizer

    normalizers = NormalizerRegistry()
    normalizers.register(AWSNormalizer())

    # -- Control mapper with rules --
    mapper = ControlMapper()
    # IAM users without MFA → NIST AC-2
    mapper.add_explicit_rule(
        ExplicitRule(
            source="aws",
            event_type="misconfiguration",
            framework="nist_800_53",
            control_id="IA-2",
            control_family="IA",
        )
    )
    # Resource-type rule: iam_user → AC-2
    from warlock.mappers.control_mapper import ResourceRule

    mapper.add_resource_rule(
        ResourceRule(
            resource_type="iam_user",
            framework="nist_800_53",
            control_ids=["AC-2"],
            control_family="AC",
        )
    )
    # GuardDuty → SI-4
    mapper.add_explicit_rule(
        ExplicitRule(
            source="aws",
            event_type="misconfiguration",
            framework="nist_800_53",
            control_id="SI-4",
            control_family="SI",
        )
    )
    # Crosswalk: NIST IA-2 → SOC2 CC6.1
    mapper.add_crosswalk(
        CrosswalkEdge(
            source_framework="nist_800_53",
            source_control="IA-2",
            target_framework="soc2",
            target_control="CC6.1",
            confidence=0.9,
        )
    )

    # -- Assertion engine --
    assertion_engine = AssertionEngine()

    @assertion_engine.assertion("mfa_enabled")
    def check_mfa(detail, raw_data):
        issues = detail.get("issues", [])
        if "console_access_without_mfa" in issues:
            return False, ["User has console access but MFA is not enabled"]
        return True, []

    assertion_engine.bind_control("nist_800_53", "IA-2", "mfa_enabled")
    assertion_engine.set_remediation(
        "mfa_enabled",
        {
            "summary": "Enable MFA for all IAM users with console access",
            "steps": ["Go to IAM console", "Select user", "Enable MFA device"],
            "console_path": "https://console.aws.amazon.com/iam/home#/users",
        },
    )

    assessor = Assessor(engine=assertion_engine)

    # -- Build and run pipeline --
    pipeline = Pipeline(
        connectors=connectors,
        normalizers=normalizers,
        mapper=mapper,
        assessor=assessor,
        bus=bus,
    )
    stats = pipeline.run(session)
    session.commit()

    # -- Assertions --

    # Stats
    assert stats.raw_events_collected == 2, (
        f"Expected 2 raw events, got {stats.raw_events_collected}"
    )
    assert stats.findings_normalized > 0, "Expected at least one finding"
    assert stats.connectors_succeeded == 1
    assert stats.connectors_failed == 0

    # Database: connector_runs
    runs = session.query(ConnectorRun).all()
    assert len(runs) == 1
    assert runs[0].status == "success"

    # Database: raw_events
    raw_events = session.query(RawEvent).all()
    assert len(raw_events) == 2

    # Database: findings
    findings = session.query(Finding).all()
    assert len(findings) >= 3  # 2 IAM users + 1 GuardDuty not enabled

    # Check that we got the MFA finding
    mfa_findings = [f for f in findings if "console_access_without_mfa" in f.title]
    assert len(mfa_findings) == 1, f"Expected 1 MFA finding, got {len(mfa_findings)}"
    assert mfa_findings[0].severity == "high"

    # Check GuardDuty finding
    gd_findings = [f for f in findings if "GuardDuty" in f.title and "not enabled" in f.title]
    assert len(gd_findings) == 1
    assert gd_findings[0].severity == "high"

    # Database: control_mappings
    mappings = session.query(ControlMapping).all()
    assert len(mappings) > 0

    # Check crosswalk happened (NIST IA-2 → SOC2 CC6.1)
    soc2_mappings = [m for m in mappings if m.framework == "soc2"]
    assert len(soc2_mappings) > 0, "Expected crosswalk to SOC2"
    assert any(m.control_id == "CC6.1" for m in soc2_mappings)

    # Database: control_results
    results = session.query(ControlResult).all()
    assert len(results) > 0

    # Check that MFA assertion ran and failed
    mfa_results = [
        r for r in results if r.assertion_name == "mfa_enabled" and not r.assertion_passed
    ]
    assert len(mfa_results) > 0, "Expected MFA assertion to fail for admin-user"
    assert mfa_results[0].status == "non_compliant"
    assert mfa_results[0].remediation_summary  # has remediation

    # Event bus received events
    event_types = [e.event_type for e in events_received]
    assert "raw_event.created" in event_types
    assert "finding.normalized" in event_types
    assert "finding.mapped" in event_types
    assert "control.assessed" in event_types

    # Print summary
    print(f"\n{'=' * 60}")
    print("PIPELINE TEST PASSED")
    print(f"{'=' * 60}")
    print(f"Raw events:      {len(raw_events)}")
    print(f"Findings:        {len(findings)}")
    print(f"Control mappings:{len(mappings)}")
    print(f"Control results: {len(results)}")
    print(f"Bus events:      {len(events_received)}")
    print(f"Duration:        {stats.duration_seconds:.2f}s")
    print()
    print("Findings:")
    for f in findings:
        print(f"  [{f.severity:8s}] {f.observation_type:20s} {f.title[:60]}")
    print()
    print("Results:")
    for r in results:
        print(f"  [{r.status:14s}] {r.framework}:{r.control_id} — {r.assessor}")

    session.close()


if __name__ == "__main__":
    test_full_pipeline()
