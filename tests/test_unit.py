"""Unit tests for every pipeline component."""

import json
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker

from warlock.db.models import (
    Base,
    ConnectorRun,
    RawEvent,
    Finding,
    ControlMapping,
    ControlResult,
)
from warlock.pipeline.bus import EventBus, PipelineEvent
from warlock.connectors.base import (
    BaseConnector,
    ConnectorConfig,
    ConnectorRegistry,
    ConnectorResult,
    RawEventData,
    SourceType,
)
from warlock.normalizers.base import BaseNormalizer, FindingData, NormalizerRegistry
from warlock.normalizers.aws import AWSNormalizer
from warlock.normalizers.generic import GenericNormalizer
from warlock.mappers.control_mapper import (
    ControlMapper,
    ControlMappingData,
    ExplicitRule,
    ResourceRule,
    CrosswalkEdge,
    MappedFinding,
)
from warlock.assessors.engine import AssertionEngine, Assessor, ControlResultData
from warlock.assessors.ai_reasoning import AIReasoningResult, create_reasoner
from warlock.connectors.webhook import WebhookReceiver
from warlock.pipeline.orchestrator import Pipeline


# ===================================================================
# 1. EVENT BUS
# ===================================================================


def test_event_bus():
    bus = EventBus()
    received = []

    bus.subscribe("test.event", lambda e: received.append(e))
    bus.publish(PipelineEvent(event_type="test.event", payload_id="abc"))
    bus.publish(PipelineEvent(event_type="other.event", payload_id="xyz"))

    assert len(received) == 1, "subscribe receives matching events"
    assert received[0].payload_id == "abc", "subscribe ignores non-matching events"

    # Wildcard
    all_events = []
    bus.subscribe_all(lambda e: all_events.append(e))
    bus.publish(PipelineEvent(event_type="any.thing", payload_id="123"))
    assert len(all_events) == 1, "subscribe_all receives everything"

    # Error handling — handlers that throw don't crash publish
    bus.subscribe("error.test", lambda e: 1 / 0)
    try:
        bus.publish(PipelineEvent(event_type="error.test", payload_id="err"))
        assert True, "handler exception doesn't crash publish"
    except Exception:
        assert False, "handler exception doesn't crash publish — Exception propagated"

    # Clear
    bus.clear()
    before = len(received)
    bus.publish(PipelineEvent(event_type="test.event", payload_id="after"))
    assert len(received) == before, "clear removes all subscriptions"


# ===================================================================
# 2. RAW EVENT DATA
# ===================================================================


def test_raw_event_data():
    raw = RawEventData(
        source="aws",
        source_type=SourceType.CLOUD,
        provider="aws",
        event_type="test",
        raw_data={"key": "value"},
    )
    assert len(raw.id) == 36, "has UUID id"
    assert len(raw.sha256) == 64, "has sha256"

    # Same data -> same hash
    raw2 = RawEventData(
        source="aws",
        source_type=SourceType.CLOUD,
        provider="aws",
        event_type="test",
        raw_data={"key": "value"},
    )
    assert raw.sha256 == raw2.sha256, "deterministic sha256"

    # Different data -> different hash
    raw3 = RawEventData(
        source="aws",
        source_type=SourceType.CLOUD,
        provider="aws",
        event_type="test",
        raw_data={"key": "other"},
    )
    assert raw.sha256 != raw3.sha256, "different data -> different sha256"


# ===================================================================
# 3. CONNECTOR REGISTRY
# ===================================================================


def test_connector_registry():
    class GoodConnector(BaseConnector):
        def validate(self):
            return []

        def health_check(self):
            return True

        def collect(self):
            r = ConnectorResult(
                connector_name=self.name,
                source="test",
                source_type=SourceType.CUSTOM,
                provider="test",
            )
            r.events.append(
                RawEventData(
                    source="test",
                    source_type=SourceType.CUSTOM,
                    provider="test",
                    event_type="test_event",
                    raw_data={"x": 1},
                )
            )
            r.complete()
            return r

    class BadConnector(BaseConnector):
        def validate(self):
            return ["Missing API key"]

        def health_check(self):
            return False

        def collect(self):
            return ConnectorResult(
                connector_name=self.name,
                source="bad",
                source_type=SourceType.CUSTOM,
                provider="bad",
            )

    reg = ConnectorRegistry()
    reg.register("good", GoodConnector)
    reg.register("bad", BadConnector)

    assert set(reg.list_types()) == {"good", "bad"}, "list_types returns registered"

    # Good connector creates successfully
    conn = reg.create(ConnectorConfig(name="g1", source_type=SourceType.CUSTOM, provider="good"))
    assert conn is not None, "good connector created"
    assert "g1" in reg.list_active(), "active list updated"

    # Bad connector fails validation
    try:
        reg.create(ConnectorConfig(name="b1", source_type=SourceType.CUSTOM, provider="bad"))
        assert False, "bad connector rejected — Should have raised ValueError"
    except ValueError:
        pass  # expected

    # Unknown provider
    try:
        reg.create(ConnectorConfig(name="u1", source_type=SourceType.CUSTOM, provider="unknown"))
        assert False, "unknown provider rejected"
    except ValueError:
        pass  # expected

    # collect_all
    results = reg.collect_all()
    assert len(results) == 1, "collect_all returns results"
    assert results[0].event_count == 1, "collect_all result has events"
    assert results[0].status == "success", "collect_all result status"


# ===================================================================
# 4. CONNECTOR RESULT
# ===================================================================


def test_connector_result():
    r = ConnectorResult(
        connector_name="test",
        source="test",
        source_type=SourceType.CUSTOM,
        provider="test",
    )
    r.events.append(
        RawEventData(
            source="test",
            source_type=SourceType.CUSTOM,
            provider="test",
            event_type="e1",
            raw_data={},
        )
    )
    r.complete()
    assert r.status == "success", "success when events and no errors"
    assert r.duration_seconds is not None, "duration computed"
    assert r.event_count == 1, "event_count property"

    # Partial
    r2 = ConnectorResult(
        connector_name="test",
        source="test",
        source_type=SourceType.CUSTOM,
        provider="test",
    )
    r2.events.append(
        RawEventData(
            source="test",
            source_type=SourceType.CUSTOM,
            provider="test",
            event_type="e1",
            raw_data={},
        )
    )
    r2.errors.append("some error")
    r2.complete()
    assert r2.status == "partial", "partial when events + errors"

    # Error
    r3 = ConnectorResult(
        connector_name="test",
        source="test",
        source_type=SourceType.CUSTOM,
        provider="test",
    )
    r3.errors.append("fatal")
    r3.complete()
    assert r3.status == "error", "error when only errors"


# ===================================================================
# 5. NORMALIZER REGISTRY
# ===================================================================


def test_normalizer_registry():
    reg = NormalizerRegistry()

    class TestNormalizer(BaseNormalizer):
        def can_handle(self, raw):
            return raw.source == "test"

        def normalize(self, raw):
            return [
                FindingData(
                    raw_event_id=raw.id,
                    observation_type="test",
                    title="test finding",
                    detail={},
                    source="test",
                    source_type=SourceType.CUSTOM,
                    provider="test",
                )
            ]

    reg.register(TestNormalizer())

    raw = RawEventData(
        source="test", source_type=SourceType.CUSTOM, provider="test", event_type="e1", raw_data={}
    )
    findings = reg.normalize(raw)
    assert len(findings) == 1, "normalizer produces findings"
    assert findings[0].observation_type == "test", "finding has correct type"

    # Unhandled source returns empty
    raw2 = RawEventData(
        source="unknown",
        source_type=SourceType.CUSTOM,
        provider="unknown",
        event_type="e1",
        raw_data={},
    )
    findings2 = reg.normalize(raw2)
    assert len(findings2) == 0, "unhandled source returns empty"

    # Normalizer that throws returns empty (not crash)
    class CrashNormalizer(BaseNormalizer):
        def can_handle(self, raw):
            return raw.source == "crash"

        def normalize(self, raw):
            raise RuntimeError("boom")

    reg.register(CrashNormalizer())
    raw3 = RawEventData(
        source="crash",
        source_type=SourceType.CUSTOM,
        provider="crash",
        event_type="e1",
        raw_data={},
    )
    findings3 = reg.normalize(raw3)
    assert len(findings3) == 0, "crashing normalizer returns empty"


# ===================================================================
# 6. AWS NORMALIZER — detailed checks
# ===================================================================


def test_aws_normalizer():
    norm = AWSNormalizer()

    # Credential report
    raw = RawEventData(
        source="aws",
        source_type=SourceType.CLOUD,
        provider="aws",
        event_type="iam_credential_report",
        raw_data={
            "region": "us-east-1",
            "account_id": "111111111111",
            "response": {
                "Content": (
                    "user,arn,user_creation_time,password_enabled,password_last_used,"
                    "password_last_changed,password_next_rotation,mfa_active,"
                    "access_key_1_active,access_key_1_last_rotated,"
                    "access_key_2_active,access_key_2_last_rotated\n"
                    "<root_account>,arn:aws:iam::111:root,2020-01-01,not_supported,"
                    "2024-01-01,not_supported,not_supported,true,true,2023-01-01,false,N/A\n"
                    "good-user,arn:aws:iam::111:user/good-user,2024-01-01,true,"
                    "2024-06-01,2024-01-01,N/A,true,false,N/A,false,N/A\n"
                    "bad-user,arn:aws:iam::111:user/bad-user,2024-01-01,true,"
                    "2024-06-01,2024-01-01,N/A,false,true,2024-01-01,false,N/A\n"
                )
            },
        },
    )
    assert norm.can_handle(raw), "can handle credential report"
    findings = norm.normalize(raw)
    assert len(findings) == 3, "credential report produces 3 findings"

    root = [f for f in findings if "root" in f.resource_id]
    assert len(root) == 1, "root account found"
    assert root[0].severity == "critical", "root has critical severity (access keys)"

    bad = [f for f in findings if "bad-user" in f.title]
    assert len(bad) == 1, "bad-user found"
    assert bad[0].severity == "high", "bad-user is high severity (no MFA)"
    assert bad[0].observation_type == "misconfiguration", "bad-user is misconfiguration"

    good = [f for f in findings if "good-user" in f.title]
    assert len(good) == 1, "good-user found"
    assert good[0].severity == "info", "good-user is info severity"
    assert good[0].observation_type == "inventory", "good-user is inventory"

    # Security groups
    raw_sg = RawEventData(
        source="aws",
        source_type=SourceType.CLOUD,
        provider="aws",
        event_type="ec2_security_groups",
        raw_data={
            "region": "us-east-1",
            "account_id": "111111111111",
            "response": {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-bad",
                        "GroupName": "open",
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
                        "GroupId": "sg-good",
                        "GroupName": "closed",
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
    sg_findings = norm.normalize(raw_sg)
    assert len(sg_findings) == 2, "security groups produce 2 findings"
    open_sg = [f for f in sg_findings if f.severity == "high"]
    assert len(open_sg) == 1, "open SG is high severity"

    # Can't handle unknown event type
    raw_unk = RawEventData(
        source="aws",
        source_type=SourceType.CLOUD,
        provider="aws",
        event_type="unknown_type",
        raw_data={},
    )
    assert not norm.can_handle(raw_unk), "rejects unknown event type"

    # Empty credential report
    raw_empty = RawEventData(
        source="aws",
        source_type=SourceType.CLOUD,
        provider="aws",
        event_type="iam_credential_report",
        raw_data={"region": "us-east-1", "account_id": "111", "response": {"Content": ""}},
    )
    empty_findings = norm.normalize(raw_empty)
    assert len(empty_findings) == 0, "empty credential report returns empty"


# ===================================================================
# 7. GENERIC NORMALIZER
# ===================================================================


def test_generic_normalizer():
    norm = GenericNormalizer()

    # Structured payload with common fields
    raw = RawEventData(
        source="webhook",
        source_type=SourceType.CUSTOM,
        provider="custom",
        event_type="alert",
        raw_data={"title": "Test Alert", "severity": "high", "description": "Something bad"},
    )
    assert norm.can_handle(raw), "can handle any event"
    findings = norm.normalize(raw)
    assert len(findings) >= 1, "structured payload produces finding"
    assert findings[0].severity == "high", "extracts severity"
    assert "Test Alert" in findings[0].title, "extracts title"

    # Completely empty payload
    raw_empty = RawEventData(
        source="webhook",
        source_type=SourceType.CUSTOM,
        provider="custom",
        event_type="unknown",
        raw_data={},
    )
    findings_empty = norm.normalize(raw_empty)
    assert len(findings_empty) >= 1, "empty payload still produces a finding"

    # Payload with list of items
    raw_list = RawEventData(
        source="webhook",
        source_type=SourceType.CUSTOM,
        provider="custom",
        event_type="batch",
        raw_data={
            "alerts": [
                {"title": "Alert 1", "severity": "critical"},
                {"title": "Alert 2", "severity": "low"},
            ]
        },
    )
    findings_list = norm.normalize(raw_list)
    assert len(findings_list) >= 2, "list payload fans out"


# ===================================================================
# 8. CONTROL MAPPER
# ===================================================================


def test_control_mapper():
    mapper = ControlMapper()

    # Explicit rule
    mapper.add_explicit_rule(
        ExplicitRule(
            source="aws",
            event_type="misconfiguration",
            framework="nist",
            control_id="AC-2",
            control_family="AC",
        )
    )
    # Resource rule
    mapper.add_resource_rule(
        ResourceRule(
            resource_type="iam_user",
            framework="nist",
            control_ids=["AC-2", "IA-2"],
            control_family="AC",
        )
    )
    # Crosswalk
    mapper.add_crosswalk(
        CrosswalkEdge(
            source_framework="nist",
            source_control="AC-2",
            target_framework="soc2",
            target_control="CC6.1",
            confidence=0.9,
        )
    )

    finding = FindingData(
        raw_event_id="raw-1",
        observation_type="misconfiguration",
        title="test",
        detail={},
        source="aws",
        source_type=SourceType.CLOUD,
        provider="aws",
        resource_type="iam_user",
        severity="high",
    )

    mapped = mapper.map(finding)
    assert len(mapped.mappings) > 0, "produces mappings"

    frameworks = {m.framework for m in mapped.mappings}
    assert "nist" in frameworks, "maps to NIST"
    assert "soc2" in frameworks, "crosswalks to SOC2"

    controls = {m.control_id for m in mapped.mappings}
    assert "AC-2" in controls, "explicit rule maps AC-2"
    assert "IA-2" in controls, "resource rule maps IA-2"
    assert "CC6.1" in controls, "crosswalk maps CC6.1"

    # Verify no duplicates
    pairs = [(m.framework, m.control_id) for m in mapped.mappings]
    assert len(pairs) == len(set(pairs)), "no duplicate mappings"

    # Crosswalk confidence is min(chain)
    cw = [m for m in mapped.mappings if m.mapping_method == "crosswalk"]
    assert len(cw) > 0 and cw[0].confidence == 0.9, "crosswalk has confidence"

    # Finding with no matching rules
    finding2 = FindingData(
        raw_event_id="raw-2",
        observation_type="inventory",
        title="test",
        detail={},
        source="gcp",
        source_type=SourceType.CLOUD,
        provider="gcp",
        resource_type="gke_cluster",
        severity="info",
    )
    mapped2 = mapper.map(finding2)
    assert len(mapped2.mappings) == 0, "unmatched finding returns empty mappings"


# ===================================================================
# 9. ASSERTION ENGINE
# ===================================================================


def test_assertion_engine():
    eng = AssertionEngine()

    @eng.assertion("test_pass")
    def always_pass(detail, raw):
        return True, []

    @eng.assertion("test_fail")
    def always_fail(detail, raw):
        return False, ["Something wrong"]

    @eng.assertion("test_crash")
    def always_crash(detail, raw):
        raise RuntimeError("boom")

    eng.bind_control("nist", "AC-1", "test_pass")
    eng.bind_control("nist", "AC-2", "test_fail")
    eng.bind_control("nist", "AC-3", "test_crash")
    eng.set_remediation("test_fail", {"summary": "Fix it", "steps": ["Step 1"]})

    # Pass
    passed, reasons = eng.evaluate("test_pass", {}, {})
    assert passed is True, "passing assertion returns True"
    assert len(reasons) == 0, "passing assertion returns empty reasons"

    # Fail
    passed, reasons = eng.evaluate("test_fail", {}, {})
    assert passed is False, "failing assertion returns False"
    assert len(reasons) == 1, "failing assertion returns reasons"

    # Crash
    passed, reasons = eng.evaluate("test_crash", {}, {})
    assert passed is False, "crashing assertion returns False"
    assert "error" in reasons[0].lower(), "crashing assertion returns error reason"

    # Unknown assertion
    passed, reasons = eng.evaluate("nonexistent", {}, {})
    assert passed is False, "unknown assertion returns False"

    # Control binding lookup
    assert eng.get_assertion_for_control("nist", "AC-1") == ["test_pass"], "bound control found"
    assert eng.get_assertion_for_control("nist", "ZZ-99") is None, "unbound control returns None"


# ===================================================================
# 10. ASSESSOR
# ===================================================================


def test_assessor():
    eng = AssertionEngine()

    @eng.assertion("check_mfa")
    def check_mfa(detail, raw):
        if detail.get("mfa_active"):
            return True, []
        return False, ["MFA not active"]

    eng.bind_control("nist", "IA-2", "check_mfa")
    eng.set_remediation("check_mfa", {"summary": "Enable MFA"})

    assessor = Assessor(engine=eng)

    finding = FindingData(
        raw_event_id="r1",
        observation_type="misconfiguration",
        title="No MFA",
        detail={"mfa_active": False},
        source="aws",
        source_type=SourceType.CLOUD,
        provider="aws",
        severity="high",
    )
    mapping_bound = ControlMappingData(
        finding_id=finding.id,
        framework="nist",
        control_id="IA-2",
    )
    mapping_unbound = ControlMappingData(
        finding_id=finding.id,
        framework="nist",
        control_id="ZZ-99",
    )
    mapped = MappedFinding(finding=finding, mappings=[mapping_bound, mapping_unbound])

    results = assessor.assess(mapped)
    assert len(results) == 2, "produces result per mapping"

    bound_result = [r for r in results if r.control_id == "IA-2"][0]
    assert bound_result.status == "non_compliant", "bound control is non_compliant"
    assert "check_mfa" in bound_result.assertion_name, "assertion ran"
    assert bound_result.remediation_summary == "Enable MFA", "has remediation"
    assert len(bound_result.evidence_ids) > 0, "has evidence ids"

    unbound_result = [r for r in results if r.control_id == "ZZ-99"][0]
    assert unbound_result.status == "not_assessed", "unbound control is not_assessed"


# ===================================================================
# 11. WEBHOOK RECEIVER
# ===================================================================


def test_webhook_receiver():
    receiver = WebhookReceiver()

    raw = receiver.ingest(
        payload={"alert": "test", "severity": "high"},
        source="webhook",
        provider="pagerduty",
        event_type="incident",
    )
    assert isinstance(raw, RawEventData), "returns RawEventData"
    assert raw.source == "webhook", "source is webhook"
    assert raw.provider == "pagerduty", "provider is pagerduty"
    assert raw.event_type == "incident", "event_type is incident"
    assert raw.raw_data["alert"] == "test", "raw_data preserved"
    assert len(raw.sha256) == 64, "has sha256"

    # Batch
    events = receiver.ingest_batch(
        payloads=[{"a": 1}, {"b": 2}],
        source="manual",
        provider="csv",
        event_type="upload",
    )
    assert len(events) == 2, "batch returns correct count"
    assert events[0].id != events[1].id, "batch events have different ids"


# ===================================================================
# 12. DATABASE PERSISTENCE (via Pipeline)
# ===================================================================


def test_database_persistence():
    engine_db = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine_db)
    Session = sessionmaker(bind=engine_db, expire_on_commit=False)
    session = Session()

    bus = EventBus()

    class SimpleConnector(BaseConnector):
        def validate(self):
            return []

        def health_check(self):
            return True

        def collect(self):
            r = ConnectorResult(
                connector_name=self.name,
                source="test",
                source_type=SourceType.CUSTOM,
                provider="test",
            )
            r.events.append(
                RawEventData(
                    source="test",
                    source_type=SourceType.CUSTOM,
                    provider="test",
                    event_type="simple_event",
                    raw_data={"message": "hello"},
                )
            )
            r.complete()
            return r

    class SimpleNormalizer(BaseNormalizer):
        def can_handle(self, raw):
            return raw.source == "test"

        def normalize(self, raw):
            return [
                FindingData(
                    raw_event_id=raw.id,
                    observation_type="test",
                    title="Test finding",
                    detail={"test": True},
                    source="test",
                    source_type=SourceType.CUSTOM,
                    provider="test",
                    resource_type="test_resource",
                    severity="medium",
                )
            ]

    connectors = ConnectorRegistry()
    connectors.register("test", SimpleConnector)
    connectors.create(ConnectorConfig(name="t1", source_type=SourceType.CUSTOM, provider="test"))

    normalizers = NormalizerRegistry()
    normalizers.register(SimpleNormalizer())

    mapper = ControlMapper()
    mapper.add_resource_rule(
        ResourceRule(
            resource_type="test_resource",
            framework="nist",
            control_ids=["TEST-1"],
            control_family="TEST",
        )
    )

    eng = AssertionEngine()
    assessor = Assessor(engine=eng)

    pipeline = Pipeline(
        connectors=connectors,
        normalizers=normalizers,
        mapper=mapper,
        assessor=assessor,
        bus=bus,
    )
    stats = pipeline.run(session)
    session.commit()

    # Verify all tables populated
    assert session.query(ConnectorRun).count() == 1, "connector_runs persisted"
    assert session.query(RawEvent).count() == 1, "raw_events persisted"
    assert session.query(Finding).count() == 1, "findings persisted"
    assert session.query(ControlMapping).count() == 1, "control_mappings persisted"
    assert session.query(ControlResult).count() == 1, "control_results persisted"

    # Verify relationships
    finding = session.query(Finding).first()
    assert finding.raw_event_id is not None, "finding links to raw_event"
    raw = session.query(RawEvent).first()
    assert raw.connector_run_id is not None, "raw_event links to connector_run"
    mapping = session.query(ControlMapping).first()
    assert mapping.finding_id == finding.id, "mapping links to finding"
    result = session.query(ControlResult).first()
    assert result.control_mapping_id == mapping.id, "result links to mapping"
    assert result.finding_id == finding.id, "result links to finding"

    # Verify sha256 integrity
    assert len(raw.sha256) == 64, "raw_event has sha256"
    assert len(finding.sha256) == 64, "finding has sha256"

    session.close()


# ===================================================================
# 13. FRAMEWORK YAML LOADING
# ===================================================================


def test_framework_loading():
    from warlock.pipeline.loader import load_framework_configs

    mapper = ControlMapper()
    from pathlib import Path

    framework_dir = str(Path(__file__).resolve().parent.parent / "warlock" / "frameworks")
    load_framework_configs(framework_dir, mapper)

    assert len(mapper._explicit_rules) > 100, "explicit rules loaded"
    assert len(mapper._resource_rules) > 100, "resource rules loaded"
    assert sum(len(v) for v in mapper._crosswalk_graph.values()) > 30, "crosswalk edges loaded"
    assert "nist_800_53" in mapper._active_frameworks, "nist framework active"
    assert "soc2" in mapper._active_frameworks, "soc2 framework active"
    assert "iso_27001" in mapper._active_frameworks, "iso 27001 in crosswalks"


# ===================================================================
# 14. ASSERTIONS LIBRARY
# ===================================================================


def test_assertions_library():
    from warlock.assessors.engine import engine
    from warlock.assessors import assertions  # noqa: F401 — triggers registration

    # Verify all 15 registered
    expected = [
        "mfa_enabled",
        "no_root_access_keys",
        "cloudtrail_enabled",
        "guardduty_enabled",
        "securityhub_enabled",
        "no_open_security_groups",
        "encryption_at_rest",
        "password_policy_compliant",
        "config_recorder_enabled",
        "no_public_storage",
        "endpoint_protection_active",
        "vulnerability_scan_current",
        "privileged_access_managed",
        "access_reviews_current",
        "siem_monitoring_active",
    ]
    for name in expected:
        assert name in engine._assertions, f"assertion '{name}' registered"

    # Test MFA assertion with different inputs (uses finding detail fields, not issues list)
    fn = engine._assertions["mfa_enabled"]
    passed, reasons = fn({"mfa_active": True, "password_enabled": True}, {})
    assert passed, "mfa_enabled passes when MFA active"

    passed, reasons = fn({"mfa_active": False, "password_enabled": True, "user": "test-user"}, {})
    assert not passed, "mfa_enabled fails when MFA inactive + console access"
    assert len(reasons) > 0, "mfa_enabled gives reason"

    # Test with empty detail — fail-closed when no MFA evidence
    passed, reasons = fn({}, {})
    assert not passed, "mfa_enabled fails closed on empty detail"

    # Test no_open_security_groups
    fn_sg = engine._assertions["no_open_security_groups"]
    passed, reasons = fn_sg({"issues": ["open_to_world_port_22"]}, {})
    assert not passed, "open SG detected"

    passed, reasons = fn_sg({"issues": []}, {})
    assert passed, "closed SG passes"

    # Test password_policy
    fn_pw = engine._assertions["password_policy_compliant"]
    passed, reasons = fn_pw({"issues": ["min_length_under_14", "no_symbols_required"]}, {})
    assert not passed, "bad password policy detected"
    assert len(reasons) >= 2, "multiple issues reported"

    # Verify control bindings exist
    assert "mfa_enabled" in (engine.get_assertion_for_control("nist_800_53", "IA-2") or []), (
        "IA-2 bound to mfa_enabled"
    )
    assert "cloudtrail_enabled" in (
        engine.get_assertion_for_control("nist_800_53", "AU-2") or []
    ), "AU-2 bound to cloudtrail_enabled"


# ===================================================================
# 15. ALL CONNECTOR TYPES IMPORTABLE
# ===================================================================


def test_all_connectors_importable():
    from warlock.pipeline.loader import load_all_connectors
    from warlock.connectors.base import registry

    load_all_connectors()
    expected = [
        "aws",
        "azure",
        "gcp",
        "crowdstrike",
        "defender",
        "sentinelone",
        "okta",
        "entra_id",
        "cyberark",
        "sailpoint",
        "tenable",
        "qualys",
        "wiz",
        "prisma",
        "sentinel",
        "splunk",
        "elastic",
    ]
    for provider in expected:
        assert provider in registry.list_types(), f"connector '{provider}' registered"


# ===================================================================
# 16. ALL NORMALIZERS IMPORTABLE
# ===================================================================


def test_all_normalizers_importable():
    from warlock.pipeline.loader import load_all_normalizers
    from warlock.normalizers.base import registry

    load_all_normalizers()
    assert len(registry._normalizers) >= 18, "18+ normalizers registered"

    # Verify each normalizer has can_handle and normalize methods
    for n in registry._normalizers:
        assert hasattr(n, "can_handle"), f"{type(n).__name__} has can_handle"
        assert hasattr(n, "normalize"), f"{type(n).__name__} has normalize"


# ===================================================================
# 17. AI REASONING RESULT
# ===================================================================


def test_ai_reasoning():
    result = AIReasoningResult(
        status="non_compliant",
        assessment="Control is not met because MFA is disabled.",
        confidence=0.85,
        model="claude-sonnet-4",
    )
    assert result.status == "non_compliant", "AIReasoningResult fields"
    assert result.confidence == 0.85, "AIReasoningResult confidence"

    # Factory function
    try:
        reasoner = create_reasoner("ollama", "", "llama3", "http://localhost:11434")
        assert reasoner is not None, "create_reasoner works"
    except Exception as e:
        assert False, f"create_reasoner works — {e}"

    try:
        create_reasoner("nonexistent", "", "model", "")
        assert False, "create_reasoner rejects unknown provider"
    except ValueError:
        pass  # expected


# ===================================================================
# 18. PIPELINE STATS
# ===================================================================


def test_pipeline_stats():
    from warlock.pipeline.orchestrator import PipelineRunStats

    stats = PipelineRunStats()
    assert stats.raw_events_collected == 0, "initial stats are zero"
    assert stats.duration_seconds is None, "duration is None before completion"

    stats.raw_events_collected = 10
    stats.findings_normalized = 5
    stats.controls_mapped = 20
    stats.results_assessed = 20
    stats.completed_at = datetime.now(timezone.utc)
    assert stats.duration_seconds is not None, "duration computed after completion"
    assert stats.duration_seconds >= 0, "duration is positive"
