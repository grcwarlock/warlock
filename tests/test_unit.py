"""Unit tests for every pipeline component."""

import json
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker

from warlock.db.models import (
    Base, ConnectorRun, RawEvent, Finding, ControlMapping, ControlResult,
)
from warlock.pipeline.bus import EventBus, PipelineEvent
from warlock.connectors.base import (
    BaseConnector, ConnectorConfig, ConnectorRegistry, ConnectorResult,
    RawEventData, SourceType,
)
from warlock.normalizers.base import BaseNormalizer, FindingData, NormalizerRegistry
from warlock.normalizers.aws import AWSNormalizer
from warlock.normalizers.generic import GenericNormalizer
from warlock.mappers.control_mapper import (
    ControlMapper, ControlMappingData, ExplicitRule, ResourceRule, CrosswalkEdge, MappedFinding,
)
from warlock.assessors.engine import AssertionEngine, Assessor, ControlResultData
from warlock.assessors.ai_reasoning import AIReasoningResult, create_reasoner
from warlock.connectors.webhook import WebhookReceiver
from warlock.pipeline.orchestrator import Pipeline


PASS = 0
FAIL = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL: {name} — {detail}")


# ===================================================================
# 1. EVENT BUS
# ===================================================================

def test_event_bus():
    print("\n--- Event Bus ---")
    bus = EventBus()
    received = []

    bus.subscribe("test.event", lambda e: received.append(e))
    bus.publish(PipelineEvent(event_type="test.event", payload_id="abc"))
    bus.publish(PipelineEvent(event_type="other.event", payload_id="xyz"))

    check("subscribe receives matching events", len(received) == 1)
    check("subscribe ignores non-matching events", received[0].payload_id == "abc")

    # Wildcard
    all_events = []
    bus.subscribe_all(lambda e: all_events.append(e))
    bus.publish(PipelineEvent(event_type="any.thing", payload_id="123"))
    check("subscribe_all receives everything", len(all_events) == 1)

    # Error handling — handlers that throw don't crash publish
    bus.subscribe("error.test", lambda e: 1/0)
    try:
        bus.publish(PipelineEvent(event_type="error.test", payload_id="err"))
        check("handler exception doesn't crash publish", True)
    except Exception:
        check("handler exception doesn't crash publish", False, "Exception propagated")

    # Clear
    bus.clear()
    before = len(received)
    bus.publish(PipelineEvent(event_type="test.event", payload_id="after"))
    check("clear removes all subscriptions", len(received) == before)


# ===================================================================
# 2. RAW EVENT DATA
# ===================================================================

def test_raw_event_data():
    print("\n--- RawEventData ---")
    raw = RawEventData(
        source="aws", source_type=SourceType.CLOUD, provider="aws",
        event_type="test", raw_data={"key": "value"},
    )
    check("has UUID id", len(raw.id) == 36)
    check("has sha256", len(raw.sha256) == 64)

    # Same data → same hash
    raw2 = RawEventData(
        source="aws", source_type=SourceType.CLOUD, provider="aws",
        event_type="test", raw_data={"key": "value"},
    )
    check("deterministic sha256", raw.sha256 == raw2.sha256)

    # Different data → different hash
    raw3 = RawEventData(
        source="aws", source_type=SourceType.CLOUD, provider="aws",
        event_type="test", raw_data={"key": "other"},
    )
    check("different data → different sha256", raw.sha256 != raw3.sha256)


# ===================================================================
# 3. CONNECTOR REGISTRY
# ===================================================================

def test_connector_registry():
    print("\n--- Connector Registry ---")

    class GoodConnector(BaseConnector):
        def validate(self): return []
        def health_check(self): return True
        def collect(self):
            r = ConnectorResult(
                connector_name=self.name, source="test",
                source_type=SourceType.CUSTOM, provider="test",
            )
            r.events.append(RawEventData(
                source="test", source_type=SourceType.CUSTOM, provider="test",
                event_type="test_event", raw_data={"x": 1},
            ))
            r.complete()
            return r

    class BadConnector(BaseConnector):
        def validate(self): return ["Missing API key"]
        def health_check(self): return False
        def collect(self): return ConnectorResult(
            connector_name=self.name, source="bad",
            source_type=SourceType.CUSTOM, provider="bad",
        )

    reg = ConnectorRegistry()
    reg.register("good", GoodConnector)
    reg.register("bad", BadConnector)

    check("list_types returns registered", set(reg.list_types()) == {"good", "bad"})

    # Good connector creates successfully
    conn = reg.create(ConnectorConfig(name="g1", source_type=SourceType.CUSTOM, provider="good"))
    check("good connector created", conn is not None)
    check("active list updated", "g1" in reg.list_active())

    # Bad connector fails validation
    try:
        reg.create(ConnectorConfig(name="b1", source_type=SourceType.CUSTOM, provider="bad"))
        check("bad connector rejected", False, "Should have raised ValueError")
    except ValueError:
        check("bad connector rejected", True)

    # Unknown provider
    try:
        reg.create(ConnectorConfig(name="u1", source_type=SourceType.CUSTOM, provider="unknown"))
        check("unknown provider rejected", False)
    except ValueError:
        check("unknown provider rejected", True)

    # collect_all
    results = reg.collect_all()
    check("collect_all returns results", len(results) == 1)
    check("collect_all result has events", results[0].event_count == 1)
    check("collect_all result status", results[0].status == "success")


# ===================================================================
# 4. CONNECTOR RESULT
# ===================================================================

def test_connector_result():
    print("\n--- ConnectorResult ---")
    r = ConnectorResult(
        connector_name="test", source="test",
        source_type=SourceType.CUSTOM, provider="test",
    )
    r.events.append(RawEventData(
        source="test", source_type=SourceType.CUSTOM, provider="test",
        event_type="e1", raw_data={},
    ))
    r.complete()
    check("success when events and no errors", r.status == "success")
    check("duration computed", r.duration_seconds is not None)
    check("event_count property", r.event_count == 1)

    # Partial
    r2 = ConnectorResult(
        connector_name="test", source="test",
        source_type=SourceType.CUSTOM, provider="test",
    )
    r2.events.append(RawEventData(
        source="test", source_type=SourceType.CUSTOM, provider="test",
        event_type="e1", raw_data={},
    ))
    r2.errors.append("some error")
    r2.complete()
    check("partial when events + errors", r2.status == "partial")

    # Error
    r3 = ConnectorResult(
        connector_name="test", source="test",
        source_type=SourceType.CUSTOM, provider="test",
    )
    r3.errors.append("fatal")
    r3.complete()
    check("error when only errors", r3.status == "error")


# ===================================================================
# 5. NORMALIZER REGISTRY
# ===================================================================

def test_normalizer_registry():
    print("\n--- Normalizer Registry ---")
    reg = NormalizerRegistry()

    class TestNormalizer(BaseNormalizer):
        def can_handle(self, raw): return raw.source == "test"
        def normalize(self, raw):
            return [FindingData(
                raw_event_id=raw.id, observation_type="test",
                title="test finding", detail={}, source="test",
                source_type=SourceType.CUSTOM, provider="test",
            )]

    reg.register(TestNormalizer())

    raw = RawEventData(source="test", source_type=SourceType.CUSTOM,
                       provider="test", event_type="e1", raw_data={})
    findings = reg.normalize(raw)
    check("normalizer produces findings", len(findings) == 1)
    check("finding has correct type", findings[0].observation_type == "test")

    # Unhandled source returns empty
    raw2 = RawEventData(source="unknown", source_type=SourceType.CUSTOM,
                        provider="unknown", event_type="e1", raw_data={})
    findings2 = reg.normalize(raw2)
    check("unhandled source returns empty", len(findings2) == 0)

    # Normalizer that throws returns empty (not crash)
    class CrashNormalizer(BaseNormalizer):
        def can_handle(self, raw): return raw.source == "crash"
        def normalize(self, raw): raise RuntimeError("boom")

    reg.register(CrashNormalizer())
    raw3 = RawEventData(source="crash", source_type=SourceType.CUSTOM,
                        provider="crash", event_type="e1", raw_data={})
    findings3 = reg.normalize(raw3)
    check("crashing normalizer returns empty", len(findings3) == 0)


# ===================================================================
# 6. AWS NORMALIZER — detailed checks
# ===================================================================

def test_aws_normalizer():
    print("\n--- AWS Normalizer ---")
    norm = AWSNormalizer()

    # Credential report
    raw = RawEventData(
        source="aws", source_type=SourceType.CLOUD, provider="aws",
        event_type="iam_credential_report",
        raw_data={
            "region": "us-east-1", "account_id": "111111111111",
            "response": {"Content": (
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
            )},
        },
    )
    check("can handle credential report", norm.can_handle(raw))
    findings = norm.normalize(raw)
    check("credential report produces 3 findings", len(findings) == 3)

    root = [f for f in findings if "root" in f.resource_id]
    check("root account found", len(root) == 1)
    check("root has critical severity (access keys)", root[0].severity == "critical")

    bad = [f for f in findings if "bad-user" in f.title]
    check("bad-user found", len(bad) == 1)
    check("bad-user is high severity (no MFA)", bad[0].severity == "high")
    check("bad-user is misconfiguration", bad[0].observation_type == "misconfiguration")

    good = [f for f in findings if "good-user" in f.title]
    check("good-user found", len(good) == 1)
    check("good-user is info severity", good[0].severity == "info")
    check("good-user is inventory", good[0].observation_type == "inventory")

    # Security groups
    raw_sg = RawEventData(
        source="aws", source_type=SourceType.CLOUD, provider="aws",
        event_type="ec2_security_groups",
        raw_data={
            "region": "us-east-1", "account_id": "111111111111",
            "response": {"SecurityGroups": [
                {"GroupId": "sg-bad", "GroupName": "open",
                 "IpPermissions": [{"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp",
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
                {"GroupId": "sg-good", "GroupName": "closed",
                 "IpPermissions": [{"FromPort": 443, "ToPort": 443, "IpProtocol": "tcp",
                                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]},
            ]},
        },
    )
    sg_findings = norm.normalize(raw_sg)
    check("security groups produce 2 findings", len(sg_findings) == 2)
    open_sg = [f for f in sg_findings if f.severity == "high"]
    check("open SG is high severity", len(open_sg) == 1)

    # Can't handle unknown event type
    raw_unk = RawEventData(
        source="aws", source_type=SourceType.CLOUD, provider="aws",
        event_type="unknown_type", raw_data={},
    )
    check("rejects unknown event type", not norm.can_handle(raw_unk))

    # Empty credential report
    raw_empty = RawEventData(
        source="aws", source_type=SourceType.CLOUD, provider="aws",
        event_type="iam_credential_report",
        raw_data={"region": "us-east-1", "account_id": "111", "response": {"Content": ""}},
    )
    empty_findings = norm.normalize(raw_empty)
    check("empty credential report returns empty", len(empty_findings) == 0)


# ===================================================================
# 7. GENERIC NORMALIZER
# ===================================================================

def test_generic_normalizer():
    print("\n--- Generic Normalizer ---")
    norm = GenericNormalizer()

    # Structured payload with common fields
    raw = RawEventData(
        source="webhook", source_type=SourceType.CUSTOM, provider="custom",
        event_type="alert",
        raw_data={"title": "Test Alert", "severity": "high", "description": "Something bad"},
    )
    check("can handle any event", norm.can_handle(raw))
    findings = norm.normalize(raw)
    check("structured payload produces finding", len(findings) >= 1)
    check("extracts severity", findings[0].severity == "high")
    check("extracts title", "Test Alert" in findings[0].title)

    # Completely empty payload
    raw_empty = RawEventData(
        source="webhook", source_type=SourceType.CUSTOM, provider="custom",
        event_type="unknown", raw_data={},
    )
    findings_empty = norm.normalize(raw_empty)
    check("empty payload still produces a finding", len(findings_empty) >= 1)

    # Payload with list of items
    raw_list = RawEventData(
        source="webhook", source_type=SourceType.CUSTOM, provider="custom",
        event_type="batch",
        raw_data={"alerts": [
            {"title": "Alert 1", "severity": "critical"},
            {"title": "Alert 2", "severity": "low"},
        ]},
    )
    findings_list = norm.normalize(raw_list)
    check("list payload fans out", len(findings_list) >= 2)


# ===================================================================
# 8. CONTROL MAPPER
# ===================================================================

def test_control_mapper():
    print("\n--- Control Mapper ---")
    mapper = ControlMapper()

    # Explicit rule
    mapper.add_explicit_rule(ExplicitRule(
        source="aws", event_type="misconfiguration",
        framework="nist", control_id="AC-2", control_family="AC",
    ))
    # Resource rule
    mapper.add_resource_rule(ResourceRule(
        resource_type="iam_user", framework="nist",
        control_ids=["AC-2", "IA-2"], control_family="AC",
    ))
    # Crosswalk
    mapper.add_crosswalk(CrosswalkEdge(
        source_framework="nist", source_control="AC-2",
        target_framework="soc2", target_control="CC6.1",
        confidence=0.9,
    ))

    finding = FindingData(
        raw_event_id="raw-1", observation_type="misconfiguration",
        title="test", detail={}, source="aws", source_type=SourceType.CLOUD,
        provider="aws", resource_type="iam_user", severity="high",
    )

    mapped = mapper.map(finding)
    check("produces mappings", len(mapped.mappings) > 0)

    frameworks = {m.framework for m in mapped.mappings}
    check("maps to NIST", "nist" in frameworks)
    check("crosswalks to SOC2", "soc2" in frameworks)

    controls = {m.control_id for m in mapped.mappings}
    check("explicit rule maps AC-2", "AC-2" in controls)
    check("resource rule maps IA-2", "IA-2" in controls)
    check("crosswalk maps CC6.1", "CC6.1" in controls)

    # Verify no duplicates
    pairs = [(m.framework, m.control_id) for m in mapped.mappings]
    check("no duplicate mappings", len(pairs) == len(set(pairs)))

    # Crosswalk confidence is min(chain)
    cw = [m for m in mapped.mappings if m.mapping_method == "crosswalk"]
    check("crosswalk has confidence", len(cw) > 0 and cw[0].confidence == 0.9)

    # Finding with no matching rules
    finding2 = FindingData(
        raw_event_id="raw-2", observation_type="inventory",
        title="test", detail={}, source="gcp", source_type=SourceType.CLOUD,
        provider="gcp", resource_type="gke_cluster", severity="info",
    )
    mapped2 = mapper.map(finding2)
    check("unmatched finding returns empty mappings", len(mapped2.mappings) == 0)


# ===================================================================
# 9. ASSERTION ENGINE
# ===================================================================

def test_assertion_engine():
    print("\n--- Assertion Engine ---")
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
    check("passing assertion returns True", passed is True)
    check("passing assertion returns empty reasons", len(reasons) == 0)

    # Fail
    passed, reasons = eng.evaluate("test_fail", {}, {})
    check("failing assertion returns False", passed is False)
    check("failing assertion returns reasons", len(reasons) == 1)

    # Crash
    passed, reasons = eng.evaluate("test_crash", {}, {})
    check("crashing assertion returns False", passed is False)
    check("crashing assertion returns error reason", "error" in reasons[0].lower())

    # Unknown assertion
    passed, reasons = eng.evaluate("nonexistent", {}, {})
    check("unknown assertion returns False", passed is False)

    # Control binding lookup
    check("bound control found", eng.get_assertion_for_control("nist", "AC-1") == ["test_pass"])
    check("unbound control returns None", eng.get_assertion_for_control("nist", "ZZ-99") is None)


# ===================================================================
# 10. ASSESSOR
# ===================================================================

def test_assessor():
    print("\n--- Assessor ---")
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
        raw_event_id="r1", observation_type="misconfiguration",
        title="No MFA", detail={"mfa_active": False},
        source="aws", source_type=SourceType.CLOUD, provider="aws",
        severity="high",
    )
    mapping_bound = ControlMappingData(
        finding_id=finding.id, framework="nist", control_id="IA-2",
    )
    mapping_unbound = ControlMappingData(
        finding_id=finding.id, framework="nist", control_id="ZZ-99",
    )
    mapped = MappedFinding(finding=finding, mappings=[mapping_bound, mapping_unbound])

    results = assessor.assess(mapped)
    check("produces result per mapping", len(results) == 2)

    bound_result = [r for r in results if r.control_id == "IA-2"][0]
    check("bound control is non_compliant", bound_result.status == "non_compliant")
    check("assertion ran", "check_mfa" in bound_result.assertion_name)
    check("has remediation", bound_result.remediation_summary == "Enable MFA")
    check("has evidence ids", len(bound_result.evidence_ids) > 0)

    unbound_result = [r for r in results if r.control_id == "ZZ-99"][0]
    check("unbound control is not_assessed", unbound_result.status == "not_assessed")


# ===================================================================
# 11. WEBHOOK RECEIVER
# ===================================================================

def test_webhook_receiver():
    print("\n--- Webhook Receiver ---")
    receiver = WebhookReceiver()

    raw = receiver.ingest(
        payload={"alert": "test", "severity": "high"},
        source="webhook", provider="pagerduty", event_type="incident",
    )
    check("returns RawEventData", isinstance(raw, RawEventData))
    check("source is webhook", raw.source == "webhook")
    check("provider is pagerduty", raw.provider == "pagerduty")
    check("event_type is incident", raw.event_type == "incident")
    check("raw_data preserved", raw.raw_data["alert"] == "test")
    check("has sha256", len(raw.sha256) == 64)

    # Batch
    events = receiver.ingest_batch(
        payloads=[{"a": 1}, {"b": 2}],
        source="manual", provider="csv", event_type="upload",
    )
    check("batch returns correct count", len(events) == 2)
    check("batch events have different ids", events[0].id != events[1].id)


# ===================================================================
# 12. DATABASE PERSISTENCE (via Pipeline)
# ===================================================================

def test_database_persistence():
    print("\n--- Database Persistence ---")
    engine_db = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine_db)
    Session = sessionmaker(bind=engine_db, expire_on_commit=False)
    session = Session()

    bus = EventBus()

    class SimpleConnector(BaseConnector):
        def validate(self): return []
        def health_check(self): return True
        def collect(self):
            r = ConnectorResult(
                connector_name=self.name, source="test",
                source_type=SourceType.CUSTOM, provider="test",
            )
            r.events.append(RawEventData(
                source="test", source_type=SourceType.CUSTOM, provider="test",
                event_type="simple_event",
                raw_data={"message": "hello"},
            ))
            r.complete()
            return r

    class SimpleNormalizer(BaseNormalizer):
        def can_handle(self, raw): return raw.source == "test"
        def normalize(self, raw):
            return [FindingData(
                raw_event_id=raw.id, observation_type="test",
                title="Test finding", detail={"test": True},
                source="test", source_type=SourceType.CUSTOM, provider="test",
                resource_type="test_resource", severity="medium",
            )]

    connectors = ConnectorRegistry()
    connectors.register("test", SimpleConnector)
    connectors.create(ConnectorConfig(name="t1", source_type=SourceType.CUSTOM, provider="test"))

    normalizers = NormalizerRegistry()
    normalizers.register(SimpleNormalizer())

    mapper = ControlMapper()
    mapper.add_resource_rule(ResourceRule(
        resource_type="test_resource", framework="nist",
        control_ids=["TEST-1"], control_family="TEST",
    ))

    eng = AssertionEngine()
    assessor = Assessor(engine=eng)

    pipeline = Pipeline(
        connectors=connectors, normalizers=normalizers,
        mapper=mapper, assessor=assessor, bus=bus,
    )
    stats = pipeline.run(session)
    session.commit()

    # Verify all tables populated
    check("connector_runs persisted", session.query(ConnectorRun).count() == 1)
    check("raw_events persisted", session.query(RawEvent).count() == 1)
    check("findings persisted", session.query(Finding).count() == 1)
    check("control_mappings persisted", session.query(ControlMapping).count() == 1)
    check("control_results persisted", session.query(ControlResult).count() == 1)

    # Verify relationships
    finding = session.query(Finding).first()
    check("finding links to raw_event", finding.raw_event_id is not None)
    raw = session.query(RawEvent).first()
    check("raw_event links to connector_run", raw.connector_run_id is not None)
    mapping = session.query(ControlMapping).first()
    check("mapping links to finding", mapping.finding_id == finding.id)
    result = session.query(ControlResult).first()
    check("result links to mapping", result.control_mapping_id == mapping.id)
    check("result links to finding", result.finding_id == finding.id)

    # Verify sha256 integrity
    check("raw_event has sha256", len(raw.sha256) == 64)
    check("finding has sha256", len(finding.sha256) == 64)

    session.close()


# ===================================================================
# 13. FRAMEWORK YAML LOADING
# ===================================================================

def test_framework_loading():
    print("\n--- Framework YAML Loading ---")
    from warlock.pipeline.loader import load_framework_configs

    mapper = ControlMapper()
    from pathlib import Path
    framework_dir = str(Path(__file__).resolve().parent.parent / "warlock" / "frameworks")
    load_framework_configs(framework_dir, mapper)

    check("explicit rules loaded", len(mapper._explicit_rules) > 100)
    check("resource rules loaded", len(mapper._resource_rules) > 100)
    check("crosswalk edges loaded", sum(len(v) for v in mapper._crosswalk_graph.values()) > 30)
    check("nist framework active", "nist_800_53" in mapper._active_frameworks)
    check("soc2 framework active", "soc2" in mapper._active_frameworks)
    check("iso 27001 in crosswalks", "iso_27001" in mapper._active_frameworks)


# ===================================================================
# 14. ASSERTIONS LIBRARY
# ===================================================================

def test_assertions_library():
    print("\n--- Assertions Library ---")
    from warlock.assessors.engine import engine
    from warlock.assessors import assertions  # noqa: F401 — triggers registration

    # Verify all 15 registered
    expected = [
        "mfa_enabled", "no_root_access_keys", "cloudtrail_enabled",
        "guardduty_enabled", "securityhub_enabled", "no_open_security_groups",
        "encryption_at_rest", "password_policy_compliant", "config_recorder_enabled",
        "no_public_storage", "endpoint_protection_active", "vulnerability_scan_current",
        "privileged_access_managed", "access_reviews_current", "siem_monitoring_active",
    ]
    for name in expected:
        check(f"assertion '{name}' registered", name in engine._assertions)

    # Test MFA assertion with different inputs (uses finding detail fields, not issues list)
    fn = engine._assertions["mfa_enabled"]
    passed, reasons = fn({"mfa_active": True, "password_enabled": True}, {})
    check("mfa_enabled passes when MFA active", passed)

    passed, reasons = fn({"mfa_active": False, "password_enabled": True, "user": "test-user"}, {})
    check("mfa_enabled fails when MFA inactive + console access", not passed)
    check("mfa_enabled gives reason", len(reasons) > 0)

    # Test with empty detail — fail-closed when no MFA evidence
    passed, reasons = fn({}, {})
    check("mfa_enabled fails closed on empty detail", not passed)  # no recognizable fields = fail closed

    # Test no_open_security_groups
    fn_sg = engine._assertions["no_open_security_groups"]
    passed, reasons = fn_sg({"issues": ["open_to_world_port_22"]}, {})
    check("open SG detected", not passed)

    passed, reasons = fn_sg({"issues": []}, {})
    check("closed SG passes", passed)

    # Test password_policy
    fn_pw = engine._assertions["password_policy_compliant"]
    passed, reasons = fn_pw({"issues": ["min_length_under_14", "no_symbols_required"]}, {})
    check("bad password policy detected", not passed)
    check("multiple issues reported", len(reasons) >= 2)

    # Verify control bindings exist
    check("IA-2 bound to mfa_enabled",
          "mfa_enabled" in (engine.get_assertion_for_control("nist_800_53", "IA-2") or []))
    check("AU-2 bound to cloudtrail_enabled",
          "cloudtrail_enabled" in (engine.get_assertion_for_control("nist_800_53", "AU-2") or []))


# ===================================================================
# 15. ALL CONNECTOR TYPES IMPORTABLE
# ===================================================================

def test_all_connectors_importable():
    print("\n--- All Connectors Importable ---")
    from warlock.pipeline.loader import load_all_connectors
    from warlock.connectors.base import registry

    load_all_connectors()
    expected = [
        "aws", "azure", "gcp", "crowdstrike", "defender", "sentinelone",
        "okta", "entra_id", "cyberark", "sailpoint",
        "tenable", "qualys", "wiz", "prisma",
        "sentinel", "splunk", "elastic",
    ]
    for provider in expected:
        check(f"connector '{provider}' registered", provider in registry.list_types())


# ===================================================================
# 16. ALL NORMALIZERS IMPORTABLE
# ===================================================================

def test_all_normalizers_importable():
    print("\n--- All Normalizers Importable ---")
    from warlock.pipeline.loader import load_all_normalizers
    from warlock.normalizers.base import registry

    load_all_normalizers()
    check("18+ normalizers registered", len(registry._normalizers) >= 18)

    # Verify each normalizer has can_handle and normalize methods
    for n in registry._normalizers:
        check(f"{type(n).__name__} has can_handle", hasattr(n, "can_handle"))
        check(f"{type(n).__name__} has normalize", hasattr(n, "normalize"))


# ===================================================================
# 17. AI REASONING RESULT
# ===================================================================

def test_ai_reasoning():
    print("\n--- AI Reasoning ---")
    result = AIReasoningResult(
        status="non_compliant",
        assessment="Control is not met because MFA is disabled.",
        confidence=0.85,
        model="claude-sonnet-4",
    )
    check("AIReasoningResult fields", result.status == "non_compliant")
    check("AIReasoningResult confidence", result.confidence == 0.85)

    # Factory function
    try:
        reasoner = create_reasoner("ollama", "", "llama3", "http://localhost:11434")
        check("create_reasoner works", reasoner is not None)
    except Exception as e:
        check("create_reasoner works", False, str(e))

    try:
        create_reasoner("nonexistent", "", "model", "")
        check("create_reasoner rejects unknown provider", False)
    except ValueError:
        check("create_reasoner rejects unknown provider", True)


# ===================================================================
# 18. PIPELINE STATS
# ===================================================================

def test_pipeline_stats():
    print("\n--- Pipeline Stats ---")
    from warlock.pipeline.orchestrator import PipelineRunStats

    stats = PipelineRunStats()
    check("initial stats are zero", stats.raw_events_collected == 0)
    check("duration is None before completion", stats.duration_seconds is None)

    stats.raw_events_collected = 10
    stats.findings_normalized = 5
    stats.controls_mapped = 20
    stats.results_assessed = 20
    stats.completed_at = datetime.now(timezone.utc)
    check("duration computed after completion", stats.duration_seconds is not None)
    check("duration is positive", stats.duration_seconds >= 0)


# ===================================================================
# RUN ALL
# ===================================================================

if __name__ == "__main__":
    test_event_bus()
    test_raw_event_data()
    test_connector_registry()
    test_connector_result()
    test_normalizer_registry()
    test_aws_normalizer()
    test_generic_normalizer()
    test_control_mapper()
    test_assertion_engine()
    test_assessor()
    test_webhook_receiver()
    test_database_persistence()
    test_framework_loading()
    test_assertions_library()
    test_all_connectors_importable()
    test_all_normalizers_importable()
    test_ai_reasoning()
    test_pipeline_stats()

    print(f"\n{'='*60}")
    print(f"  {PASS} passed, {FAIL} failed")
    print(f"{'='*60}")
    if FAIL > 0:
        exit(1)
