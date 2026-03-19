"""Tests for the OPA compliance evaluation engine.

Covers:
  - PolicyRegistry: scanning, framework resolution, caching
  - NormalizedDataAssembler: AWS IAM, multi-source merging
  - OPAComplianceEvaluator: graceful fallback, response parsing
  - UCF policy registration
"""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from warlock.assessors.data_assembler import NormalizedDataAssembler
from warlock.assessors.engine import ControlResultData
from warlock.assessors.opa_evaluator import OPAComplianceEvaluator, OPAPolicyResult
from warlock.assessors.policy_registry import PolicyRegistry
from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import FindingData


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_raw_event(
    source: str = "aws",
    event_type: str = "iam_credential_report",
    raw_data: dict | None = None,
    event_id: str | None = None,
) -> RawEventData:
    return RawEventData(
        id=event_id or str(uuid4()),
        source=source,
        source_type=SourceType.CLOUD,
        provider=source,
        event_type=event_type,
        raw_data=raw_data or {},
        observed_at=datetime.now(timezone.utc),
    )


def _make_finding(
    source: str = "aws",
    raw_event_id: str = "",
    detail: dict | None = None,
    resource_type: str = "iam_user",
    resource_name: str = "test-user",
) -> FindingData:
    return FindingData(
        id=str(uuid4()),
        raw_event_id=raw_event_id,
        source=source,
        source_type=SourceType.CLOUD,
        provider=source,
        observation_type="inventory",
        title=f"Test finding: {resource_name}",
        detail=detail or {},
        resource_id=f"arn:aws:iam::user/{resource_name}",
        resource_type=resource_type,
        resource_name=resource_name,
        severity="info",
        observed_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# PolicyRegistry tests
# ---------------------------------------------------------------------------

class TestPolicyRegistry:
    """Tests for the PolicyRegistry scanner."""

    def test_policy_registry_scans_all_policies(self):
        """Registry should discover all non-test, non-terraform Rego policies."""
        registry = PolicyRegistry()
        policy_map = registry.policy_map

        # We know there are 296 non-test policy files and 12 UCF ones we just added
        # Not all will map (terraform excluded), but we should have a substantial count
        assert len(policy_map) > 200, (
            f"Expected 200+ policies in registry, got {len(policy_map)}"
        )

        # Should have multiple frameworks
        frameworks = registry.list_frameworks()
        assert len(frameworks) >= 5, (
            f"Expected 5+ frameworks, got {frameworks}"
        )

        # Verify known frameworks are present
        for fw in ["nist_800_53", "soc2", "iso_27001", "cmmc", "hipaa"]:
            assert fw in frameworks, f"Missing framework: {fw}"

    def test_nist_control_resolution(self):
        """NIST package paths should resolve to correct control IDs."""
        registry = PolicyRegistry()
        pm = registry.policy_map

        # nist.ac.ac_2 should map to ("nist_800_53", "AC-2")
        assert "nist.ac.ac_2" in pm
        fw, ctrl = pm["nist.ac.ac_2"]
        assert fw == "nist_800_53"
        assert ctrl == "AC-2"

    def test_soc2_control_resolution(self):
        """SOC 2 package paths should resolve to correct control IDs."""
        registry = PolicyRegistry()
        pm = registry.policy_map

        assert "soc2.cc6" in pm
        fw, ctrl = pm["soc2.cc6"]
        assert fw == "soc2"
        assert ctrl == "CC6.1"

    def test_reverse_map(self):
        """Reverse map should allow lookup by (framework, control_id)."""
        registry = PolicyRegistry()
        rm = registry.reverse_map

        assert ("nist_800_53", "AC-2") in rm
        assert rm[("nist_800_53", "AC-2")] == "nist.ac.ac_2"

    def test_ucf_policies_registered(self):
        """UCF policies we created should appear in the registry."""
        registry = PolicyRegistry()
        pm = registry.policy_map

        ucf_policies = {pkg: ctrl for pkg, (fw, ctrl) in pm.items() if fw == "ucf"}
        assert len(ucf_policies) >= 10, (
            f"Expected 10+ UCF policies, got {len(ucf_policies)}: {list(ucf_policies.keys())}"
        )

        # Verify specific UCF controls
        assert "ucf.gov.ucf_gov_1" in pm
        fw, ctrl = pm["ucf.gov.ucf_gov_1"]
        assert fw == "ucf"
        assert ctrl == "UCF-GOV-1"

    def test_get_framework_policies(self):
        """Should filter policies by framework."""
        registry = PolicyRegistry()
        nist_policies = registry.get_framework_policies("nist_800_53")
        assert len(nist_policies) > 50
        assert all(
            pkg.startswith("nist.") for pkg in nist_policies
        )

    def test_cache_invalidation(self):
        """Invalidate should force re-scan on next access."""
        registry = PolicyRegistry()
        _ = registry.policy_map  # trigger scan
        registry.invalidate()
        assert registry._policy_map is None
        _ = registry.policy_map  # re-scan
        assert registry._policy_map is not None


# ---------------------------------------------------------------------------
# NormalizedDataAssembler tests
# ---------------------------------------------------------------------------

class TestDataAssembler:
    """Tests for the NormalizedDataAssembler."""

    def test_data_assembler_aws_iam(self):
        """AWS IAM credential report should produce users[] and root_account."""
        assembler = NormalizedDataAssembler()

        raw_id = str(uuid4())
        raw_event = _make_raw_event(
            source="aws",
            event_type="iam_credential_report",
            event_id=raw_id,
        )

        findings = [
            _make_finding(
                source="aws",
                raw_event_id=raw_id,
                detail={
                    "user": "alice",
                    "mfa_active": True,
                    "password_enabled": True,
                    "access_key_1_active": False,
                    "access_key_2_active": False,
                },
                resource_name="alice",
            ),
            _make_finding(
                source="aws",
                raw_event_id=raw_id,
                detail={
                    "user": "bob",
                    "mfa_active": False,
                    "password_enabled": True,
                    "access_key_1_active": True,
                    "access_key_2_active": False,
                },
                resource_name="bob",
            ),
        ]

        result = assembler.assemble(findings, [raw_event])

        assert len(result["users"]) == 2
        alice = next(u for u in result["users"] if u["username"] == "alice")
        assert alice["mfa_enabled"] is True
        bob = next(u for u in result["users"] if u["username"] == "bob")
        assert bob["mfa_enabled"] is False

    def test_data_assembler_merges_sources(self):
        """Assembler should merge data from multiple sources."""
        assembler = NormalizedDataAssembler()

        # AWS credential report
        aws_raw_id = str(uuid4())
        aws_raw = _make_raw_event(
            source="aws",
            event_type="iam_credential_report",
            event_id=aws_raw_id,
        )
        aws_finding = _make_finding(
            source="aws",
            raw_event_id=aws_raw_id,
            detail={
                "user": "alice",
                "mfa_active": True,
                "password_enabled": True,
                "access_key_1_active": False,
                "access_key_2_active": False,
            },
        )

        # CrowdStrike devices
        cs_raw_id = str(uuid4())
        cs_raw = _make_raw_event(
            source="crowdstrike",
            event_type="falcon_devices",
            event_id=cs_raw_id,
        )
        cs_finding = _make_finding(
            source="crowdstrike",
            raw_event_id=cs_raw_id,
            detail={
                "device_id": "dev-001",
                "hostname": "laptop-1",
                "platform_name": "Mac",
                "status": "online",
            },
            resource_type="endpoint",
            resource_name="laptop-1",
        )

        result = assembler.assemble(
            [aws_finding, cs_finding],
            [aws_raw, cs_raw],
        )

        # Should have both users and endpoints
        assert len(result["users"]) >= 1
        assert len(result["endpoints"]) >= 1
        assert result["endpoints"][0]["hostname"] == "laptop-1"

    def test_data_assembler_empty_input(self):
        """Assembler with empty input should return the default document."""
        assembler = NormalizedDataAssembler()
        result = assembler.assemble([], [])

        assert "users" in result
        assert "root_account" in result
        assert "security_groups" in result
        assert isinstance(result["users"], list)

    def test_data_assembler_unknown_source_passthrough(self):
        """Unregistered sources should passthrough finding details."""
        assembler = NormalizedDataAssembler()

        raw_id = str(uuid4())
        raw_event = _make_raw_event(
            source="custom_source",
            event_type="custom_event",
            event_id=raw_id,
        )
        finding = _make_finding(
            source="custom_source",
            raw_event_id=raw_id,
            detail={"custom_field": "custom_value"},
        )

        result = assembler.assemble([finding], [raw_event])
        # The passthrough should have merged the detail into the doc
        assert result.get("custom_field") == "custom_value"


# ---------------------------------------------------------------------------
# OPAComplianceEvaluator tests
# ---------------------------------------------------------------------------

class TestOPAEvaluator:
    """Tests for the OPAComplianceEvaluator."""

    def test_opa_evaluator_graceful_fallback(self):
        """When OPA is unreachable, fail-open mode should return empty."""
        evaluator = OPAComplianceEvaluator(
            base_url="http://localhost:99999/v1/data",
            timeout=1.0,
            fail_mode="open",
        )

        # Health check should fail gracefully
        assert evaluator.health_check() is False

        # Policy evaluation should return None (fail-open)
        result = evaluator.evaluate_policy("nist.ac.ac_2", {"users": []})
        assert result is None

        # Framework evaluation should return empty list
        policy_map = {"nist.ac.ac_2": ("nist_800_53", "AC-2")}
        results = evaluator.evaluate_framework("nist_800_53", {"users": []}, policy_map)
        assert results == []

    def test_opa_evaluator_parses_result(self):
        """Evaluator should correctly parse OPA response into ControlResultData."""
        evaluator = OPAComplianceEvaluator(
            base_url="http://localhost:8181/v1/data",
            timeout=5.0,
            fail_mode="open",
        )

        # Mock the httpx client
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "result": {
                "control_id": "AC-2",
                "compliant": False,
                "findings": ["AC-2: User 'bob' does not have MFA enabled"],
                "severity": "high",
                "checked_users": 2,
            }
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        evaluator._client = mock_client

        result = evaluator.evaluate_policy("nist.ac.ac_2", {"users": []})

        assert result is not None
        assert result.package_path == "nist.ac.ac_2"
        assert result.control_id == "AC-2"
        assert result.compliant is False
        assert len(result.findings) == 1
        assert result.severity == "high"

        # Verify the URL was constructed correctly
        mock_client.post.assert_called_once()
        call_url = mock_client.post.call_args[0][0]
        assert call_url == "http://localhost:8181/v1/data/nist/ac/ac_2/result"

    def test_opa_evaluator_evaluate_framework(self):
        """evaluate_framework should produce ControlResultData for each policy."""
        evaluator = OPAComplianceEvaluator(
            base_url="http://localhost:8181/v1/data",
            fail_mode="open",
        )

        # Mock responses for two policies
        responses = {
            "http://localhost:8181/v1/data/nist/ac/ac_2/result": {
                "result": {
                    "control_id": "AC-2",
                    "compliant": True,
                    "findings": [],
                    "severity": "high",
                }
            },
            "http://localhost:8181/v1/data/nist/ac/ac_6/result": {
                "result": {
                    "control_id": "AC-6",
                    "compliant": False,
                    "findings": ["AC-6: Overprivileged role found"],
                    "severity": "high",
                }
            },
        }

        def mock_post(url, json=None):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = responses.get(url, {"result": None})
            resp.raise_for_status = MagicMock()
            return resp

        mock_client = MagicMock()
        mock_client.post.side_effect = mock_post
        evaluator._client = mock_client

        policy_map = {
            "nist.ac.ac_2": ("nist_800_53", "AC-2"),
            "nist.ac.ac_6": ("nist_800_53", "AC-6"),
            "soc2.cc6": ("soc2", "CC6.1"),  # different framework, should be skipped
        }

        results = evaluator.evaluate_framework("nist_800_53", {}, policy_map)

        assert len(results) == 2
        ac2 = next(r for r in results if r.control_id == "AC-2")
        assert ac2.status == "compliant"
        assert ac2.assessor == "opa:nist.ac.ac_2"

        ac6 = next(r for r in results if r.control_id == "AC-6")
        assert ac6.status == "non_compliant"
        assert len(ac6.assertion_findings) == 1

    def test_opa_evaluator_fail_closed(self):
        """Fail-closed mode should raise when OPA is unreachable."""
        evaluator = OPAComplianceEvaluator(
            base_url="http://localhost:99999/v1/data",
            timeout=1.0,
            fail_mode="closed",
        )

        # Mock client that raises on post
        mock_client = MagicMock()
        mock_client.post.side_effect = Exception("Connection refused")
        evaluator._client = mock_client

        with pytest.raises(Exception, match="Connection refused"):
            evaluator.evaluate_policy("nist.ac.ac_2", {})

    def test_opa_evaluator_no_result_in_response(self):
        """When OPA returns no result key, should return None."""
        evaluator = OPAComplianceEvaluator(
            base_url="http://localhost:8181/v1/data",
            fail_mode="open",
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}  # no "result" key
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        evaluator._client = mock_client

        result = evaluator.evaluate_policy("nist.ac.ac_2", {})
        assert result is None


# ---------------------------------------------------------------------------
# UCF policy registration test
# ---------------------------------------------------------------------------

class TestUCFPolicies:
    """Tests that UCF policies are correctly registered and mapped."""

    def test_ucf_policies_registered(self):
        """All 12 UCF Rego policies should be discoverable."""
        registry = PolicyRegistry()
        pm = registry.policy_map

        expected_ucf_controls = [
            "UCF-GOV-1",
            "UCF-IAM-2",
            "UCF-ASM-1",
            "UCF-NET-1",
            "UCF-LOG-1",
            "UCF-HRS-1",
            "UCF-HRS-3",
            "UCF-DAT-1",
            "UCF-EPP-1",
            "UCF-RSK-4",
            "UCF-CFG-2",
            "UCF-AIM-1",
        ]

        ucf_controls = {ctrl for pkg, (fw, ctrl) in pm.items() if fw == "ucf"}

        for expected in expected_ucf_controls:
            assert expected in ucf_controls, (
                f"UCF control {expected} not found in registry. "
                f"Found: {sorted(ucf_controls)}"
            )

    def test_ucf_framework_listed(self):
        """UCF should appear in the list of frameworks."""
        registry = PolicyRegistry()
        assert "ucf" in registry.list_frameworks()
