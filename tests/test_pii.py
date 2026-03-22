"""Tests for warlock.utils.pii — PII detection and pseudonymization."""

from __future__ import annotations

from warlock.utils.pii import pseudonymize, scrub_detail, scrub_finding, scrub_string


class TestPseudonymize:
    def test_deterministic(self):
        """Same input always produces the same pseudonym."""
        assert pseudonymize("jane@co.com") == pseudonymize("jane@co.com")

    def test_different_inputs_differ(self):
        assert pseudonymize("jane@co.com") != pseudonymize("bob@co.com")

    def test_case_insensitive(self):
        """Normalization: email casing shouldn't matter."""
        assert pseudonymize("Jane@Co.com") == pseudonymize("jane@co.com")

    def test_format(self):
        result = pseudonymize("jane@co.com")
        assert result.startswith("person:")
        assert len(result) == len("person:") + 8


class TestScrubString:
    def test_email_detected(self):
        scrubbed, found = scrub_string("Action by jane@company.com on server")
        assert found is True
        assert "jane@company.com" not in scrubbed
        assert "person:" in scrubbed

    def test_ssn_detected(self):
        scrubbed, found = scrub_string("SSN is 123-45-6789")
        assert found is True
        assert "123-45-6789" not in scrubbed

    def test_phone_detected(self):
        scrubbed, found = scrub_string("Call (555) 123-4567")
        assert found is True
        assert "(555) 123-4567" not in scrubbed

    def test_no_pii(self):
        scrubbed, found = scrub_string("Server us-east-1 has 3 findings")
        assert found is False
        assert scrubbed == "Server us-east-1 has 3 findings"

    def test_multiple_emails(self):
        scrubbed, found = scrub_string("from a@b.com to c@d.com")
        assert found is True
        assert "a@b.com" not in scrubbed
        assert "c@d.com" not in scrubbed


class TestScrubDetail:
    def test_removes_raw_dump(self):
        detail = {
            "event_type": "login",
            "event": {"raw": "data", "user_email": "x@y.com"},
        }
        scrubbed, found = scrub_detail(detail)
        assert found is True
        assert "event" not in scrubbed
        assert scrubbed["event_type"] == "login"

    def test_pseudonymizes_known_pii_fields(self):
        detail = {
            "email": "jane@co.com",
            "severity": "high",
        }
        scrubbed, found = scrub_detail(detail)
        assert found is True
        assert scrubbed["email"].startswith("person:")
        assert scrubbed["severity"] == "high"

    def test_scans_string_values_for_patterns(self):
        detail = {
            "description": "User jane@co.com failed login",
        }
        scrubbed, found = scrub_detail(detail)
        assert found is True
        assert "jane@co.com" not in scrubbed["description"]

    def test_recurses_into_nested_dicts(self):
        detail = {
            "metadata": {
                "actor_email": "a@b.com",
                "count": 5,
            }
        }
        scrubbed, found = scrub_detail(detail)
        assert found is True
        assert scrubbed["metadata"]["actor_email"].startswith("person:")
        assert scrubbed["metadata"]["count"] == 5

    def test_recurses_into_lists(self):
        detail = {
            "users": [
                {"email": "a@b.com"},
                {"email": "c@d.com"},
            ]
        }
        scrubbed, found = scrub_detail(detail)
        assert found is True
        assert scrubbed["users"][0]["email"].startswith("person:")
        assert scrubbed["users"][1]["email"].startswith("person:")

    def test_no_pii(self):
        detail = {
            "resource_id": "arn:aws:s3:::bucket",
            "severity": "critical",
            "count": 42,
        }
        scrubbed, found = scrub_detail(detail)
        assert found is False
        assert scrubbed == detail

    def test_raw_dump_only_removed_if_dict_or_list(self):
        """'event' as a plain string is not a raw dump — keep it."""
        detail = {"event": "org.user.login"}
        scrubbed, found = scrub_detail(detail)
        assert "event" in scrubbed
        assert scrubbed["event"] == "org.user.login"


class TestScrubFinding:
    def _make_finding(self, **kwargs):
        from warlock.normalizers.base import FindingData

        defaults = {
            "raw_event_id": "test-001",
            "observation_type": "alert",
            "title": "Test finding",
            "detail": {},
        }
        defaults.update(kwargs)
        return FindingData(**defaults)

    def test_scrubs_title(self):
        f = self._make_finding(title="Login by jane@co.com failed")
        scrub_finding(f)
        assert "jane@co.com" not in f.title
        assert f.pii_detected is True

    def test_scrubs_resource_name(self):
        f = self._make_finding(resource_name="failed:bob@co.com")
        scrub_finding(f)
        assert "bob@co.com" not in f.resource_name
        assert f.pii_detected is True

    def test_scrubs_detail(self):
        f = self._make_finding(
            detail={
                "user_name": "jane@co.com",
                "event": {"raw": "dump"},
            }
        )
        scrub_finding(f)
        assert f.detail["user_name"].startswith("person:")
        assert "event" not in f.detail
        assert f.pii_detected is True

    def test_no_pii_leaves_flag_false(self):
        f = self._make_finding(
            title="S3 bucket public",
            detail={"bucket": "my-bucket", "region": "us-east-1"},
        )
        scrub_finding(f)
        assert f.pii_detected is False

    def test_returns_same_object(self):
        f = self._make_finding()
        result = scrub_finding(f)
        assert result is f
