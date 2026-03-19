"""KnowBe4 normalizer — transforms raw KnowBe4 API responses into Findings.

Normalizes training campaigns (completion rates), enrollments (overdue status),
phishing campaigns, phishing results (click rates), and users (risk scores).
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class KnowBe4Normalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "kb4_training_campaigns": "_normalize_training_campaigns",
        "kb4_training_enrollments": "_normalize_training_enrollments",
        "kb4_phishing_campaigns": "_normalize_phishing_campaigns",
        "kb4_phishing_results": "_normalize_phishing_results",
        "kb4_users": "_normalize_users",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "knowbe4" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all KnowBe4 findings."""
        return {
            "raw_event_id": raw.id,
            "source": "knowbe4",
            "source_type": SourceType.TRAINING,
            "provider": "knowbe4",
            "account_id": raw.raw_data.get("region", ""),
            "region": raw.raw_data.get("region", ""),
            "observed_at": raw.observed_at,
        }

    # -- Training Campaigns --

    def _normalize_training_campaigns(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        campaigns = raw.raw_data.get("response", [])

        for campaign in campaigns:
            name = campaign.get("name", "unknown")
            campaign_id = str(campaign.get("campaign_id", campaign.get("id", "")))
            completion_pct = campaign.get("completion_percentage", 100)

            # Also calculate from counts if percentage not directly available
            if completion_pct == 100 and "modules_completed" in campaign:
                total = campaign.get("modules_total", 0)
                completed = campaign.get("modules_completed", 0)
                if total > 0:
                    completion_pct = (completed / total) * 100

            issues = []
            severity = "info"
            obs_type = "inventory"

            if completion_pct < 95:
                issues.append(f"low_completion_{completion_pct:.0f}_pct")
                severity = "high"
                obs_type = "misconfiguration"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"Training campaign: {name}"
                      + (f" -- {completion_pct:.0f}% complete" if issues else ""),
                detail={
                    "campaign_id": campaign_id,
                    "name": name,
                    "completion_percentage": completion_pct,
                    "status": campaign.get("status", ""),
                    "start_date": campaign.get("start_date", ""),
                    "end_date": campaign.get("end_date", ""),
                    "issues": issues,
                    "campaign": campaign,
                },
                resource_id=campaign_id,
                resource_type="training_campaign",
                resource_name=name,
                severity=severity,
            ))

        return findings

    # -- Training Enrollments --

    def _normalize_training_enrollments(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        enrollments = raw.raw_data.get("response", [])
        now = datetime.now(timezone.utc)

        for enrollment in enrollments:
            enrollment_id = str(enrollment.get("enrollment_id", enrollment.get("id", "")))
            user_name = enrollment.get("user", {}).get("name", "") or enrollment.get("user_name", "unknown")
            module_name = enrollment.get("module_name", enrollment.get("content_name", "unknown"))
            status = enrollment.get("status", "").lower()

            # Check for overdue: status is not complete and due date has passed
            due_date_str = enrollment.get("due_date", "")
            is_overdue = False
            if due_date_str and status not in ("completed", "passed"):
                try:
                    due_date = datetime.fromisoformat(due_date_str.replace("Z", "+00:00"))
                    if due_date < now:
                        is_overdue = True
                except (ValueError, TypeError):
                    pass

            if status in ("completed", "passed"):
                obs_type = "inventory"
                severity = "info"
                title = f"Training completed: {user_name} -- {module_name}"
            elif is_overdue:
                obs_type = "policy_violation"
                severity = "medium"
                title = f"Overdue training: {user_name} -- {module_name}"
            else:
                obs_type = "inventory"
                severity = "info"
                title = f"Training enrollment: {user_name} -- {module_name}"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=title,
                detail={
                    "enrollment_id": enrollment_id,
                    "user_name": user_name,
                    "module_name": module_name,
                    "status": status,
                    "due_date": due_date_str,
                    "is_overdue": is_overdue,
                    "completion_date": enrollment.get("completion_date", ""),
                    "enrollment": enrollment,
                },
                resource_id=enrollment_id,
                resource_type="training_enrollment",
                resource_name=f"{user_name}: {module_name}",
                severity=severity,
            ))

        return findings

    # -- Phishing Campaigns --

    def _normalize_phishing_campaigns(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        campaigns = raw.raw_data.get("response", [])

        for campaign in campaigns:
            name = campaign.get("name", "unknown")
            campaign_id = str(campaign.get("campaign_id", campaign.get("id", "")))

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Phishing campaign: {name}",
                detail={
                    "campaign_id": campaign_id,
                    "name": name,
                    "status": campaign.get("status", ""),
                    "start_date": campaign.get("start_date", ""),
                    "end_date": campaign.get("end_date", ""),
                    "campaign": campaign,
                },
                resource_id=campaign_id,
                resource_type="phishing_campaign",
                resource_name=name,
                severity="info",
            ))

        return findings

    # -- Phishing Results --

    def _normalize_phishing_results(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        tests = raw.raw_data.get("response", [])

        total_recipients = 0
        total_clicked = 0

        for test in tests:
            test_id = str(test.get("pst_id", test.get("id", "")))
            test_name = test.get("name", "unknown")
            recipients = test.get("recipients", [])

            for recipient in recipients:
                user_name = recipient.get("user", {}).get("name", "") or recipient.get("email", "unknown")
                clicked = recipient.get("clicked_link", False) or recipient.get("clicked", False)

                total_recipients += 1
                if clicked:
                    total_clicked += 1
                    findings.append(FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Phishing click: {user_name} -- {test_name}",
                        detail={
                            "test_id": test_id,
                            "test_name": test_name,
                            "user_name": user_name,
                            "email": recipient.get("email", ""),
                            "clicked": True,
                            "reported": recipient.get("reported", False),
                            "opened": recipient.get("opened_email", False),
                            "recipient": recipient,
                        },
                        resource_id=recipient.get("recipient_id", recipient.get("id", "")),
                        resource_type="phishing_result",
                        resource_name=user_name,
                        severity="low",
                    ))

        # Org-level click rate check
        if total_recipients > 0:
            click_rate = (total_clicked / total_recipients) * 100
            if click_rate > 5:
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title=f"High org phishing click rate: {click_rate:.1f}%",
                    detail={
                        "total_recipients": total_recipients,
                        "total_clicked": total_clicked,
                        "click_rate_pct": round(click_rate, 2),
                        "threshold_pct": 5,
                    },
                    resource_id="org_phishing_click_rate",
                    resource_type="phishing_result",
                    resource_name="Organization phishing click rate",
                    severity="medium",
                ))

        return findings

    # -- Users --

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        users = raw.raw_data.get("response", [])

        for user in users:
            user_id = str(user.get("id", ""))
            name = (
                f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
                or user.get("email", "unknown")
            )
            email = user.get("email", "")
            risk_score = user.get("current_risk_score", user.get("risk_score", 0)) or 0

            severity = "info"
            obs_type = "inventory"
            issues = []

            if risk_score > 60:
                severity = "medium"
                obs_type = "alert"
                issues.append(f"high_risk_score_{risk_score}")

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"KnowBe4 user: {name}" + (f" -- risk score {risk_score}" if issues else ""),
                detail={
                    "user_id": user_id,
                    "name": name,
                    "email": email,
                    "risk_score": risk_score,
                    "phish_prone_percentage": user.get("phish_prone_percentage"),
                    "status": user.get("status", ""),
                    "groups": user.get("groups", []),
                    "issues": issues,
                    "user": user,
                },
                resource_id=user_id,
                resource_type="training_user",
                resource_name=name,
                severity=severity,
            ))

        return findings


# Register
registry.register(KnowBe4Normalizer())
