"""Exchange Online normalizer — transforms raw Microsoft Graph API responses into Findings.

Handles message traces, mail flow rules, mailbox settings, and ATP policies.
Flags: external forwarding rules, mailboxes without audit, weak ATP policies,
high-volume external sends.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ExchangeOnlineNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "exchange_message_traces": "_normalize_message_traces",
        "exchange_mail_flow_rules": "_normalize_mail_flow_rules",
        "exchange_mailbox_settings": "_normalize_mailbox_settings",
        "exchange_atp_policies": "_normalize_atp_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "exchange_online" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Exchange Online findings."""
        return {
            "raw_event_id": raw.id,
            "source": "exchange_online",
            "source_type": SourceType.EMAIL_SECURITY,
            "provider": "microsoft",
            "observed_at": raw.observed_at,
        }

    # -- Message Traces --

    def _normalize_message_traces(self, raw: RawEventData) -> list[FindingData]:
        """Inventory message activity; flag high-volume external senders."""
        findings = []
        traces = raw.raw_data.get("traces", [])

        for trace in traces:
            user_principal = trace.get("userPrincipalName", trace.get("user_principal_name", ""))
            display_name = trace.get("displayName", trace.get("display_name", ""))
            send_count = trace.get("sendCount", trace.get("send_count", 0))
            receive_count = trace.get("receiveCount", trace.get("receive_count", 0))
            external_send = trace.get("externalSendCount", trace.get("external_send_count", 0))
            report_period = trace.get("reportPeriod", trace.get("report_period", ""))

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Exchange user activity: {display_name}",
                    detail={
                        "user_principal": user_principal,
                        "display_name": display_name,
                        "send_count": send_count,
                        "receive_count": receive_count,
                        "external_send_count": external_send,
                        "report_period": report_period,
                    },
                    resource_id=user_principal,
                    resource_type="exchange_user_activity",
                    resource_name=display_name or user_principal,
                    severity="info",
                )
            )

            # Flag high-volume external senders (potential data exfiltration)
            if isinstance(external_send, (int, float)) and external_send > 500:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"High-volume external sender: {display_name} ({external_send} emails)",
                        detail={
                            "user_principal": user_principal,
                            "display_name": display_name,
                            "external_send_count": external_send,
                            "send_count": send_count,
                            "issue": "User sent an unusually high volume of external emails — potential data exfiltration or compromised account",
                        },
                        resource_id=user_principal,
                        resource_type="exchange_user_activity",
                        resource_name=display_name or user_principal,
                        severity="high",
                    )
                )

        return findings

    # -- Mail Flow Rules --

    def _normalize_mail_flow_rules(self, raw: RawEventData) -> list[FindingData]:
        """Inventory mail flow rules; flag external forwarding rules."""
        findings = []
        rules = raw.raw_data.get("rules", [])

        for rule in rules:
            rule_id = str(rule.get("id", ""))
            rule_name = rule.get("name", rule.get("displayName", ""))
            state = rule.get("state", rule.get("enabled", ""))
            priority = rule.get("priority", 0)
            actions = rule.get("actions", {})
            rule.get("conditions", {})

            # Check for external forwarding
            forward_to = actions.get("redirectTo", actions.get("forwardTo", []))
            forward_as_attachment = actions.get("forwardAsAttachmentTo", [])
            has_external_forward = bool(forward_to) or bool(forward_as_attachment)

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Mail flow rule: {rule_name} (state={state})",
                    detail={
                        "rule_id": rule_id,
                        "rule_name": rule_name,
                        "state": state,
                        "priority": priority,
                        "has_forward": has_external_forward,
                        "actions": list(actions.keys()) if isinstance(actions, dict) else [],
                    },
                    resource_id=rule_id,
                    resource_type="exchange_mail_flow_rule",
                    resource_name=rule_name,
                    severity="info",
                )
            )

            # Flag external forwarding rules
            if has_external_forward and state in ("Enabled", True, "enabled"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"External forwarding rule: {rule_name}",
                        detail={
                            "rule_id": rule_id,
                            "rule_name": rule_name,
                            "state": state,
                            "forward_to": forward_to,
                            "forward_as_attachment": forward_as_attachment,
                            "issue": "Mail flow rule forwards email externally — potential data exfiltration vector, review immediately",
                        },
                        resource_id=rule_id,
                        resource_type="exchange_mail_flow_rule",
                        resource_name=rule_name,
                        severity="critical",
                    )
                )

        return findings

    # -- Mailbox Settings --

    def _normalize_mailbox_settings(self, raw: RawEventData) -> list[FindingData]:
        """Inventory mailbox settings; flag mailboxes without audit and with auto-forward."""
        findings = []
        settings_list = raw.raw_data.get("mailbox_settings", [])

        for settings in settings_list:
            user_id = settings.get("user_id", "")
            display_name = settings.get("display_name", "")
            mail = settings.get("mail", "")
            auto_reply = settings.get("automaticRepliesSetting", {})
            auto_reply_status = auto_reply.get("status", "disabled")

            # Check for auto-forwarding
            delegate_settings = settings.get("delegateMeetingMessageDeliveryOptions", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Mailbox settings: {display_name}",
                    detail={
                        "user_id": user_id,
                        "display_name": display_name,
                        "mail": mail,
                        "auto_reply_status": auto_reply_status,
                        "delegate_settings": delegate_settings,
                    },
                    resource_id=user_id,
                    resource_type="exchange_mailbox",
                    resource_name=display_name or mail,
                    severity="info",
                )
            )

            # Flag auto-replies that include external recipients (data leak risk)
            external_audience = auto_reply.get("externalAudience", "none")
            if auto_reply_status == "alwaysEnabled" and external_audience != "none":
                external_message = auto_reply.get("externalReplyMessage", "")
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Mailbox with external auto-reply: {display_name}",
                        detail={
                            "user_id": user_id,
                            "display_name": display_name,
                            "auto_reply_status": auto_reply_status,
                            "external_audience": external_audience,
                            "has_external_message": bool(external_message),
                            "issue": "Mailbox has auto-reply enabled for external recipients — may leak internal information",
                        },
                        resource_id=user_id,
                        resource_type="exchange_mailbox",
                        resource_name=display_name or mail,
                        severity="medium",
                    )
                )

        return findings

    # -- ATP Policies --

    def _normalize_atp_policies(self, raw: RawEventData) -> list[FindingData]:
        """Inventory ATP policies; flag weak configurations."""
        findings = []
        policies = raw.raw_data.get("policies", [])

        for policy in policies:
            policy_id = str(policy.get("id", ""))
            category = policy.get("category", "")
            content_type = policy.get("contentType", "")
            status = policy.get("status", "")
            created_by = policy.get("createdBy", {}).get("user", {}).get("displayName", "")
            created_dt = str(policy.get("createdDateTime", ""))

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"ATP assessment: {category} ({status})",
                    detail={
                        "policy_id": policy_id,
                        "category": category,
                        "content_type": content_type,
                        "status": status,
                        "created_by": created_by,
                        "created_datetime": created_dt,
                    },
                    resource_id=policy_id,
                    resource_type="exchange_atp_policy",
                    resource_name=f"atp:{category}",
                    severity="info",
                )
            )

            # Flag completed assessments that found threats
            if status == "completed" and category in ("malware", "phish", "spam"):
                result_info = policy.get("result", {})
                result_type = result_info.get("resultType", "") if isinstance(result_info, dict) else ""
                if result_type in ("malware", "phish", "spam"):
                    findings.append(
                        FindingData(
                            **self._base(raw),
                            observation_type="alert",
                            title=f"Threat detected: {result_type} ({category})",
                            detail={
                                "policy_id": policy_id,
                                "category": category,
                                "result_type": result_type,
                                "created_by": created_by,
                                "issue": f"ATP detected {result_type} threat — review and remediate affected mailboxes",
                            },
                            resource_id=policy_id,
                            resource_type="exchange_atp_policy",
                            resource_name=f"threat:{result_type}",
                            severity="high",
                        )
                    )

        return findings


# Register
registry.register(ExchangeOnlineNormalizer())
