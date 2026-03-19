"""IBM Cloud normalizer — transforms raw IBM Cloud API responses into Findings.

Each event_type gets a normalizer function that knows the shape of that
specific API response and extracts structured observations from it.
"""

from __future__ import annotations


from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class IBMCloudNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "ibm_security_findings": "_normalize_security_findings",
        "ibm_iam_users": "_normalize_iam_users",
        "ibm_iam_groups": "_normalize_iam_groups",
        "ibm_activity_events": "_normalize_activity_events",
        "ibm_key_protect": "_normalize_key_protect",
        "ibm_security_groups": "_normalize_security_groups",
        "ibm_compliance_profiles": "_normalize_compliance_profiles",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "ibm_cloud" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all IBM Cloud findings."""
        return {
            "raw_event_id": raw.id,
            "source": "ibm_cloud",
            "source_type": SourceType.CLOUD,
            "provider": "ibm_cloud",
            "account_id": raw.raw_data.get("account_id", ""),
            "region": raw.raw_data.get("region", ""),
            "observed_at": raw.observed_at,
        }

    # -- Security & Compliance Center Findings --

    def _normalize_security_findings(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        occurrences = response.get("occurrences", [])

        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
        }

        for occ in occurrences:
            kind = occ.get("kind", "")
            sev = occ.get("finding", {}).get("severity", "MEDIUM").upper()
            mapped_severity = severity_map.get(sev, "medium")

            # Determine observation type from kind
            if kind == "FINDING":
                finding_detail = occ.get("finding", {})
                finding_detail.get("next_steps", [])
                obs_type = "vulnerability"
                if any(
                    kw in occ.get("note_name", "").lower()
                    for kw in ("config", "misconfiguration", "setting")
                ):
                    obs_type = "misconfiguration"
            else:
                obs_type = "misconfiguration"

            resource_url = occ.get("resource_url", "")
            note_name = occ.get("note_name", "")

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"IBM finding: {note_name.split('/')[-1] if note_name else kind}",
                detail={
                    "kind": kind,
                    "severity": sev,
                    "note_name": note_name,
                    "resource_url": resource_url,
                    "finding": occ.get("finding", {}),
                    "context": occ.get("context", {}),
                    "remediation": occ.get("remediation", ""),
                },
                resource_id=resource_url,
                resource_type=occ.get("context", {}).get("resource_type", "ibm_resource"),
                resource_name=resource_url.split("/")[-1] if resource_url else "",
                severity=mapped_severity,
            ))

        return findings

    # -- IAM Users --

    def _normalize_iam_users(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        users = response.get("resources", [])

        for user in users:
            user_id = user.get("iam_id", user.get("id", ""))
            email = user.get("email", "")
            state = user.get("state", "")
            user.get("phonetic_name", "")
            user_name = user.get("user_id", email)

            issues = []
            severity = "info"
            obs_type = "inventory"

            # Flag inactive users
            if state and state.lower() != "active":
                issues.append(f"user_inactive_{state}")
                severity = "medium"
                obs_type = "misconfiguration"

            # Flag users without MFA
            settings = user.get("settings", {})
            if not settings.get("mfa", True):
                issues.append("mfa_disabled")
                severity = "high"
                obs_type = "misconfiguration"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"IAM user: {user_name}" + (
                    f" — {', '.join(issues)}" if issues else ""
                ),
                detail={
                    "iam_id": user_id,
                    "email": email,
                    "state": state,
                    "settings": settings,
                    "issues": issues,
                },
                resource_id=user_id,
                resource_type="iam_user",
                resource_name=user_name,
                severity=severity,
            ))

        return findings

    # -- IAM Access Groups --

    def _normalize_iam_groups(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        groups = response.get("groups", [])

        for group in groups:
            group_id = group.get("id", "")
            group_name = group.get("name", "unknown")
            member_count = group.get("membership_count", 0)
            is_federated = group.get("is_federated", False)

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"IAM access group: {group_name}",
                detail={
                    "group_id": group_id,
                    "name": group_name,
                    "description": group.get("description", ""),
                    "membership_count": member_count,
                    "is_federated": is_federated,
                    "created_at": group.get("created_at", ""),
                },
                resource_id=group_id,
                resource_type="iam_access_group",
                resource_name=group_name,
                severity="info",
            ))

        return findings

    # -- Activity Tracker Events --

    def _normalize_activity_events(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        events = response.get("events", response.get("lines", []))

        for event in events:
            level = event.get("level", event.get("_level", "info")).lower()

            # Only surface error/warning events
            if level not in ("error", "warning", "critical", "alert"):
                continue

            severity_map = {
                "critical": "critical",
                "alert": "critical",
                "error": "high",
                "warning": "medium",
            }
            mapped_severity = severity_map.get(level, "info")

            action = event.get("action", event.get("_line", "unknown_action"))
            outcome = event.get("outcome", "")
            target = event.get("target", {})
            initiator = event.get("initiator", {})

            findings.append(FindingData(
                **self._base(raw),
                observation_type="alert",
                title=f"Activity event: {action} — {level}",
                detail={
                    "action": action,
                    "level": level,
                    "outcome": outcome,
                    "target": target,
                    "initiator": initiator,
                    "message": event.get("message", ""),
                    "timestamp": event.get("eventTime", event.get("_ts", "")),
                },
                resource_id=target.get("id", ""),
                resource_type=target.get("typeURI", "ibm_activity"),
                resource_name=target.get("name", action),
                severity=mapped_severity,
            ))

        return findings

    # -- Key Protect --

    def _normalize_key_protect(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        keys = response.get("resources", [])

        warning_states = {"destroyed", "deactivated", "suspended"}

        for key in keys:
            key_id = key.get("id", "")
            key_name = key.get("name", "unknown")
            state = key.get("state", 0)
            key.get("algorithmMetadata", {}).get("state", "")

            # IBM Key Protect states: 1=Pre-activation, 2=Active, 3=Suspended,
            # 4=Deactivated, 5=Destroyed
            state_labels = {
                1: "pre_activation",
                2: "active",
                3: "suspended",
                4: "deactivated",
                5: "destroyed",
            }
            resolved_state = state_labels.get(state, str(state))

            issues = []
            severity = "info"
            obs_type = "inventory"

            if resolved_state in warning_states:
                issues.append(f"key_state_{resolved_state}")
                severity = "medium"
                obs_type = "misconfiguration"

            # Check for non-rotation
            extractable = key.get("extractable", False)
            if extractable:
                issues.append("key_extractable")
                severity = "high"
                obs_type = "misconfiguration"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"Key Protect key: {key_name}" + (
                    f" — {', '.join(issues)}" if issues else ""
                ),
                detail={
                    "key_id": key_id,
                    "name": key_name,
                    "state": resolved_state,
                    "extractable": extractable,
                    "algorithm_type": key.get("algorithmType", ""),
                    "created_by": key.get("createdBy", ""),
                    "creation_date": key.get("creationDate", ""),
                    "last_rotate_date": key.get("lastRotateDate", ""),
                    "issues": issues,
                },
                resource_id=key_id,
                resource_type="kms_key",
                resource_name=key_name,
                severity=severity,
            ))

        return findings

    # -- VPC Security Groups --

    def _normalize_security_groups(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        sec_groups = response.get("security_groups", [])

        for sg in sec_groups:
            sg_id = sg.get("id", "")
            sg_name = sg.get("name", "unknown")
            rules = sg.get("rules", [])

            issues = []
            for rule in rules:
                direction = rule.get("direction", "")
                if direction != "inbound":
                    continue

                remote = rule.get("remote", {})
                cidr = remote.get("cidr_block", "")

                if cidr == "0.0.0.0/0":
                    protocol = rule.get("protocol", "all")
                    port_min = rule.get("port_min", 0)
                    port_max = rule.get("port_max", 65535)

                    if port_min == 0 and port_max == 65535:
                        issues.append(f"all_{protocol}_ports_open_to_internet")
                    else:
                        sensitive_ports = {22, 3389, 3306, 5432, 1433, 27017, 6379}
                        for p in sensitive_ports:
                            if port_min <= p <= port_max:
                                issues.append(f"open_to_internet_port_{p}")

            severity = "info"
            obs_type = "inventory"
            if issues:
                severity = "high"
                obs_type = "misconfiguration"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"VPC security group: {sg_name}" + (
                    f" — {len(issues)} open ports" if issues else ""
                ),
                detail={
                    "security_group": sg,
                    "issues": issues,
                },
                resource_id=sg_id,
                resource_type="vpc_security_group",
                resource_name=sg_name,
                severity=severity,
            ))

        return findings

    # -- Compliance Profiles --

    def _normalize_compliance_profiles(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        profiles = response.get("profiles", [])

        for profile in profiles:
            profile_id = profile.get("id", "")
            profile_name = profile.get("name", "unknown")
            controls = profile.get("controls", [])

            for control in controls:
                status = control.get("status", "").lower()
                if status not in ("fail", "failed", "unable_to_perform"):
                    continue

                control_id = control.get("id", control.get("control_id", ""))
                control_name = control.get("control_name", control.get("description", ""))

                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="policy_violation",
                    title=f"Compliance control failed: {control_name or control_id}",
                    detail={
                        "profile_id": profile_id,
                        "profile_name": profile_name,
                        "control_id": control_id,
                        "control_name": control_name,
                        "status": status,
                        "severity": control.get("severity", ""),
                        "assessment": control.get("assessment", {}),
                        "remediation": control.get("remediation", ""),
                    },
                    resource_id=f"{profile_id}/{control_id}",
                    resource_type="compliance_control",
                    resource_name=control_name or control_id,
                    severity=control.get("severity", "medium").lower()
                    if control.get("severity") else "medium",
                ))

        return findings


# Register
registry.register(IBMCloudNormalizer())
