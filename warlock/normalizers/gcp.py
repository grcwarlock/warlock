"""GCP normalizer — transforms raw GCP API responses into Findings.

Each event_type gets a normalizer function that knows the shape of that
specific API response and extracts structured observations from it.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class GCPNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "scc_findings": "_normalize_scc_findings",
        "iam_policies": "_normalize_iam_policies",
        "compute_firewall_rules": "_normalize_firewall_rules",
        "storage_buckets": "_normalize_storage_buckets",
        "audit_logs": "_normalize_audit_logs",
        "gke_clusters": "_normalize_gke_clusters",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "gcp" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all GCP findings."""
        return {
            "raw_event_id": raw.id,
            "source": "gcp",
            "source_type": SourceType.CLOUD,
            "provider": "gcp",
            "account_id": raw.raw_data.get("project_id", ""),
            "region": raw.raw_data.get("region", ""),
            "observed_at": raw.observed_at,
        }

    # -- Security Command Center --

    def _normalize_scc_findings(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        scc_findings = response.get("findings", [])

        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
        }

        for finding in scc_findings:
            scc_severity = finding.get("severity", "MEDIUM")
            mapped_severity = severity_map.get(scc_severity, "medium")
            category = finding.get("category", "unknown")
            resource_name = finding.get("resource_name", "")
            state = finding.get("state", "")

            # Only report active findings
            if state == "INACTIVE":
                continue

            obs_type = "vulnerability"
            finding_class = finding.get("finding_class", "")
            if finding_class == "MISCONFIGURATION":
                obs_type = "misconfiguration"
            elif finding_class == "THREAT":
                obs_type = "alert"
            elif finding_class == "VULNERABILITY":
                obs_type = "vulnerability"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"SCC finding: {category}",
                    detail={
                        "category": category,
                        "finding_class": finding_class,
                        "state": state,
                        "severity": scc_severity,
                        "resource_name": resource_name,
                        "source_properties": finding.get("source_properties", {}),
                        "external_uri": finding.get("external_uri", ""),
                        "description": finding.get("description", ""),
                    },
                    resource_id=resource_name,
                    resource_type=finding.get("resource_name", "").split("/")[3]
                    if len(finding.get("resource_name", "").split("/")) > 3
                    else "gcp_resource",
                    resource_name=resource_name.split("/")[-1] if resource_name else "",
                    severity=mapped_severity,
                )
            )

        return findings

    # -- IAM Policies --

    def _normalize_iam_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        bindings = response.get("bindings", [])

        # Overly permissive roles to flag
        risky_roles = {
            "roles/owner": "critical",
            "roles/editor": "high",
            "roles/iam.securityAdmin": "high",
            "roles/iam.serviceAccountAdmin": "high",
            "roles/iam.serviceAccountKeyAdmin": "high",
        }

        for binding in bindings:
            role = binding.get("role", "")
            members = binding.get("members", [])

            issues = []
            severity = "info"
            obs_type = "inventory"

            # Check for risky roles
            if role in risky_roles:
                severity = risky_roles[role]
                obs_type = "misconfiguration"
                issues.append(f"privileged_role_{role}")

            # Check for allUsers / allAuthenticatedUsers
            for member in members:
                if member in ("allUsers", "allAuthenticatedUsers"):
                    issues.append(f"public_access_{member}")
                    severity = "critical"
                    obs_type = "misconfiguration"

            # Check for external (non-service-account) members with owner
            if role == "roles/owner":
                external = [
                    m
                    for m in members
                    if not m.startswith("serviceAccount:")
                    and m not in ("allUsers", "allAuthenticatedUsers")
                ]
                if len(external) > 3:
                    issues.append(f"too_many_owners_{len(external)}")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"IAM binding: {role}" + (f" — {', '.join(issues)}" if issues else ""),
                    detail={
                        "role": role,
                        "members": members,
                        "member_count": len(members),
                        "issues": issues,
                    },
                    resource_id=f"projects/{raw.raw_data.get('project_id', '')}/iam/{role}",
                    resource_type="iam_binding",
                    resource_name=role,
                    severity=severity,
                )
            )

        return findings

    # -- Compute Firewall Rules --

    def _normalize_firewall_rules(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        rules = response.get("firewall_rules", [])
        sensitive_ports = {22, 3389, 3306, 5432, 1433, 27017, 6379}

        for rule in rules:
            if rule.get("direction", "").upper() != "INGRESS":
                continue
            if rule.get("disabled", False):
                continue

            issues = []
            source_ranges = rule.get("source_ranges", [])
            has_open_source = "0.0.0.0/0" in source_ranges

            if has_open_source:
                allowed = rule.get("allowed", [])
                for allow in allowed:
                    protocol = allow.get("I_p_protocol", allow.get("IPProtocol", ""))
                    ports = allow.get("ports", [])

                    if not ports and protocol in ("tcp", "udp", "all"):
                        issues.append(f"all_{protocol}_ports_open_to_internet")
                    else:
                        for port_spec in ports:
                            try:
                                if "-" in str(port_spec):
                                    # Port range
                                    start, end = port_spec.split("-")
                                    for p in sensitive_ports:
                                        if int(start) <= p <= int(end):
                                            issues.append(f"open_to_internet_port_{p}")
                                else:
                                    port = int(port_spec)
                                    if port in sensitive_ports:
                                        issues.append(f"open_to_internet_port_{port}")
                            except (ValueError, TypeError):
                                pass

            severity = "info"
            obs_type = "inventory"
            if issues:
                severity = "high"
                obs_type = "misconfiguration"

            rule_name = rule.get("name", "unknown")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Firewall rule: {rule_name}"
                    + (f" — {len(issues)} open ports" if issues else ""),
                    detail={"firewall_rule": rule, "issues": issues},
                    resource_id=rule.get("self_link", rule.get("id", "")),
                    resource_type="compute_firewall_rule",
                    resource_name=rule_name,
                    severity=severity,
                )
            )

        return findings

    # -- Cloud Storage Buckets --

    def _normalize_storage_buckets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        buckets = response.get("buckets", [])

        for bucket in buckets:
            bucket_name = bucket.get("name", "unknown")
            issues = []

            if not bucket.get("versioning_enabled", False):
                issues.append("versioning_disabled")

            iam_config = bucket.get("iam_configuration", {})
            if not iam_config.get("uniform_bucket_level_access_enabled", False):
                issues.append("uniform_bucket_level_access_disabled")

            severity = "info"
            obs_type = "inventory"
            if issues:
                severity = "medium"
                obs_type = "misconfiguration"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"GCS bucket: {bucket_name}"
                    + (f" — {', '.join(issues)}" if issues else ""),
                    detail={"bucket": bucket, "issues": issues},
                    resource_id=f"gs://{bucket_name}",
                    resource_type="storage_bucket",
                    resource_name=bucket_name,
                    severity=severity,
                )
            )

        return findings

    # -- Cloud Audit Logs --

    def _normalize_audit_logs(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        entries = response.get("log_entries", [])

        for entry in entries:
            severity = entry.get("severity", "DEFAULT")
            if severity in ("DEFAULT", "DEBUG", "INFO", "NOTICE"):
                continue

            severity_map = {
                "CRITICAL": "critical",
                "ALERT": "critical",
                "EMERGENCY": "critical",
                "ERROR": "high",
                "WARNING": "medium",
            }
            mapped_severity = severity_map.get(severity, "info")

            resource = entry.get("resource", {})
            resource_type = resource.get("type", "")
            log_name = entry.get("log_name", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Audit log: {log_name.split('/')[-1] if log_name else 'unknown'} — {severity}",
                    detail={
                        "log_name": log_name,
                        "severity": severity,
                        "resource_type": resource_type,
                        "resource_labels": resource.get("labels", {}),
                        "payload": entry.get("payload", {}),
                        "timestamp": entry.get("timestamp", ""),
                    },
                    resource_id=str(resource.get("labels", {}).get("project_id", "")),
                    resource_type=resource_type or "gcp_audit",
                    resource_name=log_name.split("/")[-1] if log_name else "",
                    severity=mapped_severity,
                )
            )

        return findings

    # -- GKE Clusters --

    def _normalize_gke_clusters(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        clusters = response.get("clusters", [])

        for cluster in clusters:
            cluster_name = cluster.get("name", "unknown")
            issues = []

            # Check for legacy ABAC
            if cluster.get("legacy_abac", {}).get("enabled", False):
                issues.append("legacy_abac_enabled")

            # Check master authorized networks
            master_auth_config = cluster.get("master_authorized_networks_config", {})
            if not master_auth_config.get("enabled", False):
                issues.append("master_authorized_networks_disabled")

            # Check network policy
            network_policy = cluster.get("network_policy", {})
            if not network_policy.get("enabled", False):
                issues.append("network_policy_disabled")

            # Check binary authorization
            binary_auth = cluster.get("binary_authorization", {})
            if not binary_auth.get("enabled", False):
                issues.append("binary_authorization_disabled")

            # Check shielded nodes
            shielded_nodes = cluster.get("shielded_nodes", {})
            if not shielded_nodes.get("enabled", False):
                issues.append("shielded_nodes_disabled")

            severity = "info"
            obs_type = "inventory"
            if issues:
                severity = "medium"
                obs_type = "misconfiguration"
                if "legacy_abac_enabled" in issues:
                    severity = "high"

            location = cluster.get("location", "")

            base = self._base(raw)
            if location:
                base["region"] = location
            findings.append(
                FindingData(
                    **base,
                    observation_type=obs_type,
                    title=f"GKE cluster: {cluster_name}"
                    + (f" — {len(issues)} issues" if issues else ""),
                    detail={"cluster": cluster, "issues": issues},
                    resource_id=cluster.get("self_link", ""),
                    resource_type="gke_cluster",
                    resource_name=cluster_name,
                    severity=severity,
                )
            )

        return findings


# Register
registry.register(GCPNormalizer())
