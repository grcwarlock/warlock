"""Jenkins normalizer — transforms raw Jenkins API responses into Findings.

Handles jobs, nodes, credentials, and security configuration.
Flags: failed builds on security-related jobs, nodes with outdated agents,
credentials not rotated, anonymous access enabled, no CSRF protection.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class JenkinsNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "jenkins_jobs": "_normalize_jobs",
        "jenkins_nodes": "_normalize_nodes",
        "jenkins_credentials": "_normalize_credentials",
        "jenkins_security": "_normalize_security",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "jenkins" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Jenkins findings."""
        return {
            "raw_event_id": raw.id,
            "source": "jenkins",
            "source_type": SourceType.CI_CD,
            "provider": "jenkins",
            "observed_at": raw.observed_at,
        }

    # -- Jobs --

    def _normalize_jobs(self, raw: RawEventData) -> list[FindingData]:
        """Inventory jobs; flag failed builds on security-related jobs."""
        findings = []
        jobs = raw.raw_data.get("jobs", [])

        security_keywords = {
            "security",
            "sast",
            "dast",
            "scan",
            "audit",
            "compliance",
            "vuln",
            "pentest",
        }

        for job in jobs:
            name = job.get("name", "")
            color = job.get("color", "")
            url = job.get("url", "")
            last_build = job.get("lastBuild") or {}
            build_result = last_build.get("result", "")
            build_number = last_build.get("number", "")
            health = job.get("healthReport", [])

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Jenkins job: {name} ({color})",
                    detail={
                        "name": name,
                        "color": color,
                        "url": url,
                        "last_build_number": build_number,
                        "last_build_result": build_result,
                        "health_report": health,
                    },
                    resource_id=name,
                    resource_type="jenkins_job",
                    resource_name=name,
                    severity="info",
                )
            )

            # Flag failed builds on security-related jobs
            name_lower = name.lower()
            is_security_job = any(kw in name_lower for kw in security_keywords)
            if is_security_job and build_result in ("FAILURE", "UNSTABLE"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Security job failed: {name} (build #{build_number})",
                        detail={
                            "name": name,
                            "build_number": build_number,
                            "build_result": build_result,
                            "url": url,
                            "issue": f"Security-related job '{name}' has a {build_result} build — security checks may not be running",
                        },
                        resource_id=name,
                        resource_type="jenkins_job",
                        resource_name=name,
                        severity="high",
                    )
                )

        return findings

    # -- Nodes --

    def _normalize_nodes(self, raw: RawEventData) -> list[FindingData]:
        """Inventory nodes; flag offline nodes and outdated agents."""
        findings = []
        nodes = raw.raw_data.get("nodes", [])

        for node in nodes:
            display_name = node.get("displayName", "")
            offline = node.get("offline", False)
            temporarily_offline = node.get("temporarilyOffline", False)
            num_executors = node.get("numExecutors", 0)
            monitor_data = node.get("monitorData", {})

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Jenkins node: {display_name} ({'offline' if offline else 'online'})",
                    detail={
                        "display_name": display_name,
                        "offline": offline,
                        "temporarily_offline": temporarily_offline,
                        "num_executors": num_executors,
                        "monitor_data_keys": list(monitor_data.keys())
                        if isinstance(monitor_data, dict)
                        else [],
                    },
                    resource_id=display_name,
                    resource_type="jenkins_node",
                    resource_name=display_name,
                    severity="info",
                )
            )

            # Flag offline nodes (may indicate outdated or misconfigured agents)
            if offline and not temporarily_offline:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Jenkins node offline: {display_name}",
                        detail={
                            "display_name": display_name,
                            "offline": True,
                            "temporarily_offline": False,
                            "issue": f"Node '{display_name}' is offline — agent may be outdated, misconfigured, or unreachable",
                        },
                        resource_id=display_name,
                        resource_type="jenkins_node",
                        resource_name=display_name,
                        severity="medium",
                    )
                )

        return findings

    # -- Credentials --

    def _normalize_credentials(self, raw: RawEventData) -> list[FindingData]:
        """Inventory credentials; flag potential rotation issues."""
        findings = []
        credentials = raw.raw_data.get("credentials", [])

        for cred in credentials:
            cred_id = cred.get("id", "")
            type_name = cred.get("typeName", "")
            display_name = cred.get("displayName", "")
            description = cred.get("description", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Jenkins credential: {display_name or cred_id} ({type_name})",
                    detail={
                        "id": cred_id,
                        "type_name": type_name,
                        "display_name": display_name,
                        "description": description,
                    },
                    resource_id=cred_id,
                    resource_type="jenkins_credential",
                    resource_name=display_name or cred_id,
                    severity="info",
                )
            )

            # Flag credentials with no description (may indicate unmanaged/stale secrets)
            if not description:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"Jenkins credential without description: {display_name or cred_id}",
                        detail={
                            "id": cred_id,
                            "type_name": type_name,
                            "display_name": display_name,
                            "issue": "Credential has no description — may be unmanaged or not rotated regularly",
                        },
                        resource_id=cred_id,
                        resource_type="jenkins_credential",
                        resource_name=display_name or cred_id,
                        severity="medium",
                    )
                )

        return findings

    # -- Security --

    def _normalize_security(self, raw: RawEventData) -> list[FindingData]:
        """Evaluate Jenkins security configuration."""
        findings = []
        security = raw.raw_data.get("security", {})

        # Inventory
        findings.append(
            FindingData(
                **self._base(raw),
                observation_type="inventory",
                title="Jenkins security configuration",
                detail={
                    "security_keys": list(security.keys()) if isinstance(security, dict) else []
                },
                resource_id="jenkins-security",
                resource_type="jenkins_security_config",
                resource_name="Jenkins Security",
                severity="info",
            )
        )

        # Flag if CSRF protection is disabled
        use_crumbs = security.get("useCrumbs", security.get("crumbIssuer"))
        if use_crumbs is False or use_crumbs is None:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title="Jenkins CSRF protection disabled",
                    detail={
                        "use_crumbs": use_crumbs,
                        "issue": "CSRF protection (crumb issuer) is not enabled — Jenkins is vulnerable to cross-site request forgery attacks",
                    },
                    resource_id="jenkins-security",
                    resource_type="jenkins_security_config",
                    resource_name="Jenkins Security",
                    severity="critical",
                )
            )

        # Flag anonymous read access
        auth_strategy = security.get("authorizationStrategy", {})
        strategy_class = auth_strategy.get("$class", "") if isinstance(auth_strategy, dict) else ""
        if "Unsecured" in strategy_class or "AuthorizationStrategy$Unsecured" in strategy_class:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title="Jenkins anonymous access enabled",
                    detail={
                        "authorization_strategy": strategy_class,
                        "issue": "Jenkins uses unsecured authorization — anyone can access and modify Jenkins without authentication",
                    },
                    resource_id="jenkins-security",
                    resource_type="jenkins_security_config",
                    resource_name="Jenkins Security",
                    severity="critical",
                )
            )

        return findings


# Register
registry.register(JenkinsNormalizer())
