"""Kubernetes normalizer — transforms raw K8s API responses into Findings.

Normalizes namespaces, network policies, RBAC bindings, admission controls,
running pods, and deployments with container security finding generation.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class KubernetesNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "k8s_namespaces": "_normalize_namespaces",
        "k8s_network_policies": "_normalize_network_policies",
        "k8s_rbac_bindings": "_normalize_rbac_bindings",
        "k8s_admission_controls": "_normalize_admission_controls",
        "k8s_running_pods": "_normalize_running_pods",
        "k8s_deployments": "_normalize_deployments",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "kubernetes" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "kubernetes",
            "source_type": SourceType.CLOUD,
            "provider": "kubernetes",
            "account_id": raw.raw_data.get("api_url", ""),
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Namespaces --

    def _normalize_namespaces(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        namespaces = raw.raw_data.get("response", [])

        for ns in namespaces:
            metadata = ns.get("metadata", {})
            name = metadata.get("name", "")
            uid = metadata.get("uid", "")
            status = ns.get("status", {}).get("phase", "")

            issues = []
            severity = "info"
            obs_type = "inventory"

            # Default namespace with active workloads is a concern
            if name == "default" and status == "Active":
                issues.append("default_namespace_active")
                severity = "medium"
                obs_type = "misconfiguration"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"K8s namespace: {name}" + (f" -- {', '.join(issues)}" if issues else ""),
                    detail={
                        "name": name,
                        "uid": uid,
                        "status": status,
                        "labels": metadata.get("labels", {}),
                        "annotations": metadata.get("annotations", {}),
                        "issues": issues,
                    },
                    resource_id=uid,
                    resource_type="k8s_namespace",
                    resource_name=name,
                    severity=severity,
                )
            )

        return findings

    # -- Network Policies --

    def _normalize_network_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        policies = raw.raw_data.get("response", [])

        # Collect which namespaces have policies
        covered_namespaces = set()
        for policy in policies:
            metadata = policy.get("metadata", {})
            ns = metadata.get("namespace", "")
            name = metadata.get("name", "")
            uid = metadata.get("uid", "")
            covered_namespaces.add(ns)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"K8s network policy: {ns}/{name}",
                    detail={
                        "name": name,
                        "namespace": ns,
                        "uid": uid,
                        "spec": policy.get("spec", {}),
                    },
                    resource_id=uid,
                    resource_type="k8s_network_policy",
                    resource_name=f"{ns}/{name}",
                    severity="info",
                )
            )

        # Flag if no network policies exist at all
        if not policies:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title="No Kubernetes network policies found in any namespace",
                    detail={
                        "recommendation": "Define network policies to restrict pod-to-pod traffic",
                    },
                    resource_id="k8s_network_policies",
                    resource_type="k8s_network_policy",
                    resource_name="k8s_network_policies",
                    severity="high",
                )
            )

        return findings

    # -- RBAC Bindings --

    def _normalize_rbac_bindings(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        bindings = raw.raw_data.get("response", [])

        for binding in bindings:
            metadata = binding.get("metadata", {})
            name = metadata.get("name", "")
            uid = metadata.get("uid", "")
            role_ref = binding.get("roleRef", {})
            role_name = role_ref.get("name", "")
            subjects = binding.get("subjects", [])

            issues = []
            severity = "info"
            obs_type = "inventory"

            for subject in subjects:
                subject_name = subject.get("name", "")

                # Anonymous bindings are critical
                if subject_name == "system:anonymous":
                    issues.append(f"anonymous_binding:{role_name}")
                    severity = "critical"
                    obs_type = "misconfiguration"

            # cluster-admin bindings are high risk
            if role_name == "cluster-admin" and not issues:
                issues.append("cluster_admin_binding")
                severity = "high"
                obs_type = "misconfiguration"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"K8s RBAC binding: {name} -> {role_name}"
                    + (f" -- {', '.join(issues)}" if issues else ""),
                    detail={
                        "name": name,
                        "uid": uid,
                        "role_ref": role_ref,
                        "subjects": subjects,
                        "issues": issues,
                    },
                    resource_id=uid,
                    resource_type="k8s_rbac_binding",
                    resource_name=name,
                    severity=severity,
                )
            )

        return findings

    # -- Admission Controls --

    def _normalize_admission_controls(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        webhooks = raw.raw_data.get("response", [])

        if not webhooks:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title="No validating webhook configurations found",
                    detail={
                        "recommendation": "Configure admission controllers for pod security enforcement",
                    },
                    resource_id="k8s_admission",
                    resource_type="k8s_admission_control",
                    resource_name="k8s_admission",
                    severity="medium",
                )
            )
            return findings

        for webhook in webhooks:
            metadata = webhook.get("metadata", {})
            name = metadata.get("name", "")
            uid = metadata.get("uid", "")
            hooks = webhook.get("webhooks", [])

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"K8s validating webhook: {name} ({len(hooks)} hooks)",
                    detail={
                        "name": name,
                        "uid": uid,
                        "webhook_count": len(hooks),
                        "webhooks": [h.get("name", "") for h in hooks],
                    },
                    resource_id=uid,
                    resource_type="k8s_admission_control",
                    resource_name=name,
                    severity="info",
                )
            )

        return findings

    # -- Running Pods --

    def _normalize_running_pods(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        pods = raw.raw_data.get("response", [])

        for pod in pods:
            metadata = pod.get("metadata", {})
            name = metadata.get("name", "")
            namespace = metadata.get("namespace", "")
            uid = metadata.get("uid", "")
            spec = pod.get("spec", {})
            containers = spec.get("containers", [])

            issues = []
            severity = "info"
            obs_type = "inventory"

            for container in containers:
                c_name = container.get("name", "")
                sec_ctx = container.get("securityContext", {})
                resources = container.get("resources", {})

                # Privileged containers — critical
                if sec_ctx.get("privileged"):
                    issues.append(f"privileged_container:{c_name}")
                    if severity != "critical":
                        severity = "critical"
                    obs_type = "misconfiguration"

                # Root containers — high
                run_as_user = sec_ctx.get("runAsUser")
                run_as_non_root = sec_ctx.get("runAsNonRoot", False)
                if run_as_user == 0 or (not run_as_non_root and not sec_ctx.get("runAsUser")):
                    if f"privileged_container:{c_name}" not in issues:
                        issues.append(f"root_container:{c_name}")
                        if severity not in ("critical",):
                            severity = "high"
                        obs_type = "misconfiguration"

                # No resource limits — medium
                if not resources.get("limits"):
                    issues.append(f"no_resource_limits:{c_name}")
                    if severity not in ("critical", "high"):
                        severity = "medium"
                    obs_type = "misconfiguration"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"K8s pod: {namespace}/{name}"
                    + (f" -- {', '.join(issues)}" if issues else ""),
                    detail={
                        "name": name,
                        "namespace": namespace,
                        "uid": uid,
                        "container_count": len(containers),
                        "node_name": spec.get("nodeName", ""),
                        "service_account": spec.get("serviceAccountName", ""),
                        "host_network": spec.get("hostNetwork", False),
                        "host_pid": spec.get("hostPID", False),
                        "issues": issues,
                    },
                    resource_id=uid,
                    resource_type="k8s_pod",
                    resource_name=f"{namespace}/{name}",
                    severity=severity,
                )
            )

        return findings

    # -- Deployments --

    def _normalize_deployments(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        deployments = raw.raw_data.get("response", [])

        for deploy in deployments:
            metadata = deploy.get("metadata", {})
            name = metadata.get("name", "")
            namespace = metadata.get("namespace", "")
            uid = metadata.get("uid", "")
            spec = deploy.get("spec", {})
            replicas = spec.get("replicas", 1)
            status = deploy.get("status", {})

            issues = []
            severity = "info"
            obs_type = "inventory"

            # Single replica in non-system namespaces
            if replicas <= 1 and namespace not in (
                "kube-system",
                "kube-public",
                "kube-node-lease",
            ):
                issues.append("single_replica")
                severity = "medium"
                obs_type = "misconfiguration"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"K8s deployment: {namespace}/{name} ({replicas} replicas)"
                    + (f" -- {', '.join(issues)}" if issues else ""),
                    detail={
                        "name": name,
                        "namespace": namespace,
                        "uid": uid,
                        "replicas": replicas,
                        "ready_replicas": status.get("readyReplicas", 0),
                        "available_replicas": status.get("availableReplicas", 0),
                        "strategy": spec.get("strategy", {}).get("type", ""),
                        "issues": issues,
                    },
                    resource_id=uid,
                    resource_type="k8s_deployment",
                    resource_name=f"{namespace}/{name}",
                    severity=severity,
                )
            )

        return findings


# Register
registry.register(KubernetesNormalizer())
