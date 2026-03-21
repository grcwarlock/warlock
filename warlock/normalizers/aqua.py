"""Aqua Security normalizer — transforms raw Aqua CSP API responses into Findings.

Handles images, runtime policies, compliance (CIS benchmarks), and secrets.
Flags: images with critical/high CVEs, runtime policy violations,
CIS benchmark failures, exposed secrets.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class AquaNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "aqua_images": "_normalize_images",
        "aqua_runtime_policies": "_normalize_runtime_policies",
        "aqua_compliance": "_normalize_compliance",
        "aqua_secrets": "_normalize_secrets",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "aqua" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Aqua findings."""
        return {
            "raw_event_id": raw.id,
            "source": "aqua",
            "source_type": SourceType.CONTAINER_SECURITY,
            "provider": "aqua",
            "observed_at": raw.observed_at,
        }

    # -- Images --

    def _normalize_images(self, raw: RawEventData) -> list[FindingData]:
        """Inventory images; flag images with critical/high CVEs."""
        findings = []
        images = raw.raw_data.get("images", [])

        for image in images:
            image_name = image.get("name", image.get("repository", ""))
            registry_name = image.get("registry", "")
            tag = image.get("tag", "latest")
            image_id = image.get("docker_id", image.get("id", ""))
            scan_status = image.get("scan_status", "")
            critical_vulns = image.get("critical_vulnerabilities", 0)
            high_vulns = image.get("high_vulnerabilities", 0)
            medium_vulns = image.get("medium_vulnerabilities", 0)
            low_vulns = image.get("low_vulnerabilities", 0)
            total_vulns = image.get("vulnerabilities_count", 0)
            malware_count = image.get("malware", 0)
            disallowed = image.get("disallowed", False)

            display_name = f"{registry_name}/{image_name}:{tag}" if registry_name else f"{image_name}:{tag}"

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Container image: {display_name}",
                    detail={
                        "image_name": image_name,
                        "registry": registry_name,
                        "tag": tag,
                        "image_id": image_id,
                        "scan_status": scan_status,
                        "critical_vulns": critical_vulns,
                        "high_vulns": high_vulns,
                        "medium_vulns": medium_vulns,
                        "low_vulns": low_vulns,
                        "total_vulns": total_vulns,
                        "disallowed": disallowed,
                    },
                    resource_id=image_id or display_name,
                    resource_type="container_image",
                    resource_name=display_name,
                    severity="info",
                )
            )

            # Flag images with critical CVEs
            if critical_vulns and critical_vulns > 0:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="vulnerability",
                        title=f"Image with critical CVEs: {display_name} ({critical_vulns} critical)",
                        detail={
                            "image_name": display_name,
                            "image_id": image_id,
                            "critical_vulns": critical_vulns,
                            "high_vulns": high_vulns,
                            "total_vulns": total_vulns,
                            "issue": f"Container image has {critical_vulns} critical vulnerabilities requiring immediate remediation",
                        },
                        resource_id=image_id or display_name,
                        resource_type="container_image",
                        resource_name=display_name,
                        severity="critical",
                    )
                )

            # Flag images with high CVEs (only if no critical — avoid double-flag)
            elif high_vulns and high_vulns > 0:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="vulnerability",
                        title=f"Image with high CVEs: {display_name} ({high_vulns} high)",
                        detail={
                            "image_name": display_name,
                            "image_id": image_id,
                            "high_vulns": high_vulns,
                            "total_vulns": total_vulns,
                            "issue": f"Container image has {high_vulns} high-severity vulnerabilities",
                        },
                        resource_id=image_id or display_name,
                        resource_type="container_image",
                        resource_name=display_name,
                        severity="high",
                    )
                )

            # Flag images with malware
            if malware_count and malware_count > 0:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Malware detected in image: {display_name}",
                        detail={
                            "image_name": display_name,
                            "image_id": image_id,
                            "malware_count": malware_count,
                            "issue": "Container image contains detected malware — do not deploy",
                        },
                        resource_id=image_id or display_name,
                        resource_type="container_image",
                        resource_name=display_name,
                        severity="critical",
                    )
                )

        return findings

    # -- Runtime Policies --

    def _normalize_runtime_policies(self, raw: RawEventData) -> list[FindingData]:
        """Inventory runtime policies; flag disabled or audit-only policies."""
        findings = []
        policies = raw.raw_data.get("policies", [])

        for policy in policies:
            policy_name = policy.get("name", "")
            policy_id = policy.get("id", str(policy.get("policy_id", "")))
            enabled = policy.get("enabled", True)
            enforce = policy.get("enforce", False)
            policy_type = policy.get("type", "")
            scope = policy.get("scope", {})

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Aqua runtime policy: {policy_name}",
                    detail={
                        "policy_id": policy_id,
                        "policy_name": policy_name,
                        "enabled": enabled,
                        "enforce": enforce,
                        "policy_type": policy_type,
                        "scope": scope,
                    },
                    resource_id=str(policy_id),
                    resource_type="aqua_runtime_policy",
                    resource_name=policy_name,
                    severity="info",
                )
            )

            # Flag disabled runtime policies
            if not enabled:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Runtime policy disabled: {policy_name}",
                        detail={
                            "policy_id": policy_id,
                            "policy_name": policy_name,
                            "enabled": False,
                            "issue": "Runtime protection policy is disabled — containers run without enforcement",
                        },
                        resource_id=str(policy_id),
                        resource_type="aqua_runtime_policy",
                        resource_name=policy_name,
                        severity="high",
                    )
                )

            # Flag audit-only (not enforcing) policies
            elif not enforce:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Runtime policy in audit-only mode: {policy_name}",
                        detail={
                            "policy_id": policy_id,
                            "policy_name": policy_name,
                            "enforce": False,
                            "issue": "Runtime policy is in audit-only mode — violations are logged but not blocked",
                        },
                        resource_id=str(policy_id),
                        resource_type="aqua_runtime_policy",
                        resource_name=policy_name,
                        severity="medium",
                    )
                )

        return findings

    # -- Compliance (CIS Benchmarks) --

    def _normalize_compliance(self, raw: RawEventData) -> list[FindingData]:
        """Flag CIS benchmark failures."""
        findings = []
        benchmarks = raw.raw_data.get("benchmarks", [])

        for bench in benchmarks:
            bench_id = bench.get("id", bench.get("benchmark_id", ""))
            bench_name = bench.get("name", bench.get("title", ""))
            node_name = bench.get("node_name", bench.get("host", ""))
            status = bench.get("status", "")
            total_tests = bench.get("total_tests", 0)
            passed = bench.get("passed", 0)
            failed = bench.get("failed", 0)
            warn = bench.get("warn", 0)

            # Flag benchmark failures
            if failed and failed > 0:
                sev = "high" if failed > 5 else "medium"
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"CIS benchmark failures: {bench_name} on {node_name} ({failed} failed)",
                        detail={
                            "benchmark_id": str(bench_id),
                            "benchmark_name": bench_name,
                            "node_name": node_name,
                            "status": status,
                            "total_tests": total_tests,
                            "passed": passed,
                            "failed": failed,
                            "warn": warn,
                            "issue": f"CIS benchmark {bench_name} has {failed} failed checks out of {total_tests} total",
                        },
                        resource_id=str(bench_id),
                        resource_type="cis_benchmark",
                        resource_name=f"{bench_name}:{node_name}",
                        severity=sev,
                    )
                )

        return findings

    # -- Secrets --

    def _normalize_secrets(self, raw: RawEventData) -> list[FindingData]:
        """Flag exposed secrets detected in container images."""
        findings = []
        secrets = raw.raw_data.get("secrets", [])

        for secret in secrets:
            secret_type = secret.get("type", secret.get("secret_type", ""))
            image_name = secret.get("image", secret.get("image_name", ""))
            path = secret.get("path", secret.get("filename", ""))
            secret_id = secret.get("id", f"{image_name}:{path}")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Exposed secret in container image: {image_name}",
                    detail={
                        "secret_type": secret_type,
                        "image_name": image_name,
                        "path": path,
                        "issue": f"Secret of type '{secret_type}' found at {path} in container image — credentials may be leaked in image layer",
                    },
                    resource_id=str(secret_id),
                    resource_type="container_secret",
                    resource_name=f"{image_name}:{path}",
                    severity="critical",
                )
            )

        return findings


# Register
registry.register(AquaNormalizer())
