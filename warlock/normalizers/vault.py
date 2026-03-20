"""Vault normalizer — transforms raw Vault API responses into Findings.

Normalizes secret engines, auth methods, policies, audit devices, seal status,
and cluster health with security-relevant finding generation.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class VaultNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "vault_secret_engines": "_normalize_secret_engines",
        "vault_auth_methods": "_normalize_auth_methods",
        "vault_policies": "_normalize_policies",
        "vault_audit_devices": "_normalize_audit_devices",
        "vault_seal_status": "_normalize_seal_status",
        "vault_health": "_normalize_health",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "vault" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "vault",
            "source_type": SourceType.IAM,
            "provider": "vault",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Secret Engines --

    def _normalize_secret_engines(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        engines = response.get("data", response) if isinstance(response, dict) else response

        for path, config in engines.items():
            if isinstance(config, dict) and config.get("type"):
                engine_type = config.get("type", "")
                description = config.get("description", "")
                options = config.get("options", {}) or {}

                issues = []
                severity = "info"
                obs_type = "inventory"

                # Flag engines with no rotation / max TTL configured
                max_lease = config.get("config", {}).get("max_lease_ttl", 0)
                if max_lease == 0 and engine_type not in ("system", "identity", "cubbyhole"):
                    issues.append("no_rotation_policy")
                    severity = "medium"
                    obs_type = "misconfiguration"

                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type=obs_type,
                        title=f"Vault secret engine: {path} ({engine_type})"
                        + (f" -- {', '.join(issues)}" if issues else ""),
                        detail={
                            "path": path,
                            "type": engine_type,
                            "description": description,
                            "options": options,
                            "config": config.get("config", {}),
                            "issues": issues,
                        },
                        resource_id=path,
                        resource_type="secret_engine",
                        resource_name=path,
                        severity=severity,
                    )
                )

        return findings

    # -- Auth Methods --

    def _normalize_auth_methods(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        methods = response.get("data", response) if isinstance(response, dict) else response

        has_mfa = False
        for path, config in methods.items():
            if isinstance(config, dict) and config.get("type"):
                auth_type = config.get("type", "")
                if auth_type in ("totp", "okta", "ldap", "oidc"):
                    has_mfa = True

                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="inventory",
                        title=f"Vault auth method: {path} ({auth_type})",
                        detail={
                            "path": path,
                            "type": auth_type,
                            "description": config.get("description", ""),
                            "config": config.get("config", {}),
                        },
                        resource_id=path,
                        resource_type="auth_method",
                        resource_name=path,
                        severity="info",
                    )
                )

        # Flag if no MFA-capable auth method is enabled
        if not has_mfa and methods:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title="Vault has no MFA-capable auth method enabled",
                    detail={
                        "auth_methods": list(methods.keys()),
                        "recommendation": "Enable an MFA-capable auth method (OIDC, LDAP, Okta, TOTP)",
                    },
                    resource_id="vault_auth",
                    resource_type="auth_method",
                    resource_name="vault_auth",
                    severity="high",
                )
            )

        return findings

    # -- Policies --

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        # ACL list endpoint returns {"keys": [...]}
        policies = response.get("keys", response.get("data", {}).get("keys", []))
        if isinstance(policies, dict):
            policies = policies.get("keys", [])

        for policy_name in policies:
            issues = []
            severity = "info"
            obs_type = "inventory"

            # Flag wildcard / overly permissive well-known policies
            if policy_name in ("root",):
                issues.append("root_policy")
                severity = "high"
                obs_type = "misconfiguration"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Vault policy: {policy_name}"
                    + (f" -- {', '.join(issues)}" if issues else ""),
                    detail={
                        "policy_name": policy_name,
                        "issues": issues,
                    },
                    resource_id=policy_name,
                    resource_type="vault_policy",
                    resource_name=policy_name,
                    severity=severity,
                )
            )

        return findings

    # -- Audit Devices --

    def _normalize_audit_devices(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        devices = response.get("data", response) if isinstance(response, dict) else response

        if not devices or (isinstance(devices, dict) and len(devices) == 0):
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="policy_violation",
                    title="Vault has no audit logging enabled",
                    detail={
                        "recommendation": "Enable at least one audit device for compliance",
                    },
                    resource_id="vault_audit",
                    resource_type="audit_device",
                    resource_name="vault_audit",
                    severity="critical",
                )
            )
            return findings

        for path, config in devices.items():
            if isinstance(config, dict):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="inventory",
                        title=f"Vault audit device: {path} ({config.get('type', 'unknown')})",
                        detail={
                            "path": path,
                            "type": config.get("type", ""),
                            "description": config.get("description", ""),
                            "options": config.get("options", {}),
                        },
                        resource_id=path,
                        resource_type="audit_device",
                        resource_name=path,
                        severity="info",
                    )
                )

        return findings

    # -- Seal Status --

    def _normalize_seal_status(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})

        sealed = response.get("sealed", False)
        initialized = response.get("initialized", False)
        cluster_name = response.get("cluster_name", "")

        if sealed:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title="Vault is sealed",
                    detail={
                        "sealed": True,
                        "initialized": initialized,
                        "cluster_name": cluster_name,
                        "response": response,
                    },
                    resource_id=cluster_name or "vault",
                    resource_type="vault_cluster",
                    resource_name=cluster_name or "vault",
                    severity="critical",
                )
            )
        else:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Vault seal status: unsealed (cluster: {cluster_name})",
                    detail={
                        "sealed": False,
                        "initialized": initialized,
                        "cluster_name": cluster_name,
                        "cluster_id": response.get("cluster_id", ""),
                        "version": response.get("version", ""),
                        "response": response,
                    },
                    resource_id=cluster_name or "vault",
                    resource_type="vault_cluster",
                    resource_name=cluster_name or "vault",
                    severity="info",
                )
            )

        # Check HA status
        if initialized and not response.get("cluster_name"):
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title="Vault is not configured for high availability",
                    detail={
                        "initialized": initialized,
                        "recommendation": "Configure Vault HA for production resilience",
                        "response": response,
                    },
                    resource_id="vault_ha",
                    resource_type="vault_cluster",
                    resource_name="vault_ha",
                    severity="medium",
                )
            )

        return findings

    # -- Health --

    def _normalize_health(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})

        cluster_name = response.get("cluster_name", "vault")
        standby = response.get("standby", False)
        perf_standby = response.get("performance_standby", False)

        status_parts = []
        if standby:
            status_parts.append("standby")
        if perf_standby:
            status_parts.append("performance_standby")
        if not standby and not perf_standby:
            status_parts.append("active")

        findings.append(
            FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Vault health: {', '.join(status_parts)} (cluster: {cluster_name})",
                detail={
                    "initialized": response.get("initialized", False),
                    "sealed": response.get("sealed", False),
                    "standby": standby,
                    "performance_standby": perf_standby,
                    "replication_performance_mode": response.get(
                        "replication_performance_mode", ""
                    ),
                    "replication_dr_mode": response.get("replication_dr_mode", ""),
                    "server_time_utc": response.get("server_time_utc", ""),
                    "version": response.get("version", ""),
                    "cluster_name": cluster_name,
                    "cluster_id": response.get("cluster_id", ""),
                },
                resource_id=cluster_name,
                resource_type="vault_cluster",
                resource_name=cluster_name,
                severity="info",
            )
        )

        return findings


# Register
registry.register(VaultNormalizer())
