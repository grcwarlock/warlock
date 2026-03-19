"""OVHcloud normalizer — transforms raw OVH API responses into Findings.

Each event_type gets a handler that knows the shape of that specific
API response and extracts structured observations from it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class OVHNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "ovh_projects": "_normalize_projects",
        "ovh_instances": "_normalize_instances",
        "ovh_cloud_users": "_normalize_cloud_users",
        "ovh_networks": "_normalize_networks",
        "ovh_storage": "_normalize_storage",
        "ovh_kubernetes": "_normalize_kubernetes",
        "ovh_certificates": "_normalize_certificates",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "ovh" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all OVH findings."""
        return {
            "raw_event_id": raw.id,
            "source": "ovh",
            "source_type": SourceType.CLOUD,
            "provider": "ovh",
            "account_id": raw.raw_data.get("service_name", ""),
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Cloud Projects --

    def _normalize_projects(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", [])

        # /cloud/project returns a list of project IDs (strings)
        if isinstance(response, list):
            for project_id in response:
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"OVH cloud project: {project_id}",
                    detail={"project_id": project_id},
                    resource_id=str(project_id),
                    resource_type="ovh_cloud_project",
                    resource_name=str(project_id),
                    severity="info",
                ))
        return findings

    # -- Cloud Instances --

    def _normalize_instances(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", [])

        status_severity = {
            "ACTIVE": "info",
            "SHUTOFF": "low",
            "ERROR": "high",
            "BUILD": "info",
            "REBUILD": "info",
            "RESCUED": "medium",
            "SUSPENDED": "medium",
            "DELETED": "low",
        }

        for instance in response if isinstance(response, list) else []:
            instance_id = instance.get("id", "")
            instance_name = instance.get("name", "unknown")
            status = instance.get("status", "UNKNOWN").upper()
            region = instance.get("region", "")

            issues = []
            severity = status_severity.get(status, "info")
            obs_type = "inventory"

            if status == "ERROR":
                issues.append("instance_in_error_state")
                obs_type = "misconfiguration"
            elif status == "SHUTOFF":
                issues.append("instance_shutoff")

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"OVH instance: {instance_name}" + (
                    f" — {', '.join(issues)}" if issues else ""
                ),
                detail={
                    "instance": instance,
                    "status": status,
                    "issues": issues,
                },
                resource_id=instance_id,
                resource_type="ovh_cloud_instance",
                resource_name=instance_name,
                severity=severity,
                region=region,
            ))

        return findings

    # -- Cloud Users (S3) --

    def _normalize_cloud_users(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", [])

        for user in response if isinstance(response, list) else []:
            user_id = str(user.get("id", ""))
            username = user.get("username", user.get("description", "unknown"))
            status = user.get("status", "")
            roles = user.get("roles", [])

            issues = []
            severity = "info"
            obs_type = "inventory"

            # Flag users with admin/objectstore roles
            role_names = [r.get("name", "") if isinstance(r, dict) else str(r) for r in roles]
            admin_roles = [r for r in role_names if "admin" in r.lower()]
            if admin_roles:
                issues.append(f"admin_roles: {', '.join(admin_roles)}")
                severity = "medium"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"OVH cloud user: {username}" + (
                    f" — {', '.join(issues)}" if issues else ""
                ),
                detail={
                    "user": user,
                    "status": status,
                    "roles": role_names,
                    "issues": issues,
                },
                resource_id=user_id,
                resource_type="ovh_cloud_user",
                resource_name=username,
                severity=severity,
            ))

        return findings

    # -- Private Networks --

    def _normalize_networks(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", [])

        for network in response if isinstance(response, list) else []:
            network_id = network.get("id", "")
            network_name = network.get("name", "unknown")
            status = network.get("status", "")
            vlan_id = network.get("vlanId", "")
            regions = network.get("regions", [])

            region_names = [
                r.get("region", "") if isinstance(r, dict) else str(r)
                for r in regions
            ]

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"OVH private network: {network_name}",
                detail={
                    "network": network,
                    "status": status,
                    "vlan_id": vlan_id,
                    "regions": region_names,
                },
                resource_id=str(network_id),
                resource_type="ovh_private_network",
                resource_name=network_name,
                severity="info",
            ))

        return findings

    # -- Object Storage Containers --

    def _normalize_storage(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", [])

        for container in response if isinstance(response, list) else []:
            container_name = container.get("name", "unknown")
            region = container.get("region", "")
            stored_objects = container.get("storedObjects", 0)
            stored_bytes = container.get("storedBytes", 0)
            is_public = container.get("public", False)

            issues = []
            severity = "info"
            obs_type = "inventory"

            if is_public:
                issues.append("container_publicly_accessible")
                severity = "high"
                obs_type = "misconfiguration"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"OVH storage container: {container_name}" + (
                    f" — {', '.join(issues)}" if issues else ""
                ),
                detail={
                    "container": container,
                    "stored_objects": stored_objects,
                    "stored_bytes": stored_bytes,
                    "public": is_public,
                    "issues": issues,
                },
                resource_id=container_name,
                resource_type="ovh_storage_container",
                resource_name=container_name,
                severity=severity,
                region=region,
            ))

        return findings

    # -- Kubernetes Clusters --

    def _normalize_kubernetes(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", [])

        for cluster in response if isinstance(response, list) else []:
            cluster_id = cluster.get("id", "")
            cluster_name = cluster.get("name", "unknown")
            version = cluster.get("version", "")
            region = cluster.get("region", "")
            status = cluster.get("status", "")
            update_policy = cluster.get("updatePolicy", {})

            issues = []
            severity = "info"
            obs_type = "inventory"

            # Check version currency — flag old minor versions
            if version:
                try:
                    parts = version.split(".")
                    minor = int(parts[1]) if len(parts) > 1 else 0
                    # Kubernetes releases roughly every 4 months;
                    # flag if minor version is more than 3 behind latest common
                    # We flag versions < 1.28 as potentially stale
                    if minor < 28:
                        issues.append(f"outdated_k8s_version_{version}")
                        severity = "medium"
                        obs_type = "misconfiguration"
                except (ValueError, IndexError):
                    pass

            # Check update policy
            policy_name = ""
            if isinstance(update_policy, dict):
                policy_name = update_policy.get("updateType", "")
            elif isinstance(update_policy, str):
                policy_name = update_policy

            if policy_name.upper() == "MANUAL":
                issues.append("manual_update_policy")
                if severity == "info":
                    severity = "low"
                    obs_type = "misconfiguration"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"OVH Kubernetes: {cluster_name}" + (
                    f" — {len(issues)} issues" if issues else ""
                ),
                detail={
                    "cluster": cluster,
                    "version": version,
                    "status": status,
                    "update_policy": policy_name,
                    "issues": issues,
                },
                resource_id=cluster_id,
                resource_type="ovh_kubernetes_cluster",
                resource_name=cluster_name,
                severity=severity,
                region=region,
            ))

        return findings

    # -- SSL Certificates --

    def _normalize_certificates(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", [])
        now = datetime.now(timezone.utc)
        expiry_threshold = now + timedelta(days=30)

        for cert in response if isinstance(response, list) else []:
            # /ssl returns service names (strings); full details need sub-calls.
            # If response contains dicts with certificate details, use them.
            if isinstance(cert, str):
                # Bare service name — inventory only
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"OVH SSL certificate: {cert}",
                    detail={"service_name": cert},
                    resource_id=cert,
                    resource_type="ovh_ssl_certificate",
                    resource_name=cert,
                    severity="info",
                ))
                continue

            cert_id = cert.get("serviceName", cert.get("id", "unknown"))
            cn = cert.get("cn", cert.get("commonName", cert_id))
            expires_str = cert.get("expireDate", cert.get("validTo", ""))

            issues = []
            severity = "info"
            obs_type = "inventory"

            if expires_str:
                try:
                    # Try ISO format first, then common OVH date format
                    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
                        try:
                            expires = datetime.strptime(expires_str, fmt)
                            if expires.tzinfo is None:
                                expires = expires.replace(tzinfo=timezone.utc)
                            break
                        except ValueError:
                            continue
                    else:
                        expires = None

                    if expires is not None:
                        if expires < now:
                            issues.append("certificate_expired")
                            severity = "critical"
                            obs_type = "misconfiguration"
                        elif expires < expiry_threshold:
                            days_left = (expires - now).days
                            issues.append(f"certificate_expiring_in_{days_left}_days")
                            severity = "high"
                            obs_type = "misconfiguration"
                except Exception:
                    pass

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"OVH SSL certificate: {cn}" + (
                    f" — {', '.join(issues)}" if issues else ""
                ),
                detail={
                    "certificate": cert,
                    "common_name": cn,
                    "expire_date": expires_str,
                    "issues": issues,
                },
                resource_id=str(cert_id),
                resource_type="ovh_ssl_certificate",
                resource_name=cn,
                severity=severity,
            ))

        return findings


# Register
registry.register(OVHNormalizer())
