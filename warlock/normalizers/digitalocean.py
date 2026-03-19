"""DigitalOcean normalizer — transforms raw DO API responses into Findings.

Each event_type gets a handler that knows the shape of the corresponding
API response and extracts structured observations from it.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class DigitalOceanNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "do_firewalls": "_normalize_firewalls",
        "do_droplets": "_normalize_droplets",
        "do_spaces": "_normalize_spaces",
        "do_databases": "_normalize_databases",
        "do_kubernetes": "_normalize_kubernetes",
        "do_load_balancers": "_normalize_load_balancers",
        "do_domains": "_normalize_domains",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return (
            raw_event.source == "digitalocean"
            and raw_event.event_type in self.HANDLERS
        )

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all DigitalOcean findings."""
        return {
            "raw_event_id": raw.id,
            "source": "digitalocean",
            "source_type": SourceType.CLOUD,
            "provider": "digitalocean",
            "observed_at": raw.observed_at,
        }

    # -- Firewalls --

    def _normalize_firewalls(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        firewalls = raw.raw_data.get("response", [])
        sensitive_ports = {22, 3389, 3306, 5432, 1433, 27017, 6379}

        # Build set of droplet IDs protected by at least one firewall
        protected_droplet_ids: set[str] = set()
        for fw in firewalls:
            for did in fw.get("droplet_ids", []):
                protected_droplet_ids.add(str(did))

        for fw in firewalls:
            fw_name = fw.get("name", "unknown")
            fw_id = fw.get("id", "")
            issues = []

            inbound_rules = fw.get("inbound_rules", [])
            for rule in inbound_rules:
                sources = rule.get("sources", {})
                addresses = sources.get("addresses", [])
                has_open_source = "0.0.0.0/0" in addresses or "::/0" in addresses

                if not has_open_source:
                    continue

                protocol = rule.get("protocol", "")
                ports = rule.get("ports", "")

                if ports == "0" or ports == "all":
                    issues.append(f"all_{protocol}_ports_open_to_internet")
                elif ports:
                    for port_spec in ports.split(","):
                        port_spec = port_spec.strip()
                        try:
                            if "-" in port_spec:
                                start, end = port_spec.split("-")
                                for p in sensitive_ports:
                                    if int(start) <= p <= int(end):
                                        issues.append(
                                            f"open_to_internet_port_{p}"
                                        )
                            else:
                                port = int(port_spec)
                                if port in sensitive_ports:
                                    issues.append(
                                        f"open_to_internet_port_{port}"
                                    )
                        except (ValueError, TypeError):
                            pass

            severity = "info"
            obs_type = "inventory"
            if issues:
                severity = "high"
                obs_type = "misconfiguration"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"DO firewall: {fw_name}" + (
                    f" — {len(issues)} issues" if issues else ""
                ),
                detail={
                    "firewall": fw,
                    "issues": issues,
                    "droplet_ids": fw.get("droplet_ids", []),
                },
                resource_id=fw_id,
                resource_type="do_firewall",
                resource_name=fw_name,
                severity=severity,
            ))

        return findings

    # -- Droplets --

    def _normalize_droplets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        droplets = raw.raw_data.get("response", [])

        for droplet in droplets:
            droplet_name = droplet.get("name", "unknown")
            droplet_id = str(droplet.get("id", ""))
            issues = []

            # Check for public IP
            networks = droplet.get("networks", {})
            v4_networks = networks.get("v4", [])
            has_public_ip = any(
                n.get("type") == "public" for n in v4_networks
            )
            if has_public_ip:
                issues.append("public_facing")

            # Check backups enabled
            if not droplet.get("backup_ids"):
                features = droplet.get("features", [])
                if "backups" not in features:
                    issues.append("backups_disabled")

            # Check monitoring enabled
            features = droplet.get("features", [])
            if "monitoring" not in features:
                issues.append("monitoring_disabled")

            severity = "info"
            obs_type = "inventory"
            if issues:
                severity = "low"
                obs_type = "inventory"
                if "backups_disabled" in issues and has_public_ip:
                    severity = "medium"

            region = droplet.get("region", {})
            region_slug = region.get("slug", "") if isinstance(region, dict) else str(region)

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"DO droplet: {droplet_name}" + (
                    f" — {', '.join(issues)}" if issues else ""
                ),
                detail={
                    "droplet": droplet,
                    "issues": issues,
                    "has_public_ip": has_public_ip,
                },
                resource_id=droplet_id,
                resource_type="do_droplet",
                resource_name=droplet_name,
                severity=severity,
                region=region_slug,
            ))

        return findings

    # -- Spaces --

    def _normalize_spaces(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        spaces = raw.raw_data.get("response", [])

        for space in spaces:
            space_name = space.get("name", "unknown")

            # DO Spaces API provides limited ACL visibility; report as inventory
            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"DO space: {space_name}",
                detail={
                    "space": space,
                    "note": "Limited ACL visibility via DO API; review permissions in console",
                },
                resource_id=space_name,
                resource_type="do_space",
                resource_name=space_name,
                severity="info",
                region=space.get("region", {}).get("slug", "")
                if isinstance(space.get("region"), dict)
                else str(space.get("region", "")),
            ))

        return findings

    # -- Databases --

    def _normalize_databases(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        databases = raw.raw_data.get("response", [])

        for db in databases:
            db_name = db.get("name", "unknown")
            db_id = db.get("id", "")
            issues = []

            # Check trusted sources — empty means publicly accessible
            rules = db.get("rules", [])
            trusted_sources = [
                r for r in rules if r.get("type") != "ip_addr" or r.get("value") != "0.0.0.0/0"
            ]
            all_sources = rules
            has_open_access = any(
                r.get("value") == "0.0.0.0/0" for r in all_sources
            )
            if not rules or has_open_access:
                issues.append("publicly_accessible")

            # Check SSL enforcement
            connection = db.get("connection", {})
            private_connection = db.get("private_connection", {})
            if connection and not connection.get("ssl", False):
                issues.append("ssl_not_enforced")

            severity = "info"
            obs_type = "inventory"
            if issues:
                obs_type = "misconfiguration"
                if "publicly_accessible" in issues:
                    severity = "critical"
                elif "ssl_not_enforced" in issues:
                    severity = "high"

            region = db.get("region", "")

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"DO database: {db_name}" + (
                    f" — {', '.join(issues)}" if issues else ""
                ),
                detail={
                    "database": db,
                    "issues": issues,
                    "engine": db.get("engine", ""),
                    "version": db.get("version", ""),
                    "num_nodes": db.get("num_nodes", 0),
                },
                resource_id=db_id,
                resource_type="do_database",
                resource_name=db_name,
                severity=severity,
                region=region,
            ))

        return findings

    # -- Kubernetes Clusters --

    def _normalize_kubernetes(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        clusters = raw.raw_data.get("response", [])

        for cluster in clusters:
            cluster_name = cluster.get("name", "unknown")
            cluster_id = cluster.get("id", "")
            issues = []

            # Check auto_upgrade
            if not cluster.get("auto_upgrade", False):
                issues.append("auto_upgrade_disabled")

            # Check surge_upgrade
            if not cluster.get("surge_upgrade", False):
                issues.append("surge_upgrade_disabled")

            # Check RBAC
            # DO DOKS clusters have RBAC enabled by default but check
            # the cluster_subnet and service_subnet for potential misconfig
            if cluster.get("rbac") is not None and not cluster.get("rbac", True):
                issues.append("rbac_disabled")

            # Check if running an unsupported/old version
            version = cluster.get("version_slug", "")

            severity = "info"
            obs_type = "inventory"
            if issues:
                obs_type = "misconfiguration"
                severity = "medium"
                if "rbac_disabled" in issues:
                    severity = "high"

            region = cluster.get("region", "")

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"DO k8s cluster: {cluster_name}" + (
                    f" — {', '.join(issues)}" if issues else ""
                ),
                detail={
                    "cluster": cluster,
                    "issues": issues,
                    "version": version,
                    "node_pools": cluster.get("node_pools", []),
                    "ha": cluster.get("ha", False),
                },
                resource_id=cluster_id,
                resource_type="do_kubernetes_cluster",
                resource_name=cluster_name,
                severity=severity,
                region=region,
            ))

        return findings

    # -- Load Balancers --

    def _normalize_load_balancers(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        lbs = raw.raw_data.get("response", [])

        for lb in lbs:
            lb_name = lb.get("name", "unknown")
            lb_id = lb.get("id", "")
            issues = []

            # Check redirect HTTP to HTTPS
            if not lb.get("redirect_http_to_https", False):
                issues.append("no_http_to_https_redirect")

            # Check sticky sessions
            sticky = lb.get("sticky_sessions", {})
            if sticky.get("type") == "none" or not sticky:
                issues.append("sticky_sessions_disabled")

            # Check forwarding rules for plain HTTP without redirect
            forwarding_rules = lb.get("forwarding_rules", [])
            for rule in forwarding_rules:
                if (
                    rule.get("entry_protocol") == "http"
                    and not lb.get("redirect_http_to_https", False)
                ):
                    issues.append("http_entry_without_redirect")
                    break

            severity = "info"
            obs_type = "inventory"
            if "no_http_to_https_redirect" in issues:
                severity = "medium"
                obs_type = "misconfiguration"

            region = lb.get("region", {})
            region_slug = region.get("slug", "") if isinstance(region, dict) else str(region)

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"DO load balancer: {lb_name}" + (
                    f" — {', '.join(issues)}" if issues else ""
                ),
                detail={
                    "load_balancer": lb,
                    "issues": issues,
                    "forwarding_rules": forwarding_rules,
                    "droplet_ids": lb.get("droplet_ids", []),
                },
                resource_id=lb_id,
                resource_type="do_load_balancer",
                resource_name=lb_name,
                severity=severity,
                region=region_slug,
            ))

        return findings

    # -- Domains --

    def _normalize_domains(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        domains = raw.raw_data.get("response", [])

        for domain in domains:
            domain_name = domain.get("name", "unknown")
            ttl = domain.get("ttl", 0)

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"DO domain: {domain_name}",
                detail={
                    "domain": domain,
                    "ttl": ttl,
                    "zone_file": domain.get("zone_file", ""),
                },
                resource_id=domain_name,
                resource_type="do_domain",
                resource_name=domain_name,
                severity="info",
            ))

        return findings


# Register
registry.register(DigitalOceanNormalizer())
