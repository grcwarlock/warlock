"""Ansible/AWX normalizer — transforms raw AWX API responses into Findings.

Normalizes hosts, inventories, and job templates — all as inventory findings,
since AWX data represents infrastructure asset state rather than active alerts.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class AnsibleNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "ansible_hosts": "_normalize_hosts",
        "ansible_inventories": "_normalize_inventories",
        "ansible_job_templates": "_normalize_job_templates",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "ansible" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "ansible",
            "source_type": SourceType.INFRASTRUCTURE,
            "provider": "ansible",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_hosts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for host in items:
            host_id = str(host.get("id", ""))
            name = host.get("name", "unknown")
            enabled = host.get("enabled", True)
            inventory = host.get("inventory", 0)
            description = host.get("description", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Ansible host: {name}",
                    detail={
                        "host_id": host_id,
                        "name": name,
                        "enabled": enabled,
                        "inventory_id": inventory,
                        "description": description,
                        "variables": host.get("variables", ""),
                        "has_active_failures": host.get("has_active_failures", False),
                        "last_job": host.get("last_job", None),
                    },
                    resource_id=host_id,
                    resource_type="ansible_host",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_inventories(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for inventory in items:
            inv_id = str(inventory.get("id", ""))
            name = inventory.get("name", "unknown")
            kind = inventory.get("kind", "")
            host_count = inventory.get("total_hosts", 0)
            failed_hosts = inventory.get("hosts_with_active_failures", 0)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Ansible inventory: {name}",
                    detail={
                        "inventory_id": inv_id,
                        "name": name,
                        "kind": kind,
                        "total_hosts": host_count,
                        "hosts_with_active_failures": failed_hosts,
                        "description": inventory.get("description", ""),
                        "variables": inventory.get("variables", ""),
                    },
                    resource_id=inv_id,
                    resource_type="ansible_inventory",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_job_templates(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for template in items:
            tmpl_id = str(template.get("id", ""))
            name = template.get("name", "unknown")
            playbook = template.get("playbook", "")
            become_enabled = template.get("become_enabled", False)
            ask_become_on_launch = template.get("ask_become_on_launch", False)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Ansible job template: {name}",
                    detail={
                        "template_id": tmpl_id,
                        "name": name,
                        "playbook": playbook,
                        "become_enabled": become_enabled,
                        "ask_become_on_launch": ask_become_on_launch,
                        "description": template.get("description", ""),
                        "last_job_run": template.get("last_job_run", ""),
                        "last_job_failed": template.get("last_job_failed", False),
                    },
                    resource_id=tmpl_id,
                    resource_type="ansible_job_template",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(AnsibleNormalizer())
