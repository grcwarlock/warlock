"""Central registry of all domain services."""

from __future__ import annotations

from warlock.domains.base import DomainService, QueryFilters, RelatedItem, UrgentItem


class DomainRegistry:
    """Aggregates domain services for cross-domain queries."""

    def __init__(self) -> None:
        self._services: dict[str, DomainService] = {}

    def register(self, service: DomainService) -> None:
        self._services[service.domain_name] = service

    def get(self, domain_name: str) -> DomainService | None:
        return self._services.get(domain_name)

    def all_services(self) -> list[DomainService]:
        return list(self._services.values())

    def get_related_to(
        self, entity_type: str, entity_id: str
    ) -> dict[str, list[RelatedItem]]:
        result: dict[str, list[RelatedItem]] = {}
        for svc in self._services.values():
            related = svc.get_related_to(entity_type, entity_id)
            if related:
                result[svc.domain_name] = related
        return result

    def get_briefing(
        self, filters: QueryFilters | None = None
    ) -> list[UrgentItem]:
        filters = filters or QueryFilters()
        items: list[UrgentItem] = []
        for svc in self._services.values():
            items.extend(svc.get_urgent_items(filters))
        return sorted(items, key=lambda i: i.priority_score, reverse=True)
