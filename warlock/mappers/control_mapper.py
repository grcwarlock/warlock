"""Layer 2/3 bridge — Control Mapping.

Takes a Finding and determines which compliance controls it maps to,
across all active frameworks. Then crosswalks to related frameworks.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from warlock.normalizers.base import FindingData

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mapping output
# ---------------------------------------------------------------------------

@dataclass
class ControlMappingData:
    finding_id: str
    framework: str
    control_id: str
    control_family: str = ""
    mapping_method: str = "explicit"   # explicit, resource_rule, keyword, crosswalk
    confidence: float = 1.0
    crosswalk_path: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid4()))


@dataclass
class MappedFinding:
    finding: FindingData
    mappings: list[ControlMappingData]


# ---------------------------------------------------------------------------
# Mapping rules
# ---------------------------------------------------------------------------

@dataclass
class ExplicitRule:
    """Direct mapping: source event_type + check → control."""
    source: str
    event_type: str
    framework: str
    control_id: str
    control_family: str = ""


@dataclass
class ResourceRule:
    """Resource-type based: any finding about 'iam_user' → these controls."""
    resource_type: str
    framework: str
    control_ids: list[str] = field(default_factory=list)
    control_family: str = ""


@dataclass
class CrosswalkEdge:
    """Maps a control in one framework to a control in another."""
    source_framework: str
    source_control: str
    target_framework: str
    target_control: str
    confidence: float = 0.9
    notes: str = ""


# ---------------------------------------------------------------------------
# Control Mapper
# ---------------------------------------------------------------------------

class ControlMapper:
    """Maps findings to framework controls using layered rules."""

    def __init__(self) -> None:
        self._explicit_rules: list[ExplicitRule] = []
        self._resource_rules: list[ResourceRule] = []
        self._crosswalk_graph: dict[tuple[str, str], list[CrosswalkEdge]] = defaultdict(list)
        self._active_frameworks: set[str] = set()

    # -- Configuration --

    def add_explicit_rule(self, rule: ExplicitRule) -> None:
        self._explicit_rules.append(rule)
        self._active_frameworks.add(rule.framework)

    def add_resource_rule(self, rule: ResourceRule) -> None:
        self._resource_rules.append(rule)
        self._active_frameworks.add(rule.framework)

    def add_crosswalk(self, edge: CrosswalkEdge) -> None:
        key = (edge.source_framework, edge.source_control)
        self._crosswalk_graph[key].append(edge)
        self._active_frameworks.add(edge.source_framework)
        self._active_frameworks.add(edge.target_framework)

    def load_framework_yaml(self, framework_id: str, config: dict[str, Any]) -> None:
        """Load mapping rules from a framework YAML config.

        Expected structure:
          control_families:
            AC:
              controls:
                AC-2:
                  checks:
                    - id: check_id
                      event_types: [iam_credential_report]
                      resource_types: [iam_user]
        """
        families = config.get("control_families", {})
        for family_id, family in families.items():
            controls = family.get("controls", {})
            for control_id, control in controls.items():
                for check in control.get("checks", []):
                    # Explicit rules from event_types
                    for event_type in check.get("event_types", []):
                        self.add_explicit_rule(ExplicitRule(
                            source=check.get("source", "*"),
                            event_type=event_type,
                            framework=framework_id,
                            control_id=control_id,
                            control_family=family_id,
                        ))
                    # Resource rules
                    for resource_type in check.get("resource_types", []):
                        self.add_resource_rule(ResourceRule(
                            resource_type=resource_type,
                            framework=framework_id,
                            control_ids=[control_id],
                            control_family=family_id,
                        ))

    def load_crosswalk_yaml(self, crosswalks: list[dict[str, Any]]) -> None:
        """Load crosswalk edges from config.

        Expected: [{source_framework, source_control, target_framework, target_control, confidence}]
        """
        for cw in crosswalks:
            self.add_crosswalk(CrosswalkEdge(**cw))

    # -- Mapping --

    def map(self, finding: FindingData) -> MappedFinding:
        """Map a finding to all applicable controls across all frameworks."""
        mappings: list[ControlMappingData] = []
        seen: set[tuple[str, str]] = set()

        # Priority 1: Explicit rules (source + event_type → control)
        for rule in self._explicit_rules:
            if rule.source not in ("*", finding.source):
                continue
            if rule.event_type == finding.observation_type or rule.event_type == "*":
                key = (rule.framework, rule.control_id)
                if key not in seen:
                    seen.add(key)
                    mappings.append(ControlMappingData(
                        finding_id=finding.id,
                        framework=rule.framework,
                        control_id=rule.control_id,
                        control_family=rule.control_family,
                        mapping_method="explicit",
                        confidence=1.0,
                    ))

        # Priority 2: Resource-type rules
        if finding.resource_type:
            for rule in self._resource_rules:
                if rule.resource_type == finding.resource_type:
                    for ctrl_id in rule.control_ids:
                        key = (rule.framework, ctrl_id)
                        if key not in seen:
                            seen.add(key)
                            mappings.append(ControlMappingData(
                                finding_id=finding.id,
                                framework=rule.framework,
                                control_id=ctrl_id,
                                control_family=rule.control_family,
                                mapping_method="resource_rule",
                                confidence=0.85,
                            ))

        # Priority 3: Crosswalk — expand existing mappings to other frameworks
        crosswalked: list[ControlMappingData] = []
        for m in mappings:
            graph_key = (m.framework, m.control_id)
            for edge in self._crosswalk_graph.get(graph_key, []):
                target_key = (edge.target_framework, edge.target_control)
                if target_key not in seen:
                    seen.add(target_key)
                    crosswalked.append(ControlMappingData(
                        finding_id=finding.id,
                        framework=edge.target_framework,
                        control_id=edge.target_control,
                        mapping_method="crosswalk",
                        confidence=min(m.confidence, edge.confidence),
                        crosswalk_path=[
                            f"{m.framework}:{m.control_id}",
                            f"{edge.target_framework}:{edge.target_control}",
                        ],
                    ))

        mappings.extend(crosswalked)
        return MappedFinding(finding=finding, mappings=mappings)
