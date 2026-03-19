"""Framework version diffing.

Compares two framework YAML files to identify added, removed, and
modified controls. Supports regulatory change impact analysis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import yaml

log = logging.getLogger(__name__)


@dataclass
class ControlChange:
    """Describes what changed in a modified control."""

    control_id: str
    field_changes: dict[str, dict[str, Any]]  # {field: {old, new}}


@dataclass
class FrameworkDiffResult:
    """Result of diffing two framework versions."""

    old_version: str
    new_version: str
    old_framework_id: str
    new_framework_id: str

    added_controls: list[str] = field(default_factory=list)
    removed_controls: list[str] = field(default_factory=list)
    modified_controls: list[ControlChange] = field(default_factory=list)
    unchanged_controls: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.added_controls
            or self.removed_controls
            or self.modified_controls
        )

    @property
    def summary(self) -> str:
        return (
            f"added={len(self.added_controls)}, "
            f"removed={len(self.removed_controls)}, "
            f"modified={len(self.modified_controls)}, "
            f"unchanged={len(self.unchanged_controls)}"
        )


# Fields compared to detect modifications
_COMPARISON_FIELDS = frozenset({
    "checks", "event_types", "resource_types", "severity",
    "monitoring_frequency", "description", "title",
})


class FrameworkDiff:
    """Diffs two framework YAML files to find control changes."""

    def diff(self, old_path: str, new_path: str) -> FrameworkDiffResult:
        """Load two YAML framework files and compare their controls.

        Args:
            old_path: Path to the old framework YAML.
            new_path: Path to the new framework YAML.

        Returns:
            FrameworkDiffResult with categorized changes.
        """
        old_data = self._load_yaml(old_path)
        new_data = self._load_yaml(new_path)

        old_controls = self._extract_controls(old_data)
        new_controls = self._extract_controls(new_data)

        old_ids = set(old_controls.keys())
        new_ids = set(new_controls.keys())

        result = FrameworkDiffResult(
            old_version=old_data.get("version", "unknown"),
            new_version=new_data.get("version", "unknown"),
            old_framework_id=old_data.get("framework_id", "unknown"),
            new_framework_id=new_data.get("framework_id", "unknown"),
            added_controls=sorted(new_ids - old_ids),
            removed_controls=sorted(old_ids - new_ids),
        )

        # Check shared controls for modifications
        for cid in sorted(old_ids & new_ids):
            changes = self._compare_control(old_controls[cid], new_controls[cid])
            if changes:
                result.modified_controls.append(
                    ControlChange(control_id=cid, field_changes=changes)
                )
            else:
                result.unchanged_controls.append(cid)

        log.info(
            "Framework diff %s -> %s: %s",
            old_path,
            new_path,
            result.summary,
        )
        return result

    @staticmethod
    def _load_yaml(path: str) -> dict:
        """Load and return a YAML file as dict."""
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}

    @staticmethod
    def _extract_controls(data: dict) -> dict[str, dict]:
        """Extract a flat map of control_id -> control_data from framework YAML.

        Supports both flat `controls:` lists and nested `control_families:`
        structures.
        """
        controls: dict[str, dict] = {}

        # Flat controls list
        for ctrl in data.get("controls", []):
            cid = ctrl.get("control_id") or ctrl.get("id")
            if cid:
                controls[cid] = ctrl

        # Nested under control_families (dict of family_id -> family_data)
        families = data.get("control_families", {})
        if isinstance(families, dict):
            for family_id, family in families.items():
                if not isinstance(family, dict):
                    continue
                family_controls = family.get("controls", {})
                if isinstance(family_controls, dict):
                    for ctrl_id, ctrl_data in family_controls.items():
                        controls[ctrl_id] = ctrl_data if isinstance(ctrl_data, dict) else {}
                elif isinstance(family_controls, list):
                    for ctrl in family_controls:
                        cid = ctrl.get("control_id") or ctrl.get("id")
                        if cid:
                            controls[cid] = ctrl

        return controls

    @staticmethod
    def _compare_control(
        old: dict,
        new: dict,
    ) -> dict[str, dict[str, Any]]:
        """Compare two control dicts, return changed fields."""
        changes: dict[str, dict[str, Any]] = {}

        all_keys = _COMPARISON_FIELDS & (set(old.keys()) | set(new.keys()))

        for key in sorted(all_keys):
            old_val = old.get(key)
            new_val = new.get(key)
            if old_val != new_val:
                changes[key] = {"old": old_val, "new": new_val}

        return changes
