"""Policy registry -- maps Rego package paths to (framework, control_id).

Scans the ``policies/`` directory for non-test ``.rego`` files, parses
``package`` declarations, and builds bidirectional maps between OPA
package paths and framework control identifiers.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Regex to extract the package declaration from a Rego file
_PACKAGE_RE = re.compile(r"^package\s+([\w.]+)", re.MULTILINE)


# ---------------------------------------------------------------------------
# Framework mapping rules
# ---------------------------------------------------------------------------

# Maps the top-level package prefix to (framework_id, control_id_extractor)
# The extractor converts the package path into a human-readable control ID.

def _nist_control_id(parts: list[str]) -> str:
    """nist.ac.ac_2 -> AC-2, nist.ac.ac_2_1 -> AC-2(1)"""
    if len(parts) < 3:
        return ""
    # parts = ["nist", "ac", "ac_2"] or ["nist", "ac", "ac_2_1"]
    control_part = parts[2]  # e.g. "ac_2" or "ac_2_1"
    # Remove the family prefix if duplicated: ac_2 -> 2
    family = parts[1].upper()
    # Split on underscores: ["ac", "2"] or ["ac", "2", "1"]
    tokens = control_part.split("_")
    if len(tokens) >= 2 and tokens[0].upper() == family:
        base_num = tokens[1]
        if len(tokens) >= 3:
            # Enhancement: AC-2(1)
            enhancement = tokens[2]
            return f"{family}-{base_num}({enhancement})"
        return f"{family}-{base_num}"
    return control_part.upper().replace("_", "-")


def _soc2_control_id(parts: list[str]) -> str:
    """soc2.cc6 -> CC6.1, soc2.cc1 -> CC1.1"""
    if len(parts) < 2:
        return ""
    raw = parts[1].upper()  # e.g. "CC6", "A1", "P1"
    # SOC 2 control IDs like CC6.1 -- if no dot suffix in package, use .1
    if len(parts) >= 3:
        return f"{raw}.{parts[2]}"
    # Default to .1 for top-level packages
    return f"{raw}.1"


def _iso27001_control_id(parts: list[str]) -> str:
    """iso_27001.a5.a5_01 -> A.5.1"""
    if len(parts) < 3:
        return ""
    # parts = ["iso_27001", "a5", "a5_01"]
    control_part = parts[2]  # e.g. "a5_01"
    tokens = control_part.split("_")
    if len(tokens) >= 2:
        # a5_01 -> A.5.1
        section = tokens[0].upper().replace("A", "A.")
        if not section.startswith("A."):
            section = f"A.{section}"
        num = tokens[1].lstrip("0") or "0"
        return f"{section}.{num}"
    return control_part.upper()


def _cmmc_control_id(parts: list[str]) -> str:
    """cmmc.ac.ac_l2_3_1_1 -> AC.L2-3.1.1"""
    if len(parts) < 3:
        return ""
    control_part = parts[2]  # e.g. "ac_l2_3_1_1"
    tokens = control_part.split("_")
    if len(tokens) >= 5:
        family = tokens[0].upper()
        level = tokens[1].upper()
        nums = ".".join(tokens[2:])
        return f"{family}.{level}-{nums}"
    return control_part.upper().replace("_", "-")


def _hipaa_control_id(parts: list[str]) -> str:
    """hipaa.s164_308.s164_308_a_1 -> 164.308(a)(1)"""
    if len(parts) < 3:
        return ""
    control_part = parts[2]  # e.g. "s164_308_a_1"
    # Remove leading 's'
    raw = control_part.lstrip("s")
    # Split: ["164", "308", "a", "1"]
    tokens = raw.split("_")
    if len(tokens) >= 4:
        section = f"{tokens[0]}.{tokens[1]}"
        subsections = "".join(f"({t})" for t in tokens[2:])
        return f"{section}{subsections}"
    return control_part


def _ucf_control_id(parts: list[str]) -> str:
    """ucf.gov.ucf_gov_1 -> UCF-GOV-1"""
    if len(parts) < 3:
        return ""
    control_part = parts[2]  # e.g. "ucf_gov_1"
    return control_part.upper().replace("_", "-")


# Framework prefix -> (framework_id, extractor)
_FRAMEWORK_MAP: dict[str, tuple[str, Any]] = {
    "nist": ("nist_800_53", _nist_control_id),
    "soc2": ("soc2", _soc2_control_id),
    "iso_27001": ("iso_27001", _iso27001_control_id),
    "cmmc": ("cmmc", _cmmc_control_id),
    "hipaa": ("hipaa", _hipaa_control_id),
    "ucf": ("ucf", _ucf_control_id),
}


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class PolicyRegistry:
    """Scans Rego policies and maps package paths to framework controls.

    Auto-populates on first access. Results are cached.
    """

    def __init__(self, policies_dir: str | None = None) -> None:
        self._policies_dir = policies_dir
        self._policy_map: dict[str, tuple[str, str]] | None = None
        self._reverse_map: dict[tuple[str, str], str] | None = None

    @property
    def policies_dir(self) -> str:
        if self._policies_dir:
            return self._policies_dir
        # Default: look for policies/ relative to the project root
        return str(Path(__file__).resolve().parent.parent.parent / "policies")

    @property
    def policy_map(self) -> dict[str, tuple[str, str]]:
        """Map of {package_path: (framework, control_id)}."""
        if self._policy_map is None:
            self._scan()
        return self._policy_map  # type: ignore[return-value]

    @property
    def reverse_map(self) -> dict[tuple[str, str], str]:
        """Map of {(framework, control_id): package_path}."""
        if self._reverse_map is None:
            self._scan()
        return self._reverse_map  # type: ignore[return-value]

    def get_framework_policies(self, framework: str) -> dict[str, str]:
        """Return {package_path: control_id} for a specific framework."""
        return {
            pkg: ctrl
            for pkg, (fw, ctrl) in self.policy_map.items()
            if fw == framework
        }

    def list_frameworks(self) -> list[str]:
        """Return sorted list of discovered framework IDs."""
        return sorted({fw for fw, _ in self.policy_map.values()})

    def invalidate(self) -> None:
        """Force a re-scan on next access."""
        self._policy_map = None
        self._reverse_map = None

    # ------------------------------------------------------------------
    # Scanner
    # ------------------------------------------------------------------

    def _scan(self) -> None:
        """Walk the policies directory and parse package declarations."""
        policy_map: dict[str, tuple[str, str]] = {}
        reverse_map: dict[tuple[str, str], str] = {}

        policies_path = Path(self.policies_dir)
        if not policies_path.is_dir():
            log.warning("Policies directory does not exist: %s", self.policies_dir)
            self._policy_map = policy_map
            self._reverse_map = reverse_map
            return

        for rego_file in policies_path.rglob("*.rego"):
            # Skip test files
            if rego_file.stem.endswith("_test"):
                continue
            # Skip terraform policies (different input schema)
            if "terraform" in str(rego_file):
                continue

            try:
                content = rego_file.read_text(encoding="utf-8")
            except Exception:
                log.debug("Could not read %s", rego_file)
                continue

            match = _PACKAGE_RE.search(content)
            if not match:
                continue

            package_path = match.group(1)
            parts = package_path.split(".")

            # Find matching framework
            framework_id, control_id = self._resolve_framework(parts)
            if framework_id and control_id:
                policy_map[package_path] = (framework_id, control_id)
                # First policy wins for reverse map
                key = (framework_id, control_id)
                if key not in reverse_map:
                    reverse_map[key] = package_path

        self._policy_map = policy_map
        self._reverse_map = reverse_map
        log.info(
            "Policy registry: %d policies across %d frameworks",
            len(policy_map),
            len({fw for fw, _ in policy_map.values()}),
        )

    def _resolve_framework(self, parts: list[str]) -> tuple[str, str]:
        """Resolve package path parts to (framework_id, control_id)."""
        if not parts:
            return ("", "")

        # Try single-token prefix first (nist, soc2, cmmc, ucf)
        prefix = parts[0]
        if prefix in _FRAMEWORK_MAP:
            fw_id, extractor = _FRAMEWORK_MAP[prefix]
            control_id = extractor(parts)
            return (fw_id, control_id) if control_id else ("", "")

        # Try two-token prefix (iso_27001)
        if len(parts) >= 2:
            prefix2 = f"{parts[0]}_{parts[1]}"
            if prefix2 in _FRAMEWORK_MAP:
                fw_id, extractor = _FRAMEWORK_MAP[prefix2]
                control_id = extractor(parts)
                return (fw_id, control_id) if control_id else ("", "")

        return ("", "")


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_registry: PolicyRegistry | None = None


def get_policy_registry(policies_dir: str | None = None) -> PolicyRegistry:
    """Get the global PolicyRegistry singleton."""
    global _registry
    if _registry is None:
        _registry = PolicyRegistry(policies_dir=policies_dir)
    return _registry
