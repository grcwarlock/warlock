#!/usr/bin/env python3
"""Add monitoring_frequency to framework YAML controls.

Frequencies based on NIST 800-53A Table D-2 and FedRAMP ConMon guidance:
- High-volatility controls (AC-2, AU-6, SI-4, etc.): daily/weekly
- Medium-volatility controls (access, config mgmt): monthly
- Low-volatility controls (policy, physical, planning): quarterly/annual
"""

from pathlib import Path

import yaml


# NIST 800-53 control family frequency defaults based on FedRAMP ConMon
NIST_FAMILY_DEFAULTS = {
    # High volatility — daily/weekly monitoring
    "AC": "weekly",  # Access Control — account changes happen constantly
    "AU": "weekly",  # Audit & Accountability — log review
    "SI": "weekly",  # System & Info Integrity — vulnerability/malware
    "IA": "weekly",  # Identification & Authentication — credential status
    "SC": "monthly",  # System & Communications Protection
    "CM": "monthly",  # Configuration Management
    "RA": "monthly",  # Risk Assessment
    "CA": "monthly",  # Assessment, Authorization & Monitoring
    "IR": "monthly",  # Incident Response
    "SA": "monthly",  # System & Services Acquisition
    "SR": "monthly",  # Supply Chain Risk Management
    "MA": "quarterly",  # Maintenance
    "MP": "quarterly",  # Media Protection
    "CP": "quarterly",  # Contingency Planning
    "AT": "quarterly",  # Awareness & Training
    "PS": "quarterly",  # Personnel Security
    "PE": "annual",  # Physical & Environmental Protection
    "PL": "annual",  # Planning
    "PM": "annual",  # Program Management
    "PT": "annual",  # PII Processing & Transparency
}

# Override specific high-volatility controls to daily
NIST_CONTROL_OVERRIDES = {
    "AC-2": "daily",  # Account management — user provisioning/deprovisioning
    "AC-6": "weekly",  # Least privilege
    "AU-6": "daily",  # Audit review, analysis, and reporting
    "AU-6(1)": "daily",  # Automated process integration
    "SI-4": "daily",  # System monitoring
    "SI-2": "weekly",  # Flaw remediation
    "SI-3": "daily",  # Malicious code protection
    "IA-5": "weekly",  # Authenticator management (password/MFA)
    "RA-5": "weekly",  # Vulnerability monitoring and scanning
    "CA-7": "weekly",  # Continuous monitoring (meta — monitors itself)
    "CM-6": "weekly",  # Configuration settings
    "CM-3": "weekly",  # Configuration change control
}

# SOC 2 TSC defaults
SOC2_DEFAULTS = {
    "CC1": "quarterly",  # Control environment
    "CC2": "quarterly",  # Communication & information
    "CC3": "monthly",  # Risk assessment
    "CC4": "monthly",  # Monitoring activities
    "CC5": "monthly",  # Control activities
    "CC6": "weekly",  # Logical & physical access
    "CC7": "weekly",  # System operations
    "CC8": "monthly",  # Change management
    "CC9": "quarterly",  # Risk mitigation
    "A1": "monthly",  # Availability
    "C1": "monthly",  # Confidentiality
    "PI1": "monthly",  # Processing integrity
    "P1": "quarterly",  # Privacy
}

# ISO 27001 defaults — most are monthly, some exceptions
ISO27001_DEFAULTS = {
    "A.5": "quarterly",  # Information security policies
    "A.6": "monthly",  # Organization of information security
    "A.7": "monthly",  # Human resource security
    "A.8": "monthly",  # Asset management
    "A.9": "weekly",  # Access control
    "A.10": "monthly",  # Cryptography
    "A.11": "annual",  # Physical and environmental security
    "A.12": "weekly",  # Operations security
    "A.13": "monthly",  # Communications security
    "A.14": "monthly",  # System acquisition, development, maintenance
    "A.15": "quarterly",  # Supplier relationships
    "A.16": "weekly",  # Info security incident management
    "A.17": "quarterly",  # Business continuity
    "A.18": "quarterly",  # Compliance
}

# Default for frameworks without specific guidance
FALLBACK = "monthly"


def get_frequency(framework_id: str, family: str, control_id: str) -> str:
    """Determine monitoring frequency for a control."""
    if framework_id == "nist_800_53":
        if control_id in NIST_CONTROL_OVERRIDES:
            return NIST_CONTROL_OVERRIDES[control_id]
        # Check base control (e.g., AC-2(1) -> AC-2)
        base = control_id.split("(")[0]
        if base in NIST_CONTROL_OVERRIDES:
            return NIST_CONTROL_OVERRIDES[base]
        return NIST_FAMILY_DEFAULTS.get(family, FALLBACK)
    elif framework_id == "soc2":
        # Match by prefix (CC6.1 -> CC6)
        for prefix, freq in SOC2_DEFAULTS.items():
            if control_id.startswith(prefix):
                return freq
        return FALLBACK
    elif framework_id in ("iso_27001", "iso_27701", "iso_42001"):
        # Match by section prefix
        for prefix, freq in ISO27001_DEFAULTS.items():
            if control_id.startswith(prefix):
                return freq
        return FALLBACK
    else:
        return FALLBACK


def process_yaml(path: Path) -> int:
    """Add monitoring_frequency to controls in a framework YAML. Returns count of controls updated."""
    with open(path) as f:
        data = yaml.safe_load(f)

    framework_id = data.get("framework_id", path.stem)
    families = data.get("control_families", {})
    count = 0

    for family_id, family in families.items():
        controls = family.get("controls", {})
        for control_id, control in controls.items():
            if "monitoring_frequency" not in control:
                freq = get_frequency(framework_id, family_id, control_id)
                control["monitoring_frequency"] = freq
                count += 1

    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, width=120)

    return count


def main():
    frameworks_dir = Path(__file__).parent.parent / "warlock" / "frameworks"
    yamls = sorted(frameworks_dir.glob("*.yaml"))
    # Skip crosswalk files
    yamls = [y for y in yamls if "crosswalk" not in y.name]

    total = 0
    for path in yamls:
        count = process_yaml(path)
        print(f"  {path.name}: {count} controls updated")
        total += count

    print(f"\nTotal: {total} controls with monitoring_frequency")


if __name__ == "__main__":
    main()
