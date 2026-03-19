#!/usr/bin/env python3
"""Generate N×N crosswalk matrix from UCF domain mappings.

Instead of maintaining pairwise mappings (O(N²)), this script derives
crosswalks between any two frameworks by mapping through UCF domain IDs.

Usage:
    python frameworks/unified-controls-framework/scripts/generate_crosswalks.py
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAPPINGS_FILE = ROOT / "mappings" / "framework-mappings.json"
OUTPUT_DIR = ROOT / "generated"


def main() -> None:
    with open(MAPPINGS_FILE) as f:
        data = json.load(f)

    ucf = data["ucf-mappings"]
    frameworks = [fw["key"] for fw in ucf["supported-frameworks"]]
    domains = ucf["domain-mappings"]

    # Build control → UCF domain index per framework
    # { framework_key: { control_id: [ucf_domain_id, ...] } }
    ctrl_to_domains: dict[str, dict[str, list[str]]] = {fw: {} for fw in frameworks}
    for domain in domains:
        ucf_id = domain["ucf-domain"]
        for fw_key, controls in domain["controls"].items():
            if fw_key not in ctrl_to_domains:
                continue
            for ctrl in controls:
                ctrl_to_domains[fw_key].setdefault(ctrl, []).append(ucf_id)

    # Generate pairwise crosswalks
    crosswalk_matrix: dict[str, dict] = {}

    for source_fw in frameworks:
        for target_fw in frameworks:
            if source_fw == target_fw:
                continue

            pair_key = f"{source_fw}_to_{target_fw}"
            mappings: list[dict] = []

            for domain in domains:
                ucf_id = domain["ucf-domain"]
                source_ctrls = domain["controls"].get(source_fw, [])
                target_ctrls = domain["controls"].get(target_fw, [])

                if not source_ctrls or not target_ctrls:
                    continue

                for s_ctrl in source_ctrls:
                    for t_ctrl in target_ctrls:
                        mappings.append({
                            "source_control": s_ctrl,
                            "target_control": t_ctrl,
                            "ucf_domain": ucf_id,
                            "domain_title": domain["title"],
                            "confidence": "high",
                        })

            if mappings:
                crosswalk_matrix[pair_key] = {
                    "source": source_fw,
                    "target": target_fw,
                    "mapping_count": len(mappings),
                    "mappings": mappings,
                }

    # Write full matrix
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUTPUT_DIR / "crosswalk-matrix.json"
    with open(out_path, "w") as f:
        json.dump({
            "generated": True,
            "framework_count": len(frameworks),
            "pair_count": len(crosswalk_matrix),
            "frameworks": frameworks,
            "crosswalks": crosswalk_matrix,
        }, f, indent=2)

    print(f"Generated {len(crosswalk_matrix)} crosswalk pairs for {len(frameworks)} frameworks")
    print(f"Written to: {out_path}")

    # Summary
    for pair_key, data in sorted(crosswalk_matrix.items()):
        print(f"  {pair_key}: {data['mapping_count']} mappings")


if __name__ == "__main__":
    main()
