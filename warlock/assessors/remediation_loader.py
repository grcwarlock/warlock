"""Loads remediation knowledge base from YAML files and attaches guidance to control results."""

import yaml
from pathlib import Path
from functools import lru_cache


@lru_cache(maxsize=None)
def load_remediation_kb(remediation_dir: str = None) -> dict:
    """Load all remediation YAML files into a single lookup.
    Returns: {(framework, control_id): remediation_dict}
    """
    if remediation_dir is None:
        remediation_dir = str(Path(__file__).resolve().parent.parent / "frameworks" / "remediation")

    kb = {}
    rem_path = Path(remediation_dir)
    if not rem_path.is_dir():
        return kb

    for yaml_file in rem_path.glob("*.yaml"):
        framework_id = yaml_file.stem
        data = yaml.safe_load(yaml_file.read_text()) or {}
        for ctrl_id, guidance in data.get("controls", {}).items():
            kb[(framework_id, ctrl_id)] = guidance

    return kb


def get_remediation(framework: str, control_id: str) -> dict | None:
    """Get remediation guidance for a specific control."""
    kb = load_remediation_kb()
    return kb.get((framework, control_id))


def enrich_control_result(result, framework: str, control_id: str):
    """Attach remediation data from the KB to a ControlResult if it has none."""
    if result.remediation_summary:
        return  # Already has remediation from assertion

    guidance = get_remediation(framework, control_id)
    if guidance:
        result.remediation_summary = guidance.get("summary", "")
        result.remediation_steps = guidance.get("remediation_steps", [])
        result.console_path = guidance.get("console_path", "")
