"""Syft/Grype connector — Layer 1 implementation for CONTAINER_SECURITY.

Reads local JSON output files produced by syft (SBOM) and grype (vulnerability)
CLI tools. No remote API calls. Uses SYFT_GRYPE_OUTPUT_DIR setting to locate
scan result files.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)


class SyftGrypeConnector(BaseConnector):
    """Reads syft/grype JSON output files from a local directory."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        output_dir = self.config.settings.get("output_dir", "")
        if not output_dir:
            errors.append("output_dir must be set in connector settings (SYFT_GRYPE_OUTPUT_DIR)")
        return errors

    def health_check(self) -> bool:
        output_dir = self.config.settings.get("output_dir", "")
        if not output_dir:
            return False
        return Path(output_dir).is_dir()

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="syft_grype",
            source_type=SourceType.CONTAINER_SECURITY,
            provider="syft_grype",
        )

        output_dir = self.config.settings.get("output_dir", "")
        if not output_dir:
            result.errors.append("output_dir not configured")
            result.complete("error")
            return result

        scan_dir = Path(output_dir)
        if not scan_dir.is_dir():
            result.errors.append(f"output_dir does not exist: {output_dir}")
            result.complete("error")
            return result

        json_files = list(scan_dir.glob("*.json"))
        if not json_files:
            log.debug("No JSON files found in %s", output_dir)
            result.complete()
            return result

        for json_file in json_files:
            try:
                with json_file.open("r", encoding="utf-8") as fh:
                    data = json.load(fh)

                # Detect whether this is a grype report or syft SBOM
                event_type = self._detect_type(data, json_file.name)

                result.events.append(
                    RawEventData(
                        source="syft_grype",
                        source_type=SourceType.CONTAINER_SECURITY,
                        provider="syft_grype",
                        event_type=event_type,
                        raw_data={
                            "file": str(json_file),
                            "response": data,
                        },
                        observed_at=datetime.now(timezone.utc),
                    )
                )
            except Exception as e:
                log.debug("syft_grype failed reading %s: %s", json_file, e)
                result.errors.append(f"{json_file}: {e}")

        result.complete()
        return result

    def _detect_type(self, data: dict, filename: str) -> str:
        """Classify JSON file as grype vulnerability report or syft SBOM."""
        # Grype reports contain a 'matches' key at the top level
        if "matches" in data:
            return "syft_grype_vulnerabilities"
        # Syft SBOMs contain 'artifacts' or 'packages'
        if "artifacts" in data or "packages" in data:
            return "syft_grype_sbom"
        # Fall back to filename heuristic
        lower = filename.lower()
        if "grype" in lower or "vuln" in lower:
            return "syft_grype_vulnerabilities"
        return "syft_grype_sbom"


# Register
registry.register("syft_grype", SyftGrypeConnector)
