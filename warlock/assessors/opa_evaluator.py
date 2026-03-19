"""OPA compliance evaluation client.

Bridges the 592 Rego policies into the Warlock assessment pipeline by
querying a running OPA server.  Each Rego policy exports a ``result``
object with ``control_id``, ``compliant``, ``findings[]``, and
``severity``.  This module sends the assembled ``normalized_data``
document to OPA and converts the response into ``ControlResultData``
rows that the pipeline persists alongside Tier-1/Tier-2 results.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from warlock.assessors.engine import ControlResultData

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# OPA policy result (raw response from OPA)
# ---------------------------------------------------------------------------

@dataclass
class OPAPolicyResult:
    """Parsed result from a single OPA policy evaluation."""
    package_path: str
    control_id: str = ""
    compliant: bool = False
    findings: list[str] = field(default_factory=list)
    severity: str = "info"
    raw: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# OPA Compliance Evaluator
# ---------------------------------------------------------------------------

class OPAComplianceEvaluator:
    """HTTP client for evaluating Rego compliance policies against OPA.

    Parameters
    ----------
    base_url:
        OPA server base URL (e.g. ``http://localhost:8181/v1/data``).
    timeout:
        HTTP request timeout in seconds.
    fail_mode:
        ``"open"`` (skip on failure) or ``"closed"`` (raise on failure).
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = 30.0,
        fail_mode: str = "open",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.fail_mode = fail_mode
        self._client = None

    def _get_client(self):
        """Lazy-create an httpx.Client."""
        if self._client is not None:
            return self._client
        try:
            import httpx
            self._client = httpx.Client(timeout=self.timeout)
        except ImportError:
            log.warning("httpx not installed -- OPA compliance evaluation unavailable")
            self._client = None
        return self._client

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def health_check(self) -> bool:
        """Return True if OPA is reachable."""
        client = self._get_client()
        if client is None:
            return False
        try:
            # OPA exposes /health on the default port
            health_url = self.base_url.split("/v1")[0] + "/health"
            resp = client.get(health_url)
            return resp.status_code == 200
        except Exception as exc:
            log.debug("OPA health check failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Single policy evaluation
    # ------------------------------------------------------------------

    def evaluate_policy(
        self,
        package_path: str,
        normalized_data: dict[str, Any],
    ) -> OPAPolicyResult | None:
        """Evaluate a single Rego policy package against OPA.

        Queries ``POST {base_url}/{package_path}/result`` with the
        normalized_data document as input.

        Returns None when OPA is unreachable and fail_mode is open.
        """
        client = self._get_client()
        if client is None:
            if self.fail_mode == "open":
                return None
            raise RuntimeError("OPA client unavailable (httpx not installed)")

        # Convert dotted package path to URL path segments
        url_path = package_path.replace(".", "/")
        url = f"{self.base_url}/{url_path}/result"
        payload = {"input": {"normalized_data": normalized_data}}

        try:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            log.warning(
                "OPA evaluation failed for %s: %s (fail_mode=%s)",
                package_path, exc, self.fail_mode,
            )
            if self.fail_mode == "open":
                return None
            raise

        result_data = data.get("result")
        if result_data is None:
            log.debug("OPA returned no result for %s", package_path)
            return None

        return OPAPolicyResult(
            package_path=package_path,
            control_id=result_data.get("control_id", ""),
            compliant=bool(result_data.get("compliant", False)),
            findings=result_data.get("findings", []),
            severity=result_data.get("severity", "info"),
            raw=result_data,
        )

    # ------------------------------------------------------------------
    # Framework-level evaluation
    # ------------------------------------------------------------------

    def evaluate_framework(
        self,
        framework: str,
        normalized_data: dict[str, Any],
        policy_map: dict[str, tuple[str, str]] | None = None,
    ) -> list[ControlResultData]:
        """Evaluate all policies for a framework.

        Parameters
        ----------
        framework:
            Framework identifier (e.g. ``"nist_800_53"``).
        normalized_data:
            The assembled normalized data document.
        policy_map:
            Map of ``{package_path: (framework, control_id)}``.
            Only policies whose framework matches are evaluated.

        Returns an empty list when OPA is unavailable and fail_mode
        is ``"open"``.
        """
        if policy_map is None:
            log.warning("No policy map provided for framework %s", framework)
            return []

        results: list[ControlResultData] = []

        for package_path, (fw, control_id) in policy_map.items():
            if fw != framework:
                continue

            opa_result = self.evaluate_policy(package_path, normalized_data)
            if opa_result is None:
                continue

            status = "compliant" if opa_result.compliant else "non_compliant"
            cr = ControlResultData(
                finding_id="",
                control_mapping_id="",
                framework=fw,
                control_id=control_id,
                status=status,
                severity=opa_result.severity,
                assertion_name=package_path,
                assertion_passed=opa_result.compliant,
                assertion_findings=opa_result.findings,
                assessor=f"opa:{package_path}",
                assessed_at=datetime.now(timezone.utc),
            )
            results.append(cr)

        return results

    # ------------------------------------------------------------------
    # Evaluate all frameworks at once
    # ------------------------------------------------------------------

    def evaluate_all(
        self,
        normalized_data: dict[str, Any],
        policy_map: dict[str, tuple[str, str]] | None = None,
        frameworks: list[str] | None = None,
    ) -> list[ControlResultData]:
        """Evaluate policies across all (or selected) frameworks.

        Parameters
        ----------
        normalized_data:
            The assembled normalized data document.
        policy_map:
            Full policy registry map.
        frameworks:
            Optional filter -- only evaluate these frameworks.
            ``None`` means evaluate all.
        """
        if policy_map is None:
            log.warning("No policy map provided -- skipping OPA evaluation")
            return []

        results: list[ControlResultData] = []

        for package_path, (fw, control_id) in policy_map.items():
            if frameworks and fw not in frameworks:
                continue

            opa_result = self.evaluate_policy(package_path, normalized_data)
            if opa_result is None:
                continue

            status = "compliant" if opa_result.compliant else "non_compliant"
            cr = ControlResultData(
                finding_id="",
                control_mapping_id="",
                framework=fw,
                control_id=control_id,
                status=status,
                severity=opa_result.severity,
                assertion_name=package_path,
                assertion_passed=opa_result.compliant,
                assertion_findings=opa_result.findings,
                assessor=f"opa:{package_path}",
                assessed_at=datetime.now(timezone.utc),
            )
            results.append(cr)

        return results
