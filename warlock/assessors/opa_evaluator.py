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
                package_path,
                exc,
                self.fail_mode,
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
        """Evaluate all policies for a framework in a single OPA call.

        Instead of issuing one HTTP request per policy package (N calls),
        this method posts ``normalized_data`` once to the framework's
        namespace root, then walks all rule results returned in the single
        response.  This reduces ~592 HTTP calls to ~7 (one per framework).

        Falls back to per-policy ``evaluate_policy()`` calls if the batch
        endpoint returns no parseable results, so OPA server versions that
        don't support namespace-level queries continue to work.

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

        # Collect only the packages that belong to this framework
        fw_packages = {pkg: ctrl_id for pkg, (fw, ctrl_id) in policy_map.items() if fw == framework}
        if not fw_packages:
            return []

        client = self._get_client()
        if client is None:
            if self.fail_mode == "open":
                return []
            raise RuntimeError("OPA client unavailable (httpx not installed)")

        # Derive the framework namespace root from any package path.
        # Package paths look like "nist.ac.ac_2" so the root
        # is "nist/ac" (first two segments).
        sample_pkg = next(iter(fw_packages))
        segments = sample_pkg.replace(".", "/").split("/")
        framework_root = "/".join(segments[:2]) if len(segments) >= 2 else segments[0]

        batch_url = f"{self.base_url}/{framework_root}"
        payload = {"input": {"normalized_data": normalized_data}}

        # Build a reverse index: last segment of package path -> full package
        # path.  This is more robust than reconstructing from sample_pkg
        # because packages can have varying depths within a framework.
        last_segment_to_pkg: dict[str, str] = {}
        for pkg in fw_packages:
            last_seg = pkg.rsplit(".", 1)[-1]
            last_segment_to_pkg[last_seg] = pkg

        results: list[ControlResultData] = []
        batch_succeeded = False

        try:
            resp = client.post(batch_url, json=payload)
            resp.raise_for_status()
            batch_data = resp.json()

            # OPA returns {"result": {<rule_name>: <value>, ...}} for a
            # namespace query.  Each policy exports a "result" sub-key with
            # the standard shape: {control_id, compliant, findings, severity}.
            namespace_result = batch_data.get("result")
            if isinstance(namespace_result, dict):
                for rule_name, rule_value in namespace_result.items():
                    if not isinstance(rule_value, dict):
                        continue
                    # Each rule_value may itself have a "result" sub-key (the
                    # policy-level shape) or be the result directly.
                    result_data = rule_value.get("result", rule_value)
                    if not isinstance(result_data, dict):
                        continue

                    # Resolve the package path from the rule_name using the
                    # reverse index.  Fall back to the old heuristic if the
                    # rule_name doesn't match any known last segment.
                    pkg_path = last_segment_to_pkg.get(
                        rule_name,
                        f"{sample_pkg.rsplit('.', 1)[0]}.{rule_name}",
                    )
                    # Prefer the policy_map control_id; fall back to the
                    # value embedded in the result itself.
                    control_id = fw_packages.get(pkg_path, result_data.get("control_id", rule_name))

                    compliant = bool(result_data.get("compliant", False))
                    status = "compliant" if compliant else "non_compliant"
                    cr = ControlResultData(
                        finding_id="",
                        control_mapping_id="",
                        framework=framework,
                        control_id=control_id,
                        status=status,
                        severity=result_data.get("severity", "info"),
                        assertion_name=pkg_path,
                        assertion_passed=compliant,
                        assertion_findings=result_data.get("findings", []),
                        assessor=f"opa:{pkg_path}",
                        assessed_at=datetime.now(timezone.utc),
                    )
                    results.append(cr)

                if results:
                    batch_succeeded = True
                    log.debug(
                        "OPA batch evaluation for %s: %d results from %s",
                        framework,
                        len(results),
                        batch_url,
                    )

        except Exception as exc:
            log.warning(
                "OPA batch evaluation failed for framework %s: %s — falling back to per-policy calls",
                framework,
                exc,
            )

        if batch_succeeded:
            return results

        # --- Fallback: per-policy calls (original behaviour) ---
        log.debug(
            "OPA batch returned no results for %s; falling back to %d per-policy calls",
            framework,
            len(fw_packages),
        )
        for package_path, control_id in fw_packages.items():
            opa_result = self.evaluate_policy(package_path, normalized_data)
            if opa_result is None:
                continue

            status = "compliant" if opa_result.compliant else "non_compliant"
            cr = ControlResultData(
                finding_id="",
                control_mapping_id="",
                framework=framework,
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
        """Evaluate all registered policies using batch per-framework evaluation.

        Delegates to ``evaluate_framework()`` for each unique framework,
        reducing ~592 HTTP calls to ~7 (one per framework).

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

        # Collect unique frameworks from the policy map
        discovered_frameworks: set[str] = set()
        for _pkg, (fw, _ctrl_id) in policy_map.items():
            if frameworks and fw not in frameworks:
                continue
            discovered_frameworks.add(fw)

        all_results: list[ControlResultData] = []
        for fw in sorted(discovered_frameworks):
            results = self.evaluate_framework(fw, normalized_data, policy_map=policy_map)
            all_results.extend(results)

        return all_results
