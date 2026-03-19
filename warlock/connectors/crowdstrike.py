"""CrowdStrike Falcon connector — Layer 1 implementation for EDR.

Collects device list, detections, spotlight vulnerabilities,
zero trust assessments, and sensor policies via the falconpy SDK.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)


class CrowdStrikeConnector(BaseConnector):
    """Collects compliance telemetry from CrowdStrike Falcon APIs."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import falconpy  # noqa: F401
        except ImportError:
            errors.append("falconpy not installed. Install with: pip install crowdstrike-falconpy")
        if not self._get_client_id():
            errors.append("CrowdStrike client_id not configured (set CROWDSTRIKE_CLIENT_ID or config.settings.client_id)")
        if not self._get_client_secret():
            errors.append("CrowdStrike client_secret not configured (set CROWDSTRIKE_CLIENT_SECRET or config.settings.client_secret)")
        return errors

    def health_check(self) -> bool:
        try:
            from falconpy import Hosts
            hosts = Hosts(
                client_id=self._get_client_id(),
                client_secret=self._get_client_secret(),
                base_url=self._get_base_url(),
            )
            resp = hosts.QueryDevicesByFilterScroll(limit=1)
            return resp["status_code"] == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="crowdstrike",
            source_type=SourceType.EDR,
            provider="crowdstrike",
        )

        client_id = self._get_client_id()
        client_secret = self._get_client_secret()
        base_url = self._get_base_url()

        # Collect devices
        self._collect_devices(result, client_id, client_secret, base_url)

        # Collect detections
        self._collect_detections(result, client_id, client_secret, base_url)

        # Collect spotlight vulnerabilities
        self._collect_vulnerabilities(result, client_id, client_secret, base_url)

        # Collect zero trust assessments
        self._collect_zero_trust(result, client_id, client_secret, base_url)

        # Collect sensor policies
        self._collect_sensor_policies(result, client_id, client_secret, base_url)

        result.complete()
        return result

    def _collect_devices(self, result: ConnectorResult, client_id: str, client_secret: str, base_url: str) -> None:
        try:
            from falconpy import Hosts
            hosts = Hosts(client_id=client_id, client_secret=client_secret, base_url=base_url)

            # Query device IDs
            query_resp = hosts.QueryDevicesByFilterScroll(limit=5000)
            if query_resp["status_code"] != 200:
                result.errors.append(f"falcon_devices: query failed: {query_resp['body']}")
                return

            device_ids = query_resp["body"].get("resources", [])
            result.events.append(RawEventData(
                source="crowdstrike",
                source_type=SourceType.EDR,
                provider="crowdstrike",
                event_type="falcon_devices",
                raw_data={"device_ids": device_ids, "total": len(device_ids)},
                observed_at=datetime.now(timezone.utc),
            ))

            # Get device details in batches
            batch_size = 100
            for i in range(0, len(device_ids), batch_size):
                batch = device_ids[i:i + batch_size]
                detail_resp = hosts.GetDeviceDetailsV2(ids=batch)
                if detail_resp["status_code"] == 200:
                    result.events.append(RawEventData(
                        source="crowdstrike",
                        source_type=SourceType.EDR,
                        provider="crowdstrike",
                        event_type="falcon_device_details",
                        raw_data={"devices": detail_resp["body"].get("resources", [])},
                        observed_at=datetime.now(timezone.utc),
                    ))
        except Exception as e:
            log.debug("CrowdStrike devices collection failed: %s", e)
            result.errors.append(f"falcon_devices: {e}")

    def _collect_detections(self, result: ConnectorResult, client_id: str, client_secret: str, base_url: str) -> None:
        try:
            from falconpy import Detects
            detects = Detects(client_id=client_id, client_secret=client_secret, base_url=base_url)

            query_resp = detects.QueryDetects(limit=1000)
            if query_resp["status_code"] != 200:
                result.errors.append(f"falcon_detections: query failed: {query_resp['body']}")
                return

            detection_ids = query_resp["body"].get("resources", [])
            if not detection_ids:
                result.events.append(RawEventData(
                    source="crowdstrike",
                    source_type=SourceType.EDR,
                    provider="crowdstrike",
                    event_type="falcon_detections",
                    raw_data={"detections": [], "total": 0},
                    observed_at=datetime.now(timezone.utc),
                ))
                return

            # Get detection summaries in batches
            batch_size = 100
            for i in range(0, len(detection_ids), batch_size):
                batch = detection_ids[i:i + batch_size]
                detail_resp = detects.GetDetectSummaries(body={"ids": batch})
                if detail_resp["status_code"] == 200:
                    result.events.append(RawEventData(
                        source="crowdstrike",
                        source_type=SourceType.EDR,
                        provider="crowdstrike",
                        event_type="falcon_detection_details",
                        raw_data={"detections": detail_resp["body"].get("resources", [])},
                        observed_at=datetime.now(timezone.utc),
                    ))
        except Exception as e:
            log.debug("CrowdStrike detections collection failed: %s", e)
            result.errors.append(f"falcon_detections: {e}")

    def _collect_vulnerabilities(self, result: ConnectorResult, client_id: str, client_secret: str, base_url: str) -> None:
        try:
            from falconpy import SpotlightVulnerabilities
            spotlight = SpotlightVulnerabilities(client_id=client_id, client_secret=client_secret, base_url=base_url)

            query_resp = spotlight.queryVulnerabilities(filter="status:!'closed'", limit=400)
            if query_resp["status_code"] != 200:
                result.errors.append(f"falcon_vulnerabilities: query failed: {query_resp['body']}")
                return

            vulns = query_resp["body"].get("resources", [])
            result.events.append(RawEventData(
                source="crowdstrike",
                source_type=SourceType.EDR,
                provider="crowdstrike",
                event_type="falcon_vulnerabilities",
                raw_data={"vulnerabilities": vulns, "total": len(vulns)},
                observed_at=datetime.now(timezone.utc),
            ))
        except Exception as e:
            log.debug("CrowdStrike vulnerabilities collection failed: %s", e)
            result.errors.append(f"falcon_vulnerabilities: {e}")

    def _collect_zero_trust(self, result: ConnectorResult, client_id: str, client_secret: str, base_url: str) -> None:
        try:
            from falconpy import ZeroTrustAssessment
            zta = ZeroTrustAssessment(client_id=client_id, client_secret=client_secret, base_url=base_url)

            resp = zta.getAssessmentV1()
            if resp["status_code"] == 200:
                result.events.append(RawEventData(
                    source="crowdstrike",
                    source_type=SourceType.EDR,
                    provider="crowdstrike",
                    event_type="falcon_zero_trust",
                    raw_data={"assessments": resp["body"].get("resources", [])},
                    observed_at=datetime.now(timezone.utc),
                ))
            else:
                result.errors.append(f"falcon_zero_trust: {resp['body']}")
        except Exception as e:
            log.debug("CrowdStrike zero trust collection failed: %s", e)
            result.errors.append(f"falcon_zero_trust: {e}")

    def _collect_sensor_policies(self, result: ConnectorResult, client_id: str, client_secret: str, base_url: str) -> None:
        try:
            from falconpy import SensorUpdatePolicy
            sensor = SensorUpdatePolicy(client_id=client_id, client_secret=client_secret, base_url=base_url)

            resp = sensor.querySensorUpdatePolicies(limit=500)
            if resp["status_code"] == 200:
                policy_ids = resp["body"].get("resources", [])
                result.events.append(RawEventData(
                    source="crowdstrike",
                    source_type=SourceType.EDR,
                    provider="crowdstrike",
                    event_type="falcon_sensor_policies",
                    raw_data={"policy_ids": policy_ids, "total": len(policy_ids)},
                    observed_at=datetime.now(timezone.utc),
                ))
            else:
                result.errors.append(f"falcon_sensor_policies: {resp['body']}")
        except Exception as e:
            log.debug("CrowdStrike sensor policies collection failed: %s", e)
            result.errors.append(f"falcon_sensor_policies: {e}")

    # -- Auth helpers --

    def _get_client_id(self) -> str:
        return self.config.settings.get("client_id", "") or self.get_secret("CROWDSTRIKE_CLIENT_ID")

    def _get_client_secret(self) -> str:
        return self.config.settings.get("client_secret", "") or self.get_secret("CROWDSTRIKE_CLIENT_SECRET")

    def _get_base_url(self) -> str:
        return self.config.settings.get("base_url", "https://api.crowdstrike.com")


# Register
registry.register("crowdstrike", CrowdStrikeConnector)
