"""Webhook / push receiver — accepts raw payloads and feeds them into the pipeline.

This is NOT a connector (it does not poll). Instead, it is the entry point
for external webhook deliveries and manual file uploads.  An API endpoint
calls ``WebhookReceiver.ingest()`` with the raw JSON body; the receiver
wraps it in a RawEventData and returns it for the pipeline to process.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType

log = logging.getLogger(__name__)

# Map well-known provider names to source types for convenience.
_PROVIDER_SOURCE_TYPE: dict[str, SourceType] = {
    "aws": SourceType.CLOUD,
    "azure": SourceType.CLOUD,
    "gcp": SourceType.CLOUD,
    "crowdstrike": SourceType.EDR,
    "defender": SourceType.EDR,
    "sentinelone": SourceType.EDR,
    "okta": SourceType.IAM,
    "entra_id": SourceType.IAM,
    "cyberark": SourceType.IAM,
    "sailpoint": SourceType.IAM,
    "tenable": SourceType.SCANNER,
    "qualys": SourceType.SCANNER,
    "wiz": SourceType.SCANNER,
    "prisma": SourceType.CSPM,
    "sentinel": SourceType.SIEM,
    "splunk": SourceType.SIEM,
    "elastic": SourceType.SIEM,
}


class WebhookReceiver:
    """Accepts raw payloads from webhooks / manual uploads and wraps them
    as ``RawEventData`` objects ready for the pipeline.
    """

    def ingest(
        self,
        payload: dict,
        source: str,
        provider: str,
        event_type: str,
        *,
        source_type: SourceType | None = None,
        observed_at: datetime | None = None,
    ) -> RawEventData:
        """Create a single ``RawEventData`` from an incoming payload.

        Parameters
        ----------
        payload:
            The raw JSON body received from the external system.
        source:
            Logical source identifier (e.g. ``"webhook"``, ``"manual"``).
        provider:
            The originating tool / vendor (e.g. ``"crowdstrike"``).
        event_type:
            A label for the kind of data (e.g. ``"falcon_detections"``).
        source_type:
            Optional explicit ``SourceType``.  When omitted the receiver
            attempts to infer it from *provider*; defaults to ``CUSTOM``.
        observed_at:
            Optional timestamp override.  Defaults to *now* (UTC).
        """
        resolved_source_type = source_type or _PROVIDER_SOURCE_TYPE.get(
            provider, SourceType.CUSTOM,
        )
        ts = observed_at or datetime.now(timezone.utc)

        raw = RawEventData(
            source=source,
            source_type=resolved_source_type,
            provider=provider,
            event_type=event_type,
            raw_data=payload,
            observed_at=ts,
        )
        log.info(
            "Ingested webhook event id=%s provider=%s event_type=%s",
            raw.id[:8], provider, event_type,
        )
        return raw

    def ingest_batch(
        self,
        payloads: list[dict],
        source: str,
        provider: str,
        event_type: str,
        *,
        source_type: SourceType | None = None,
    ) -> list[RawEventData]:
        """Ingest multiple payloads in one call.

        Each payload becomes its own ``RawEventData``.  All share the same
        source / provider / event_type metadata.
        """
        results: list[RawEventData] = []
        for payload in payloads:
            results.append(
                self.ingest(
                    payload,
                    source=source,
                    provider=provider,
                    event_type=event_type,
                    source_type=source_type,
                )
            )
        log.info(
            "Ingested batch of %d events provider=%s event_type=%s",
            len(results), provider, event_type,
        )
        return results
