"""Tests for the lake writer and zone writers."""

import json
from datetime import datetime, timezone

import pytest


class TestZoneWriters:
    def test_write_raw_zone(self, tmp_path):
        """Verify raw zone writes Parquet files readable by DuckDB."""
        from warlock.lake.zones import write_raw_zone
        from warlock.lake.query import LakeQueryEngine

        raw_events = [
            {
                "id": "evt-1",
                "source": "aws",
                "event_type": "iam_user_list",
                "raw_data": json.dumps({"users": [{"name": "alice"}]}, sort_keys=True),
                "sha256": "abc123",
                "ingested_at": datetime.now(timezone.utc).isoformat(),
                "connector_run_id": "run-1",
                "provider": "aws",
                "source_type": "cloud",
            }
        ]

        count = write_raw_zone(str(tmp_path), "run-1", raw_events)
        assert count == 1

        engine = LakeQueryEngine(str(tmp_path))
        result = engine.query(
            f"SELECT * FROM read_parquet('{tmp_path}/raw/**/*.parquet', union_by_name=true)"
        )
        assert len(result) == 1
        assert result[0]["id"] == "evt-1"
        engine.close()

    def test_write_raw_zone_empty(self, tmp_path):
        """Empty list returns 0 and writes nothing."""
        from warlock.lake.zones import write_raw_zone

        count = write_raw_zone(str(tmp_path), "run-1", [])
        assert count == 0

    def test_write_raw_zone_multiple_sources(self, tmp_path):
        """Multiple sources produce separate partitioned files."""
        from warlock.lake.zones import write_raw_zone

        events = [
            {
                "id": "evt-1",
                "source": "aws",
                "event_type": "iam",
                "raw_data": "{}",
                "sha256": "a",
                "ingested_at": datetime.now(timezone.utc).isoformat(),
                "connector_run_id": "run-1",
                "provider": "aws",
                "source_type": "cloud",
            },
            {
                "id": "evt-2",
                "source": "okta",
                "event_type": "users",
                "raw_data": "{}",
                "sha256": "b",
                "ingested_at": datetime.now(timezone.utc).isoformat(),
                "connector_run_id": "run-1",
                "provider": "okta",
                "source_type": "iam",
            },
        ]

        count = write_raw_zone(str(tmp_path), "run-1", events)
        assert count == 2

        # Verify both sources have separate directories
        raw_dir = tmp_path / "raw"
        sources = sorted(d.name for d in raw_dir.iterdir() if d.is_dir())
        assert "aws" in sources
        assert "okta" in sources

    def test_write_enrichment_zone(self, tmp_path):
        """Verify enrichment zone writes Parquet files readable by DuckDB."""
        from warlock.lake.zones import write_enrichment_zone
        from warlock.lake.query import LakeQueryEngine

        findings = [
            {
                "id": "find-1",
                "severity": "high",
                "source": "aws",
                "observation_type": "iam_user",
                "title": "IAM user without MFA",
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "provider": "aws",
                "source_type": "cloud",
                "raw_event_id": "evt-1",
                "detail": json.dumps({"reason": "no_mfa"}, sort_keys=True),
                "resource_id": "arn:aws:iam::123:user/alice",
                "resource_type": "iam_user",
                "confidence": 1.0,
                "ingested_at": datetime.now(timezone.utc).isoformat(),
                "sha256": "def456",
            }
        ]

        count = write_enrichment_zone(str(tmp_path), "run-1", findings)
        assert count == 1

        engine = LakeQueryEngine(str(tmp_path))
        result = engine.query(
            f"SELECT * FROM read_parquet('{tmp_path}/enrichment/**/*.parquet', union_by_name=true)"
        )
        assert len(result) == 1
        assert result[0]["severity"] == "high"
        engine.close()

    def test_write_enrichment_zone_empty(self, tmp_path):
        from warlock.lake.zones import write_enrichment_zone

        count = write_enrichment_zone(str(tmp_path), "run-1", [])
        assert count == 0

    def test_write_curated_zone(self, tmp_path):
        """Verify curated zone writes control results as Parquet."""
        from warlock.lake.zones import write_curated_zone
        from warlock.lake.query import LakeQueryEngine

        control_results = [
            {
                "id": "cr-1",
                "framework": "nist_800_53",
                "control_id": "AC-2",
                "status": "compliant",
                "severity": "high",
                "assessed_at": datetime.now(timezone.utc).isoformat(),
                "finding_id": "find-1",
                "control_mapping_id": "cm-1",
                "assertion_name": "assert_mfa_enabled",
                "assertion_passed": True,
            }
        ]

        count = write_curated_zone(str(tmp_path), "run-1", control_results, [], [])
        assert count == 1

        engine = LakeQueryEngine(str(tmp_path))
        result = engine.query(
            f"SELECT * FROM read_parquet('{tmp_path}/curated/control_results/**/*.parquet', union_by_name=true)"
        )
        assert len(result) == 1
        assert result[0]["control_id"] == "AC-2"
        engine.close()

    def test_write_curated_zone_with_mappings(self, tmp_path):
        """Curated zone can write control mappings alongside results."""
        from warlock.lake.zones import write_curated_zone

        mappings = [
            {
                "id": "cm-1",
                "finding_id": "find-1",
                "framework": "nist_800_53",
                "control_id": "AC-2",
                "control_family": "AC",
                "mapping_method": "explicit",
                "confidence": 1.0,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        ]

        count = write_curated_zone(str(tmp_path), "run-1", [], mappings, [])
        assert count == 1

    def test_write_curated_zone_with_connector_runs(self, tmp_path):
        """Curated zone can write connector run metadata."""
        from warlock.lake.zones import write_curated_zone

        connector_runs = [
            {
                "id": "crun-1",
                "connector_name": "aws_iam",
                "source": "aws",
                "source_type": "cloud",
                "provider": "aws",
                "status": "success",
                "event_count": 5,
                "error_count": 0,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": 1.23,
            }
        ]

        count = write_curated_zone(str(tmp_path), "run-1", [], [], connector_runs)
        assert count == 1

    def test_write_curated_zone_all_empty(self, tmp_path):
        from warlock.lake.zones import write_curated_zone

        count = write_curated_zone(str(tmp_path), "run-1", [], [], [])
        assert count == 0


class TestLakeWriter:
    def test_handle_event_accumulates(self):
        """Events are accumulated by type as payload IDs."""
        from warlock.lake.writer import LakeWriter
        from warlock.pipeline.bus import PipelineEvent

        writer = LakeWriter("/tmp/test-lake")
        writer.handle_event(
            PipelineEvent(
                event_type="raw_event.created",
                payload_id="evt-1",
                metadata={"source": "aws"},
            )
        )
        writer.handle_event(
            PipelineEvent(
                event_type="finding.normalized",
                payload_id="find-1",
                metadata={"severity": "high"},
            )
        )
        writer.handle_event(
            PipelineEvent(
                event_type="finding.mapped",
                payload_id="find-1",
                metadata={"mapping_count": 3},
            )
        )
        writer.handle_event(
            PipelineEvent(
                event_type="control.assessed",
                payload_id="cr-1",
                metadata={"framework": "nist_800_53"},
            )
        )

        assert len(writer._raw_event_ids) == 1
        assert len(writer._finding_ids) == 1
        assert len(writer._control_mapping_ids) == 1
        assert len(writer._control_result_ids) == 1

    def test_handle_event_ignores_unknown_types(self):
        """Unknown event types are silently ignored."""
        from warlock.lake.writer import LakeWriter
        from warlock.pipeline.bus import PipelineEvent

        writer = LakeWriter("/tmp/test-lake")
        writer.handle_event(
            PipelineEvent(
                event_type="something.unknown",
                payload_id="x-1",
                metadata={},
            )
        )
        assert writer.pending_count == 0

    def test_flush_clears_buffers(self, tmp_path):
        """Flush without session clears buffers and returns stats."""
        from warlock.lake.writer import LakeWriter
        from warlock.pipeline.bus import PipelineEvent

        writer = LakeWriter(str(tmp_path))
        writer.handle_event(
            PipelineEvent(
                event_type="raw_event.created",
                payload_id="evt-1",
                metadata={"source": "aws"},
            )
        )
        writer.handle_event(
            PipelineEvent(
                event_type="finding.normalized",
                payload_id="find-1",
                metadata={"severity": "high"},
            )
        )

        assert writer.pending_count == 2

        # flush without session — no OLTP reads, just buffer clearing
        stats = writer.flush("run-1")
        assert len(writer._raw_event_ids) == 0
        assert len(writer._finding_ids) == 0
        assert writer.pending_count == 0
        assert stats.run_id == "run-1"
        assert stats.raw_events_written == 0
        assert stats.findings_written == 0
        assert stats.duration_seconds >= 0

    def test_flush_multiple_times(self, tmp_path):
        """Multiple flushes produce independent stats."""
        from warlock.lake.writer import LakeWriter
        from warlock.pipeline.bus import PipelineEvent

        writer = LakeWriter(str(tmp_path))

        # First batch
        writer.handle_event(
            PipelineEvent(event_type="raw_event.created", payload_id="evt-1", metadata={})
        )
        stats1 = writer.flush("run-1")
        assert stats1.run_id == "run-1"
        assert writer.pending_count == 0

        # Second batch
        writer.handle_event(
            PipelineEvent(event_type="raw_event.created", payload_id="evt-2", metadata={})
        )
        stats2 = writer.flush("run-2")
        assert stats2.run_id == "run-2"
        assert writer.pending_count == 0

    def test_lake_write_stats_defaults(self):
        """LakeWriteStats has sensible defaults."""
        from warlock.lake.writer import LakeWriteStats

        stats = LakeWriteStats(run_id="test-run")
        assert stats.run_id == "test-run"
        assert stats.raw_events_written == 0
        assert stats.findings_written == 0
        assert stats.control_mappings_written == 0
        assert stats.control_results_written == 0
        assert stats.connector_runs_written == 0
        assert stats.duration_seconds == 0.0
        assert stats.errors == []

    def test_event_bus_integration(self):
        """LakeWriter integrates with EventBus.subscribe_all()."""
        from warlock.lake.writer import LakeWriter
        from warlock.pipeline.bus import EventBus, PipelineEvent

        bus = EventBus()
        writer = LakeWriter("/tmp/test-lake")
        bus.subscribe_all(writer.handle_event)

        bus.publish(
            PipelineEvent(
                event_type="raw_event.created",
                payload_id="evt-1",
                metadata={"source": "aws"},
            )
        )
        bus.publish(
            PipelineEvent(
                event_type="control.assessed",
                payload_id="cr-1",
                metadata={"framework": "soc2"},
            )
        )

        assert len(writer._raw_event_ids) == 1
        assert len(writer._control_result_ids) == 1
