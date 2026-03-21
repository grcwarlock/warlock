"""Tests for lake hardening — posture readers, ABAC, legal holds, etc."""

from datetime import datetime, timezone
from pathlib import Path
import pytest


@pytest.fixture
def lake_with_posture(tmp_path):
    """Seed lake with posture snapshot data."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    date = "2026-03-21"
    snapshots = {
        "id": ["ps-1", "ps-2", "ps-3"],
        "framework": ["nist_800_53", "nist_800_53", "soc2"],
        "control_id": ["AC-2", "AC-3", "CC6.1"],
        "system_profile_id": ["sys-1", "sys-1", "sys-1"],
        "snapshot_date": [date, date, date],
        "posture_score": ["85.0", "72.0", "91.0"],
        "status": ["compliant", "partial", "compliant"],
        "run_id": ["run-1", "run-1", "run-1"],
    }
    for fw in ["nist_800_53", "soc2"]:
        d = Path(tmp_path) / "curated" / "posture_snapshots" / fw / date
        d.mkdir(parents=True, exist_ok=True)
        fw_data = {k: [v for v, f in zip(snapshots[k], snapshots["framework"]) if f == fw]
                   for k in snapshots}
        pq.write_table(pa.table(fw_data), str(d / "run-1.parquet"))
    return str(tmp_path)


class TestPostureReaders:
    def test_latest_snapshot_date_returns_date(self, lake_with_posture):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(lake_with_posture)
        result = readers.latest_snapshot_date()
        assert result is not None
        readers.close()

    def test_latest_snapshot_date_empty_lake(self, tmp_path):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(str(tmp_path))
        result = readers.latest_snapshot_date()
        assert result is None
        readers.close()

    def test_framework_avg_scores(self, lake_with_posture):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(lake_with_posture)
        result = readers.framework_avg_scores_at()
        assert len(result) == 2  # nist_800_53 and soc2
        # Check it returns (framework, float) tuples
        for fw, score in result:
            assert isinstance(fw, str)
            assert isinstance(score, float)
        readers.close()

    def test_effectiveness_latest_all(self, lake_with_posture):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(lake_with_posture)
        result = readers.effectiveness_latest()
        assert len(result) == 3
        readers.close()

    def test_effectiveness_latest_filtered(self, lake_with_posture):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(lake_with_posture)
        result = readers.effectiveness_latest(framework="soc2")
        assert len(result) == 1
        assert result[0]["framework"] == "soc2"
        readers.close()
