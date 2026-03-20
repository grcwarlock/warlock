"""Regulatory change management — framework version tracking and impact analysis.

Tracks the version history of compliance frameworks (NIST 800-53, ISO 27001,
SOC 2, etc.), detects when new versions are available, diffs control sets
between versions, and assesses which system profiles and assessment results
are affected by regulatory changes.

Storage
-------
Version metadata is stored in a ``framework_versions`` JSON file at
``<data_dir>/framework_versions.json``.  The default data directory is
``./warlock_data/``; override with the *data_dir* constructor argument or the
``WLK_DATA_DIR`` environment variable.

The file has the following top-level structure::

    {
        "versions": [
            {
                "id": "<uuid>",
                "framework": "nist_800_53",
                "version": "rev5",
                "release_date": "2020-09-23",
                "changes_url": "https://...",
                "controls": {"AC-1": {...}, ...},
                "recorded_at": "2024-01-15T12:00:00+00:00"
            },
            ...
        ]
    }

The ``controls`` map is optional and is populated lazily from the loaded
framework YAML when ``diff_versions`` is called.

Usage
-----
::

    from sqlalchemy.orm import Session
    from warlock.workflows.framework_versioning import FrameworkVersionManager

    mgr = FrameworkVersionManager()

    # Record a new version
    entry = mgr.track_version(
        framework="nist_800_53",
        version="rev5.1",
        release_date="2024-01-01",
        changes_url="https://csrc.nist.gov/...",
    )

    # Check which frameworks are behind
    updates = mgr.check_for_updates(session)

    # Diff two versions
    diff = mgr.diff_versions("nist_800_53", "rev5", "rev5.1")

    # Impact assessment
    impact = mgr.impact_assessment(session, "nist_800_53", diff["changes"])
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import pathlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

_DEFAULT_DATA_DIR = pathlib.Path(os.environ.get("WLK_DATA_DIR", "warlock_data"))
_VERSIONS_FILENAME = "framework_versions.json"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class FrameworkVersionEntry:
    """Metadata for a single recorded framework version."""

    id: str
    framework: str
    version: str
    release_date: str       # ISO date string, e.g. "2020-09-23"
    changes_url: str
    recorded_at: str        # ISO datetime string
    controls: dict[str, Any] = field(default_factory=dict)
    notes: str = ""


@dataclass
class ControlChange:
    """Describes a single control-level change between two framework versions."""

    change_type: str   # "added", "removed", "modified"
    control_id: str
    old_value: dict[str, Any] | None = None
    new_value: dict[str, Any] | None = None
    description: str = ""


@dataclass
class VersionDiff:
    """Result of diffing two framework versions."""

    framework: str
    old_version: str
    new_version: str
    changes: list[ControlChange] = field(default_factory=list)

    @property
    def added(self) -> list[ControlChange]:
        return [c for c in self.changes if c.change_type == "added"]

    @property
    def removed(self) -> list[ControlChange]:
        return [c for c in self.changes if c.change_type == "removed"]

    @property
    def modified(self) -> list[ControlChange]:
        return [c for c in self.changes if c.change_type == "modified"]

    def summary(self) -> dict[str, int]:
        return {
            "added": len(self.added),
            "removed": len(self.removed),
            "modified": len(self.modified),
            "total": len(self.changes),
        }


@dataclass
class ImpactReport:
    """Impact of a set of control changes on existing system data."""

    framework: str
    changes_applied: list[ControlChange]
    affected_control_ids: list[str]
    affected_system_profiles: list[dict[str, Any]]
    affected_control_results: list[dict[str, Any]]
    affected_posture_snapshots: list[dict[str, Any]]
    summary: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class _VersionStore:
    """Read/write framework version metadata from a JSON file."""

    def __init__(self, data_dir: pathlib.Path) -> None:
        self._path = data_dir / _VERSIONS_FILENAME

    def _ensure_dir(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> list[FrameworkVersionEntry]:
        if not self._path.exists():
            return []
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            return [FrameworkVersionEntry(**v) for v in raw.get("versions", [])]
        except Exception:
            log.exception("Failed to read framework versions from %s", self._path)
            return []

    def save(self, entries: list[FrameworkVersionEntry]) -> None:
        self._ensure_dir()
        payload = {"versions": [asdict(e) for e in entries]}
        content = json.dumps(payload, indent=2, ensure_ascii=False)
        with open(self._path, "w", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                fh.write(content)
                fh.flush()
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def append(self, entry: FrameworkVersionEntry) -> None:
        entries = self.load()
        # Replace if same framework+version already recorded
        entries = [
            e for e in entries
            if not (e.framework == entry.framework and e.version == entry.version)
        ]
        entries.append(entry)
        self.save(entries)


# ---------------------------------------------------------------------------
# Framework YAML loader (best-effort)
# ---------------------------------------------------------------------------

def _load_framework_controls(framework: str) -> dict[str, Any]:
    """Attempt to load control metadata from the framework YAML.

    Returns a dict mapping control_id -> control metadata dict, or an empty
    dict if the YAML cannot be found.
    """
    # Try standard locations relative to the package root
    candidates = [
        pathlib.Path("warlock/frameworks") / f"{framework}.yaml",
        pathlib.Path("frameworks") / f"{framework}.yaml",
    ]
    for candidate in candidates:
        if candidate.exists():
            try:
                import yaml  # type: ignore[import-untyped]

                raw = yaml.safe_load(candidate.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    controls = raw.get("controls", {})
                    if isinstance(controls, dict):
                        return controls
                    # List-of-dicts format
                    if isinstance(controls, list):
                        return {c.get("id", str(i)): c for i, c in enumerate(controls)}
            except Exception:
                log.debug("Could not load framework YAML from %s", candidate)
    return {}


# ---------------------------------------------------------------------------
# FrameworkVersionManager
# ---------------------------------------------------------------------------

class FrameworkVersionManager:
    """Track, diff, and assess the impact of regulatory framework changes.

    Args:
        data_dir: Directory for the ``framework_versions.json`` store.
            Defaults to ``./warlock_data/`` (or ``$WLK_DATA_DIR``).
    """

    def __init__(
        self,
        data_dir: pathlib.Path | str | None = None,
    ) -> None:
        if data_dir is None:
            data_dir = _DEFAULT_DATA_DIR
        self._store = _VersionStore(pathlib.Path(data_dir))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def track_version(
        self,
        framework: str,
        version: str,
        release_date: str,
        changes_url: str,
        controls: dict[str, Any] | None = None,
        notes: str = "",
    ) -> FrameworkVersionEntry:
        """Record a framework version.

        If a version with the same *framework* + *version* identifier already
        exists it is replaced, so this method is idempotent.

        Args:
            framework: Framework identifier (e.g. ``"nist_800_53"``).
            version: Version string (e.g. ``"rev5"`` or ``"2022"``).
            release_date: Publication date as an ISO date string
                (e.g. ``"2020-09-23"``).
            changes_url: URL pointing to the official change summary or
                revision notes.
            controls: Optional map of ``control_id -> metadata`` representing
                the control catalogue for this version.  If omitted, the
                framework YAML is loaded lazily when diffs are requested.
            notes: Free-text notes about this version.

        Returns:
            The recorded ``FrameworkVersionEntry``.
        """
        entry = FrameworkVersionEntry(
            id=str(uuid4()),
            framework=framework,
            version=version,
            release_date=release_date,
            changes_url=changes_url,
            controls=controls or {},
            notes=notes,
            recorded_at=_utcnow_iso(),
        )
        self._store.append(entry)
        log.info(
            "Recorded framework version: %s %s (released %s)",
            framework,
            version,
            release_date,
        )
        return entry

    def list_versions(self, framework: str | None = None) -> list[FrameworkVersionEntry]:
        """Return all recorded versions, optionally filtered by framework."""
        entries = self._store.load()
        if framework:
            entries = [e for e in entries if e.framework == framework]
        return sorted(entries, key=lambda e: (e.framework, e.release_date))

    def check_for_updates(self, session: Session) -> list[dict[str, Any]]:
        """Compare currently loaded framework versions against recorded versions.

        For each framework that has more than one recorded version, report
        whether the version loaded in the pipeline YAML matches the latest
        recorded version.

        Also queries ``ControlResult`` rows to discover which frameworks are
        active in the database and cross-references them against the version
        store.

        Args:
            session: SQLAlchemy session for querying active frameworks.

        Returns:
            List of dicts, one per framework that may need updating::

                [
                    {
                        "framework": "nist_800_53",
                        "latest_recorded_version": "rev5.1",
                        "latest_recorded_date": "2024-01-01",
                        "changes_url": "https://...",
                        "active_in_db": True,
                        "result_count": 1248,
                    },
                    ...
                ]
        """
        from warlock.db.models import ControlResult  # avoid circular at module level

        # Gather active frameworks from DB
        try:
            rows = (
                session.query(
                    ControlResult.framework,  # type: ignore[attr-defined]
                )
                .distinct()
                .all()
            )
            active_frameworks: set[str] = {r[0] for r in rows}
        except Exception:
            log.warning("Could not query active frameworks from DB")
            active_frameworks = set()

        # Count results per framework
        result_counts: dict[str, int] = {}
        for fw in active_frameworks:
            try:
                count = (
                    session.query(ControlResult)
                    .filter(ControlResult.framework == fw)
                    .count()
                )
                result_counts[fw] = count
            except Exception:
                result_counts[fw] = 0

        entries = self._store.load()
        by_framework: dict[str, list[FrameworkVersionEntry]] = {}
        for e in entries:
            by_framework.setdefault(e.framework, []).append(e)

        report: list[dict[str, Any]] = []
        all_frameworks = active_frameworks | set(by_framework.keys())

        for fw in sorted(all_frameworks):
            fw_versions = sorted(
                by_framework.get(fw, []), key=lambda e: e.release_date
            )
            latest = fw_versions[-1] if fw_versions else None
            report.append(
                {
                    "framework": fw,
                    "latest_recorded_version": latest.version if latest else None,
                    "latest_recorded_date": latest.release_date if latest else None,
                    "changes_url": latest.changes_url if latest else None,
                    "recorded_version_count": len(fw_versions),
                    "active_in_db": fw in active_frameworks,
                    "result_count": result_counts.get(fw, 0),
                }
            )
        return report

    def diff_versions(
        self,
        framework: str,
        old_version: str,
        new_version: str,
    ) -> VersionDiff:
        """Compare two recorded versions of a framework.

        If control metadata was not stored when the versions were tracked,
        this method falls back to loading the current framework YAML for
        the *new_version* side, and treats the absence of a control in either
        version as an addition or removal.

        Args:
            framework: Framework identifier.
            old_version: Earlier version string.
            new_version: Later version string.

        Returns:
            ``VersionDiff`` with added, removed, and modified controls.

        Raises:
            KeyError: If either version is not found in the store.
        """
        entries = {e.version: e for e in self._store.load() if e.framework == framework}

        if old_version not in entries:
            raise KeyError(
                f"Version {old_version!r} not found for framework {framework!r}. "
                f"Available: {sorted(entries)}"
            )
        if new_version not in entries:
            raise KeyError(
                f"Version {new_version!r} not found for framework {framework!r}. "
                f"Available: {sorted(entries)}"
            )

        old_entry = entries[old_version]
        new_entry = entries[new_version]

        # Resolve control maps — use stored data; fall back to YAML
        old_controls = old_entry.controls or _load_framework_controls(framework)
        new_controls = new_entry.controls or _load_framework_controls(framework)

        if not old_controls and not new_controls:
            raise ValueError(
                f"Cannot diff versions {old_version!r} and {new_version!r} for "
                f"framework {framework!r}: both versions have empty control sets. "
                "Provide control metadata when tracking versions or ensure the "
                "framework YAML is available."
            )

        changes: list[ControlChange] = []

        old_ids = set(old_controls)
        new_ids = set(new_controls)

        # Added controls
        for cid in sorted(new_ids - old_ids):
            changes.append(
                ControlChange(
                    change_type="added",
                    control_id=cid,
                    new_value=new_controls[cid],
                    description=f"Control {cid} added in {new_version}",
                )
            )

        # Removed controls
        for cid in sorted(old_ids - new_ids):
            changes.append(
                ControlChange(
                    change_type="removed",
                    control_id=cid,
                    old_value=old_controls[cid],
                    description=f"Control {cid} removed in {new_version}",
                )
            )

        # Modified controls — compare JSON-normalised representations
        for cid in sorted(old_ids & new_ids):
            old_norm = json.dumps(old_controls[cid], sort_keys=True)
            new_norm = json.dumps(new_controls[cid], sort_keys=True)
            if old_norm != new_norm:
                changes.append(
                    ControlChange(
                        change_type="modified",
                        control_id=cid,
                        old_value=old_controls[cid],
                        new_value=new_controls[cid],
                        description=f"Control {cid} modified between {old_version} and {new_version}",
                    )
                )

        diff = VersionDiff(
            framework=framework,
            old_version=old_version,
            new_version=new_version,
            changes=changes,
        )
        log.info(
            "Diff %s %s -> %s: +%d -%d ~%d",
            framework,
            old_version,
            new_version,
            len(diff.added),
            len(diff.removed),
            len(diff.modified),
        )
        return diff

    def impact_assessment(
        self,
        session: Session,
        framework: str,
        changes: list[ControlChange],
    ) -> ImpactReport:
        """For changed controls, show which system profiles and results are affected.

        Queries the database for:
        * ``SystemProfile`` rows that reference the framework.
        * ``ControlResult`` rows mapped to the changed control IDs.
        * ``PostureSnapshot`` rows for the changed control IDs.

        Args:
            session: SQLAlchemy session.
            framework: Framework identifier.
            changes: List of ``ControlChange`` objects (typically from
                ``diff_versions()``).

        Returns:
            ``ImpactReport`` describing affected entities.
        """
        from warlock.db.models import (  # avoid circular at module level
            ControlResult,
            PostureSnapshot,
            SystemProfile,
        )

        affected_ids = sorted({c.control_id for c in changes})

        if not affected_ids:
            return ImpactReport(
                framework=framework,
                changes_applied=changes,
                affected_control_ids=[],
                affected_system_profiles=[],
                affected_control_results=[],
                affected_posture_snapshots=[],
                summary={"control_ids": 0, "system_profiles": 0,
                         "control_results": 0, "posture_snapshots": 0},
            )

        # System profiles that are linked to this framework
        try:
            profiles = (
                session.query(SystemProfile)
                .filter(SystemProfile.framework == framework)
                .all()
            )
        except Exception:
            log.debug("SystemProfile query failed — trying without framework filter")
            try:
                profiles = session.query(SystemProfile).all()
            except Exception:
                profiles = []

        # ControlResult rows for changed controls
        try:
            results = (
                session.query(ControlResult)
                .filter(
                    ControlResult.framework == framework,
                    ControlResult.control_id.in_(affected_ids),
                )
                .all()
            )
        except Exception:
            log.warning("ControlResult query failed in impact_assessment")
            results = []

        # PostureSnapshot rows for changed controls
        try:
            snapshots = (
                session.query(PostureSnapshot)
                .filter(
                    PostureSnapshot.framework == framework,
                    PostureSnapshot.control_id.in_(affected_ids),
                )
                .all()
            )
        except Exception:
            log.warning("PostureSnapshot query failed in impact_assessment")
            snapshots = []

        def _profile_dict(p: Any) -> dict[str, Any]:
            return {
                "id": p.id,
                "name": getattr(p, "name", ""),
                "description": getattr(p, "description", ""),
                "overall_impact": getattr(p, "overall_impact", ""),
                "authorization_status": getattr(p, "authorization_status", ""),
            }

        def _result_dict(r: Any) -> dict[str, Any]:
            return {
                "id": r.id,
                "control_id": r.control_id,
                "status": r.status,
                "assessed_at": r.assessed_at.isoformat() if r.assessed_at else None,
                "assessor": r.assessor,
                "finding_id": r.finding_id,
            }

        def _snapshot_dict(s: Any) -> dict[str, Any]:
            return {
                "id": s.id,
                "control_id": s.control_id,
                "snapshot_date": (
                    s.snapshot_date.isoformat() if s.snapshot_date else None
                ),
                "status": s.status,
                "posture_score": s.posture_score,
            }

        profile_dicts = [_profile_dict(p) for p in profiles]
        result_dicts = [_result_dict(r) for r in results]
        snapshot_dicts = [_snapshot_dict(s) for s in snapshots]

        report = ImpactReport(
            framework=framework,
            changes_applied=changes,
            affected_control_ids=affected_ids,
            affected_system_profiles=profile_dicts,
            affected_control_results=result_dicts,
            affected_posture_snapshots=snapshot_dicts,
            summary={
                "control_ids": len(affected_ids),
                "system_profiles": len(profile_dicts),
                "control_results": len(result_dicts),
                "posture_snapshots": len(snapshot_dicts),
            },
        )

        log.info(
            "Impact assessment for %s (%d changes): %d control IDs, "
            "%d profiles, %d results, %d snapshots",
            framework,
            len(changes),
            len(affected_ids),
            len(profile_dicts),
            len(result_dicts),
            len(snapshot_dicts),
        )
        return report
