"""Pipeline data lineage tracking.

Records source-to-target relationships at each pipeline stage so any
control_result can be traced back to its finding, raw_event, and
connector_run. The lineage graph is stored in-memory per pipeline run
and can be persisted to the database or lake after completion.

Usage::

    from warlock.pipeline.lineage import LineageRecorder

    recorder = LineageRecorder()
    recorder.record("raw_event", raw_id, "finding", finding_id)
    recorder.record("finding", finding_id, "control_mapping", mapping_id)
    recorder.record("finding", finding_id, "control_result", result_id)

    # Trace back from a result to its source chain
    chain = recorder.trace_back("control_result", result_id)
    # -> [("control_result", result_id), ("finding", fid), ("raw_event", rid)]
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class LineageEdge:
    """A single edge in the lineage graph."""

    source_type: str  # e.g. "raw_event", "finding", "connector_run"
    source_id: str
    target_type: str  # e.g. "finding", "control_mapping", "control_result"
    target_id: str
    stage: str = ""  # pipeline stage name: "collect", "normalize", "map", "assess"


@dataclass
class LineageRecorder:
    """In-memory lineage graph for a single pipeline run.

    Edges are stored in two indices for efficient forward and backward
    traversal.  Memory is bounded by the number of pipeline artifacts
    in a single run (typically <100K edges).
    """

    run_id: str = ""
    _forward: dict[tuple[str, str], list[LineageEdge]] = field(default_factory=dict)
    _backward: dict[tuple[str, str], list[LineageEdge]] = field(default_factory=dict)
    _edge_count: int = 0

    def record(
        self,
        source_type: str,
        source_id: str,
        target_type: str,
        target_id: str,
        stage: str = "",
    ) -> None:
        """Record a lineage relationship between two artifacts."""
        edge = LineageEdge(
            source_type=source_type,
            source_id=source_id,
            target_type=target_type,
            target_id=target_id,
            stage=stage,
        )
        src_key = (source_type, source_id)
        tgt_key = (target_type, target_id)

        self._forward.setdefault(src_key, []).append(edge)
        self._backward.setdefault(tgt_key, []).append(edge)
        self._edge_count += 1

    def trace_back(self, artifact_type: str, artifact_id: str) -> list[tuple[str, str]]:
        """Trace an artifact back to its source chain.

        Returns a list of (type, id) tuples from the target back to the
        ultimate source (e.g. connector_run).
        """
        chain: list[tuple[str, str]] = [(artifact_type, artifact_id)]
        visited: set[tuple[str, str]] = {(artifact_type, artifact_id)}
        current = (artifact_type, artifact_id)

        while current in self._backward:
            edges = self._backward[current]
            if not edges:
                break
            # Follow the first parent (lineage is typically a tree, not a DAG)
            parent = (edges[0].source_type, edges[0].source_id)
            if parent in visited:
                break  # cycle guard
            visited.add(parent)
            chain.append(parent)
            current = parent

        return chain

    def trace_forward(self, artifact_type: str, artifact_id: str) -> list[tuple[str, str]]:
        """Trace an artifact forward to all its downstream artifacts."""
        results: list[tuple[str, str]] = []
        visited: set[tuple[str, str]] = set()
        queue: list[tuple[str, str]] = [(artifact_type, artifact_id)]

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            if current != (artifact_type, artifact_id):
                results.append(current)
            for edge in self._forward.get(current, []):
                child = (edge.target_type, edge.target_id)
                if child not in visited:
                    queue.append(child)

        return results

    def get_lineage_for_result(self, result_id: str) -> dict[str, Any]:
        """Get full lineage chain for a control result.

        Returns a dict with finding_id, raw_event_id, and connector_run_id
        if they exist in the lineage graph.
        """
        chain = self.trace_back("control_result", result_id)
        lineage: dict[str, Any] = {"control_result_id": result_id}
        for art_type, art_id in chain:
            if art_type == "finding":
                lineage["finding_id"] = art_id
            elif art_type == "raw_event":
                lineage["raw_event_id"] = art_id
            elif art_type == "connector_run":
                lineage["connector_run_id"] = art_id
        return lineage

    def to_dicts(self) -> list[dict[str, str]]:
        """Export all edges as a list of dicts (for persistence)."""
        edges: list[dict[str, str]] = []
        for edge_list in self._forward.values():
            for edge in edge_list:
                edges.append(
                    {
                        "run_id": self.run_id,
                        "source_type": edge.source_type,
                        "source_id": edge.source_id,
                        "target_type": edge.target_type,
                        "target_id": edge.target_id,
                        "stage": edge.stage,
                    }
                )
        return edges

    @property
    def edge_count(self) -> int:
        """Total number of lineage edges recorded."""
        return self._edge_count

    def summary(self) -> dict[str, int]:
        """Return a summary of edge counts by stage."""
        by_stage: dict[str, int] = {}
        for edge_list in self._forward.values():
            for edge in edge_list:
                stage = edge.stage or "unknown"
                by_stage[stage] = by_stage.get(stage, 0) + 1
        return by_stage
