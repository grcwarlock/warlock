"""Assertion propagation engine.

Propagates assertion bindings across frameworks in two passes:

Pass 1 — Crosswalk propagation
    For every (framework, control) that already has an assertion binding,
    find all crosswalk targets and copy those bindings to the targets
    (only if the target has no binding yet).

Pass 2 — Enhancement inheritance
    For NIST 800-53 (and any framework using the parent(N) pattern), if a
    base control has bindings, its enhancements inherit those bindings
    with an appended note so callers know the source.

Both passes are idempotent. Re-running propagate_all() is safe.
"""

from __future__ import annotations

import logging
import os
import re
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from warlock.assessors.engine import AssertionEngine

log = logging.getLogger(__name__)

# Matches CTRL-ID(N) — e.g. AC-2(1), SC-7(5), UCF-IAM-1(2)
_ENHANCEMENT_RE = re.compile(r"^(.+?)\(\d+\)$")


# ---------------------------------------------------------------------------
# Crosswalk edge parsing
# ---------------------------------------------------------------------------

CrosswalkEdge = tuple[str, str, str, str]  # (src_fw, src_ctrl, tgt_fw, tgt_ctrl)


def _parse_crosswalk_file(path: str) -> list[CrosswalkEdge]:
    """Parse a crosswalk YAML and return a flat list of edges.

    All three shipped crosswalk files share the same top-level structure::

        crosswalks:
          - source_framework: ...
            source_control: ...
            target_framework: ...
            target_control: ...
            confidence: ...

    The parser is lenient — any entry missing a required key is skipped with
    a warning rather than raising, so new crosswalk files with partial data
    do not crash the propagator.
    """
    if not os.path.isfile(path):
        log.warning("Crosswalk file not found, skipping: %s", path)
        return []

    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict):
        log.warning("Crosswalk file has unexpected top-level type %s: %s", type(data), path)
        return []

    raw_edges = data.get("crosswalks", [])
    if not isinstance(raw_edges, list):
        log.warning("'crosswalks' key is not a list in %s", path)
        return []

    edges: list[CrosswalkEdge] = []
    for entry in raw_edges:
        if not isinstance(entry, dict):
            continue
        try:
            src_fw = str(entry["source_framework"]).strip()
            src_ctrl = str(entry["source_control"]).strip()
            tgt_fw = str(entry["target_framework"]).strip()
            tgt_ctrl = str(entry["target_control"]).strip()
        except KeyError as exc:
            log.debug("Crosswalk entry missing key %s in %s — skipping", exc, path)
            continue
        if src_fw and src_ctrl and tgt_fw and tgt_ctrl:
            edges.append((src_fw, src_ctrl, tgt_fw, tgt_ctrl))

    log.debug("Parsed %d crosswalk edges from %s", len(edges), path)
    return edges


def _load_all_crosswalk_edges(crosswalk_dir: str) -> list[CrosswalkEdge]:
    """Load and merge edges from every .yaml file in *crosswalk_dir*.

    Files are matched by a simple glob rather than hard-coded names so
    new crosswalk files added to the directory are picked up automatically.
    """
    import glob as _glob

    pattern = os.path.join(crosswalk_dir, "crosswalk*.yaml")
    files = sorted(_glob.glob(pattern))
    if not files:
        log.warning("No crosswalk YAML files found in %s", crosswalk_dir)

    all_edges: list[CrosswalkEdge] = []
    for filepath in files:
        all_edges.extend(_parse_crosswalk_file(filepath))

    log.info("Loaded %d total crosswalk edges from %d file(s)", len(all_edges), len(files))
    return all_edges


# ---------------------------------------------------------------------------
# AssertionPropagator
# ---------------------------------------------------------------------------


class AssertionPropagator:
    """Propagates assertion bindings across frameworks via crosswalks and
    enhancement inheritance.

    Usage::

        from warlock.assessors.engine import engine
        from warlock.assessors.propagation import AssertionPropagator

        propagator = AssertionPropagator(engine, "warlock/frameworks")
        propagator.propagate_all()

    Both propagation passes are additive and idempotent.  The engine's
    ``bind_control`` method already deduplicates assertion names per control,
    so calling ``propagate_all()`` multiple times is safe.
    """

    def __init__(self, engine: "AssertionEngine", crosswalk_dir: str) -> None:
        self.engine = engine
        self.crosswalk_dir = crosswalk_dir
        self._edges: list[CrosswalkEdge] | None = None  # lazy-loaded

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_edges(self) -> list[CrosswalkEdge]:
        if self._edges is None:
            self._edges = _load_all_crosswalk_edges(self.crosswalk_dir)
        return self._edges

    # ------------------------------------------------------------------
    # Pass 1 — Crosswalk propagation
    # ------------------------------------------------------------------

    def propagate_via_crosswalks(self) -> int:
        """Propagate bindings along crosswalk edges.

        For every edge (src_fw, src_ctrl) → (tgt_fw, tgt_ctrl):
        - Look up assertions on the source control.
        - If the target control has no bindings yet, copy them over.

        Bindings are never overwritten — existing target bindings take
        precedence over propagated ones (more specific beats more general).

        Returns:
            Number of new (framework, control, assertion) triples added.
        """
        edges = self._get_edges()
        added = 0

        for src_fw, src_ctrl, tgt_fw, tgt_ctrl in edges:
            src_assertions = self.engine.get_assertion_for_control(src_fw, src_ctrl)
            if not src_assertions:
                continue  # source has no bindings — nothing to propagate

            tgt_assertions = self.engine.get_assertion_for_control(tgt_fw, tgt_ctrl)
            if tgt_assertions is not None:
                continue  # target already has bindings — do not overwrite

            # Target has no binding — propagate each source assertion
            for assertion_name in src_assertions:
                self.engine.bind_control(tgt_fw, tgt_ctrl, assertion_name)
                added += 1
                log.debug(
                    "Crosswalk propagated %s → %s/%s from %s/%s",
                    assertion_name, tgt_fw, tgt_ctrl, src_fw, src_ctrl,
                )

        log.info("Crosswalk propagation: added %d assertion binding(s)", added)
        return added

    # ------------------------------------------------------------------
    # Pass 2 — Enhancement inheritance
    # ------------------------------------------------------------------

    def propagate_enhancements(self) -> int:
        """Inherit parent control bindings for NIST-style enhancements.

        For every control ID of the form ``PARENT(N)`` (e.g. ``AC-2(1)``),
        if the parent control has bindings and the enhancement does not,
        copy the parent's assertions to the enhancement.

        This covers all frameworks that use the ``CTRL-ID(N)`` notation —
        primarily NIST 800-53 and CMMC L2.

        Returns:
            Number of new (framework, control, assertion) triples added.
        """
        added = 0

        # Snapshot the current control keys so we iterate over a stable
        # collection (bind_control may add new entries during iteration).
        snapshot = list(self.engine._control_assertions.keys())

        for fw, ctrl_id in snapshot:
            m = _ENHANCEMENT_RE.match(ctrl_id)
            if m is None:
                continue  # not an enhancement

            parent_id = m.group(1).rstrip()
            parent_assertions = self.engine.get_assertion_for_control(fw, parent_id)
            if not parent_assertions:
                continue  # parent has no bindings to inherit

            child_assertions = self.engine.get_assertion_for_control(fw, ctrl_id)
            if child_assertions is not None:
                continue  # enhancement already has its own bindings

            for assertion_name in parent_assertions:
                self.engine.bind_control(fw, ctrl_id, assertion_name)
                added += 1
                log.debug(
                    "Enhancement inherited %s → %s/%s from %s/%s",
                    assertion_name, fw, ctrl_id, fw, parent_id,
                )

        # Second sweep: catch enhancements that exist in crosswalk YAML but
        # whose parent was not in the engine snapshot above (e.g. they are
        # only referenced via crosswalk edges, not directly bound).
        for src_fw, src_ctrl, tgt_fw, tgt_ctrl in self._get_edges():
            for fw, ctrl_id in [(src_fw, src_ctrl), (tgt_fw, tgt_ctrl)]:
                m = _ENHANCEMENT_RE.match(ctrl_id)
                if m is None:
                    continue

                parent_id = m.group(1).rstrip()
                parent_assertions = self.engine.get_assertion_for_control(fw, parent_id)
                if not parent_assertions:
                    continue

                child_assertions = self.engine.get_assertion_for_control(fw, ctrl_id)
                if child_assertions is not None:
                    continue

                for assertion_name in parent_assertions:
                    self.engine.bind_control(fw, ctrl_id, assertion_name)
                    added += 1
                    log.debug(
                        "Enhancement (crosswalk sweep) inherited %s → %s/%s from %s/%s",
                        assertion_name, fw, ctrl_id, fw, parent_id,
                    )

        log.info("Enhancement propagation: added %d assertion binding(s)", added)
        return added

    # ------------------------------------------------------------------
    # Combined entry point
    # ------------------------------------------------------------------

    def propagate_all(self) -> dict[str, int]:
        """Run both propagation passes.

        Pass order matters: crosswalk propagation runs first so that
        targets populated via crosswalks can then also benefit from
        enhancement inheritance in pass 2.

        Returns:
            Dict with keys ``crosswalk`` and ``enhancement`` counting how
            many new bindings each pass added.
        """
        crosswalk_added = self.propagate_via_crosswalks()
        enhancement_added = self.propagate_enhancements()
        log.info(
            "propagate_all complete: crosswalk=%d enhancement=%d total=%d",
            crosswalk_added,
            enhancement_added,
            crosswalk_added + enhancement_added,
        )
        return {"crosswalk": crosswalk_added, "enhancement": enhancement_added}
