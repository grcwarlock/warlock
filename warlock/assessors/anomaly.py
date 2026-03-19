"""Anomaly detection for compliance telemetry.

Tier 3 of the assessment engine. Detects behavioral anomalies that static
rules miss:
  - Drift: a control that was compliant is now degrading
  - Volume anomalies: unusual spike/drop in events from a source
  - Timing anomalies: events outside normal maintenance windows
  - Access anomalies: unusual privilege patterns

Uses Isolation Forest (scikit-learn if available) with a pure-Python
statistical fallback (Z-score + IQR) that works with zero dependencies.
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from warlock.db.models import ConnectorRun, ControlResult, Finding
from warlock.normalizers.base import FindingData

log = logging.getLogger(__name__)

# Try sklearn; fall back gracefully.
try:
    from sklearn.ensemble import IsolationForest as _IsolationForest

    _HAS_SKLEARN = True
except ImportError:  # pragma: no cover
    _HAS_SKLEARN = False


# ---------------------------------------------------------------------------
# Pure-Python statistical helpers
# ---------------------------------------------------------------------------

def _zscore(values: list[float]) -> list[float]:
    """Compute Z-scores using sample standard deviation."""
    if len(values) < 2:
        return [0.0] * len(values)
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
    std = variance ** 0.5
    if std < 1e-10:
        return [0.0] * len(values)
    return [(x - mean) / std for x in values]


def _iqr_outliers(values: list[float], factor: float = 1.5) -> list[bool]:
    """Return per-element boolean indicating IQR-based outlier status."""
    if len(values) < 4:
        return [False] * len(values)
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    q1 = sorted_vals[n // 4]
    q3 = sorted_vals[3 * n // 4]
    iqr = q3 - q1
    lower = q1 - factor * iqr
    upper = q3 + factor * iqr
    return [v < lower or v > upper for v in values]


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _stddev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    return (sum((x - m) ** 2 for x in values) / (len(values) - 1)) ** 0.5


def _covariance_matrix(data: list[list[float]]) -> list[list[float]]:
    """Compute sample covariance matrix for column-oriented data.

    *data* is a list of rows, each row a list of feature values.
    Returns an n_features x n_features matrix.
    """
    if not data or not data[0]:
        return []
    n_samples = len(data)
    n_features = len(data[0])
    means = [_mean([row[j] for row in data]) for j in range(n_features)]
    cov = [[0.0] * n_features for _ in range(n_features)]
    for i in range(n_features):
        for j in range(i, n_features):
            s = sum(
                (data[k][i] - means[i]) * (data[k][j] - means[j])
                for k in range(n_samples)
            )
            val = s / (n_samples - 1) if n_samples > 1 else 0.0
            cov[i][j] = val
            cov[j][i] = val
    return cov


def _invert_matrix(matrix: list[list[float]]) -> list[list[float]] | None:
    """Invert a square matrix via Gauss-Jordan elimination.

    Returns *None* if the matrix is singular (or near-singular).
    """
    n = len(matrix)
    # Build augmented matrix [M | I].
    aug = [row[:] + [1.0 if i == j else 0.0 for j in range(n)] for i, row in enumerate(matrix)]

    for col in range(n):
        # Partial pivot.
        max_row = max(range(col, n), key=lambda r: abs(aug[r][col]))
        aug[col], aug[max_row] = aug[max_row], aug[col]
        diag = aug[col][col]
        if abs(diag) < 1e-12:
            return None  # Singular
        for j in range(2 * n):
            aug[col][j] /= diag
        for row in range(n):
            if row == col:
                continue
            factor = aug[row][col]
            for j in range(2 * n):
                aug[row][j] -= factor * aug[col][j]

    return [row[n:] for row in aug]


def _mahalanobis_scores(data: list[list[float]]) -> list[float]:
    """Approximate Mahalanobis distance for each row in *data*.

    Falls back to Euclidean distance from the centroid when the
    covariance matrix is singular.
    """
    if not data or not data[0]:
        return []
    n_features = len(data[0])
    means = [_mean([row[j] for row in data]) for j in range(n_features)]
    cov = _covariance_matrix(data)
    inv_cov = _invert_matrix(cov) if cov else None

    scores: list[float] = []
    for row in data:
        diff = [row[j] - means[j] for j in range(n_features)]
        if inv_cov is not None:
            # d^2 = diff^T @ inv_cov @ diff
            tmp = [sum(diff[i] * inv_cov[i][j] for i in range(n_features)) for j in range(n_features)]
            d2 = sum(diff[j] * tmp[j] for j in range(n_features))
        else:
            # Fallback: simple Euclidean distance squared.
            d2 = sum(d ** 2 for d in diff)
        scores.append(math.sqrt(max(d2, 0.0)))
    return scores


# ---------------------------------------------------------------------------
# Severity derivation
# ---------------------------------------------------------------------------

_SEVERITY_BANDS: list[tuple[float, str]] = [
    (0.9, "critical"),
    (0.7, "high"),
    (0.5, "medium"),
]


def _severity_from_score(score: float) -> str:
    for threshold, label in _SEVERITY_BANDS:
        if score > threshold:
            return label
    return "low"


# ---------------------------------------------------------------------------
# AnomalyResult
# ---------------------------------------------------------------------------

@dataclass
class AnomalyResult:
    """A single detected anomaly."""

    anomaly_type: str          # drift, volume, timing, access, statistical
    score: float               # 0.0 (normal) to 1.0 (extremely anomalous)
    description: str
    evidence: dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def severity(self) -> str:
        return _severity_from_score(self.score)

    def to_dict(self) -> dict[str, Any]:
        return {
            "anomaly_type": self.anomaly_type,
            "score": self.score,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "timestamp": self.timestamp.isoformat(),
        }


# ---------------------------------------------------------------------------
# ComplianceDriftDetector
# ---------------------------------------------------------------------------

class ComplianceDriftDetector:
    """Tracks compliance status over time per control and detects drift.

    Drift is flagged when:
      - A control flips from compliant to non_compliant.
      - The non-compliance ratio in the sliding window exceeds a threshold.
    """

    def __init__(
        self,
        window_size: int = 20,
        degradation_threshold: float = 0.4,
    ) -> None:
        self.window_size = window_size
        self.degradation_threshold = degradation_threshold
        # key: (framework, control_id) -> list of (status, timestamp) tuples
        self._history: dict[tuple[str, str], list[tuple[str, datetime]]] = defaultdict(list)

    def feed(self, framework: str, control_id: str, status: str, timestamp: datetime) -> None:
        """Record a single control assessment result."""
        key = (framework, control_id)
        self._history[key].append((status, timestamp))
        # Keep the window bounded.
        if len(self._history[key]) > self.window_size:
            self._history[key] = self._history[key][-self.window_size:]

    def detect(self) -> list[AnomalyResult]:
        results: list[AnomalyResult] = []
        for (framework, control_id), history in self._history.items():
            if len(history) < 2:
                continue

            statuses = [s for s, _ in history]
            timestamps = [t for _, t in history]

            # --- Flip detection ---
            prev, curr = statuses[-2], statuses[-1]
            if prev == "compliant" and curr == "non_compliant":
                results.append(AnomalyResult(
                    anomaly_type="drift",
                    score=0.85,
                    description=(
                        f"Control {framework}/{control_id} flipped from "
                        f"compliant to non_compliant"
                    ),
                    evidence={
                        "framework": framework,
                        "control_id": control_id,
                        "previous_status": prev,
                        "current_status": curr,
                        "detection_method": "flip",
                    },
                    timestamp=timestamps[-1],
                ))

            # --- Gradual degradation ---
            non_compliant_count = sum(
                1 for s in statuses if s == "non_compliant"
            )
            ratio = non_compliant_count / len(statuses)
            if ratio >= self.degradation_threshold:
                score = min(ratio, 1.0)
                results.append(AnomalyResult(
                    anomaly_type="drift",
                    score=score,
                    description=(
                        f"Control {framework}/{control_id} shows degradation: "
                        f"{ratio:.0%} non-compliant over last {len(statuses)} assessments"
                    ),
                    evidence={
                        "framework": framework,
                        "control_id": control_id,
                        "non_compliance_ratio": round(ratio, 4),
                        "window_size": len(statuses),
                        "detection_method": "degradation",
                    },
                    timestamp=timestamps[-1],
                ))

        return results


# ---------------------------------------------------------------------------
# VolumeAnomalyDetector
# ---------------------------------------------------------------------------

class VolumeAnomalyDetector:
    """Detects unusual event volumes per source/connector.

    Uses rolling mean/stddev with a 3-sigma threshold and IQR as backup.
    """

    def __init__(
        self,
        window_size: int = 30,
        sigma_threshold: float = 3.0,
    ) -> None:
        self.window_size = window_size
        self.sigma_threshold = sigma_threshold
        # source -> list of (event_count, timestamp)
        self._history: dict[str, list[tuple[int, datetime]]] = defaultdict(list)

    def feed(self, source: str, event_count: int, timestamp: datetime) -> None:
        self._history[source].append((event_count, timestamp))
        if len(self._history[source]) > self.window_size:
            self._history[source] = self._history[source][-self.window_size:]

    def detect(self) -> list[AnomalyResult]:
        results: list[AnomalyResult] = []
        for source, history in self._history.items():
            if len(history) < 3:
                continue

            counts = [float(c) for c, _ in history]
            latest_count = counts[-1]
            latest_ts = history[-1][1]

            # Historical = everything except the latest.
            hist_counts = counts[:-1]
            mean = _mean(hist_counts)
            std = _stddev(hist_counts)

            flagged = False
            deviation = 0.0

            if std > 1e-10:
                z = abs(latest_count - mean) / std
                if z > self.sigma_threshold:
                    flagged = True
                    # Normalize z-score to 0-1 range (3σ→0.6, 5σ→0.8, 10σ→1.0).
                    deviation = min(z / 10.0 + 0.3, 1.0)
            else:
                # All historical values identical — use IQR on full series.
                outliers = _iqr_outliers(counts)
                if outliers[-1]:
                    flagged = True
                    deviation = 0.7

            if flagged:
                direction = "spike" if latest_count > mean else "drop"
                results.append(AnomalyResult(
                    anomaly_type="volume",
                    score=deviation,
                    description=(
                        f"Volume {direction} for source '{source}': "
                        f"{latest_count:.0f} events vs rolling mean {mean:.1f}"
                    ),
                    evidence={
                        "source": source,
                        "current_count": latest_count,
                        "rolling_mean": round(mean, 2),
                        "rolling_std": round(std, 2),
                        "direction": direction,
                        "sigma": round(abs(latest_count - mean) / std, 2) if std > 1e-10 else None,
                    },
                    timestamp=latest_ts,
                ))

        return results


# ---------------------------------------------------------------------------
# AccessPatternDetector
# ---------------------------------------------------------------------------

class AccessPatternDetector:
    """Detects unusual IAM/access patterns.

    Flags:
      - New actions never seen before for a user.
      - Actions at unusual hours (outside the user's historical pattern).
      - Sudden increase in distinct resources accessed.
    """

    def __init__(
        self,
        hour_zscore_threshold: float = 2.5,
        resource_spike_factor: float = 3.0,
    ) -> None:
        self.hour_zscore_threshold = hour_zscore_threshold
        self.resource_spike_factor = resource_spike_factor
        # user_id -> list of (action, resource, timestamp)
        self._history: dict[str, list[tuple[str, str, datetime]]] = defaultdict(list)

    def feed(self, user_id: str, action: str, resource: str, timestamp: datetime) -> None:
        self._history[user_id].append((action, resource, timestamp))

    def detect(self) -> list[AnomalyResult]:
        results: list[AnomalyResult] = []

        for user_id, events in self._history.items():
            if len(events) < 2:
                continue

            # Split into historical (all but last) and latest.
            historical = events[:-1]
            latest_action, latest_resource, latest_ts = events[-1]

            known_actions = {a for a, _, _ in historical}

            # --- New action detection ---
            if latest_action not in known_actions:
                results.append(AnomalyResult(
                    anomaly_type="access",
                    score=0.75,
                    description=(
                        f"User '{user_id}' performed new action '{latest_action}' "
                        f"never seen in history ({len(historical)} prior events)"
                    ),
                    evidence={
                        "user_id": user_id,
                        "action": latest_action,
                        "resource": latest_resource,
                        "known_actions": sorted(known_actions),
                        "detection_method": "new_action",
                    },
                    timestamp=latest_ts,
                ))

            # --- Timing anomaly ---
            hist_hours = [float(t.hour) for _, _, t in historical]
            if len(hist_hours) >= 5:
                latest_hour = float(latest_ts.hour)
                zscores = _zscore(hist_hours + [latest_hour])
                latest_z = abs(zscores[-1])
                if latest_z > self.hour_zscore_threshold:
                    score = min(latest_z / 5.0 + 0.3, 1.0)
                    results.append(AnomalyResult(
                        anomaly_type="timing",
                        score=score,
                        description=(
                            f"User '{user_id}' acted at unusual hour "
                            f"{latest_ts.hour:02d}:00 (z-score {latest_z:.1f})"
                        ),
                        evidence={
                            "user_id": user_id,
                            "action": latest_action,
                            "hour": latest_ts.hour,
                            "hour_zscore": round(latest_z, 2),
                            "mean_hour": round(_mean(hist_hours), 1),
                            "detection_method": "timing",
                        },
                        timestamp=latest_ts,
                    ))

            # --- Resource breadth spike ---
            # Compare unique resources in last N events vs historical average per window.
            window = 5
            if len(events) > window * 2:
                recent_resources = len({r for _, r, _ in events[-window:]})
                # Average unique resources per window historically.
                chunks = [events[i:i + window] for i in range(0, len(historical) - window + 1, window)]
                if chunks:
                    hist_breadths = [len({r for _, r, _ in chunk}) for chunk in chunks]
                    avg_breadth = _mean(hist_breadths)
                    if avg_breadth > 0 and recent_resources > avg_breadth * self.resource_spike_factor:
                        score = min(recent_resources / (avg_breadth * 5.0) + 0.3, 1.0)
                        results.append(AnomalyResult(
                            anomaly_type="access",
                            score=score,
                            description=(
                                f"User '{user_id}' accessed {recent_resources} distinct "
                                f"resources recently vs avg {avg_breadth:.1f}"
                            ),
                            evidence={
                                "user_id": user_id,
                                "recent_unique_resources": recent_resources,
                                "avg_unique_resources": round(avg_breadth, 2),
                                "detection_method": "resource_breadth",
                            },
                            timestamp=latest_ts,
                        ))

        return results


# ---------------------------------------------------------------------------
# StatisticalAnomalyDetector
# ---------------------------------------------------------------------------

class StatisticalAnomalyDetector:
    """General-purpose multivariate anomaly detection on finding features.

    Uses sklearn IsolationForest when available; otherwise falls back to
    pure-Python Z-score + Mahalanobis distance approximation.
    """

    def __init__(
        self,
        contamination: float = 0.1,
        zscore_threshold: float = 3.0,
        mahalanobis_threshold: float = 3.0,
    ) -> None:
        self.contamination = contamination
        self.zscore_threshold = zscore_threshold
        self.mahalanobis_threshold = mahalanobis_threshold

        self._feature_keys: list[str] = []
        self._fitted = False

        # sklearn path
        self._model: Any = None

        # Fallback path
        self._train_means: list[float] = []
        self._train_stds: list[float] = []
        self._train_data: list[list[float]] = []

    @staticmethod
    def extract_features(finding: FindingData) -> dict[str, float]:
        """Extract numeric features from a FindingData for anomaly scoring."""
        severity_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.0}
        now = datetime.now(timezone.utc)
        observed = finding.observed_at
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        delta = (now - observed).total_seconds()
        days_since = max(delta / 86400.0, 0.0)

        detail = finding.detail or {}
        resource_count = 0
        for v in detail.values():
            if isinstance(v, list):
                resource_count += len(v)
            elif isinstance(v, dict):
                resource_count += len(v)

        return {
            "severity_score": severity_map.get(finding.severity, 0.0),
            "confidence": finding.confidence,
            "days_since_observed": days_since,
            "resource_count": float(resource_count),
        }

    def _to_matrix(self, features: list[dict[str, float]]) -> list[list[float]]:
        """Convert list of feature dicts to a consistent matrix."""
        if not self._feature_keys:
            if features:
                self._feature_keys = sorted(features[0].keys())
            else:
                return []
        return [[f.get(k, 0.0) for k in self._feature_keys] for f in features]

    def fit(self, features: list[dict[str, float]]) -> None:
        """Train the anomaly detector on historical feature vectors."""
        if not features:
            log.warning("StatisticalAnomalyDetector.fit called with no data")
            return

        self._feature_keys = sorted(features[0].keys())
        matrix = self._to_matrix(features)

        if _HAS_SKLEARN:
            self._model = _IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100,
            )
            self._model.fit(matrix)
            log.info(
                "StatisticalAnomalyDetector fitted with IsolationForest on %d samples",
                len(matrix),
            )
        else:
            # Pure-Python fallback: precompute stats.
            n_features = len(self._feature_keys)
            self._train_means = [
                _mean([row[j] for row in matrix]) for j in range(n_features)
            ]
            self._train_stds = [
                _stddev([row[j] for row in matrix]) for j in range(n_features)
            ]
            self._train_data = matrix
            log.info(
                "StatisticalAnomalyDetector fitted with Z-score/Mahalanobis fallback on %d samples",
                len(matrix),
            )

        self._fitted = True

    def predict(self, features: list[dict[str, float]]) -> list[AnomalyResult]:
        """Score new feature vectors for anomalies."""
        if not self._fitted:
            log.warning("StatisticalAnomalyDetector.predict called before fit")
            return []
        if not features:
            return []

        matrix = self._to_matrix(features)
        results: list[AnomalyResult] = []

        if _HAS_SKLEARN and self._model is not None:
            predictions = self._model.predict(matrix)
            raw_scores = self._model.decision_function(matrix)
            # IsolationForest: decision_function < 0 means anomaly.
            # Convert to 0-1 where 1 is most anomalous.
            for i, (pred, raw) in enumerate(zip(predictions, raw_scores)):
                if pred == -1:  # Anomaly
                    # raw is negative for anomalies; more negative = more anomalous.
                    # Typical range is roughly -0.5 to 0.5; map to 0-1.
                    score = min(max(-raw, 0.0), 1.0)
                    results.append(AnomalyResult(
                        anomaly_type="statistical",
                        score=score,
                        description=(
                            f"Statistical anomaly detected (IsolationForest, "
                            f"raw_score={raw:.3f})"
                        ),
                        evidence={
                            "features": features[i],
                            "raw_score": round(float(raw), 4),
                            "detection_method": "isolation_forest",
                            "sample_index": i,
                        },
                    ))
        else:
            # Pure-Python: combined Z-score + Mahalanobis.
            results.extend(self._predict_fallback(features, matrix))

        return results

    def _predict_fallback(
        self,
        features: list[dict[str, float]],
        matrix: list[list[float]],
    ) -> list[AnomalyResult]:
        """Pure-Python anomaly detection using Z-score and Mahalanobis distance."""
        results: list[AnomalyResult] = []
        n_features = len(self._feature_keys)

        # Per-feature Z-score anomalies.
        for i, row in enumerate(matrix):
            max_z = 0.0
            anomalous_features: list[str] = []
            for j in range(n_features):
                std = self._train_stds[j] if j < len(self._train_stds) else 0.0
                mean = self._train_means[j] if j < len(self._train_means) else 0.0
                if std > 1e-10:
                    z = abs(row[j] - mean) / std
                    if z > self.zscore_threshold:
                        anomalous_features.append(self._feature_keys[j])
                    max_z = max(max_z, z)

            if anomalous_features:
                score = min(max_z / 6.0 + 0.3, 1.0)
                results.append(AnomalyResult(
                    anomaly_type="statistical",
                    score=score,
                    description=(
                        f"Z-score anomaly on features: {', '.join(anomalous_features)} "
                        f"(max z={max_z:.2f})"
                    ),
                    evidence={
                        "features": features[i],
                        "max_zscore": round(max_z, 4),
                        "anomalous_features": anomalous_features,
                        "detection_method": "zscore",
                        "sample_index": i,
                    },
                ))

        # Mahalanobis distance on the combined training + new data.
        if self._train_data and matrix:
            combined = self._train_data + matrix
            all_scores = _mahalanobis_scores(combined)
            new_scores = all_scores[len(self._train_data):]

            # Threshold: mean + k * std of the training distances.
            train_distances = all_scores[:len(self._train_data)]
            if train_distances:
                dist_mean = _mean(train_distances)
                dist_std = _stddev(train_distances)
                threshold = dist_mean + self.mahalanobis_threshold * dist_std

                for i, dist in enumerate(new_scores):
                    if dist > threshold and threshold > 0:
                        score = min(dist / (threshold * 2.0) + 0.3, 1.0)
                        # Avoid duplicating if already flagged by Z-score.
                        already = any(
                            r.evidence.get("sample_index") == i
                            and r.evidence.get("detection_method") == "zscore"
                            for r in results
                        )
                        if already:
                            # Upgrade the score if Mahalanobis gives higher.
                            for r in results:
                                if (
                                    r.evidence.get("sample_index") == i
                                    and r.evidence.get("detection_method") == "zscore"
                                ):
                                    r.score = max(r.score, score)
                                    r.evidence["mahalanobis_distance"] = round(dist, 4)
                                    break
                        else:
                            results.append(AnomalyResult(
                                anomaly_type="statistical",
                                score=score,
                                description=(
                                    f"Mahalanobis distance anomaly "
                                    f"(d={dist:.2f}, threshold={threshold:.2f})"
                                ),
                                evidence={
                                    "features": features[i],
                                    "mahalanobis_distance": round(dist, 4),
                                    "threshold": round(threshold, 4),
                                    "detection_method": "mahalanobis",
                                    "sample_index": i,
                                },
                            ))

        return results


# ---------------------------------------------------------------------------
# AnomalyEngine — orchestrator
# ---------------------------------------------------------------------------

class AnomalyEngine:
    """Tier 3 anomaly detection orchestrator.

    Holds all detectors and provides convenience methods to analyze
    pipeline run data, findings, and connector runs.
    """

    def __init__(self) -> None:
        self.drift_detector = ComplianceDriftDetector()
        self.volume_detector = VolumeAnomalyDetector()
        self.access_detector = AccessPatternDetector()
        self.statistical_detector = StatisticalAnomalyDetector()

    # --- High-level analysis entry points ---

    def analyze_pipeline_run(self, session: Session) -> list[AnomalyResult]:
        """Query the latest pipeline run data and feed through all detectors.

        Loads recent ControlResults, Findings, and ConnectorRuns from the
        database and runs all anomaly detectors.
        """
        results: list[AnomalyResult] = []

        # Feed control results into drift detector.
        control_results = (
            session.query(ControlResult)
            .order_by(ControlResult.assessed_at.asc())
            .all()
        )
        for cr in control_results:
            ts = cr.assessed_at or datetime.now(timezone.utc)
            self.drift_detector.feed(cr.framework, cr.control_id, cr.status, ts)
        results.extend(self.drift_detector.detect())

        # Feed connector runs into volume detector.
        connector_runs = (
            session.query(ConnectorRun)
            .order_by(ConnectorRun.started_at.asc())
            .all()
        )
        for run in connector_runs:
            ts = run.started_at or datetime.now(timezone.utc)
            count = int(run.event_count or 0)
            self.volume_detector.feed(run.source, count, ts)
        results.extend(self.volume_detector.detect())

        # Statistical analysis on recent findings.
        findings_orm = (
            session.query(Finding)
            .order_by(Finding.observed_at.desc())
            .limit(500)
            .all()
        )
        if findings_orm:
            finding_features = []
            for f in findings_orm:
                severity_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.0}
                detail = f.detail or {}
                resource_count = 0
                for v in detail.values():
                    if isinstance(v, list):
                        resource_count += len(v)
                    elif isinstance(v, dict):
                        resource_count += len(v)
                observed = f.observed_at or datetime.now(timezone.utc)
                if observed.tzinfo is None:
                    observed = observed.replace(tzinfo=timezone.utc)
                delta = (datetime.now(timezone.utc) - observed).total_seconds()
                finding_features.append({
                    "severity_score": severity_map.get(f.severity, 0.0),
                    "confidence": float(f.confidence or 1.0),
                    "days_since_observed": max(delta / 86400.0, 0.0),
                    "resource_count": float(resource_count),
                })

            if len(finding_features) >= 10:
                # Use the first 80% for training, predict on the last 20%.
                split = int(len(finding_features) * 0.8)
                train = finding_features[:split]
                test = finding_features[split:]
                self.statistical_detector.fit(train)
                results.extend(self.statistical_detector.predict(test))

        return results

    def analyze_findings(self, findings: list[FindingData]) -> list[AnomalyResult]:
        """Run statistical anomaly detection over a batch of FindingData objects."""
        if not findings:
            return []

        features = [
            StatisticalAnomalyDetector.extract_features(f) for f in findings
        ]

        if len(features) < 10:
            log.info(
                "Too few findings (%d) for statistical anomaly detection",
                len(features),
            )
            return []

        split = int(len(features) * 0.8)
        self.statistical_detector.fit(features[:split])
        return self.statistical_detector.predict(features[split:])

    def analyze_connector_runs(self, runs: list[ConnectorRun]) -> list[AnomalyResult]:
        """Run volume anomaly detection over a list of ConnectorRun ORM objects."""
        for run in runs:
            ts = run.started_at or datetime.now(timezone.utc)
            count = int(run.event_count or 0)
            source = run.source or run.connector_name
            self.volume_detector.feed(source, count, ts)
        return self.volume_detector.detect()

    def get_all_anomalies(self) -> list[AnomalyResult]:
        """Collect anomalies from all detectors (call after feeding data)."""
        results: list[AnomalyResult] = []
        results.extend(self.drift_detector.detect())
        results.extend(self.volume_detector.detect())
        results.extend(self.access_detector.detect())
        return results
