<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
"""Isolation Forest wrapper with a dependency-free fallback implementation."""
=======
"""Isolation Forest wrapper with drift-aware fallback support."""
>>>>>>> theirs
=======
"""Isolation Forest wrapper with drift-aware fallback support."""
>>>>>>> theirs
=======
"""Isolation Forest wrapper with drift-aware fallback support."""
>>>>>>> theirs
=======
"""Isolation Forest wrapper with drift-aware fallback support."""
>>>>>>> theirs
=======
"""Isolation Forest wrapper with drift-aware fallback support."""
>>>>>>> theirs
=======
"""Isolation Forest wrapper with drift-aware fallback support."""
>>>>>>> theirs

from __future__ import annotations

import json
import logging
import math
import pickle
import random
from pathlib import Path
from statistics import mean
from typing import List, Sequence

LOGGER = logging.getLogger(__name__)

try:  # pragma: no cover - optional dependency path
    import joblib  # type: ignore
except ImportError:  # pragma: no cover
    joblib = None

try:  # pragma: no cover - optional dependency path
    import numpy as np  # type: ignore
    from sklearn.ensemble import IsolationForest as SklearnIsolationForest  # type: ignore
except ImportError:  # pragma: no cover
    np = None
    SklearnIsolationForest = None

FEATURE_ORDER = [
    "connection_frequency",
    "unique_ip_count",
    "byte_transfer_rate",
    "interval_variance",
    "high_risk_port_ratio",
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
    "lineage_depth",
]
BOOTSTRAP_BASELINE = [
    [8.0, 2.0, 2048.0, 8.0e10, 0.1, 2.0],
    [10.0, 3.0, 4096.0, 1.0e11, 0.2, 2.0],
    [12.0, 4.0, 5120.0, 1.2e11, 0.15, 3.0],
    [6.0, 2.0, 1024.0, 6.0e10, 0.05, 1.0],
    [14.0, 5.0, 6144.0, 1.4e11, 0.3, 3.0],
    [7.0, 2.0, 1536.0, 7.0e10, 0.1, 2.0],
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
]


class SimpleIsolationForest:
    def __init__(self, sample_size: int = 64, n_trees: int = 100, random_state: int = 42) -> None:
        self.sample_size = sample_size
        self.n_trees = n_trees
        self.random = random.Random(random_state)
        self.trees: List[dict] = []
        self.max_depth = math.ceil(math.log2(sample_size)) if sample_size > 1 else 1

    def fit(self, matrix: Sequence[Sequence[float]]) -> None:
        rows = [list(row) for row in matrix]
        if not rows:
            raise ValueError("training matrix cannot be empty")
        self.trees = []
        for _ in range(self.n_trees):
            sample = [rows[self.random.randrange(len(rows))] for _ in range(min(self.sample_size, len(rows)))]
            self.trees.append(self._build_tree(sample, depth=0))

    def decision_function(self, matrix: Sequence[Sequence[float]]) -> List[float]:
        scores = []
        cn = self._average_path_length(self.sample_size)
        for row in matrix:
            path_lengths = [self._path_length(tree, list(row), 0) for tree in self.trees]
            avg_path = mean(path_lengths) if path_lengths else 0.0
            anomaly_score = 2 ** (-(avg_path / max(cn, 1e-9)))
            scores.append(0.5 - anomaly_score)
        return scores

    def predict(self, matrix: Sequence[Sequence[float]]) -> List[int]:
        return [-1 if score < 0 else 1 for score in self.decision_function(matrix)]

    def _build_tree(self, rows: List[List[float]], depth: int) -> dict:
        if depth >= self.max_depth or len(rows) <= 1 or self._rows_identical(rows):
            return {"leaf": True, "size": len(rows)}
        feature = self.random.randrange(len(rows[0]))
        values = [row[feature] for row in rows]
        min_v, max_v = min(values), max(values)
        if min_v == max_v:
            return {"leaf": True, "size": len(rows)}
        split = self.random.uniform(min_v, max_v)
        left = [row for row in rows if row[feature] < split]
        right = [row for row in rows if row[feature] >= split]
        if not left or not right:
            return {"leaf": True, "size": len(rows)}
        return {
            "leaf": False,
            "feature": feature,
            "split": split,
            "left": self._build_tree(left, depth + 1),
            "right": self._build_tree(right, depth + 1),
        }

    def _path_length(self, tree: dict, row: List[float], depth: int) -> float:
        if tree["leaf"]:
            size = tree.get("size", 1)
            return depth + self._average_path_length(size)
        if row[tree["feature"]] < tree["split"]:
            return self._path_length(tree["left"], row, depth + 1)
        return self._path_length(tree["right"], row, depth + 1)

    @staticmethod
    def _rows_identical(rows: List[List[float]]) -> bool:
        return all(row == rows[0] for row in rows[1:])

    @staticmethod
    def _average_path_length(n: int) -> float:
        if n <= 1:
            return 0.0
        if n == 2:
            return 1.0
        return 2.0 * (math.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)


class AgentShieldModel:
    def __init__(self, model_path: Path | None = None, contamination: float = 0.05) -> None:
        self.model_path = model_path or Path("agentshield/ml_engine/isolation_forest.joblib")
        self.contamination = contamination
        self.model = None
        self._bootstrap_model()

    def _bootstrap_model(self) -> None:
        if self.model_path.exists():
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
            LOGGER.info("Loading trained model from %s", self.model_path)
            self.model = self._load_model(self.model_path)
            return
        LOGGER.info("Training bootstrap isolation forest model")
        baseline = [
            [8.0, 2.0, 2048.0, 8.0e10, 0.1],
            [10.0, 3.0, 4096.0, 1.0e11, 0.2],
            [12.0, 4.0, 5120.0, 1.2e11, 0.15],
            [6.0, 2.0, 1024.0, 6.0e10, 0.05],
            [14.0, 5.0, 6144.0, 1.4e11, 0.3],
            [7.0, 2.0, 1536.0, 7.0e10, 0.1],
        ]
        self.model = self._new_model()
        self.model.fit(baseline)
        self._save_model(self.model_path)

=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
            try:
                LOGGER.info("Loading trained model from %s", self.model_path)
                self.model = self._load_model(self.model_path)
                self._validate_model_shape()
                return
            except Exception as exc:
                LOGGER.warning("Stored model incompatible or unreadable (%s); rebuilding bootstrap model", exc)
        LOGGER.info("Training bootstrap isolation forest model")
        self.model = self._new_model()
        self.model.fit(BOOTSTRAP_BASELINE)
        self._save_model(self.model_path)

    def _validate_model_shape(self) -> None:
        if self.model is None:
            raise RuntimeError("missing model")
        probe = [[row for row in BOOTSTRAP_BASELINE[0]]]
        if np is not None and SklearnIsolationForest is not None and hasattr(self.model, "decision_function"):
            self.model.decision_function(np.array(probe))
        else:
            self.model.decision_function(probe)

<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
    def _new_model(self):
        if SklearnIsolationForest is not None and np is not None:
            return SklearnIsolationForest(n_estimators=200, contamination=self.contamination, random_state=42)
        LOGGER.warning("scikit-learn unavailable; using built-in SimpleIsolationForest fallback")
        return SimpleIsolationForest(sample_size=64, n_trees=128, random_state=42)

    def infer(self, normalized_features: dict, raw_features: dict) -> dict:
        if self.model is None:
            raise RuntimeError("model not initialized")
        vector = [[raw_features[key] for key in FEATURE_ORDER]]
        if np is not None and SklearnIsolationForest is not None and hasattr(self.model, "decision_function"):
            arr = np.array(vector)
            decision = float(self.model.decision_function(arr)[0])
            prediction = int(self.model.predict(arr)[0])
        else:
            decision = float(self.model.decision_function(vector)[0])
            prediction = int(self.model.predict(vector)[0])
        anomaly_score = max(0.0, min(1.0, 0.5 - decision))
        label = "anomaly" if prediction == -1 else "normal"
        return {
            "features": {key: float(raw_features[key]) for key in FEATURE_ORDER},
            "normalized_features": {key: float(normalized_features[key]) for key in FEATURE_ORDER},
            "anomaly_score": anomaly_score,
            "label": label,
        }

    def retrain(self, dataset: Sequence[dict]) -> None:
        if not dataset:
            raise ValueError("dataset must not be empty")
        matrix = [[row[key] for key in FEATURE_ORDER] for row in dataset]
        self.model = self._new_model()
        self.model.fit(matrix)
        self._save_model(self.model_path)
        LOGGER.info("Retrained model with %d samples", len(dataset))

    def retrain_from_jsonl(self, dataset_path: Path) -> None:
        rows: List[dict] = []
        with dataset_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                rows.append(json.loads(line))
        self.retrain(rows)

    def _save_model(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if joblib is not None:
            joblib.dump(self.model, path)
            return
        with path.open("wb") as handle:
            pickle.dump(self.model, handle)

    def _load_model(self, path: Path):
        if joblib is not None:
            return joblib.load(path)
        with path.open("rb") as handle:
            return pickle.load(handle)
