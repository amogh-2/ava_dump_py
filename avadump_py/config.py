from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class DatasetConfig:
    dataset: str
    features: list[str]

    @staticmethod
    def load(path: str | Path) -> "DatasetConfig":
        content = Path(path).read_text(encoding="utf-8")
        raw = json.loads(content)
        dataset = str(raw.get("dataset", ""))
        features = [str(item) for item in raw.get("features", [])]
        return DatasetConfig(dataset=dataset, features=features)
