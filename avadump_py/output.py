from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .store import FlowKey


@dataclass
class JsonFlowOutput:
    flow_id: str
    features: list[float]


def format_flow_key(key: FlowKey) -> str:
    return f"{key.src_ip}-{key.dst_ip}-{key.src_port}-{key.dst_port}-{key.protocol}"


def write_json_output(output_path: str | Path, records: list[JsonFlowOutput]) -> None:
    payload = [asdict(record) for record in records]
    Path(output_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
