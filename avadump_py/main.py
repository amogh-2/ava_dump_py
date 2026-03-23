from __future__ import annotations

import csv
import sys
from pathlib import Path

from .config import DatasetConfig
from .flow import FlowEngine
from .output import JsonFlowOutput, format_flow_key, write_json_output
from .parser import parse_packet
from .reader import PcapFileReader
from .selector import select_features


def is_csv_input(path: str) -> bool:
    return Path(path).suffix.lower() == ".csv"


def build_header_index(headers: list[str]) -> dict[str, int]:
    return {header.strip().lower(): idx for idx, header in enumerate(headers)}


def feature_aliases(feature: str) -> list[str]:
    normalized = feature.strip().lower()
    aliases = {
        "total fwd packets": ["fwd_packets"],
        "total backward packets": ["bwd_packets"],
        "total length of fwd packets": ["fwd_bytes"],
        "total length of bwd packets": ["bwd_bytes"],
        "flow bytes/s": ["bytes_per_second"],
        "flow packets/s": ["packets_per_second"],
        "fin flag count": ["fin_count"],
        "syn flag count": ["syn_count"],
        "ack flag count": ["ack_count"],
    }.get(normalized, [])

    return [normalized, *aliases]


def csv_flow_id(record: list[str], header_index: dict[str, int], row_idx: int) -> str:
    for key in ("flow_id", "flow id"):
        idx = header_index.get(key)
        if idx is not None and idx < len(record):
            trimmed = record[idx].strip()
            if trimmed:
                return trimmed

    return f"csv_row_{row_idx + 1}"


def select_csv_features(record: list[str], header_index: dict[str, int], config: DatasetConfig) -> list[float]:
    out: list[float] = []

    for feature in config.features:
        value = 0.0
        for alias in feature_aliases(feature):
            idx = header_index.get(alias)
            if idx is None or idx >= len(record):
                continue
            raw = record[idx].strip()
            if not raw:
                continue
            try:
                value = float(raw)
            except ValueError:
                value = 0.0
            break
        out.append(value)

    return out


def process_csv(path: str, config: DatasetConfig, output_path: str) -> None:
    exported: list[JsonFlowOutput] = []

    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        try:
            headers = next(reader)
        except StopIteration:
            headers = []

        header_index = build_header_index(headers)

        print("CSV loaded. Extracting configured features...")
        for row_idx, row in enumerate(reader):
            selected = select_csv_features(row, header_index, config)
            flow_id = csv_flow_id(row, header_index, row_idx)
            exported.append(JsonFlowOutput(flow_id=flow_id, features=selected))

    write_json_output(output_path, exported)
    print(f"Exported {len(exported)} rows with {len(config.features)} features each to {output_path}")


def process_pcap(path: str, config: DatasetConfig, output_path: str) -> None:
    engine = FlowEngine()
    reader = PcapFileReader(path)

    print("Parsing packets and building flows...")
    try:
        while True:
            packet = reader.next_packet()
            if packet is None:
                break
            ts, data = packet
            parsed = parse_packet(data, ts)
            if parsed is None:
                continue
            key, info = parsed
            engine.process_packet(key, info)
    finally:
        reader.close()

    flows = engine.into_flows()
    print("Flows built. Extracting configured features...")

    exported: list[JsonFlowOutput] = []
    for key, features in flows.items():
        selected = select_features(features, config.features)
        exported.append(JsonFlowOutput(flow_id=format_flow_key(key), features=selected))

    write_json_output(output_path, exported)
    print(f"Exported {len(exported)} flows with {len(config.features)} features each to {output_path}")


def main() -> None:
    args = sys.argv
    if len(args) != 4:
        print("Usage: avadump_py <input_file.(pcap|csv)> <config.json> <output.json>", file=sys.stderr)
        raise SystemExit(1)

    input_path = args[1]
    config_path = args[2]
    output_path = args[3]

    config = DatasetConfig.load(config_path)

    if is_csv_input(input_path):
        process_csv(input_path, config, output_path)
    else:
        process_pcap(input_path, config, output_path)


if __name__ == "__main__":
    main()
