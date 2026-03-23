# avadump Python Port

A lightweight, single-file Python implementation of the Rust `avadump` pipeline.

## What it does
- Accepts `pcap`/`pcapng` or `csv` input
- Loads feature schema from JSON config (same format as Rust)
- Builds bidirectional 5-tuple flows from packet captures
- Computes flow statistics and dynamically selects configured features
- Writes JSON output compatible with Rust avadump format

## Setup
```bash
pip install -r requirements.txt
```

## Usage
```bash
python app.py <input.(pcap|csv)> <config.json> <output.json>
```

Examples:
```bash
python main.py single_flow.csv cicids2017.json output.json
python main.py capture.pcap cicids2017.json output.json
```

## Output
JSON array of flow records:
```json
[
  {
    "flow_id": "192.168.1.1-10.0.0.1-5000-80-6",
    "features": [6073353.0, 6.0, 0.0, 36.0, ...]
  }
]
```
