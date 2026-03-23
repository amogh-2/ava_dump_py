# avadump Python Port

This directory contains a Python implementation of the Rust `avadump` pipeline.

## What it does
- Accepts `pcap`/`pcapng` or `csv` input
- Loads feature schema from the same JSON config format used by Rust
- Builds bidirectional 5-tuple flows for packet captures
- Computes the same flow feature superset and dynamically selects configured features
- Writes JSON output compatible with Rust output shape

## Setup
```bash
pip install -r requirements.txt
```

## Run
From the `python_version` directory:
```bash
python -m avadump_py.main single_flow.csv cicids2017.json output.json
```

For pcap input:
```bash
python -m avadump_py.main <capture.pcap> cicids2017.json output.json
```
