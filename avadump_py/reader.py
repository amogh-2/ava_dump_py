from __future__ import annotations

from pathlib import Path

import dpkt


class PcapFileReader:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._file = self.path.open("rb")

        try:
            self._reader = dpkt.pcap.Reader(self._file)
        except (ValueError, dpkt.dpkt.Error):
            self._file.seek(0)
            self._reader = dpkt.pcapng.Reader(self._file)

        self._iter = iter(self._reader)

    def next_packet(self) -> tuple[float, bytes] | None:
        try:
            ts, data = next(self._iter)
            return float(ts), bytes(data)
        except StopIteration:
            return None

    def close(self) -> None:
        self._file.close()
