from __future__ import annotations

from .features import PacketInfo, update_features
from .store import FlowFeatures, FlowKey


class FlowEngine:
    def __init__(self) -> None:
        self.flows: dict[FlowKey, FlowFeatures] = {}

    def process_packet(self, key: FlowKey, packet: PacketInfo) -> None:
        is_fwd = True
        actual_key = key

        rev_key = FlowKey(
            src_ip=key.dst_ip,
            dst_ip=key.src_ip,
            src_port=key.dst_port,
            dst_port=key.src_port,
            protocol=key.protocol,
        )

        if rev_key in self.flows and key not in self.flows:
            is_fwd = False
            actual_key = rev_key

        entry = self.flows.setdefault(actual_key, FlowFeatures())
        packet_info = PacketInfo(
            timestamp=packet.timestamp,
            length=packet.length,
            is_fwd=is_fwd,
            syn=packet.syn,
            ack=packet.ack,
            fin=packet.fin,
            rst=packet.rst,
        )
        update_features(entry, packet_info)

    def into_flows(self) -> dict[FlowKey, FlowFeatures]:
        return self.flows
