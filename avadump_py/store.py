from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FlowKey:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int


@dataclass
class FlowFeatures:
    start_time: float = 0.0
    end_time: float = 0.0

    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    min_packet_size: int = 2**64 - 1
    max_packet_size: int = 0
    total_packet_size: int = 0
    sum_sq_packet_size: float = 0.0

    total_fwd_packet_size: int = 0
    total_bwd_packet_size: int = 0
    max_fwd_packet_size: int = 0
    min_bwd_packet_size: int = 2**64 - 1

    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0

    fwd_iat_total: float = 0.0
    bwd_iat_total: float = 0.0
    flow_iat_total: float = 0.0
    flow_iat_sum_sq: float = 0.0

    active_time_total: float = 0.0
    active_count: int = 0
    idle_time_total: float = 0.0
    idle_count: int = 0

    last_fwd_time: float = 0.0
    last_bwd_time: float = 0.0
    last_flow_time: float = 0.0
    current_active_start: float = 0.0
