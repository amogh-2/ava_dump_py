from __future__ import annotations

from .store import FlowFeatures


def select_features(features: FlowFeatures, configured_features: list[str]) -> list[float]:
    out: list[float] = []

    for raw_name in configured_features:
        name = raw_name.strip()
        if name == "Flow Duration":
            val = features.end_time - features.start_time
        elif name in {"Total Fwd Packets", "fwd_packets"}:
            val = float(features.fwd_packets)
        elif name in {"Total Backward Packets", "bwd_packets"}:
            val = float(features.bwd_packets)
        elif name in {"Total Length of Fwd Packets", "fwd_bytes"}:
            val = float(features.fwd_bytes)
        elif name in {"Total Length of Bwd Packets", "bwd_bytes"}:
            val = float(features.bwd_bytes)
        elif name in {"Flow Bytes/s", "bytes_per_second"}:
            duration = features.end_time - features.start_time
            total_bytes = features.fwd_bytes + features.bwd_bytes
            val = (float(total_bytes) / duration) if duration > 0.0 else 0.0
        elif name in {"Flow Packets/s", "packets_per_second"}:
            duration = features.end_time - features.start_time
            total_pkts = features.fwd_packets + features.bwd_packets
            val = (float(total_pkts) / duration) if duration > 0.0 else 0.0
        elif name in {"FIN Flag Count", "fin_count"}:
            val = float(features.fin_count)
        elif name in {"SYN Flag Count", "syn_count"}:
            val = float(features.syn_count)
        elif name in {"ACK Flag Count", "ack_count"}:
            val = float(features.ack_count)
        elif name in {"Packet Length Mean", "mean_packet_size"}:
            total_pkts = features.fwd_packets + features.bwd_packets
            val = (float(features.total_packet_size) / float(total_pkts)) if total_pkts > 0 else 0.0
        elif name == "Fwd Packet Length Mean":
            val = (
                float(features.total_fwd_packet_size) / float(features.fwd_packets)
                if features.fwd_packets > 0
                else 0.0
            )
        elif name == "Bwd Packet Length Mean":
            val = (
                float(features.total_bwd_packet_size) / float(features.bwd_packets)
                if features.bwd_packets > 0
                else 0.0
            )
        elif name == "Fwd Packet Length Max":
            val = float(features.max_fwd_packet_size)
        elif name == "Bwd Packet Length Min":
            val = 0.0 if features.min_bwd_packet_size == (2**64 - 1) else float(features.min_bwd_packet_size)
        elif name == "Down/Up Ratio":
            val = float(features.bwd_packets) / float(features.fwd_packets) if features.fwd_packets > 0 else 0.0
        elif name == "Flow IAT Mean":
            total_pkts = features.fwd_packets + features.bwd_packets
            val = features.flow_iat_total / (float(total_pkts) - 1.0) if total_pkts > 1 else 0.0
        elif name == "Flow IAT Std":
            total_pkts = features.fwd_packets + features.bwd_packets
            if total_pkts > 1:
                n = float(total_pkts - 1)
                mean = features.flow_iat_total / n
                variance = (features.flow_iat_sum_sq / n) - (mean * mean)
                val = variance**0.5 if variance > 0.0 else 0.0
            else:
                val = 0.0
        elif name == "Active Mean":
            final_burst = features.last_flow_time - features.current_active_start
            active_total = features.active_time_total + final_burst
            count = features.active_count
            if final_burst > 0.0:
                count += 1
            val = active_total / float(count) if count > 0 else 0.0
        elif name == "Idle Mean":
            val = features.idle_time_total / float(features.idle_count) if features.idle_count > 0 else 0.0
        elif name == "Subflow Fwd Bytes":
            val = float(features.fwd_bytes)
        else:
            val = 0.0

        out.append(val)

    return out
