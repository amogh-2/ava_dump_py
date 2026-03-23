from __future__ import annotations

import socket

import dpkt

from .features import PacketInfo
from .store import FlowKey


def parse_packet(packet_data: bytes, timestamp: float) -> tuple[FlowKey, PacketInfo] | None:
    try:
        eth = dpkt.ethernet.Ethernet(packet_data)
    except (dpkt.NeedData, dpkt.UnpackError):
        return None

    ip = eth.data
    src_ip: str
    dst_ip: str
    protocol: int

    if isinstance(ip, dpkt.ip.IP):
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        protocol = int(ip.p)
    elif isinstance(ip, dpkt.ip6.IP6):
        src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)
        dst_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)
        protocol = int(ip.nxt)
    else:
        return None

    transport = ip.data
    syn = False
    ack = False
    fin = False
    rst = False

    if isinstance(transport, dpkt.tcp.TCP):
        src_port = int(transport.sport)
        dst_port = int(transport.dport)
        flags = int(transport.flags)
        syn = bool(flags & dpkt.tcp.TH_SYN)
        ack = bool(flags & dpkt.tcp.TH_ACK)
        fin = bool(flags & dpkt.tcp.TH_FIN)
        rst = bool(flags & dpkt.tcp.TH_RST)
    elif isinstance(transport, dpkt.udp.UDP):
        src_port = int(transport.sport)
        dst_port = int(transport.dport)
    else:
        return None

    key = FlowKey(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
    )

    info = PacketInfo(
        timestamp=timestamp,
        length=len(packet_data),
        is_fwd=True,
        syn=syn,
        ack=ack,
        fin=fin,
        rst=rst,
    )

    return key, info
