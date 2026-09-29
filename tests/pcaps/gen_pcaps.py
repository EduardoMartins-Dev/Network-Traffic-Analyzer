#!/usr/bin/env python3
"""Gera os .pcap sintéticos da suíte de replay (determinísticos, só stdlib).

Cada arquivo exercita um detector do analyzer.c com volume acima do limiar
de calibração (SYN_FLOOD_THRESHOLD, SCAN_THRESHOLD, ...). Atacante sempre
192.168.1.100 — o mesmo src_ip dos gabaritos .json ao lado.

Uso:  python3 tests/pcaps/gen_pcaps.py   (sobrescreve os .pcap deste diretório)
"""
import hashlib
import struct
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent
ATTACKER = bytes([192, 168, 1, 100])
VICTIM = bytes([192, 168, 1, 10])
BASE_TS = 1700000000  # timestamp fixo -> pcaps idênticos a cada geração

TCP_FIN, TCP_SYN = 0x01, 0x02


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def ipv4(proto: int, payload: bytes) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0,
                      64, proto, 0, ATTACKER, VICTIM)
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    return eth + hdr + payload


def tcp(sport: int, dport: int, flags: int) -> bytes:
    return ipv4(6, struct.pack("!HHIIBBHHH", sport, dport, 0, 0,
                               5 << 4, flags, 1024, 0, 0))


def icmp_echo(seq: int) -> bytes:
    body = struct.pack("!BBHHH", 8, 0, 0, 0x1234, seq)
    body = body[:2] + struct.pack("!H", checksum(body)) + body[4:]
    return ipv4(1, body)


def dns_query(sport: int, qid: int, name: str) -> bytes:
    qname = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0"
    dns = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    return ipv4(17, struct.pack("!HHHH", sport, 53, 8 + len(dns), 0) + dns)


def write_pcap(name: str, packets, interval: float) -> None:
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, pkt in enumerate(packets):
        ts = BASE_TS + i * interval
        sec, usec = int(ts), int(round((ts % 1) * 1_000_000))
        out += struct.pack("<IIII", sec, usec, len(pkt), len(pkt)) + pkt
    (OUT_DIR / name).write_bytes(bytes(out))
    print(f"{name}: {len(packets)} pacotes")


def main() -> None:
    write_pcap("syn-flood.pcap", [tcp(40000 + i, 80, TCP_SYN) for i in range(150)], 0.01)
    write_pcap("port-scan.pcap", [tcp(40000, 1000 + i, TCP_SYN) for i in range(20)], 0.05)
    write_pcap("null-scan.pcap", [tcp(40000, 1000 + i, 0) for i in range(5)], 0.1)
    write_pcap("brute-force.pcap", [tcp(40000 + i, 22, TCP_SYN) for i in range(40)], 0.5)
    write_pcap("icmp-flood.pcap", [icmp_echo(i) for i in range(50)], 0.01)
    # Subdomain de 60 chars hex (entropia ~4 bits/char, > DNS_SUBDOMAIN_LEN=50).
    write_pcap("dns-tunnel.pcap",
               [dns_query(50000 + i, i, hashlib.sha256(str(i).encode()).hexdigest()[:60]
                          + ".exfil.example")
                for i in range(20)], 0.2)


if __name__ == "__main__":
    main()
