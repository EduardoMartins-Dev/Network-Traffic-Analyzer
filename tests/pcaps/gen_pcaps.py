#!/usr/bin/env python3
"""Gera os .pcap sintéticos da suíte de replay (determinísticos, só stdlib).

Cada arquivo exercita um detector do analyzer.c com volume acima do limiar
de calibração (SYN_FLOOD_THRESHOLD, SCAN_THRESHOLD, ...). Atacante sempre
192.168.1.100 — o mesmo src_ip dos gabaritos .json ao lado. Exceção: ARP_SPOOF
publica o IP reivindicado na resposta ARP (192.168.1.1), não o IP do atacante.

Uso:  python3 tests/pcaps/gen_pcaps.py   (sobrescreve os .pcap deste diretório)
"""
import hashlib
import socket
import struct
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent
ATTACKER = bytes([192, 168, 1, 100])
VICTIM = bytes([192, 168, 1, 10])
GATEWAY = bytes([192, 168, 1, 1])
RESOLVER = bytes([8, 8, 8, 8])
REFLECTOR = bytes([203, 0, 113, 53])   # TEST-NET-3: refletor do pcap de refletor puro
CLIENT = bytes([198, 51, 100, 20])     # cliente externo do pcap de DNS normal
ATTACKER_MAC = bytes([0x02, 0x42, 0xAC, 0x11, 0x00, 0x64])
BROADCAST_MAC = b"\xff" * 6
BASE_TS = 1700000000  # timestamp fixo -> pcaps idênticos a cada geração

# IPv6 (B09): endereços de documentação (RFC 3849), 16 bytes cada.
V6_ATTACKER = socket.inet_pton(socket.AF_INET6, "2001:db8:a::100")
V6_VICTIM = socket.inet_pton(socket.AF_INET6, "2001:db8:1::10")
V6_CLIENT = socket.inet_pton(socket.AF_INET6, "2001:db8:4::20")
V6_SERVER = socket.inet_pton(socket.AF_INET6, "2001:db8:2::9")
V6_RESOLVER = socket.inet_pton(socket.AF_INET6, "2001:db8:53::1")
V6_REFLECTOR = socket.inet_pton(socket.AF_INET6, "2001:db8:3::53")

TCP_FIN, TCP_SYN, TCP_PSH, TCP_URG, TCP_ACK = 0x01, 0x02, 0x08, 0x20, 0x10


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def ipv4(proto: int, payload: bytes, src: bytes = ATTACKER, dst: bytes = VICTIM) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0,
                      64, proto, 0, src, dst)
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


def dns_msg(qid: int, flags: int, name: str, answer: bytes = None) -> bytes:
    """Mensagem DNS com 1 pergunta A e, opcionalmente, 1 resposta TXT."""
    qname = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0"
    msg = struct.pack("!HHHHHH", qid, flags, 1, 0 if answer is None else 1, 0, 0)
    msg += qname + struct.pack("!HH", 1, 1)
    if answer is not None:
        rdata = bytes([len(answer)]) + answer
        msg += struct.pack("!HHHIH", 0xC00C, 16, 1, 300, len(rdata)) + rdata
    return msg


def udp(sport: int, dport: int, payload: bytes, src: bytes, dst: bytes) -> bytes:
    return ipv4(17, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload,
                src, dst)


def arp_reply(sender_mac: bytes, sender_ip: bytes, target_ip: bytes) -> bytes:
    """ARP reply (op=2) em quadro Ethernet de 42 bytes."""
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + sender_mac + sender_ip
    arp += b"\0" * 6 + target_ip
    eth = BROADCAST_MAC + sender_mac + b"\x08\x06"
    return eth + arp


def l4_checksum6(src: bytes, dst: bytes, proto: int, seg: bytes) -> int:
    """Checksum de camada 4 sobre IPv6 (pseudo-cabeçalho do RFC 8200)."""
    pseudo = src + dst + struct.pack("!I3xB", len(seg), proto)
    return checksum(pseudo + seg)


def ipv6_l4(src: bytes, dst: bytes, proto: int, seg: bytes, cksum_off: int) -> bytes:
    """Preenche o checksum do segmento L4 (o analyzer não verifica; aqui é
    só para o pcap ser um IPv6 válido para outras ferramentas)."""
    seg = seg[:cksum_off] + b"\0\0" + seg[cksum_off + 2:]
    c = l4_checksum6(src, dst, proto, seg)
    return seg[:cksum_off] + struct.pack("!H", c) + seg[cksum_off + 2:]


def ipv6(next_hdr: int, body: bytes, src: bytes, dst: bytes) -> bytes:
    """Quadro Ethernet + IPv6 (40 bytes) + `body` (extensões e L4). `next_hdr`
    é o primeiro cabeçalho depois do fixo (extensão, se houver)."""
    hdr = struct.pack("!IHBB", 0x60000000, len(body), next_hdr, 64) + src + dst
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x86\xdd"
    return eth + hdr + body


def hbh(next_hdr: int) -> bytes:
    """Cabeçalho de extensão Hop-by-Hop de 8 bytes (PadN)."""
    return struct.pack("!BB", next_hdr, 0) + b"\x01\x04\0\0\0\0"


def frag(next_hdr: int, offset_units: int) -> bytes:
    """Fragment header de 8 bytes; offset em unidades de 8 bytes; M = 0."""
    return struct.pack("!BBHI", next_hdr, 0, offset_units << 3, 0x1234)


def tcp6(sport: int, dport: int, flags: int, src: bytes = V6_ATTACKER,
         dst: bytes = V6_VICTIM) -> bytes:
    seg = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 1024, 0, 0)
    return ipv6(6, ipv6_l4(src, dst, 6, seg, 16), src, dst)


def icmp6_echo(seq: int, src: bytes = V6_ATTACKER, dst: bytes = V6_VICTIM,
               kind: int = 128) -> bytes:
    """ICMPv6 echo request (128) ou reply (129)."""
    body = struct.pack("!BBHHH", kind, 0, 0, 0x1234, seq)
    return ipv6(58, ipv6_l4(src, dst, 58, body, 2), src, dst)


def udp6(sport: int, dport: int, payload: bytes, src: bytes, dst: bytes) -> bytes:
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return ipv6(17, ipv6_l4(src, dst, 17, seg, 6), src, dst)


def dns6_query(sport: int, qid: int, name: str) -> bytes:
    return udp6(sport, 53, dns_msg(qid, 0x0100, name), V6_ATTACKER, V6_RESOLVER)


def write_pcap(name: str, packets, interval: float) -> None:
    """packets: bytes, ou (bytes_capturados, tamanho_original) para simular
    captura com snaplen curto (incl_len < orig_len)."""
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, pkt in enumerate(packets):
        pkt, orig_len = pkt if isinstance(pkt, tuple) else (pkt, len(pkt))
        ts = BASE_TS + i * interval
        sec, usec = int(ts), int(round((ts % 1) * 1_000_000))
        out += struct.pack("<IIII", sec, usec, len(pkt), orig_len) + pkt
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

    # XMAS (FIN+PSH+URG): XMAS_SCAN dispara no 3o pacote (STEALTH_THRESHOLD=3).
    write_pcap("xmas-scan.pcap",
               [tcp(40000, 1000 + i, TCP_FIN | TCP_PSH | TCP_URG) for i in range(20)], 0.05)
    # SYN+FIN: combinação inválida pelo RFC; SYNFIN_SCAN dispara no 3o pacote.
    write_pcap("synfin-scan.pcap",
               [tcp(40000, 1000 + i, TCP_SYN | TCP_FIN) for i in range(20)], 0.05)

    # ARP spoofing: o MAC do atacante anuncia 192.168.1.100 e depois passa a
    # responder por 192.168.1.1 (gateway). O analyzer publica o IP reivindicado
    # (192.168.1.1), sem checar HOME_NET. Cada resposta divergente gera alerta.
    arp = [arp_reply(ATTACKER_MAC, ATTACKER, VICTIM)]
    arp += [arp_reply(ATTACKER_MAC, GATEWAY, VICTIM) for _ in range(5)]
    write_pcap("arp-spoof.pcap", arp, 0.5)

    # Amplificação por refletor: 192.168.1.100 faz 3 consultas próprias pequenas
    # (~71 B cada, 213 B no total; o analyzer só conta bytes DNS a partir de 100 B)
    # e responde 10 vezes à vítima com TXT de 200 B (284 B cada, 2840 B no total,
    # 13x > AMPLIFICATION_RATIO=10). Contabilidade é por IP de origem, então o
    # refletor precisa também emitir requests para o denominador ser não nulo.
    amp = [udp(40000 + i, 53, dns_msg(i, 0x0100, "example.com"), ATTACKER, RESOLVER)
           for i in range(3)]
    amp += [udp(53, 40000 + i, dns_msg(i, 0x8180, "example.com", b"A" * 200), ATTACKER, VICTIM)
            for i in range(10)]
    write_pcap("amplification.pcap", amp, 0.1)

    # Refletor DNS puro: 203.0.113.53 só envia respostas. As consultas saem com
    # o IP da vítima (192.168.1.10) como origem (spoofing), então o analyzer
    # precisa contá-las no IP de DESTINO (o refletor). 3 consultas de ~71 B
    # (213 B) e 10 respostas de 284 B (2840 B, 13x): dispara na 8ª resposta.
    refl = [udp(40000 + i, 53, dns_msg(i, 0x0100, "example.com"), VICTIM, REFLECTOR)
            for i in range(3)]
    refl += [udp(53, 40000 + i, dns_msg(i, 0x8180, "example.com", b"A" * 200), REFLECTOR, VICTIM)
             for i in range(10)]
    write_pcap("amplification-reflector.pcap", refl, 0.1)

    # DNS normal (falso positivo): cliente externo faz 20 consultas de ~75 B e
    # recebe 20 respostas de ~128 B (razão ~1,7x, bem abaixo de 10x). Gabarito
    # vazio: qualquer alerta aparece na saída do replay como detecção extra.
    normal = []
    for i in range(20):
        normal.append(udp(40000 + i, 53, dns_msg(i, 0x0100, "www.example.com"), CLIENT, REFLECTOR))
        normal.append(udp(53, 40000 + i, dns_msg(i, 0x8180, "www.example.com", b"x" * 40), REFLECTOR, CLIENT))
    write_pcap("dns-normal.pcap", normal, 0.2)

    # Exaustão da tabela de suspeitos (regressão de B28): um cliente consulta 110
    # servidores distintos (mais que MAX_SUSPECTS=100) e depois 192.168.1.100 faz
    # port scan. O scan não pode ser ignorado por falta de vaga: gabarito PORT_SCAN.
    exh = [udp(40000 + i, 53, dns_msg(i, 0x0100, "www.example.com"), CLIENT,
               bytes([203, 0, 113, i + 1])) for i in range(110)]
    exh += [tcp(40000, 1000 + i, TCP_SYN) for i in range(30)]
    write_pcap("dns-exaustao.pcap", exh, 0.05)

    # Malformados: nenhum pode gerar leitura fora do buffer nem detecção
    # (gabarito vazio; roda sob ASan/UBSan no CI).
    null = tcp(40000, 80, 0)                                 # null scan = 54 bytes
    bad_ihl = bytearray(null); bad_ihl[14] = 0x4F            # IHL=15 (60 bytes) > pacote
    short_ihl = bytearray(null); short_ihl[14] = 0x42        # IHL=2 (< 20 bytes)
    dns_1byte = ipv4(17, struct.pack("!HHHH", 50000, 53, 9, 0) + b"\x00")
    write_pcap("malformed.pcap", [
        (null[:20], len(null)),                              # IPv4 cortado pelo snaplen
        (null[:40], len(null)),                              # TCP cortado pelo snaplen
        bytes(bad_ihl), bytes(bad_ihl), bytes(bad_ihl),
        bytes(short_ihl), bytes(short_ihl), bytes(short_ihl),
        dns_1byte,
        (dns_1byte[:38], len(dns_1byte)),                    # UDP cortado
    ], 0.1)

    # ---------------------------------------------------------------------
    # IPv6 (B09). Mesmos volumes dos pcaps IPv4 correspondentes; o atacante é
    # 2001:db8:a::100 e o gabarito usa o texto canônico (inet_ntop).
    # ---------------------------------------------------------------------
    write_pcap("ipv6-syn-flood.pcap",
               [tcp6(40000 + i, 80, TCP_SYN) for i in range(150)], 0.01)
    write_pcap("ipv6-port-scan.pcap",
               [tcp6(40000, 1000 + i, TCP_SYN) for i in range(20)], 0.05)
    write_pcap("ipv6-null-scan.pcap",
               [tcp6(40000, 1000 + i, 0) for i in range(5)], 0.1)
    write_pcap("ipv6-xmas-scan.pcap",
               [tcp6(40000, 1000 + i, TCP_FIN | TCP_PSH | TCP_URG) for i in range(20)], 0.05)
    write_pcap("ipv6-synfin-scan.pcap",
               [tcp6(40000, 1000 + i, TCP_SYN | TCP_FIN) for i in range(20)], 0.05)
    write_pcap("ipv6-brute-force.pcap",
               [tcp6(40000 + i, 22, TCP_SYN) for i in range(40)], 0.5)
    write_pcap("ipv6-icmp-flood.pcap", [icmp6_echo(i) for i in range(50)], 0.01)
    write_pcap("ipv6-dns-tunnel.pcap",
               [dns6_query(50000 + i, i, hashlib.sha256(str(i).encode()).hexdigest()[:60]
                           + ".exfil.example")
                for i in range(20)], 0.2)

    # Refletor DNS puro sobre IPv6: a vítima 2001:db8:1::10 envia consultas com
    # origem forjada para o refletor 2001:db8:3::53, que só responde. O alerta
    # sai pelo refletor, como no IPv4.
    v6refl = [udp6(40000 + i, 53, dns_msg(i, 0x0100, "example.com"), V6_VICTIM, V6_REFLECTOR)
              for i in range(3)]
    v6refl += [udp6(53, 40000 + i, dns_msg(i, 0x8180, "example.com", b"A" * 200),
                    V6_REFLECTOR, V6_VICTIM)
               for i in range(10)]
    write_pcap("ipv6-amplification-reflector.pcap", v6refl, 0.1)

    # Benigno (falso positivo): cliente 2001:db8:4::20 com ACK para uma porta só,
    # DNS proporcional, algumas respostas de echo e poucas requisições de echo
    # (abaixo do limiar de ICMP_FLOOD). Gabarito vazio.
    v6benign = [tcp6(40000 + (i % 5), 443, TCP_ACK, src=V6_CLIENT, dst=V6_SERVER)
                for i in range(100)]
    for i in range(20):
        v6benign.append(udp6(40000 + i, 53, dns_msg(i, 0x0100, "www.example.com"),
                             V6_CLIENT, V6_RESOLVER))
        v6benign.append(udp6(53, 40000 + i, dns_msg(i, 0x8180, "www.example.com", b"x" * 40),
                             V6_RESOLVER, V6_CLIENT))
    v6benign += [icmp6_echo(i, src=V6_CLIENT, dst=V6_SERVER, kind=129) for i in range(30)]
    v6benign += [icmp6_echo(i, src=V6_CLIENT, dst=V6_SERVER) for i in range(5)]
    write_pcap("ipv6-benign.pcap", v6benign, 0.2)

    # Malformados IPv6 (gabarito vazio; roda sob ASan/UBSan no CI). Nenhum pode
    # ler fora do quadro nem gerar detecção: os três nulos do fragmento não
    # inicial e da cadeia de 9 extensões provariam a leitura se fossem aceitos.
    v6full = tcp6(40000, 80, 0)                              # null scan, 74 bytes
    v6_ver4 = bytearray(v6full); v6_ver4[14] = 0x40          # versão 4 com EtherType 6
    v6_hbh_big = bytearray(v6full); v6_hbh_big[20] = 0       # next = Hop-by-Hop
    v6_hbh_big[54] = 6; v6_hbh_big[55] = 255                 # ext de 2048 bytes
    tcp_seg = tcp6(40000, 80, 0)[54:]                        # segmento TCP sem IPv6
    # 9 extensões Hop-by-Hop (o limite é 8); a última aponta para TCP null.
    chain_pkt = ipv6(0, b"".join(hbh(0) for _ in range(8)) + hbh(6) + tcp_seg,
                     V6_ATTACKER, V6_VICTIM)
    # Fragmento não inicial (offset 1 = 8 bytes): sem L4, não pode ser analisado.
    frag_n = [ipv6(44, frag(6, 1) + tcp6(40000, 1000 + i, 0)[54:], V6_ATTACKER, V6_VICTIM)
              for i in range(3)]
    esp = [ipv6(50, b"\x00" * 20, V6_ATTACKER, V6_VICTIM) for _ in range(3)]
    write_pcap("ipv6-malformed.pcap", [
        (v6full[:20], len(v6full)),                          # IPv6 cortado pelo snaplen
        (v6full[:50], len(v6full)),                          # cabeçalho fixo incompleto
        bytes(v6_ver4), bytes(v6_ver4),
        bytes(v6_hbh_big), bytes(v6_hbh_big),
        chain_pkt, chain_pkt, chain_pkt,
        *frag_n,
        *esp,
        (v6full[:60], len(v6full)),                          # TCP cortado
    ], 0.1)

    # Exaustão por origens IPv6 (B09): 110 origens IPv6 distintas, cada uma com
    # um SYN, consomem a tabela IPv6 e não a IPv4. Depois, 192.168.1.100 faz port
    # scan: tem que continuar detectado (gabarito PORT_SCAN em IPv4).
    v6exh = [tcp6(40000, 80, TCP_SYN,
                  src=socket.inet_pton(socket.AF_INET6, f"2001:db8:b::{i + 1:x}"))
             for i in range(110)]
    v6exh += [tcp(40000, 1000 + i, TCP_SYN) for i in range(30)]
    write_pcap("ipv6-exaustao.pcap", v6exh, 0.05)


if __name__ == "__main__":
    main()
