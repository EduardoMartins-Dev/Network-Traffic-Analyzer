#!/usr/bin/env python3
"""Gera o corpus inicial do fuzzer: um arquivo por frame dos .pcap de tests/pcaps.

Cada entrada do harness é um frame Ethernet cru, então cada pcap é desmontado
registro a registro (só stdlib). A saída deve ficar fora do repositório:

    python3 tests/fuzz/make_corpus.py tests/pcaps build-fuzz/corpus
"""
import struct
import sys
from pathlib import Path

# pcap clássico: magic -> ordem dos bytes (microssegundos e nanossegundos).
# pcapng não é suportado (os pcaps do projeto são clássicos).
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">",
}
LINKTYPE_ETHERNET = 1
MAX_FRAME = 65535


def frames(path):
    data = path.read_bytes()
    endian = PCAP_MAGICS.get(data[:4])
    if endian is None:
        raise ValueError(f"{path}: magic desconhecido (só pcap clássico)")
    *_, linktype = struct.unpack(endian + "IHHiIII", data[:24])
    if linktype != LINKTYPE_ETHERNET:
        raise ValueError(f"{path}: linktype {linktype}, esperado Ethernet (1)")

    off = 24
    while off + 16 <= len(data):
        _, _, incl_len, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if incl_len > MAX_FRAME or off + incl_len > len(data):
            raise ValueError(f"{path}: registro truncado ou inválido em {off - 16}")
        yield data[off:off + incl_len]
        off += incl_len


def main(argv):
    if len(argv) != 3:
        print(f"uso: {argv[0]} <dir-pcaps> <dir-saida>", file=sys.stderr)
        return 2

    src, out = Path(argv[1]), Path(argv[2])
    out.mkdir(parents=True, exist_ok=True)

    total = 0
    for pcap in sorted(src.glob("*.pcap")):
        for i, frame in enumerate(frames(pcap)):
            (out / f"{pcap.stem}-{i:05d}.bin").write_bytes(frame)
            total += 1

    if total == 0:
        print(f"nenhum .pcap em {src}", file=sys.stderr)
        return 1
    print(f"{total} frame(s) escritos em {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
