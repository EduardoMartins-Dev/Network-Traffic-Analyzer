# PCAPs de Teste — NTA v4.1

Os `.pcap` versionados aqui são **sintéticos e determinísticos**, gerados por
`gen_pcaps.py` (só stdlib) com volume acima dos limiares do `analyzer.c`. São
eles que o CI (`.github/workflows/test-ids.yml`) roda a cada push/PR:

```bash
python3 tests/pcaps/gen_pcaps.py   # regenera (mesmos bytes a cada execução)
```

Para validar com tráfego real, pcaps podem vir de datasets públicos como:
- **CICIDS2017**: https://www.unb.ca/cic/datasets/ids-2017.html
- **Malware Traffic Analysis**: https://www.malware-traffic-analysis.net/
- **CTF captures**: datasets de competições públicas

## Convenção de nomes

Cada arquivo `.pcap` deve ter um gabarito `.json` com o mesmo nome:

| PCAP               | Gabarito            | Attack Type    | src_ip no gabarito |
|--------------------|---------------------|----------------|--------------------|
| syn-flood.pcap     | syn-flood.json      | SYN_FLOOD      | 192.168.1.100      |
| port-scan.pcap     | port-scan.json      | PORT_SCAN      | 192.168.1.100      |
| null-scan.pcap     | null-scan.json      | NULL_SCAN      | 192.168.1.100      |
| brute-force.pcap   | brute-force.json    | BRUTE_FORCE    | 192.168.1.100      |
| dns-tunnel.pcap    | dns-tunnel.json     | DNS_TUNNEL     | 192.168.1.100      |
| icmp-flood.pcap    | icmp-flood.json     | ICMP_FLOOD     | 192.168.1.100      |
| xmas-scan.pcap     | xmas-scan.json      | XMAS_SCAN      | 192.168.1.100      |
| synfin-scan.pcap   | synfin-scan.json    | SYNFIN_SCAN    | 192.168.1.100      |
| arp-spoof.pcap     | arp-spoof.json      | ARP_SPOOF      | 192.168.1.1        |
| amplification.pcap | amplification.json  | AMPLIFICATION  | 192.168.1.100      |

Notas sobre os gabaritos novos:
- **ARP_SPOOF**: o `src_ip` é o IP **reivindicado** na resposta ARP divergente
  (192.168.1.1, o gateway), que é o que o analyzer publica. A detecção ignora
  HOME_NET.
- **AMPLIFICATION**: a contagem é por IP de origem. O gerador faz o atacante
  emitir algumas consultas próprias (denominador) além das respostas grandes
  (numerador). Um refletor que só envia respostas **não** é detectado pelo
  analyzer atual (lacuna conhecida, não coberta por estes pcaps).

## Executar testes

```bash
# Arquivo único
./build/NetworkTrafficAnalyzer --replay tests/pcaps/syn-flood.pcap \
  --expect tests/pcaps/syn-flood.json

# Diretório completo
./build/NetworkTrafficAnalyzer --replay-dir tests/pcaps/ \
  --report tests/report.json
```
