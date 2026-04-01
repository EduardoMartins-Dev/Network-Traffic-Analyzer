# PCAPs de Teste — NTA v4.1

Os arquivos `.pcap` devem ser obtidos de datasets públicos como:
- **CICIDS2017**: https://www.unb.ca/cic/datasets/ids-2017.html
- **Malware Traffic Analysis**: https://www.malware-traffic-analysis.net/
- **CTF captures**: datasets de competições públicas

## Convenção de nomes

Cada arquivo `.pcap` deve ter um gabarito `.json` com o mesmo nome:

| PCAP             | Gabarito          | Attack Type    |
|------------------|-------------------|----------------|
| syn-flood.pcap   | syn-flood.json    | SYN_FLOOD      |
| port-scan.pcap   | port-scan.json    | PORT_SCAN      |
| null-scan.pcap   | null-scan.json    | NULL_SCAN      |
| brute-force.pcap | brute-force.json  | BRUTE_FORCE    |
| dns-tunnel.pcap  | dns-tunnel.json   | DNS_TUNNEL     |
| icmp-flood.pcap  | icmp-flood.json   | ICMP_FLOOD     |

## Executar testes

```bash
# Arquivo único
./build/NetworkTrafficAnalyzer --replay tests/pcaps/syn-flood.pcap \
  --expect tests/pcaps/syn-flood.json

# Diretório completo
./build/NetworkTrafficAnalyzer --replay-dir tests/pcaps/ \
  --report tests/report.json
```
