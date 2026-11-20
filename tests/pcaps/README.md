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
| amplification-reflector.pcap | amplification-reflector.json | AMPLIFICATION | 203.0.113.53 |
| dns-exaustao.pcap  | dns-exaustao.json   | PORT_SCAN      | 192.168.1.100      |
| dns-normal.pcap    | dns-normal.json     | (nenhum)       | vazio: 0 alertas   |

Notas sobre os gabaritos novos:
- **ARP_SPOOF**: o `src_ip` é o IP **reivindicado** na resposta ARP divergente
  (192.168.1.1, o gateway), que é o que o analyzer publica. A detecção ignora
  HOME_NET.
- **AMPLIFICATION** (`amplification.pcap`): o atacante é o IP que pede e
  responde. Ele emite consultas próprias (denominador) e respostas grandes
  (numerador), e o alerta sai pelo próprio IP.
- **AMPLIFICATION** (`amplification-reflector.pcap`): refletor `203.0.113.53`
  que só envia respostas. As consultas saem com a vítima `192.168.1.10` como
  origem forjada. O analyzer conta a consulta também no IP de destino (o
  servidor), e o alerta sai pelo IP do refletor. Só funciona quando o sensor
  vê a consulta com origem fora de `HOME_NET` (ver CLAUDE.md, pendências).
- **PORT_SCAN** (`dns-exaustao.pcap`): regressão. Um cliente consulta 110
  servidores distintos (mais que as 100 vagas de suspeitos) e depois
  `192.168.1.100` faz port scan. O scan tem que continuar detectado: as
  consultas não podem consumir as vagas de `suspects[]`.
- **Sem gabarito** (`dns-normal.pcap`): DNS proporcional (consulta de 71 B,
  resposta de 128 B, ~1,7x). Não pode gerar nenhum alerta. O replay não
  reprova detecção extra quando o gabarito é vazio, então a prova é a linha
  `Detecções capturadas: 0` na saída do replay e o teste unitário
  `test_dns_normal_nao_dispara`.

## Executar testes

```bash
# Arquivo único
./build/NetworkTrafficAnalyzer --replay tests/pcaps/syn-flood.pcap \
  --expect tests/pcaps/syn-flood.json

# Diretório completo
./build/NetworkTrafficAnalyzer --replay-dir tests/pcaps/ \
  --report tests/report.json
```
