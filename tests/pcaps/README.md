# PCAPs de Teste — NTA

Os `.pcap` versionados aqui são **sintéticos e determinísticos**, gerados por
`gen_pcaps.py` (só stdlib) com volume acima dos limiares padrão de `include/agent/rules.h`. São
eles que o CI (`.github/workflows/test-ids.yml`) roda a cada push/PR:

```bash
python3 tests/pcaps/gen_pcaps.py   # regenera (mesmos bytes a cada execução)
```

Para validar com tráfego real, pcaps podem vir de datasets públicos como:
- **CICIDS2017**: https://www.unb.ca/cic/datasets/ids-2017.html
- **Malware Traffic Analysis**: https://www.malware-traffic-analysis.net/
- **CTF captures**: datasets de competições públicas

São 34 `.pcap`: 26 com detecção esperada no gabarito e 8 com gabarito vazio (`expected: []`).

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
| malformed.pcap     | malformed.json      | (nenhum)       | vazio: 0 alertas (robustez) |
| dns-log-basico.pcap | dns-log-basico.json | (nenhum)       | vazio: 0 alertas. Log de DNS (B16): só com `AGENT_PROTO_LOGS=dns` gera 10 linhas `[PROTO]`; não entra no score agregado |
| ipv6-syn-flood.pcap | ipv6-syn-flood.json | SYN_FLOOD     | 2001:db8:a::100    |
| ipv6-port-scan.pcap | ipv6-port-scan.json | PORT_SCAN     | 2001:db8:a::100    |
| ipv6-null-scan.pcap | ipv6-null-scan.json | NULL_SCAN     | 2001:db8:a::100    |
| ipv6-xmas-scan.pcap | ipv6-xmas-scan.json | XMAS_SCAN     | 2001:db8:a::100    |
| ipv6-synfin-scan.pcap | ipv6-synfin-scan.json | SYNFIN_SCAN | 2001:db8:a::100  |
| ipv6-brute-force.pcap | ipv6-brute-force.json | BRUTE_FORCE | 2001:db8:a::100    |
| ipv6-icmp-flood.pcap | ipv6-icmp-flood.json | ICMP_FLOOD   | 2001:db8:a::100    |
| ipv6-dns-tunnel.pcap | ipv6-dns-tunnel.json | DNS_TUNNEL   | 2001:db8:a::100    |
| ipv6-amplification-reflector.pcap | ipv6-amplification-reflector.json | AMPLIFICATION | 2001:db8:3::53 |
| ipv6-exaustao.pcap | ipv6-exaustao.json  | PORT_SCAN      | 192.168.1.100 (IPv4) |
| ipv6-benign.pcap   | ipv6-benign.json    | (nenhum)       | vazio: 0 alertas   |
| ipv6-malformed.pcap | ipv6-malformed.json | (nenhum)      | vazio: 0 alertas   |
| vlan-port-scan.pcap | vlan-port-scan.json | PORT_SCAN     | 192.168.1.100      |
| qinq-syn-flood.pcap | qinq-syn-flood.json | SYN_FLOOD     | 192.168.1.100      |
| vlan-arp-spoof.pcap | vlan-arp-spoof.json | ARP_SPOOF     | 192.168.1.1        |
| vlan-malformado.pcap | vlan-malformado.json | (nenhum)    | vazio: 0 alertas   |
| frag-ipv4-inicial.pcap | frag-ipv4-inicial.json | PORT_SCAN | 192.168.1.100    |
| frag-ipv4-nao-inicial.pcap | frag-ipv4-nao-inicial.json | (nenhum) | vazio: 0 alertas |
| frag-ipv4-tiny.pcap | frag-ipv4-tiny.json | (nenhum)      | vazio: 0 alertas   |

Notas sobre os gabaritos novos:
- **VLAN e QinQ (B10)**: `vlan-port-scan`, `qinq-syn-flood` e `vlan-arp-spoof`
  repetem os pcaps sem tag, com uma tag 802.1Q (0x8100) ou uma pilha QinQ
  (0x88A8 + 0x8100). Gabarito igual ao do pcap sem tag. `vlan-malformado` tem
  tag cortada pelo snaplen, QinQ cortada no meio e pilha de 5 tags (o limite é
  4). Nenhum pode alertar nem ler além do quadro.
- **Fragmentos IPv4 (B10)**: `frag-ipv4-nao-inicial` tem 30 fragmentos com
  offset != 0 cujo começo parece um TCP SYN com portas distintas. Não podem
  gerar alerta (o binário anterior ao B10 gerava 16 PORT_SCAN). `frag-ipv4-tiny`
  tem o primeiro fragmento com 8 bytes de L4 e o flag SYN no padding de Ethernet
  depois do datagrama (o binário anterior gerava 6 PORT_SCAN). `frag-ipv4-inicial`
  tem fragmentos com offset 0 e MF=1 e o cabeçalho TCP inteiro: são analisados
  (gabarito PORT_SCAN).
- **ARP_SPOOF**: o `src_ip` é o IP **reivindicado** na resposta ARP divergente
  (192.168.1.1, o gateway), que é o que o analyzer publica. O primeiro ARP
  reply liga o MAC do atacante a 192.168.1.100; a primeira resposta com
  192.168.1.1 dispara o alerta. A detecção não aplica HOME_NET (que vale só
  para o IP layer).
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
- **IPv6 (B09)**: os `ipv6-*.pcap` repetem os volumes dos pcaps IPv4 de cada
  detector. Endereços são de documentação (RFC 3849) e o gabarito usa o texto
  canônico (`inet_ntop`). O `ipv6-exaustao.pcap` mede a regressão com origens
  IPv6: 110 origens com um SYN cada, e depois um port scan IPv4. Sem gabarito:
  `ipv6-benign.pcap` (tráfego normal) e `ipv6-malformed.pcap` (cabeçalhos
  truncados, cadeia de 9 extensões, fragmento não inicial e ESP, que não podem
  gerar alerta). Checksums de L4 são calculados, mas o analyzer não os verifica.
  ARP e NDP sobre IPv6 não têm pcap: NDP spoof está fora do escopo.
- **Log de DNS (B16)** (`dns-log-basico.pcap`): 11 pacotes, dos quais 10 geram registro. O 11º é uma resposta sem pergunta, que não gera registro. Com `AGENT_PROTO_LOGS=dns`, o `--replay` imprime 10 linhas `[PROTO]`; sem a variável, nenhuma. Gabarito vazio: não pode alertar. Teste: `test_proto_dns_replay`.
- **Sem gabarito** (`dns-normal.pcap`): DNS proporcional (consulta de 71 B,
  resposta de 128 B, ~1,7x). Não pode gerar nenhum alerta. Com
  gabarito vazio, o `--replay-dir` deixa o arquivo fora do score agregado, e o
  `--replay` de arquivo único sai com rc 0 sem alerta e com rc 1 se houver
  alerta (PR #39). A prova é a linha `Detecções capturadas: 0` na saída do
  replay e o teste unitário `test_dns_normal_nao_dispara`.

## Executar testes

```bash
# Arquivo único
./build/NetworkTrafficAnalyzer --replay tests/pcaps/syn-flood.pcap \
  --expect tests/pcaps/syn-flood.json

# Diretório completo
./build/NetworkTrafficAnalyzer --replay-dir tests/pcaps/ \
  --report tests/report.json
```
