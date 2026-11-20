# CLAUDE.md — Network Traffic Analyzer (NTA)

Contexto do projeto para o Claude Code e para quem clonar o repositório.

- **Repositório:** https://github.com/EduardoMartins-Dev/Network-Traffic-Analyzer
- **Licença:** MIT · **Branch principal:** `main` · **Releases:** https://github.com/EduardoMartins-Dev/Network-Traffic-Analyzer/releases
- **Uso:** educacional e de pesquisa em segurança defensiva (Blue Team). Executar só em redes autorizadas.

## O que é

IDS em **C11** com arquitetura **Agent/Server**. Cada agente captura pacotes no host monitorado, detecta ataques de forma comportamental (baseline EWMA + correlação de kill chain, com tags MITRE ATT&CK) e publica eventos por AMQP. O `nta-server` (também em C) consome a fila, enriquece com threat intelligence, grava no InfluxDB e gera narrativas de incidentes por LLM. Grafana exibe e alerta.

## Arquitetura (resumo)

```
Host → libpcap/Npcap → Analyzer (EWMA + kill chain) → Publisher AMQP → RabbitMQ
     → nta-server → InfluxDB → Grafana
nta-server → narrator_queue → Groq (LLM) → incident_narrative
```

| Componente | Onde | Função |
|---|---|---|
| Agente (`NetworkTrafficAnalyzer`) | host monitorado | captura, análise, publicação em lote |
| RabbitMQ 3.13 | servidor | filas `traffic_queue`, `traffic_metrics`, `narrator_queue` |
| `nta-server` | servidor (container) | consumo, GeoIP/ASN, IoC, AbuseIPDB, WHOIS, narrator, scaler, `/health` |
| InfluxDB 2.7 | servidor | séries temporais (bucket 7 d + warm 90 d) |
| Grafana 13.1.2 | servidor | dashboards e alertas (Telegram) |

**Pipeline do agente (4 threads):** `capture_th` → `rb_pkt` → `analysis_th` → `rb_evt` → `publish_th` (+ `metrics_th`). Filas SPSC lock-free com atômicos C11; publicação em lote (`AGENT_BATCH_SIZE`, `AGENT_BATCH_TIMEOUT_MS`).

**Detecções (10):** Port Scan, ICMP Flood, SYN Flood, Null Scan, Xmas Scan, SYN/FIN Scan, Brute Force (22/21/3389), DNS Tunneling, ARP Spoofing, DDoS Amplification. O agente analisa IPv4 (EtherType `0x0800`) e IPv6 (`0x86DD`, com até 8 cabeçalhos de extensão). Sobre IPv6 valem Port Scan, SYN Flood, Null/Xmas/SYN-FIN Scan, Brute Force, DNS Tunneling, ICMP Flood (ICMPv6 echo request) e DDoS Amplification; ARP Spoofing fica só em IPv4 e NDP spoof está fora do escopo. O agente pula tags VLAN 802.1Q (`0x8100`) e 802.1ad/QinQ (`0x88A8`), até 4 empilhadas; quadro com tag cortada ou com mais de 4 tags é descartado. Fragmentos IPv4 com offset != 0 e IPv6 não iniciais são descartados e contados (`frag_discarded`); fragmento inicial só analisa o L4 que cabe em `tot_len` (IPv4) ou `payload_len` (IPv6). Não há remontagem de fragmentos. Kill chain: `IDLE → RECON → EXPLOIT → EXFIL → COMPLETE`, janela de 30 min, score 0–100; o narrator dispara com `kc_score >= 80` ou `abuse_score >= 75`.

## Especificações técnicas

| Item | Uso atual |
|---|---|
| Linguagem | C11 (atômicos, pthreads) |
| Build | CMake; MSYS2 UCRT64 + Ninja no Windows (**MSVC não suportado**) |
| Captura | libpcap (Linux/BSD/macOS) · Npcap + SDK 1.16 (Windows) |
| Mensageria | librabbitmq (AMQP 0.9.1), TLS na 5671, mTLS com SASL EXTERNAL |
| JSON | cJSON (vendored em `third_party/`) |
| HTTP no servidor | libcurl · GeoIP: libmaxminddb (GeoLite2 City + ASN) · WHOIS: sockets BSD (porta 43) |
| LLM | Groq, modelo padrão `llama-3.3-70b-versatile` |
| Scripts auxiliares | Bash; Python 3 com `pika` e `requests` (`ctl.py`, `agent_ctl.py`, `dash_gen.py`) |
| Instalador Windows | Inno Setup (`installer/nta-agent.iss`) |
| CI | GitHub Actions: `test-ids.yml` (testes, replay ≥ 80 %, sanitizers, Windows, Docker) e `release.yml` (tag `v*`) |

Plataformas do agente: Linux, FreeBSD, macOS e Windows nativo (serviço `NTAAgent`). O `nta-server` só compila fora do Windows e roda em container.

## Estrutura

```
include/agent|server/   headers          src/agent/{analysis,capture,core,output,platform,replay}
src/server/             um .c por módulo  third_party/cjson   cJSON vendored
tests/unit/             ctest             tests/pcaps/        33 pcaps sintéticos (26 com gabarito de detecção; 7 com `expected: []`, 0 alertas)
tests/fuzz/             libFuzzer         tests/bench/        benchmark de pps (opcional)
deploy/ scripts/ grafana/ installer/ .github/workflows/        infra, automação, dashboards, CI
```

## Comandos

```bash
# Build (Linux/macOS/BSD)
cmake -B build -S . && cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure

# Validar o IDS contra os pcaps (sem privilégio nem RabbitMQ)
./build/NetworkTrafficAnalyzer --replay-dir tests/pcaps/ --report tests/report.json

# Benchmark de throughput (opcional, sem rede nem privilégio; use --pps para medir capacidade)
cmake -S . -B build-bench -DNTA_BUILD_BENCH=ON && cmake --build build-bench --target bench_pps
./build-bench/bench_pps --packets 400000 --pps 200000

# Rodar o agente
./build/NetworkTrafficAnalyzer --list-interfaces
./build/NetworkTrafficAnalyzer eth0          # precisa de root ou setcap cap_net_raw,cap_net_admin+ep

# Stack do servidor (Docker/Podman) e atalhos
make quickstart      # install + up + smoke-test
make up / make down / make smoke
```

Windows (terminal UCRT64): `cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DNPCAP_SDK_DIR="C:/Npcap-sdk"`.
Configuração do agente: variáveis `AGENT_*` ou `--config <arquivo>` (o ambiente vence o arquivo); modelo em `deploy/agent.env.example`.

## Convenções

- Commits em português no estilo Conventional Commits (`feat(agent):`, `fix(analyzer):`, `chore:`, `docs:`, `test:`, `refactor:`), com corpo explicando o motivo e como foi verificado.
- Trabalho em branches `feat/*`, `fix/*`, `chore/*`, `test/*`, integradas por Pull Request em `main`; releases por tag `vX.Y.Z`.
- Mudou comportamento de detecção: rode `ctest` e o replay; o CI reprova score < 80 %. Pacotes malformados também passam por ASan/UBSan.
- Segredos ficam fora do git (`.env`, `deploy/secrets/*.env`); só os `*.example` são versionados.
- Não commitar binários nem `build/`.
- Cada item de trabalho vai em branch e PR próprios, sempre a partir de `origin/main` atualizado (compare com `origin/main`, não com o `main` local). O `analyzer.c` e o `nta_net.h` têm um dono por vez.
- O CI inclui um job de fuzzing (`fuzz-smoke`, 120 s) que é **não bloqueante**: um crash aparece no artefato `fuzz-parser-artifacts`, não como falha do CI.

## Estado e pendências conhecidas

- Entregue até a **v8.1** (agente nativo no Windows, servidor em Docker, reconexão AMQP). Depois da `v8.1.1` já estão em `main`, sem tag: o agente com o Npcap padrão, sem o modo WinPcap-compatível (PR #13), o reload do IoC por SIGHUP, canais extras de alerta, os pcaps de cobertura, o suporte a IPv6 no agente (B09), a classificação de IPv6 privado no servidor (B33, PR #35), VLAN/QinQ e fragmentação IPv4 no agente (B10, PR #36) e os demais PRs (PRs #14 a #36; o #32 é o redesenho dos dashboards).
- Planejado: v9.0 (AF_PACKET/TPACKET_V3, zero-copy) e v10.0 (VPS, Terraform, Nginx, Let's Encrypt, cluster RabbitMQ).
- `AMPLIFICATION` detecta um refletor DNS que só envia respostas quando o sensor vê a consulta forjada com origem fora de `HOME_NET` (o request é contado no IP de destino, numa tabela fixa de 64 servidores). Não detecta quando a vítima está em `HOME_NET` (gateway da vítima): o skip descarta a consulta. Com a mistura de consultas DNSSEC/ANY, um resolvedor pode disparar com algo entre 60 % e 70 % de consultas com resposta de ~1 KB (medido com pcap sintético: 60 % deu ratio acumulado 9,8, sem alerta; 70 % deu 11,2, com alerta; o limiar 10:1 é cruzado perto de 61 % por interpolação linear).
- **Resolvido (B29, PR #28):** o `analyzer.c` usava `inet_ntoa`, que no Windows só funciona com o Winsock já inicializado. Agora usa `inet_ntop` com buffers locais `INET_ADDRSTRLEN` em ARP, ICMP, TCP, UDP e `report_addr` (`src/agent/analysis/analyzer.c`). Medido pelo orquestrador no Windows (Ryzen 7 7700X, MSYS2 UCRT64, Release): com `bench_pps` a 20 mil pps oferecidos o `rb_pkt` tinha 80,08 % de overflow, e a 200 mil pps, 96,05 %; depois da mudança, 0 % nos dois. A causa era `inet_ntoa` sem `WSAStartup` (~238 µs por chamada, micro-teste do agente do B29). O replay e o benchmark não abrem AMQP. O agente real com AMQP não tinha esse custo em regime: o rabbitmq-c chama `WSAStartup` ao abrir o socket (sonda do B29, ~0,01 a 0,3 µs), mas a proteção dependia desse efeito colateral.
- **Pendências do IPv6 (B09, PR #31):**
  - Mais de 100 origens IPv6 distintas ativas ao mesmo tempo esgotam as vagas da família (`MAX_SUSPECTS` = 100, igual ao IPv4). Uma origem sem vaga fica sem nenhuma detecção IPv6 (não só do mesmo tipo): `find_or_create_suspect` devolve NULL e `analyze_packet` retorna 0. Decisão em aberto: agregar por /64, despejar por LRU ou ADR.
  - Não verificado em captura ao vivo com IPv6 real (nem auto-detecção de HOME_NET, publicação AMQP ou enriquecimento GeoIP/IoC com IPv6). A validação foi com pcaps sintéticos e replay.
  - Resolvido no B33 (PR #35): o servidor classifica IPv6 privado com `nta_ip_is_private` (`include/server/nta_ipclass.h`, usado por `nta_abuse.c`, `nta_geoip.c` e `nta_whois.c`): `::`, `::1`, `fe80::/10`, `fc00::/7`, `ff00::/8`, `2001:db8::/32` e IPv4-mapeado.
- **Pendências do VLAN e fragmentação (B10, PR #36):**
  - Política: descarte e contagem, sem remontagem. A evasão por fragmentação continua aberta: um fragmento inicial com L4 menor que o cabeçalho exigido (menos de 20 bytes em TCP) é descartado e contado em `frag_discarded`; fragmentos não iniciais não chegam aos detectores, então ICMP Flood e SYN Flood podem ser subcontados quando o tráfego vem fragmentado.
  - Mudança visível: tráfego com VLAN, antes ignorado, agora é analisado, e pode gerar alertas novos.
  - `vlan_frames`, `frag_seen` e `frag_discarded` já são gravados em `pipeline_metrics` no InfluxDB (gravação genérica em `nta_influx.c`), mas os dashboards do Grafana ainda não os mostram.
  - Verificado só com pcaps sintéticos; captura real com VLAN ou fragmentos não foi testada.
- **Pendências anteriores ao B10, ainda não corrigidas:**
  - `--replay` de arquivo único com gabarito vazio sai com rc=1 (`main.c`: `g && r.score < 80`, e `compare_results` retorna sem preencher o score). `--replay-dir` não é afetado.
  - Padding de Ethernet pode entrar no L4 de datagrama IPv4 ou IPv6 não fragmentado, porque sem fragmento o L4 vai até o fim do quadro.
  - TCP e UDP chamam `ntohs()` por pacote em `analyzer.c`; no MinGW essa chamada cai no ws2_32.
- O `ROADMAP.MD` e o `README.md` foram alinhados ao código em 2026-11 (PR #16), mas podem restar divergências: em caso de dúvida, **o código vale**.

## Documentação detalhada

Notas aprofundadas (versões, cada detecção, decisões de arquitetura, configuração) estão numa base de conhecimento em Obsidian mantida pelo autor e **não versionada** aqui. Para o que está no repositório, comece por `README.md` e `ROADMAP.MD`.
