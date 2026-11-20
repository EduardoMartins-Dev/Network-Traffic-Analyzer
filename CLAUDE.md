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

**Detecções (10):** Port Scan, ICMP Flood, SYN Flood, Null Scan, Xmas Scan, SYN/FIN Scan, Brute Force (22/21/3389), DNS Tunneling, ARP Spoofing, DDoS Amplification. Kill chain: `IDLE → RECON → EXPLOIT → EXFIL → COMPLETE`, janela de 30 min, score 0–100; o narrator dispara com `kc_score >= 80` ou `abuse_score >= 75`.

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
tests/unit/             ctest             tests/pcaps/        14 pcaps sintéticos (12 com gabarito)
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

- Entregue até a **v8.1** (agente nativo no Windows, servidor em Docker, reconexão AMQP). Depois da `v8.1.1` já estão em `main`, sem tag: o agente com o Npcap padrão, sem o modo WinPcap-compatível (PR #13), o reload do IoC por SIGHUP, canais extras de alerta e os pcaps de cobertura (PRs #14 a #18).
- Planejado: v9.0 (AF_PACKET/TPACKET_V3, zero-copy) e v10.0 (VPS, Terraform, Nginx, Let's Encrypt, cluster RabbitMQ).
- `AMPLIFICATION` detecta um refletor DNS que só envia respostas quando o sensor vê a consulta forjada com origem fora de `HOME_NET` (o request é contado no IP de destino, numa tabela fixa de 64 servidores). Não detecta quando a vítima está em `HOME_NET` (gateway da vítima): o skip descarta a consulta. Com a mistura de consultas DNSSEC/ANY, um resolvedor pode disparar a partir de ~70 % de consultas com resposta de ~1 KB (medido com pcaps sintéticos: ratio acumulado 9,8 não dispara; 11,2 dispara).
- O `analyzer.c` depende de o Winsock ter sido inicializado por outra parte do programa para usar `inet_ntoa` no Windows; o benchmark mede ~3,6 mil pps lá porque substitui o AMQP, e não está provado que o agente real sofra o mesmo.
- O `ROADMAP.MD` e o `README.md` foram alinhados ao código em 2026-11 (PR #16), mas podem restar divergências: em caso de dúvida, **o código vale**.

## Documentação detalhada

Notas aprofundadas (versões, cada detecção, decisões de arquitetura, configuração) estão numa base de conhecimento em Obsidian mantida pelo autor e **não versionada** aqui. Para o que está no repositório, comece por `README.md` e `ROADMAP.MD`.
