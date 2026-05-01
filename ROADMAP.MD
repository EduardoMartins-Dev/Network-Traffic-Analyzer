# Roadmap: Network Traffic Analyzer

Evolução do projeto desde um sniffer básico até um **IDS comportamental com correlação de kill chain e narração por IA** — rodando em produção com infra provisionada via Terraform. **Stack 100% C** no caminho de dados (captura, análise, ingestão, narração).

```
v1.0    v2.0      v3.0         v4.0       v5.0       v5.5         v6.0           v7.0           v8.0          v9.0       v10.0
Captura→Mensageria→Agent/Server→IDS Engine→Multi-Thr→DX+LLM-Tools→AI Narrator(C)→nta-server→Threat Intel→Alta Perf→Prod + IaC
  ✅      ✅         ✅            ✅         ✅         ✅           PARCIAL(Py)    PARCIAL       PLANEJADO    PLANEJADO  PLANEJADO
```

> **Nota de ordem (revisão 2026-04):** o deploy em VPS foi movido para o **final** do roadmap (v10.0). Motivo: evitar pagar VPS + domínio durante o desenvolvimento das features (v6.0 → v9.0). A infra de produção entra só quando o stack estiver completo e estável localmente.
>
> **Nota de revisão 2026-05:** v6.0 implementado em **Python** (não em C como originalmente planejado). Decisão: priorizar tempo-de-feature; reescrita em C fica para v7.0 quando o `nta-server` for o único consumidor da fila. v5.5 inserida como camada de DX e ferramentas LLM auxiliares.

---

## Versões concluídas

### v1.0 — Fundação e Captura ✅

**Objetivo:** captura de pacotes brutos e interação com a interface de rede.

* Inicialização de dispositivo via libpcap em modo promíscuo
* Loop de captura com filtros BPF (TCP / UDP / ICMP)
* Parsing de cabeçalhos via aritmética de ponteiros (Ethernet → IP → TCP/UDP)

### v2.0 — Mensageria e IDS Engine ✅

**Objetivo:** desacoplar captura de armazenamento e implementar detecção comportamental.

* Infraestrutura RabbitMQ via Docker (porta 5674)
* Serialização de pacotes para JSON com cJSON
* Publicação assíncrona via librabbitmq (AMQP 0.9.1)
* Detector de Port Scan (limiar: ≥15 portas únicas por IP)
* Detector de ICMP Flood (limiar: ≥20 pacotes por IP)
* Tabela de IPs suspeitos com garbage collection (timeout: 300s)
* Ingestor Python: RabbitMQ → InfluxDB com enriquecimento GeoIP *(substituído pelo `nta-server` em C na v7.0)*
* Schema InfluxDB com tags indexadas (`src_ip`, `protocol`)
* Integração Grafana com datasource InfluxDB (Flux)

### v3.0 — Arquitetura Agent/Server ✅

**Objetivo:** transformar o sniffer em um agente distribuído configurável, inspirado no modelo Zabbix.

* Configuração 100% via variáveis de ambiente (zero recompilação)
* Suporte a TLS/SSL na conexão AMQP (`AGENT_USE_TLS=1`)
* Modo produção: validação de CA com `AGENT_CA_CERT`
* Fila durável (`durable=1`) e mensagens persistentes (`delivery_mode=2`)
* Verificação de privilégios multiplataforma (`#ifdef _WIN32`)
* Listagem automática de interfaces com `pcap_findalldevs`
* CMakeLists.txt multiplataforma: Linux (libpcap) e Windows (Npcap SDK)

### v4.0 — IDS Engine avançado ✅

> **Prioridade máxima.** A infraestrutura (RabbitMQ, InfluxDB, Grafana, Docker, TLS) está madura. O motor de detecção precisa acompanhar. Hoje o projeto detecta 2 tipos de ataque; esta versão leva para 8+, cobrindo a cadeia completa de reconhecimento → exploração → exfiltração.

**Novas detecções no `analyzer.c`:**

* **SYN Flood:** contador de pacotes SYN sem ACK correspondente por IP de origem. Limiar adaptativo baseado no baseline do IP
* **Stealth Scans:** detecção de combinações anômalas de TCP flags:
  * Null Scan (flags = 0x00)
  * Xmas Scan (FIN + PSH + URG)
  * SYN/FIN Scan (SYN + FIN simultâneos)
* **DNS Tunneling:** análise de payload DNS — subdomains anormalmente longos (>50 chars), volume anômalo de queries para o mesmo domínio, entropia alta no subdomain (base64/hex encoding)
* **ARP Spoofing:** tabela MAC→IP mantida em memória. Alerta quando um MAC já associado a um IP aparece reivindicando outro (gratuitous ARP com IP diferente)
* **SSH/FTP Brute Force:** contador de conexões SYN para portas 22/21/3389 por IP de origem em janela de tempo. Limiar: ≥30 tentativas em 60 segundos
* **DDoS Amplification:** detecção de respostas DNS/NTP desproporcionais ao volume de requests (response ratio > 10:1)

**Baseline adaptativo (EWMA):**

* Cada IP rastreado mantém um `ip_baseline_t` com média móvel exponencialmente ponderada de: pacotes/segundo, portas únicas/minuto, DNS queries/minuto, proporção TCP/UDP/ICMP
* Período de calibração: primeiras 100 amostras com alpha=0.3 (aprende rápido), depois alpha=0.1 (adapta devagar)
* Detecção de anomalia: alerta quando `|valor_atual - ewma| > N * stddev` (sigma threshold configurável)
* Elimina thresholds hardcoded — cada rede aprende seus próprios limites

**Kill chain correlator:**

* Máquina de estados por IP: `IDLE → RECON → EXPLOIT → EXFIL → COMPLETE`
* Eventos avançam o estágio dentro de uma janela temporal (default: 30 minutos)
* Score de severidade 0-100 baseado no número de estágios completados + velocidade de progressão + criticidade das portas alvo
* Agrupamento de alertas em "incidentes" — em vez de 5 alertas separados, um incidente com contexto completo
* Mapeamento de cada detecção para MITRE ATT&CK techniques (tags no JSON publicado)

**Impacto estimado:**

* Cobertura de ameaças: 2/8 → 8/8 vetores comuns
* Cobertura MITRE ATT&CK: 3 → 14+ techniques
* Falsos negativos estimados: ~78% → ~35%
* Overhead de CPU: +60% por pacote (~0.8µs → ~1.3µs) — ainda suporta 85k+ pps

---

### v4.1 — PCAP Replay e Test Framework ✅

> **Qualidade de engenharia.** Sem testes reprodutíveis, cada nova detecção pode quebrar as existentes. Esta versão cria o framework que valida o IDS com tráfego real capturado.

**Modo replay no agente:**

* Flag `--replay <arquivo.pcap>` que lê pacotes de um arquivo em vez da interface de rede
* Flag `--expect <gabarito.json>` com lista de detecções esperadas (tipo, IP, janela de tempo)
* Output estruturado: `[PASS]`/`[FAIL]` por detecção + score final (% de acerto)
* Suporte a diretório de pcaps: `--replay-dir attacks/` executa todos os arquivos e gera relatório consolidado

**Dataset de testes:**

* PCAPs curados de ataques conhecidos: CICIDS2017, Malware Traffic Analysis, CTF captures
* Um pcap por tipo de ataque: `syn-flood.pcap`, `null-scan.pcap`, `dns-tunnel.pcap`, `arp-spoof.pcap`
* Gabaritos JSON com tempos esperados e tolerâncias

**CI/CD no GitHub Actions:**

* Workflow `.github/workflows/test-ids.yml` executado a cada PR
* Compila o agente, roda replay em todos os pcaps, valida detecções
* Badge no README: ![IDS Score](https://img.shields.io/badge/IDS_Score-87%25-green)
* Fail automático se score cair abaixo de 80%

---

### v5.0 — Multi-Threading e Performance ✅

> **Recuperar throughput.** As novas detecções da v4.0 adicionam overhead ao pipeline single-thread. Esta versão separa captura, análise e publicação em threads independentes, triplicando o throughput.

**Pipeline multi-thread com pthreads:**

* Thread 1 (captura): `pcap_loop()` → ring buffer lock-free. Prioridade SCHED_FIFO (best-effort)
* Thread 2 (análise): ring buffer → `analyzer.c` → segundo ring buffer. Roda EWMA + correlator
* Thread 3 (publicação): ring buffer → batch AMQP publish. Agrupa N eventos em array JSON
* Thread 4 (métricas): publica profundidade dos buffers, overflows e throughput em routing key separada

**Ring buffer lock-free:**

* Implementação SPSC (Single Producer, Single Consumer) sem mutex
* Baseado em C11 `<stdatomic.h>` com memory ordering acquire/release
* Tamanho configurável via env var `AGENT_BUFFER_SIZE` (default: 4096 slots; arredondado para pow2)
* Contador atômico de overflow para pacotes descartados por buffer cheio

**Batch publishing:**

* Acumula N eventos (default: `AGENT_BATCH_SIZE=50`) ou timeout de `AGENT_BATCH_TIMEOUT_MS=100`
* Serializa todos os eventos em um único array JSON com cJSON e publica em uma única chamada AMQP
* Ingestor atualizado para aceitar tanto arrays (v5.0) quanto objetos únicos (compat)

**Impacto estimado:**

* Throughput: 85k pps (single-thread v4) → 350k+ pps (multi-thread)
* Suporta links de 1 Gbps sem packet loss
* Latência de publicação: reduzida ~10x com batching

---

### v5.5 — DX e LLM Tooling ✅

> **Reduzir atrito de instalação e expandir uso do LLM além de narrativas.** Versão transversal: não introduz feature de detecção, mas elimina horas de setup manual e adiciona geração de dashboards via LLM local.

**Onboarding unificado:**

* `scripts/install.sh` — bootstrap idempotente. Detecta SO (apt/dnf/pacman/pkg/brew) e instala todo o stack (server + agente). Flags `--server-only`, `--agent-only`, `--no-build`. Aplica `setcap cap_net_raw` no binário automaticamente
* `scripts/quickstart.sh` — orquestra `install` → `up` → `smoke-test`. Path zero-a-rodando em uma chamada
* `scripts/up.sh --foreground` — consolida o antigo `server-up.sh` (que virou wrapper de back-compat). Default continua background
* `Makefile` na raiz — atalhos: `install`, `quickstart`, `up`, `down`, `build`, `agent IFACE=`, `smoke`, `dash NAME= DESC=`, `clean`

**LLM Dashboard Generator (`scripts/dash_gen.py`):**

* CLI Python que recebe descrição em PT-BR e gera dashboard Grafana
* Backend LLM: Ollama local (mesmo container do narrator) — modelo default `llama3.1:8b` (configurável via `DASH_GEN_MODEL`)
* Prompt inclui schema do InfluxDB (measurements, tags, fields) — LLM nunca inventa nomes de campo
* Validação estrutural: panels mínimos, queries Flux começam com `from(bucket:`, ids únicos, datasource UID correto
* **Publicação via Grafana API** (`POST /api/dashboards/db`) — dashboard aparece no UI imediatamente, é editável e persiste em `grafana_data`
* Auth: basic auth admin/admin (default) ou service account token (`GRAFANA_API_KEY`)
* `--save-file` opcional para também versionar o JSON em `grafana/dashboards/`
* Tags `nta` + `ai-gen` + UID `nta-ai-<slug>` para diferenciar de dashboards versionados manualmente
* Reuso do `requests` já em `requirements.txt` — zero deps novas

**Impacto:**

* Setup do projeto: ~30 minutos (manual, multi-passo) → ~5 minutos (`make quickstart`)
* Dashboards: criação manual no Grafana (10-30 min/dash) → `make dash NAME=foo DESC="..."` (~30s)
* Cobertura multi-distro: testado mentalmente p/ Debian, Fedora, Arch, FreeBSD, macOS
* Desbloqueia v10.0 (deploy VPS): bootstrap.sh do Terraform vai reusar `install.sh`

---

## Próximas versões

### v5.1 — Validação Windows (pausada)

> **Confirmar suporte multiplataforma com as novas features.**
> Status: pausada por falta de máquina Windows física para teste — será retomada quando houver acesso a um host Windows.

* Compilar v4+v5 com MinGW-w64 / Visual Studio no Windows
* Validar captura via Npcap + análise multi-thread em ambiente real
* Ajustar nomes de interface para formato GUID (`\Device\NPF_{...}`)
* Testar publicação AMQP (TCP e TLS) a partir do Windows
* Thread API: `pthreads-w32` ou `_beginthreadex` nativo do Windows

---

### v6.0 — AI Narrator (LLM Integration)

> **Status (2026-05):** **PARCIAL — implementado em Python**, não em C.
>
> O `src/ingestor/narrator.py` chama LLM (Ollama local OU Groq cloud) quando um incidente passa do `NARRATOR_MIN_SCORE` (default 80). A narrativa é gravada na measurement `incident_narrative` no InfluxDB e exibida no painel "Narrativas IA" do dashboard.
>
> **Decisão de arquitetura:** narrator em C foi adiado para v7.0 (junto com a reescrita do ingestor → `nta-server`). Razão: implementar em Python desbloqueou a feature em ~1 dia vs ~1 semana em C, e o fluxo continua válido — só o consumidor muda. As partes restantes do escopo original (roteamento inteligente entre 3 modelos, batch API, prompt caching) ficam para a versão C.

**Implementado:**

* Backend dual: Ollama (default, sem custo, roda local) ou Groq cloud
* Threshold configurável (`NARRATOR_MIN_SCORE`)
* Sistema prompt fixo em PT-BR no formato "INCIDENT | Severidade | O QUE ACONTECEU | POR QUÊ | AÇÃO | MITRE"
* Carregamento automático de `GROQ_API_KEY` de `deploy/secrets/groq.env`
* Métrica `incident_narrative` no InfluxDB com tags `agent_id`, `src_ip`, `attack_type`, `kill_chain_stage`, `backend`
* Logs estruturados de chamadas LLM no ingestor (`📝 [NARRATIVE]`)

**Restante (movido para v7.0 — narrator em C):**

**Arquitetura do narrator:**

* Thread dedicada no agente (ou no `nta-server` quando v7.0 for entregue): a cada N segundos busca incidentes pendentes (sem narrativa)
* Para cada incidente, monta JSON de request com cJSON: system prompt + JSON do incidente + metadados GeoIP + baselines do IP
* Chamada HTTP POST ao Groq API via libcurl: latência ~1-2s, throughput 394 tok/s
* Parse da resposta com cJSON, narrativa extraída e gravada no InfluxDB via HTTP API (libcurl)
* **Thread isolada**: não bloqueia consumo da fila nem análise de pacotes

**Roteamento inteligente de modelos:**

* Score < 50: Llama 3.1 8B Instant ($0.05/$0.08 por MTok) — triage rápido
* Score 50-80: Qwen3 32B ($0.29/$0.59 por MTok) — narrativa intermediária
* Score > 80: Llama 3.3 70B Versatile ($0.59/$0.79 por MTok) — narrativa completa com recomendações
* Batch API para incidentes não-urgentes (50% de desconto)
* Prompt caching para system prompt fixo (50% de desconto no input)

**Formato da narrativa:**

```
INCIDENT-0042 | Severidade: Crítica (94/100) | 2026-XX-XX 09:08:12 UTC

O QUE ACONTECEU:
Host 192.168.1.50 (TTL=128, provável Windows) iniciou ataque coordenado
contra servidor .100. Sequência: ARP spoofing (T+0s) → null scan (T+45s) →
brute force SSH com ~200 tentativas (T+5min) → exfiltração via DNS tunnel
com subdomains codificados em base64 (T+8min).

POR QUE É CRÍTICO:
4 de 5 estágios da kill chain completos. DNS tunneling ativo — dados
saindo agora. Volume: 47 queries/min vs baseline de 3/min.

AÇÃO RECOMENDADA:
iptables -A INPUT -s 192.168.1.50 -j DROP
Verificar logs SSH de .100. Decodificar DNS queries para identificar dados exfiltrados.

MITRE ATT&CK: T1557, T1046, T1110, T1071.004, T1498
```

**Custo estimado:**

* ~100 incidentes/dia × ~2.5k tokens × 30 dias = ~7.5M tokens/mês
* Roteamento inteligente: ~80% no 8B + ~15% no 32B + ~5% no 70B
* Custo total: ~US$ 1.70/mês (~R$ 9/mês)

---

### v7.0 — Escalabilidade, Multi-Agente e Ingestão Elástica

> **Status (2026-05):** **PARCIAL — esqueleto C presente, integração pendente.**
>
> Headers já criados: `nta_server.h`, `nta_consumer.h`, `nta_influx.h`, `nta_geoip.h`. Sources em `src/server/`. CMake já produz binário `nta-server` ligado a libcurl + libmaxminddb. Falta: thread pool adaptativo, integração com narrator (porta do Python para C), substituição do `data_ingestor.py` no `up.sh`, RabbitMQ cluster.

> **Quando um único agente não é suficiente.** Preparar o sistema para operar com múltiplos agentes reportando para o mesmo servidor central, com capacidade de processamento que escala automaticamente.

**`nta-server` — Servidor Central em C:**

Binário C que substitui o ingestor Python. Responsável por:
* Consumir fila RabbitMQ (librabbitmq — mesma lib do agente)
* Parsear eventos com cJSON (já no projeto)
* Enriquecer com GeoIP offline via libmaxminddb (~1µs por lookup)
* Gravar no InfluxDB via HTTP API (libcurl)
* Chamar Groq API para narrativas (libcurl + cJSON, thread isolada)
* **Dependência nova: apenas libcurl. Zero Python.**

**Arquitetura elástica (thread pool adaptativo):**

> O servidor não deve ter capacidade fixa. O número de threads consumidoras cresce e encolhe com base na profundidade da fila RabbitMQ — latência baixa em picos, zero desperdício em períodos quietos.

```
┌──────────────────────────────────────────────┐
│           nta-server (processo único C)       │
│                                              │
│  ┌─────────────────────────────────────────┐ │
│  │  Scaler Thread (monitora queue_depth)   │ │
│  │  depth > HIGH_WATERMARK → +1 thread     │ │
│  │  depth < LOW_WATERMARK  → -1 thread     │ │
│  │  Limites: MIN_THREADS=1, MAX_THREADS=8  │ │
│  └────────────┬────────────────────────────┘ │
│               │ pthread_create / pthread_join │
│    ┌──────────┼──────────┐                   │
│  Worker-1  Worker-2  Worker-N                │
│  (consume) (consume) (consume)               │
│    └──────────┼──────────┘                   │
│           RabbitMQ Queue                     │
│                                              │
│  ┌─────────────────────────────────────────┐ │
│  │  Narrator Thread (a cada 5min)          │ │
│  │  incidentes → Groq API → InfluxDB      │ │
│  └─────────────────────────────────────────┘ │
│                                              │
│  ┌─────────────────────────────────────────┐ │
│  │  Metrics Thread                         │ │
│  │  worker_count, queue_depth → InfluxDB   │ │
│  └─────────────────────────────────────────┘ │
└──────────────────────────────────────────────┘
```

* Scaler consulta Management API do RabbitMQ (`/api/queues`) via libcurl a cada N segundos
* Threads consumidoras usam `prefetch_count` para distribuição justa de carga
* Métricas do scaler exportadas ao InfluxDB: `worker_count`, `queue_depth`, `scale_events`
* Graceful shutdown: SIGTERM → sinaliza todas as threads → `pthread_join` em cada uma

**RabbitMQ cluster (3 nodes):**

* Quorum queues com Raft consensus para alta disponibilidade
* Consistent-hash-exchange para sharding por `agent_id`
* HAProxy na frente para load balancing das conexões AMQP

**Provisionamento de agentes:**

* mTLS: certificado de cliente único por agente
* Registro via API REST com `AGENT_ID` e `AGENT_TOKEN`
* Dashboard Grafana com visão multi-host (filtro por `agent_id`)
* Alertas específicos por agente: "Host A offline há 5 minutos"

**InfluxDB otimizado:**

* Retention policies: hot (7 dias), warm (downsampled 90 dias), cold (export para S3/MinIO)
* Flux tasks de downsampling automático: agregação por minuto em vez de por segundo
* Tags adicionais: `agent_id`, `kill_chain_stage`, `mitre_technique`

---

### v8.0 — Threat Intelligence

> **Enriquecer eventos com contexto externo em C.** Transformar IPs em informação acionável.

* MaxMind GeoIP2 via libmaxminddb para geolocalização offline (cidade + ASN) — ~1µs por lookup
* AbuseIPDB API via libcurl + cJSON: reputação de IPs (score de abuso, reports anteriores)
* Cache em memória (hashtable C) com TTL de 24h para evitar chamadas repetidas
* WHOIS lookup via socket TCP na porta 43 — implementação nativa em C
* Intel framework: lista de IoCs (IPs, hashes, domínios) carregada de arquivo. Alerta automático quando um IoC aparece no tráfego

---

### v9.0 — Alta Performance

> **Para redes de alta densidade.** Otimizações que só fazem sentido em links de 1 Gbps+.

* Migração de libpcap para AF_PACKET com TPACKET_V3 (mmap ring buffer no kernel)
* Zero-copy capture: pacotes vão direto do NIC para userspace sem cópia kernel
* PF_RING como alternativa para NICs Intel com drivers compatíveis
* NUMA-aware pinning: threads fixadas em CPUs do mesmo domínio NUMA que a NIC
* Métricas de performance: packet loss rate, CPU por core, ring buffer utilization

---

### v10.0 — Produção, IaC e Observabilidade (deploy final)

> **Infra de produção real — deixada por último.** Antes de pagar VPS + domínio, todas as features (v6.0 → v9.0) precisam estar prontas e estáveis localmente. Aqui o projeto sai do Docker Compose local para uma VPS acessível na internet, provisionada via Terraform, com HTTPS, domínio próprio e dashboards públicos.

**Stack de produção (budget: ~R$ 40/mês):**

| Componente | Serviço | Custo |
|---|---|---|
| VPS | Hetzner CX22 (2 vCPU, 4 GB, 40 GB SSD) | ~R$ 25/mês |
| LLM API | Groq Developer (Llama 3.3 70B) | ~R$ 9/mês |
| Domínio | `.dev` via Google Domains / Namecheap | ~R$ 5/mês |
| DNS + CDN | Cloudflare (free tier) | R$ 0 |
| CI/CD | GitHub Actions (free para OSS) | R$ 0 |
| GeoIP | MaxMind GeoLite2 (free com registro) | R$ 0 |
| Alertas | Telegram Bot API | R$ 0 |
| Dashboard | Grafana (self-hosted na VPS) | R$ 0 |

**Terraform (Infrastructure-as-Code):**

* `main.tf`: provisionamento da VPS Hetzner via provider `hcloud`
* `dns.tf`: registros DNS no Cloudflare (subdomínios `grafana.*`, `rabbitmq.*`, `docs.*`)
* `bootstrap.sh`: script de user-data que instala Docker, clona o repo, e sobe Docker Compose
* `variables.tf`: tokens e configs parametrizadas (nunca hardcoded)
* Documentação: `terraform plan` → `terraform apply` → sistema rodando em < 5 minutos

**Nginx reverse proxy + TLS:**

* Nginx na VPS como entry point único na porta 443
* Subdomínios roteados para containers internos:
  * `grafana.seuids.dev` → Grafana :3000
  * `rabbitmq.seuids.dev` → RabbitMQ Management :15672
  * `docs.seuids.dev` → Static docs site
* Certificados TLS automáticos via Let's Encrypt + Certbot
* Headers de segurança: HSTS, X-Content-Type-Options, X-Frame-Options

**Dashboards Grafana otimizados para demo:**

* Painel 1: "Live traffic" — gráfico de linha com pacotes/segundo em tempo real
* Painel 2: "Threat map" — tabela de IPs suspeitos com GeoIP, tipo de ataque, score
* Painel 3: "Kill chain timeline" — timeline visual de incidentes com estágios coloridos
* Painel 4: "AI narrative" — texto do LLM narrator exibindo a última narrativa de incidente
* Painel 5: "Detection score" — gauge mostrando taxa de detecção do IDS (alimentado pelo replay)
* Viewer anônimo habilitado (entrevistadores acessam sem login)

**Alertas em tempo real:**

* Telegram: mensagem formatada com tipo de ataque, IP, score, e ação recomendada
* Grafana alerting: thresholds configuráveis por tipo de detecção
* Webhook genérico: integração futura com Slack/Discord/PagerDuty

---

## Referência: Stack de Produção Recomendada

```
┌────────────────────────────────────────────────────────────────┐
│  Agentes (hosts monitorados)                                   │
│  libpcap → analyzer.c (EWMA + kill chain) → publisher.c       │
│  Configuração 100% via env vars | Suporte Linux + Windows      │
└────────────────────────┬───────────────────────────────────────┘
                         │ AMQP / TLS
┌────────────────────────▼───────────────────────────────────────┐
│  Hetzner VPS CX22 (~R$ 25/mês) — Docker Compose               │
│                                                                │
│  ┌──────────┐  ┌──────────────┐  ┌──────────┐  ┌───────────┐ │
│  │RabbitMQ  │→ │ nta-server   │→ │InfluxDB  │→ │  Grafana  │ │
│  │  :5672   │  │  (C + curl)  │  │  :8086   │  │  :3000    │ │
│  └──────────┘  └──────────────┘  └──────────┘  └───────────┘ │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ Nginx reverse proxy (:443) + Let's Encrypt TLS          │ │
│  │ grafana.seuids.dev | rabbitmq.seuids.dev | docs.*       │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                                │
│  Provisionado via Terraform | CI/CD via GitHub Actions         │
└────────────────────────────────────────────────────────────────┘
```

**Budget mensal: ~R$ 39/mês (buffer de R$ 21 reservado)**

---

## Referência: Cobertura MITRE ATT&CK por versão

| Tática | Technique | v3.0 | v4.0 |
|---|---|---|---|
| Reconnaissance | T1046 Network scan | ✅ | ✅ |
| Reconnaissance | T1018 Remote discovery | — | ✅ |
| Discovery | T1040 Network sniffing | — | ✅ |
| Discovery | T1016 System network | — | ✅ |
| Lateral Movement | T1557 ARP spoofing | — | ✅ |
| Credential Access | T1110 Brute force | — | ✅ |
| Command & Control | T1071 DNS tunneling | — | ✅ |
| Command & Control | T1571 Non-standard port | — | ✅ |
| Exfiltration | T1048 Exfil over DNS | — | ✅ |
| Impact | T1498 ICMP flood | ✅ | ✅ |
| Impact | T1498 SYN flood | — | ✅ |
| Impact | T1498 Amplification | — | ✅ |
| **Total** | | **3** | **14** |

---

## Referência: Comparativo com IDS do mercado

| Feature | Suricata | Snort 3 | Zeek | Wazuh | NTA (este projeto) |
|---|---|---|---|---|---|
| Detecção por assinatura | 40k+ regras | 30k+ regras | Via scripts | Via decoder | — |
| Detecção comportamental | Limitada | — | Via scripts | Limitada | **EWMA + baselines** |
| Kill chain correlation | — | — | — | Parcial | **Nativo** |
| LLM narrative | — | — | — | — | **Groq + Llama (C)** |
| PCAP replay testing | Suricata-verify | — | Btest | — | **Integrado + CI/CD** |
| Multi-threading | Nativo | Snort 3+ | Cluster mode | N/A | **v5.0 (pthreads)** |
| Agent/Server | — | — | Cluster | **Nativo** | **Nativo** |
| Infra as Code | — | — | — | Ansible | **Terraform** |
| Stack de dados | — | — | — | — | **100% C (zero Python)** |
| Custo de operação | Free | Free | Free | Free | **~R$ 39/mês** |
