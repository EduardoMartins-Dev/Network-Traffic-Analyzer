# Roadmap: Network Traffic Analyzer

Evolução do projeto desde um sniffer básico até uma arquitetura distribuída Agent/Server de detecção de intrusão em tempo real.

---

## v1.0 — Fundação e Captura

**Objetivo:** captura de pacotes brutos e interação com a interface de rede.

- [x] Inicialização de dispositivo via libpcap em modo promíscuo
- [x] Loop de captura com filtros BPF (TCP / UDP / ICMP)
- [x] Parsing de cabeçalhos via aritmética de ponteiros (Ethernet → IP → TCP/UDP)

---

## v2.0 — Mensageria e IDS Engine

**Objetivo:** desacoplar captura de armazenamento e implementar detecção comportamental.

- [x] Infraestrutura RabbitMQ via Docker (porta 5674)
- [x] Serialização de pacotes para JSON com cJSON
- [x] Publicação assíncrona via librabbitmq (AMQP 0.9.1)
- [x] Detector de Port Scan (limiar: ≥15 portas únicas por IP)
- [x] Detector de ICMP Flood (limiar: ≥20 pacotes por IP)
- [x] Tabela de IPs suspeitos com garbage collection (timeout de inatividade: 300s)
- [x] Ingestor Python: RabbitMQ → InfluxDB com enriquecimento GeoIP
- [x] Schema InfluxDB com tags indexadas (`src_ip`, `protocol`)
- [x] Integração Grafana com datasource InfluxDB (Flux)

---

## v3.0 — Arquitetura Agent/Server (atual)

**Objetivo:** transformar o sniffer em um agente distribuído configurável, inspirado no modelo Zabbix.

- [x] Configuração 100% via variáveis de ambiente (zero recompilação para trocar de servidor)
- [x] Suporte a TLS/SSL na conexão AMQP (`AGENT_USE_TLS=1`)
- [x] Modo produção: validação de CA com `AGENT_CA_CERT`
- [x] Fila durável (`durable=1`): sobrevive a reinicializações do broker
- [x] Mensagens persistentes (`delivery_mode=2`): eventos forenses não são perdidos
- [x] Verificação de privilégios multiplataforma (`#ifdef _WIN32`: `IsUserAnAdmin` vs `getuid`)
- [x] Listagem automática de interfaces com `pcap_findalldevs` (Linux e Windows)
- [x] CMakeLists.txt multiplataforma: bloco `if(WIN32)` com Npcap SDK, `wpcap.lib` e `Ws2_32`
- [x] Remoção de arquivos obsoletos (`output.c`, `output.h`, `ingestor_obsoleto.c`)

---

## v3.1 — Validação Windows

**Objetivo:** confirmar compilação e captura nativa no Windows com Npcap.

- [ ] Compilar com MinGW-w64 / Visual Studio no Windows
- [ ] Validar captura de pacotes via Npcap em ambiente real
- [ ] Ajustar nomes de interface para o formato GUID do Windows (`\Device\NPF_{...}`)
- [ ] Testar publicação AMQP (TCP e TLS) a partir do Windows

---

## v4.0 — Servidor Central e Multi-Agente

**Objetivo:** operação real com múltiplos agentes enviando para um servidor centralizado.

- [ ] RabbitMQ central exposto com AMQPS (porta 5671) e TLS configurado
- [ ] Provisionamento de usuários AMQP por agente (um token por host)
- [ ] mTLS: certificado de cliente único por agente para autenticação criptográfica
- [ ] Ingestor Python adaptado para identificar origem do agente (tag `agent_id`)
- [ ] Dashboard Grafana com visão multi-host e alertas de `is_scan == 1`

---

## v5.0 — Threat Intelligence

**Objetivo:** enriquecer eventos com contexto externo.

- [ ] Integração MaxMind GeoIP para geolocalização offline
- [ ] Consulta AbuseIPDB para reputação de IPs
- [ ] Integração WHOIS para identificar ASN e provedor do atacante
- [ ] Detecção de Stealth Scans (flags TCP anômalas: Null, Xmas, SYN/FIN)

---

## v6.0 — Alertas e Alta Performance

**Objetivo:** notificações em tempo real e otimização para redes de alta densidade.

- [ ] Notificações automáticas via Telegram / Discord ao detectar scans críticos
- [ ] Multi-threading: separar captura, análise e publicação em threads (`pthreads`)
- [ ] Zero-copy capture: migrar para AF_PACKET ou PF_RING para reduzir CPU

---

> *Do sniffer acadêmico à arquitetura distribuída de defesa de rede.*
