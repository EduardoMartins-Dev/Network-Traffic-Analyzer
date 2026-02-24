# 🗺️ Roadmap: Network Traffic Analyzer (SOC Edition)

Este documento descreve a evolução do projeto **Network Traffic Analyzer**. Saímos de um sniffer básico para uma arquitetura de microsserviços focada em detecção de intrusão (IDS) em tempo real.

---

## ✅ Fase 1: Fundação e Captura (The Sniffer)
**Objetivo:** Garantir a captura de pacotes brutos e interação com a interface de rede.

- [x] **Hello World Libpcap:** Inicialização de dispositivo em modo promíscuo e loop de captura.
- [x] **Filtros BPF:** Implementação de filtros para focar em protocolos de interesse (TCP/UDP/ICMP).
- [x] **Aritmética de Ponteiros:** Lógica para "pular" cabeçalhos e extrair dados formatados.

## ✅ Fase 2: Camada de Mensageria (Middleware)
**Objetivo:** Desacoplar a captura do armazenamento para garantir alta performance.

- [x] **Infraestrutura RabbitMQ:** Serviço rodando via Docker na porta 5674.
- [x] **Serialização JSON:** Integração de lógica para converter pacotes em C para objetos JSON.
- [x] **Conector AMQP:** Publicação assíncrona utilizando a biblioteca `librabbitmq`.

## 🧠 Fase 3: Inteligência de Segurança (IDS Engine)
**Objetivo:** Implementar lógica de análise comportamental para detecção de anomalias em nível de kernel/user-space.

- [x] **Detector de Port Scan:** Identificação de varreduras baseada em limiar de portas únicas (TCP/UDP).
- [x] **Detector de DoS (ICMP Flood):** Identificação de inundação de pings por segundo.
- [x] **Gerenciamento de Estado:** Tabela de IPs suspeitos com **Garbage Collection** (limpeza de memória de IPs inativos).
- [ ] **Detecção de Stealth Scans:** Identificar flags TCP anômalas (Null, Xmas, SYN/FIN).

## ⚙️ Fase 4: O Worker e Persistência (The Ingestor)
**Objetivo:** Consumo de mensagens em alta velocidade e gravação em banco de dados Time Series.

- [x] **Python Data Ingestor:** Migração da ingestão para Python para maior flexibilidade e tratamento de erros.
- [x] **InfluxDB Schema:** Mapeamento de `src_ip` e `protocol` como tags para buscas ultra-rápidas.
- [x] **Ambiente Isolado:** Implementação de ambiente virtual (venv) para gestão de dependências Python.

## 📊 Fase 5: Visualização e Operação (SOC Dashboard)
**Objetivo:** Transformar métricas em inteligência visual para o analista.

- [x] **Grafana Integration:** Conexão Flux com InfluxDB funcionando.
- [ ] **Dashboards de Ameaças:** Painéis de "Ataques em Tempo Real" que piscam em vermelho no `is_scan == 1`.
- [ ] **Alertas Ativos:** Notificações automáticas via Telegram ou Discord ao detectar scans críticos.

## 🚀 Fase 6: Enriquecimento (Threat Intelligence) - PRÓXIMOS PASSOS
**Objetivo:** Adicionar contexto externo aos IPs capturados.

- [ ] **Geolocalização IP:** Integrar base MaxMind/GeoIP para mapear a origem geográfica dos ataques.
- [ ] **Reputação Global:** Consultar APIs de Threat Intel (AbuseIPDB) para identificar IPs já reportados como maliciosos.
- [ ] **WHOIS Integration:** Identificar a qual organização ou provedor pertence o IP atacante.

## ⚡ Fase 7: Alta Performance (Enterprise Tuning)
**Objetivo:** Otimizar o sensor C para redes de alta densidade.

- [ ] **Multi-threading:** Separar captura, análise e publicação em threads (`pthreads`) distintas.
- [ ] **Zero-Copy Capture:** Migrar de pcap padrão para AF_PACKET ou PF_RING para reduzir carga de CPU.

---
> *Este projeto evoluiu de um sensor acadêmico para uma arquitetura distribuída de defesa de rede.*
