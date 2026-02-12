# 🗺️ Roadmap: Network Traffic Analyzer

Este documento descreve o plano de evolução do projeto, dividido em fases incrementais de complexidade, do básico ao avançado.

## 🏁 Fase 1: Fundação e Captura (The Sniffer)
**Objetivo:** Estabelecer o ambiente de desenvolvimento e realizar a captura básica de pacotes.

- [ ] **Configuração do Lab:**
    - [ ] Subir VM Kali Linux (Monitor) e VM Alvo.
    - [ ] Garantir conectividade isolada (Host-only/NAT Network).
- [ ] **Hello World Libpcap:**
    - [ ] Inicializar dispositivo de rede.
    - [ ] Loop de captura simples.
    - [ ] Imprimir mensagem a cada pacote recebido.
- [ ] **Filtros Básicos:**
    - [ ] Aplicar filtros BPF para capturar apenas TCP/UDP.

## 🧠 Fase 2: O Motor de Análise (Protocol Dissector)
**Objetivo:** Traduzir bytes brutos em informações estruturadas (IPs, Portas).

- [ ] **Estruturas de Dados (Structs):**
    - [ ] Mapear cabeçalho Ethernet (MAC Address).
    - [ ] Mapear cabeçalho IP (IP Src/Dst, Protocolo).
    - [ ] Mapear cabeçalho TCP (Portas, Flags).
- [ ] **Lógica de Ponteiros:**
    - [ ] Implementar aritmética de ponteiros para navegar pelos cabeçalhos.
    - [ ] Extrair e imprimir: `[PROTOCOLO] IP_Origem -> IP_Destino : Porta`.

## ⚙️ Fase 3: Escalabilidade (Multithreading) - OPCIONAL 
**Objetivo:** Desacoplar a captura da análise para alta performance.

- [ ] **Arquitetura Produtor-Consumidor:**
    - [ ] Criar Thread de Captura (Produtor) e Thread de Análise (Consumidor).
- [ ] **Gerenciamento de Memória:**
    - [ ] Implementar buffer circular.
    - [ ] Utilizar Mutex para evitar condições de corrida (*Race Conditions*).

## 📊 Fase 4: Pipeline de Dados & Visualização
**Objetivo:** Integração com banco de dados e dashboards gráficos.

- [ ] **Infraestrutura Docker:**
    - [ ] Criar `docker-compose.yml` para InfluxDB e Grafana.
- [ ] **Conector de Dados (C):**
    - [ ] Implementar cliente HTTP (`libcurl`) ou Socket UDP.
    - [ ] Formatar dados para o *Line Protocol* do InfluxDB.
- [ ] **Grafana Dashboard v1:**
    - [ ] Gráficos de Throughput e Pacotes/seg.
    - [ ] Tabela de logs em tempo real.

## 🛡️ Fase 5: Inteligência de Segurança (Security Engine)
**Objetivo:** Implementar regras de detecção de intrusão (IDS).

- [ ] **Análise de Flags TCP:**
    - [ ] Detectar varreduras suspeitas (Null Scan, Xmas Scan).
- [ ] **Detector de Port Scan:**
    - [ ] Algoritmo para identificar varredura de portas em curto intervalo.
- [ ] **Detector de Anomalia de Tráfego:**
    - [ ] Detecção de picos repentinos (possível DoS).
- [ ] **Alertas:**
    - [ ] Enviar logs críticos para painel de alertas.
