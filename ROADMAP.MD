# 🗺️ Roadmap: Network Traffic Analyzer (Enterprise Architecture)

Este documento descreve o plano de evolução do projeto **Network Traffic Analyzer**, focado em alta performance, escalabilidade e desacoplamento de serviços utilizando uma **Arquitetura Orientada a Eventos (EDA)**.

---

## 🏁 Fase 1: Fundação e Captura (The Sniffer)
**Objetivo:** Estabelecer o ambiente de desenvolvimento e garantir que o código em C consiga "enxergar" e interagir com a interface de rede via `libpcap`.

- [ ] **Configuração do Lab:**
    - [ ] Subir VM Kali Linux (Monitor) e VM Alvo.
    - [ ] Garantir conectividade isolada (Host-only/NAT Network).
- [ ] **Hello World Libpcap:**
    - [ ] Inicializar dispositivo de rede em modo promíscuo.
    - [ ] Implementar loop de captura simples (`pcap_loop`).
    - [ ] Imprimir mensagem no terminal a cada pacote recebido.
- [ ] **Filtros BPF (Berkeley Packet Filter):**
    - [ ] Aplicar filtros para ignorar tráfego SSH (porta 22).
    - [ ] Focar a captura apenas em protocolos de interesse (TCP/UDP/ICMP).

## 🧠 Fase 2: O Motor de Análise (Protocol Dissector)
**Objetivo:** Traduzir bytes brutos (*Raw Data*) capturados do cabo de rede em informações estruturadas e legíveis.

- [ ] **Estruturas de Dados (Structs):**
    - [ ] Mapear cabeçalho Ethernet (MAC Address).
    - [ ] Mapear cabeçalho IP (IP Src/Dst, TTL, Protocolo).
    - [ ] Mapear cabeçalho TCP/UDP (Portas, Flags).
- [ ] **Aritmética de Ponteiros:**
    - [ ] Implementar lógica matemática para "pular" cabeçalhos (Offset) e ler o payload.
    - [ ] Extrair e exibir dados formatados: `[TCP] 192.168.1.5:443 -> 192.168.1.10:55432`.

## 🐇 Fase 3: Camada de Mensageria & Serialização (Middleware)
**Objetivo:** Desacoplar a captura do armazenamento. O Sniffer (C) não deve gravar no banco diretamente para não perder performance; ele apenas "avisa" a fila.

- [ ] **Infraestrutura RabbitMQ:**
    - [ ] Adicionar serviço `rabbitmq` ao `docker-compose.yml`.
    - [ ] Configurar *Exchange* e *Queue* (ex: `network_events`).
- [ ] **Serialização de Dados (C para JSON):**
    - [ ] Integrar biblioteca de JSON em C (`cJSON` ou `Jansson`).
    - [ ] Criar função `packet_to_json()`: Converter a `struct` do pacote em string JSON.
- [ ] **Conector AMQP (C Client):**
    - [ ] Integrar biblioteca `rabbitmq-c` (librabbitmq).
    - [ ] Implementar conexão persistente com o Broker.
    - [ ] Publicar JSON na fila a cada pacote processado.

## ⚙️ Fase 4: O Consumidor e Persistência (The Worker)
**Objetivo:** Ler da fila em alta velocidade e gravar no banco de dados de forma assíncrona.

- [ ] **Worker Service (Python/Go/Telegraf):**
    - [ ] Criar um script/serviço separado que escuta a fila do RabbitMQ.
    - [ ] *Nota:* Isso remove a carga de I/O (Input/Output) do programa principal em C.
- [ ] **Banco de Dados (Time Series):**
    - [ ] Configurar **InfluxDB** via Docker.
    - [ ] Implementar escrita em lote (*Batch Write*) para otimizar performance.
    - [ ] Gravar métricas essenciais: `bytes_sent`, `packets_count`, `flags_detected`.

## 📊 Fase 5: Visualização e Operação (SOC Dashboard)
**Objetivo:** Transformar dados brutos em inteligência visual para o analista de segurança.

- [ ] **Grafana Setup:**
    - [ ] Conectar Grafana ao InfluxDB (DataSource).
- [ ] **Dashboards Operacionais:**
    - [ ] **Velocímetro:** Throughput da rede em tempo real (MB/s).
    - [ ] **Top Talkers:** Ranking dos IPs que mais geram tráfego.
    - [ ] **Mapa de Calor:** Portas e serviços mais acessados.
    - [ ] **Indicador de Ameaças:** Contagem de pacotes suspeitos/anômalos.

## 🛡️ Fase 6: Inteligência de Segurança (IDS Engine)
**Objetivo:** Implementar lógica de análise comportamental para detecção de intrusão.

- [ ] **Análise de Flags TCP:**
    - [ ] Detectar combinações anômalas (Ex: *Null Scan*, *Xmas Scan*).
- [ ] **Detector de Port Scan:**
    - [ ] Implementar lógica temporal: "Se IP X acessar > 10 portas diferentes em < 1s -> ALERTA".
    - [ ] Publicar alertas em uma fila dedicada (`security_alerts`).
- [ ] **Detector de DoS (Syn Flood):**
    - [ ] Calcular razão SYN/ACK. Desbalanceamento alto indica possível ataque.
- [ ] **Logging de Alerta:**
    - [ ] Enviar notificação crítica (Log local ou Webhook).

---
> *Este roadmap transforma o projeto de um simples script acadêmico em uma arquitetura de microsserviços utilizada em grandes empresas de segurança.*
