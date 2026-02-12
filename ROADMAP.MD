🗺️ Roadmap: Network Traffic Analyzer (Enterprise Architecture)
Este documento descreve o plano de evolução do projeto, focado em alta performance e desacoplamento de serviços usando Arquitetura Orientada a Eventos (EDA).

🏁 Fase 1: Fundação e Captura (The Sniffer)
Objetivo: Estabelecer o ambiente e garantir que o C "enxerga" a rede (Libpcap).

[ ] Configuração do Lab:

[ ] Subir VM Kali Linux (Monitor) e VM Alvo.

[ ] Garantir conectividade isolada (Host-only/NAT Network).

[ ] Hello World Libpcap:

[ ] Inicializar dispositivo de rede em modo promíscuo.

[ ] Loop de captura simples (pcap_loop).

[ ] Imprimir mensagem no terminal a cada pacote recebido.

[ ] Filtros BPF:

[ ] Aplicar filtros para ignorar tráfego SSH (porta 22) e focar em TCP/UDP/ICMP.

🧠 Fase 2: O Motor de Análise (Protocol Dissector)
Objetivo: Traduzir bytes brutos (Raw Data) em informações estruturadas.

[ ] Estruturas de Dados (Structs):

[ ] Mapear cabeçalho Ethernet (MAC Address).

[ ] Mapear cabeçalho IP (IP Src/Dst, TTL, Protocolo).

[ ] Mapear cabeçalho TCP/UDP (Portas, Flags).

[ ] Aritmética de Ponteiros:

[ ] Implementar lógica para "pular" cabeçalhos e ler o payload.

[ ] Extrair dados: [TCP] 192.168.1.5:443 -> 192.168.1.10:55432.

🐇 Fase 3: Camada de Mensageria & Serialização (Middleware)
Objetivo: Desacoplar a captura do armazenamento. O Sniffer não grava no banco, ele apenas "avisa" a fila.

[ ] Infraestrutura RabbitMQ:

[ ] Adicionar RabbitMQ ao docker-compose.yml.

[ ] Configurar Exchange e Queue (network_events).

[ ] Serialização de Dados (C para JSON):

[ ] Integrar biblioteca cJSON ou Jansson no projeto C.

[ ] Criar função packet_to_json(): Converter a struct do pacote em string JSON.

[ ] Conector AMQP (C Client):

[ ] Integrar biblioteca rabbitmq-c (librabbitmq).

[ ] Implementar conexão persistente com o Broker.

[ ] Publicar JSON na fila a cada pacote processado.

⚙️ Fase 4: O Consumidor e Persistência (The Worker)
Objetivo: Ler da fila em alta velocidade e gravar no banco de dados.

[ ] Worker Service (Python/Go/Telegraf):

[ ] Criar um script/serviço separado que escuta a fila do RabbitMQ.

[ ] Nota: Isso tira o peso de I/O (Input/Output) do programa em C principal.

[ ] Banco de Dados (Time Series):

[ ] Configurar InfluxDB via Docker.

[ ] Implementar escrita em lote (Batch Write) para performance.

[ ] Gravar métricas: bytes_sent, packets_count, flags_detected.

📊 Fase 5: Visualização e Operação (SOC Dashboard)
Objetivo: Transformar dados em inteligência visual.

[ ] Grafana Setup:

[ ] Conectar Grafana ao InfluxDB.

[ ] Dashboards Operacionais:

[ ] Velocímetro: Throughput da rede em tempo real (MB/s).

[ ] Top Talkers: Quem são os IPs que mais geram tráfego?

[ ] Mapa de Calor: Portas mais acessadas.

[ ] Indicador de Ameaças: Contagem de pacotes suspeitos.

🛡️ Fase 6: Inteligência de Segurança (IDS Engine)
Objetivo: Análise comportamental para detecção de intrusão.

[ ] Análise de Flags TCP:

[ ] Detectar anomalias (Ex: Null Scan, Xmas Scan).

[ ] Detector de Port Scan:

[ ] Lógica temporal: "Se IP X acessar > 10 portas em < 1s -> ALERTA".

[ ] Publicar alerta em uma fila separada (security_alerts).

[ ] Detector de DoS (Syn Flood):

[ ] Calcular razão SYN/ACK. Desbalanceamento indica ataque.

[ ] Logging de Alerta:

[ ] Enviar notificação crítica (Log ou Webhook).
