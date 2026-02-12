# 📡 Network Traffic Analyzer (NTA)

![Status](https://img.shields.io/badge/Status-Development-orange)
![Language](https://img.shields.io/badge/Language-C11-blue)
![License](https://img.shields.io/badge/License-Educational-green)

O **Network Traffic Analyzer** é um motor de monitoramento de rede desenvolvido em C. Projetado para capturar, analisar e visualizar tráfego de rede em tempo real, com foco em performance e detecção de padrões de segurança (IDS).

---

## ⚠️ Aviso de Segurança e Ética

> **IMPORTANTE:** Este software foi desenvolvido estritamente para fins educacionais e de pesquisa em segurança defensiva (Blue Team).
>
> * **Ambiente de Execução:** Deve ser operado exclusivamente em redes laboratoriais isoladas (VMs locais), redes privadas autorizadas ou plataformas de treino.
> * **Propósito:** O objetivo é estudar a pilha TCP/IP, entender o funcionamento de ferramentas de defesa e praticar programação de baixo nível.
> * **Isenção de Responsabilidade:** O autor não se responsabiliza pelo uso indevido deste código para monitoramento não autorizado de terceiros.

---

## 🏗️ Arquitetura do Sistema

O projeto adota uma arquitetura de **Pipeline de Dados** baseada no padrão *Producer-Consumer* para garantir escalabilidade e evitar perda de pacotes (*packet loss*) em redes de alto tráfego.

### Fluxo de Dados

1.  **Camada de Ingestão (O Produtor - C):**
    * Captura bruta de pacotes via `libpcap` em modo promíscuo.
    * Armazena pacotes em um *Ring Buffer* (Memória Compartilhada).

2.  **Camada de Processamento (O Consumidor - C):**
    * Threads dedicadas leem do buffer.
    * Realizam o *parsing* (dissecção) dos cabeçalhos Ethernet, IP e TCP/UDP.
    * Executam lógica de detecção de ameaças (Port Scan, DoS).

3.  **Camada de Armazenamento e Visualização (Docker):**
    * **InfluxDB:** Banco de dados de séries temporais para armazenar métricas.
    * **Grafana:** Dashboards para visualização de tráfego e alertas em tempo real.

---

## 💻 Tech Stack

| Componente | Tecnologia | Descrição |
| :--- | :--- | :--- |
| **Linguagem Core** | **C (C11)** | Performance crítica e acesso direto à memória. |
| **Captura** | **libpcap** | Biblioteca padrão para captura de pacotes. |
| **Concorrência** | **POSIX Threads** | Multithreading para separar captura e análise. |
| **Comunicação** | **libcurl / UDP** | Envio de dados para a API do banco de dados. |
| **Database** | **InfluxDB** | Armazenamento otimizado para logs temporais. |
| **Dashboard** | **Grafana** | Interface visual para o analista de segurança. |
| **Ambiente** | **Linux (Kali/Ubuntu)** | Sistema Operacional base. |

---

## 📂 Estrutura de Diretórios (Sugestão)

```text
NetworkTrafficAnalyzer/
├── src/                # Código fonte em C
│   ├── capture/        # Módulos de captura (libpcap)
│   ├── analysis/       # Lógica de dissecção de protocolos
│   └── output/         # Conectores para InfluxDB/Logs
├── include/            # Arquivos de cabeçalho (.h) e Structs
├── docker/             # Docker Compose para InfluxDB e Grafana
├── docs/               # Documentação e diagramas
├── Makefile            # Script de compilação automatizada
└── README.md           # Este arquivo