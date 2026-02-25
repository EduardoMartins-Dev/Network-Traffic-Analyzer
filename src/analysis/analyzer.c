#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <time.h>
#include "../include/analyzer.h"
#include "../include/publisher.h"

/* Configurações e limites operacionais do IDS */
#define MAX_SUSPECTS 100       // Quantidade máxima de IPs rastreados simultaneamente
#define SCAN_THRESHOLD 15      // Quantidade de portas distintas para classificar um TCP Port Scan
#define ICMP_THRESHOLD 20      // Máximo de pacotes ICMP por IP antes de alertar um Flood
#define CLEANUP_INTERVAL 60    // Intervalo mínimo (em segundos) entre as execuções da limpeza
#define INACTIVE_TIMEOUT 300   // Tempo (em segundos) de inatividade para um IP ser esquecido

/**
 * @struct Suspect
 * @brief Estrutura responsável por rastrear as métricas comportamentais de um IP de origem.
 */
typedef struct {
    uint32_t ip;                        // Endereço IP de origem (formato de rede)
    uint16_t ports[SCAN_THRESHOLD];     // Histórico de portas de destino acessadas unicamente
    int port_count;                     // Contador de portas distintas acessadas
    int icmp_count;                     // Contador de requisições ICMP (pings)
    time_t last_seen;                   // Timestamp do último pacote recebido deste IP
} Suspect;

// Estado global do IDS
Suspect suspects[MAX_SUSPECTS];
int suspect_count = 0;
time_t last_cleanup = 0;

/**
 * @brief Remove IPs inativos da memória para evitar esgotamento do vetor de suspeitos.
 * * Executa periodicamente com base na constante CLEANUP_INTERVAL. Caso um IP
 * não envie pacotes durante o INACTIVE_TIMEOUT, ele é descartado do rastreamento.
 */
void cleanup_suspects() {
    time_t now = time(NULL);

    // Garante que a limpeza não consuma CPU excessivamente rodando a cada pacote
    if (difftime(now, last_cleanup) < CLEANUP_INTERVAL) return;

    int active = 0;
    for (int i = 0; i < suspect_count; i++) {
        // Mantém apenas os suspeitos que tiveram atividade recente
        if (difftime(now, suspects[i].last_seen) < INACTIVE_TIMEOUT) {
            suspects[active++] = suspects[i];
        }
    }

    suspect_count = active;
    last_cleanup = now;

    printf("[IDS] Limpeza de rotina realizada. IPs rastreados ativos: %d\n", suspect_count);
}

/**
 * @brief Analisa pacotes de rede interceptados em busca de anomalias e ataques.
 * * Inspeciona os cabeçalhos das camadas de Enlace (Ethernet), Rede (IP) e Transporte
 * para identificar assinaturas de comportamento malicioso (Ex: Port Scan, ICMP Flood).
 * * @param packet Buffer contendo os bytes brutos do pacote interceptado.
 * @param length Tamanho total do pacote capturado.
 * @return Retorna 1 se um ataque foi detectado; 0 caso o tráfego seja benigno.
 */
int analyze_packet(const u_char *packet, int length) {
    // Executa a rotina de manutenção de memória antes da análise
    cleanup_suspects();

    // Salta os primeiros 14 bytes (Cabeçalho Ethernet) para acessar o Cabeçalho IP diretamente
    struct ip *ip_header = (struct ip *)(packet + 14);
    uint32_t src_ip = ip_header->ip_src.s_addr;

    int is_scan = 0;
    time_t now = time(NULL);

    // ---------------------------------------------------------
    // ANÁLISE DE TRÁFEGO ICMP (Detecção de Ping Flood)
    // ---------------------------------------------------------
    if (ip_header->ip_p == IPPROTO_ICMP) {
        for (int i = 0; i < suspect_count; i++) {
            if (suspects[i].ip == src_ip) {
                suspects[i].icmp_count++;
                suspects[i].last_seen = now;

                // Dispara o alerta caso a volumetria de ICMP ultrapasse o limite
                if (suspects[i].icmp_count > ICMP_THRESHOLD) {
                    printf("[IDS] ICMP FLOOD detectado da origem: %s!\n", inet_ntoa(ip_header->ip_src));
                    publish_packet(inet_ntoa(ip_header->ip_src), 0, "ICMP", length, 1);
                    return 1;
                }
                break;
            }
        }
    }

    // ---------------------------------------------------------
    // ANÁLISE DE TRÁFEGO TCP (Detecção de Port Scan)
    // ---------------------------------------------------------
    if (ip_header->ip_p == IPPROTO_TCP) {
        // Calcula o offset dinâmico do cabeçalho TCP (ip_hl indica palavras de 32 bits, multiplicamos por 4 via bitshift)
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2));
        uint16_t dest_port = ntohs(tcp_header->th_dport);

        for (int i = 0; i < suspect_count; i++) {
            if (suspects[i].ip == src_ip) {
                suspects[i].last_seen = now;

                // Verifica se a porta de destino já foi registrada para este IP
                int new_port = 1;
                for (int j = 0; j < suspects[i].port_count; j++) {
                    if (suspects[i].ports[j] == dest_port) {
                        new_port = 0;
                        break;
                    }
                }

                // Registra a nova porta caso o limite de rastreamento ainda não tenha sido atingido
                if (new_port && suspects[i].port_count < SCAN_THRESHOLD) {
                    suspects[i].ports[suspects[i].port_count++] = dest_port;
                }

                // Sinaliza ataque se a contagem de portas únicas atingir o limiar
                if (suspects[i].port_count >= SCAN_THRESHOLD) {
                    is_scan = 1;
                }

                // Publica a telemetria do pacote no broker de mensageria
                publish_packet(inet_ntoa(ip_header->ip_src), dest_port, "TCP", length, is_scan);
                return is_scan;
            }
        }
    }

    // ---------------------------------------------------------
    // RASTREAMENTO DE NOVOS DISPOSITIVOS
    // ---------------------------------------------------------
    // Caso seja o primeiro contato deste IP e haja espaço na memória, inicia o rastreamento
    if (suspect_count < MAX_SUSPECTS) {
        suspects[suspect_count].ip = src_ip;
        suspects[suspect_count].last_seen = now;
        suspect_count++;
    }

    return 0;
}