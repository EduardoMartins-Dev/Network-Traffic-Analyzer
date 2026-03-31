#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "../include/analyzer.h"
#include "../include/publisher.h"

/* ========================================================================= *
 * THRESHOLDS E LIMITES OPERACIONAIS DO IDS (v4.0)                          *
 *                                                                           *
 * Serão substituídos por baselines adaptativos (EWMA) na Etapa 2.          *
 * ========================================================================= */
#define MAX_SUSPECTS        100
#define CLEANUP_INTERVAL    60
#define INACTIVE_TIMEOUT    300

/* Detecções existentes (v2.0) */
#define SCAN_THRESHOLD      15       // portas únicas para Port Scan
#define ICMP_THRESHOLD      20       // pacotes ICMP para Flood

/* Novas detecções (v4.0) */
#define SYN_FLOOD_THRESHOLD 100      // SYNs sem ACK por IP
#define STEALTH_THRESHOLD   3        // qualquer stealth scan é suspeito
#define BRUTE_THRESHOLD     30       // conexões em janela temporal
#define BRUTE_WINDOW_SEC    60       // janela de 60 segundos
#define DNS_SUBDOMAIN_LEN   50       // tamanho de subdomain suspeito
#define DNS_ENTROPY_THRESH  3.5      // Shannon entropy para base64/hex
#define DNS_SUSPICIOUS_MAX  10       // queries suspeitas para alertar
#define AMPLIFICATION_RATIO 10       // ratio response/request bytes
#define MAX_ARP_ENTRIES     256      // tabela MAC→IP

/* Portas-alvo de brute force */
#define PORT_SSH  22
#define PORT_FTP  21
#define PORT_RDP  3389

/* ========================================================================= *
 * ESTRUTURAS DE DADOS                                                       *
 * ========================================================================= */

/**
 * @struct Suspect
 * @brief Rastreia métricas comportamentais de um IP de origem para todas as detecções.
 */
typedef struct {
    uint32_t ip;
    time_t   last_seen;

    /* Port Scan (v2.0) */
    uint16_t ports[SCAN_THRESHOLD];
    int      port_count;

    /* ICMP Flood (v2.0) */
    int      icmp_count;

    /* SYN Flood (v4.0) */
    int      syn_count;

    /* Stealth Scans (v4.0) */
    int      null_scan_count;
    int      xmas_scan_count;
    int      synfin_scan_count;

    /* Brute Force (v4.0) */
    int      brute_count;
    time_t   brute_window_start;

    /* DNS Tunneling (v4.0) */
    int      dns_query_count;
    int      dns_suspicious_count;

    /* DDoS Amplification (v4.0) */
    uint64_t dns_req_bytes;
    uint64_t dns_resp_bytes;
} Suspect;

/**
 * @struct ArpEntry
 * @brief Mapeamento MAC→IP para detecção de ARP Spoofing.
 */
typedef struct {
    uint8_t  mac[6];
    uint32_t ip;
} ArpEntry;

/* Estado global do IDS */
static Suspect  suspects[MAX_SUSPECTS];
static int      suspect_count = 0;
static time_t   last_cleanup  = 0;

static ArpEntry arp_table[MAX_ARP_ENTRIES];
static int      arp_count = 0;

/* ========================================================================= *
 * FUNÇÕES AUXILIARES                                                         *
 * ========================================================================= */

/**
 * @brief Remove IPs inativos da tabela de suspeitos (garbage collection).
 */
static void cleanup_suspects(void) {
    time_t now = time(NULL);
    if (difftime(now, last_cleanup) < CLEANUP_INTERVAL) return;

    int active = 0;
    for (int i = 0; i < suspect_count; i++) {
        if (difftime(now, suspects[i].last_seen) < INACTIVE_TIMEOUT) {
            suspects[active++] = suspects[i];
        }
    }

    suspect_count = active;
    last_cleanup = now;
    printf("[IDS] Limpeza de rotina. IPs rastreados: %d\n", suspect_count);
}

/**
 * @brief Busca um IP na tabela de suspeitos. Cria entrada nova se não existir.
 * @return Ponteiro para o Suspect, ou NULL se a tabela estiver cheia.
 */
static Suspect *find_or_create_suspect(uint32_t ip) {
    time_t now = time(NULL);

    for (int i = 0; i < suspect_count; i++) {
        if (suspects[i].ip == ip) {
            suspects[i].last_seen = now;
            return &suspects[i];
        }
    }

    if (suspect_count >= MAX_SUSPECTS) return NULL;

    /* Inicializa novo suspeito com todos os campos zerados */
    memset(&suspects[suspect_count], 0, sizeof(Suspect));
    suspects[suspect_count].ip = ip;
    suspects[suspect_count].last_seen = now;
    suspects[suspect_count].brute_window_start = now;

    return &suspects[suspect_count++];
}

/**
 * @brief Calcula a entropia de Shannon de uma string.
 *
 * Usado para detectar DNS tunneling: subdomains com base64/hex encoding
 * têm entropia alta (>3.5 bits/char) comparado a nomes legítimos (~2.5).
 */
static double calculate_entropy(const unsigned char *data, int len) {
    if (len <= 0) return 0.0;

    int freq[256] = {0};
    for (int i = 0; i < len; i++) freq[data[i]]++;

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / len;
        entropy -= p * log2(p);
    }
    return entropy;
}

/**
 * @brief Extrai o nome de domínio de um payload DNS.
 *
 * Formato DNS: cada label é precedida por um byte de tamanho.
 * Exemplo: [3]www[6]google[3]com[0] → "www.google.com"
 *
 * @param dns_payload  Payload DNS (após header UDP)
 * @param dns_len      Tamanho do payload
 * @param out          Buffer de saída para o nome extraído
 * @param out_size     Tamanho do buffer de saída
 * @return Tamanho do nome extraído, ou 0 se falhar.
 */
static int extract_dns_name(const unsigned char *dns_payload, int dns_len,
                            char *out, int out_size) {
    /* DNS header = 12 bytes. Query começa no byte 12. */
    if (dns_len < 13) return 0;

    const unsigned char *ptr = dns_payload + 12;
    const unsigned char *end = dns_payload + dns_len;
    int pos = 0;

    while (ptr < end && *ptr != 0) {
        int label_len = *ptr++;

        /* Proteção contra labels malformados ou ponteiros de compressão */
        if (label_len > 63 || ptr + label_len > end) return 0;

        if (pos > 0 && pos < out_size - 1) out[pos++] = '.';

        for (int i = 0; i < label_len && pos < out_size - 1; i++) {
            out[pos++] = *ptr++;
        }
    }

    out[pos] = '\0';
    return pos;
}

/* ========================================================================= *
 * FUNÇÕES DE DETECÇÃO (v4.0)                                                *
 *                                                                           *
 * Cada função recebe um Suspect e dados do pacote. Retorna o nome do        *
 * ataque detectado (string estática) ou NULL se tráfego normal.             *
 * ========================================================================= */

/**
 * @brief Detecta SYN Flood: volume anormal de pacotes SYN sem ACK.
 */
static const char *detect_syn_flood(Suspect *s, uint8_t tcp_flags) {
    if ((tcp_flags & TH_SYN) && !(tcp_flags & TH_ACK)) {
        s->syn_count++;
        if (s->syn_count > SYN_FLOOD_THRESHOLD) {
            return "SYN_FLOOD";
        }
    }
    return NULL;
}

/**
 * @brief Detecta Stealth Scans por combinações anômalas de TCP flags.
 *
 * - Null Scan:    flags == 0x00 (nenhum flag setado)
 * - Xmas Scan:    FIN + PSH + URG (todos os "decorativos" ligados)
 * - SYN/FIN Scan: SYN + FIN simultâneos (combinação inválida)
 */
static const char *detect_stealth_scan(Suspect *s, uint8_t tcp_flags) {
    /* Null Scan: nenhum flag TCP setado */
    if (tcp_flags == 0) {
        s->null_scan_count++;
        if (s->null_scan_count >= STEALTH_THRESHOLD) return "NULL_SCAN";
    }

    /* Xmas Scan: FIN + PSH + URG */
    if ((tcp_flags & (TH_FIN | TH_PUSH | TH_URG)) == (TH_FIN | TH_PUSH | TH_URG)) {
        s->xmas_scan_count++;
        if (s->xmas_scan_count >= STEALTH_THRESHOLD) return "XMAS_SCAN";
    }

    /* SYN/FIN Scan: SYN + FIN simultâneos (RFC viola: nunca legítimo) */
    if ((tcp_flags & (TH_SYN | TH_FIN)) == (TH_SYN | TH_FIN)) {
        s->synfin_scan_count++;
        if (s->synfin_scan_count >= STEALTH_THRESHOLD) return "SYNFIN_SCAN";
    }

    return NULL;
}

/**
 * @brief Detecta brute force em SSH (22), FTP (21), RDP (3389).
 *
 * Conta SYNs para portas de autenticação dentro de uma janela de 60 segundos.
 * Limiar: ≥30 tentativas na janela.
 */
static const char *detect_brute_force(Suspect *s, uint8_t tcp_flags, uint16_t dst_port,
                                      time_t now) {
    /* Só conta SYNs iniciais (tentativas de conexão) */
    if (!(tcp_flags & TH_SYN) || (tcp_flags & TH_ACK)) return NULL;

    /* Só monitora portas de autenticação */
    if (dst_port != PORT_SSH && dst_port != PORT_FTP && dst_port != PORT_RDP) return NULL;

    /* Reset da janela se expirou */
    if (difftime(now, s->brute_window_start) > BRUTE_WINDOW_SEC) {
        s->brute_count = 0;
        s->brute_window_start = now;
    }

    s->brute_count++;
    if (s->brute_count >= BRUTE_THRESHOLD) {
        return "BRUTE_FORCE";
    }

    return NULL;
}

/**
 * @brief Detecta DNS Tunneling por análise de payload.
 *
 * Indicadores: subdomain anormalmente longo (>50 chars) ou entropia alta
 * no nome (base64/hex encoding típico de exfiltração).
 */
static const char *detect_dns_tunnel(Suspect *s, const unsigned char *dns_payload,
                                     int dns_len) {
    char domain[256];
    int name_len = extract_dns_name(dns_payload, dns_len, domain, sizeof(domain));
    if (name_len <= 0) return NULL;

    s->dns_query_count++;

    /* Verifica tamanho do primeiro label (subdomain) */
    int first_label_len = 0;
    for (int i = 0; i < name_len && domain[i] != '.'; i++) {
        first_label_len++;
    }

    int suspicious = 0;

    /* Subdomain anormalmente longo */
    if (first_label_len > DNS_SUBDOMAIN_LEN) suspicious = 1;

    /* Entropia alta no nome completo (indica encoding) */
    if (calculate_entropy((const unsigned char *)domain, name_len) > DNS_ENTROPY_THRESH) {
        suspicious = 1;
    }

    if (suspicious) {
        s->dns_suspicious_count++;
        if (s->dns_suspicious_count >= DNS_SUSPICIOUS_MAX) {
            return "DNS_TUNNEL";
        }
    }

    return NULL;
}

/**
 * @brief Detecta DDoS Amplification por ratio de bytes response/request.
 *
 * Quando as respostas DNS/NTP de um IP são >10x maiores que os requests,
 * indica que o IP está sendo usado como refletor/amplificador.
 */
static const char *detect_amplification(Suspect *s, int bytes, int is_response) {
    if (is_response) {
        s->dns_resp_bytes += bytes;
    } else {
        s->dns_req_bytes += bytes;
    }

    /* Precisa de volume mínimo de requests para calcular ratio */
    if (s->dns_req_bytes < 100) return NULL;

    if (s->dns_resp_bytes > s->dns_req_bytes * AMPLIFICATION_RATIO) {
        return "AMPLIFICATION";
    }

    return NULL;
}

/**
 * @brief Detecta ARP Spoofing: mesmo MAC reivindicando IPs diferentes.
 *
 * Mantém tabela MAC→IP. Quando um MAC que já foi visto com um IP aparece
 * em um ARP reply com IP diferente, sinaliza spoofing.
 *
 * Layout do pacote ARP (após Ethernet header de 14 bytes):
 *   Offset  8: Sender MAC (6 bytes)
 *   Offset 14: Sender IP  (4 bytes)
 */
static const char *detect_arp_spoof(const unsigned char *packet, int length) {
    /* ARP header mínimo: 28 bytes após Ethernet (14) */
    if (length < 42) return NULL;

    const unsigned char *arp = packet + 14;

    /* Operação: 2 = ARP Reply (onde spoofing é mais relevante) */
    uint16_t operation = (arp[6] << 8) | arp[7];
    if (operation != 2) return NULL;

    const unsigned char *sender_mac = arp + 8;
    uint32_t sender_ip;
    memcpy(&sender_ip, arp + 14, 4);

    /* Busca o MAC na tabela */
    for (int i = 0; i < arp_count; i++) {
        if (memcmp(arp_table[i].mac, sender_mac, 6) == 0) {
            /* MAC encontrado — verifica se o IP mudou */
            if (arp_table[i].ip != sender_ip) {
                struct in_addr old_addr, new_addr;
                old_addr.s_addr = arp_table[i].ip;
                new_addr.s_addr = sender_ip;
                printf("[IDS] ARP SPOOF: MAC %02x:%02x:%02x:%02x:%02x:%02x "
                       "mudou de %s para %s!\n",
                       sender_mac[0], sender_mac[1], sender_mac[2],
                       sender_mac[3], sender_mac[4], sender_mac[5],
                       inet_ntoa(old_addr), inet_ntoa(new_addr));

                publish_packet(inet_ntoa(new_addr), 0, "ARP", length, 1, "ARP_SPOOF");
                return "ARP_SPOOF";
            }
            return NULL;
        }
    }

    /* MAC novo — registra na tabela */
    if (arp_count < MAX_ARP_ENTRIES) {
        memcpy(arp_table[arp_count].mac, sender_mac, 6);
        arp_table[arp_count].ip = sender_ip;
        arp_count++;
    }

    return NULL;
}

/* ========================================================================= *
 * DETECÇÕES EXISTENTES (v2.0) — refatoradas para nova arquitetura           *
 * ========================================================================= */

/**
 * @brief Detecta Port Scan: ≥15 portas únicas acessadas por um mesmo IP.
 */
static const char *detect_port_scan(Suspect *s, uint16_t dst_port) {
    int new_port = 1;
    for (int j = 0; j < s->port_count; j++) {
        if (s->ports[j] == dst_port) {
            new_port = 0;
            break;
        }
    }

    if (new_port && s->port_count < SCAN_THRESHOLD) {
        s->ports[s->port_count++] = dst_port;
    }

    if (s->port_count >= SCAN_THRESHOLD) return "PORT_SCAN";
    return NULL;
}

/**
 * @brief Detecta ICMP Flood: ≥20 pacotes ICMP de um mesmo IP.
 */
static const char *detect_icmp_flood(Suspect *s) {
    s->icmp_count++;
    if (s->icmp_count > ICMP_THRESHOLD) return "ICMP_FLOOD";
    return NULL;
}

/* ========================================================================= *
 * FUNÇÃO PRINCIPAL DE ANÁLISE                                               *
 * ========================================================================= */

/**
 * @brief Analisa um pacote capturado e executa todas as detecções do IDS.
 *
 * Fluxo:
 *   1. Identifica EtherType (ARP ou IP)
 *   2. Se ARP → verifica spoofing
 *   3. Se IP  → busca/cria Suspect → executa detecções por protocolo
 *   4. Publica telemetria com attack_type no JSON
 *
 * @param packet Buffer bruto do pacote (inclui Ethernet header)
 * @param length Tamanho total do pacote
 * @return 1 se ataque detectado, 0 se tráfego normal
 */
int analyze_packet(const unsigned char *packet, int length) {
    cleanup_suspects();

    /* Mínimo: Ethernet header (14 bytes) */
    if (length < 14) return 0;

    /* ------------------------------------------------------------------- *
     * CAMADA 2: Identifica EtherType                                      *
     * 0x0806 = ARP | 0x0800 = IPv4                                        *
     * ------------------------------------------------------------------- */
    uint16_t ether_type = (packet[12] << 8) | packet[13];

    if (ether_type == 0x0806) {
        return detect_arp_spoof(packet, length) ? 1 : 0;
    }

    if (ether_type != 0x0800) return 0;

    /* ------------------------------------------------------------------- *
     * CAMADA 3: Parse do cabeçalho IP                                     *
     * ------------------------------------------------------------------- */
    struct ip *ip_header = (struct ip *)(packet + 14);
    uint32_t src_ip = ip_header->ip_src.s_addr;
    int ip_hdr_len = ip_header->ip_hl << 2;

    Suspect *s = find_or_create_suspect(src_ip);
    if (!s) return 0;

    const char *attack = NULL;

    /* ------------------------------------------------------------------- *
     * ICMP                                                                 *
     * ------------------------------------------------------------------- */
    if (ip_header->ip_p == IPPROTO_ICMP) {
        attack = detect_icmp_flood(s);
        publish_packet(inet_ntoa(ip_header->ip_src), 0, "ICMP", length,
                       attack ? 1 : 0, attack);
        return attack ? 1 : 0;
    }

    /* ------------------------------------------------------------------- *
     * TCP: SYN Flood, Stealth Scan, Brute Force, Port Scan                *
     * ------------------------------------------------------------------- */
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_hdr_len);
        uint16_t dst_port = ntohs(tcp->th_dport);
        uint8_t  flags    = tcp->th_flags;
        time_t   now      = time(NULL);

        /* Verifica cada detecção em ordem de severidade */
        if (!attack) attack = detect_stealth_scan(s, flags);
        if (!attack) attack = detect_syn_flood(s, flags);
        if (!attack) attack = detect_brute_force(s, flags, dst_port, now);
        if (!attack) attack = detect_port_scan(s, dst_port);

        publish_packet(inet_ntoa(ip_header->ip_src), dst_port, "TCP", length,
                       attack ? 1 : 0, attack);
        return attack ? 1 : 0;
    }

    /* ------------------------------------------------------------------- *
     * UDP: DNS Tunneling, DDoS Amplification                              *
     * ------------------------------------------------------------------- */
    if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(packet + 14 + ip_hdr_len);
        uint16_t src_port = ntohs(udp->uh_sport);
        uint16_t dst_port = ntohs(udp->uh_dport);

        /* DNS opera na porta 53 */
        if (src_port == 53 || dst_port == 53) {
            int udp_hdr_len  = 8;
            const unsigned char *dns_payload = packet + 14 + ip_hdr_len + udp_hdr_len;
            int dns_len = length - 14 - ip_hdr_len - udp_hdr_len;

            if (dns_len > 0) {
                int is_response = (dns_payload[2] & 0x80) != 0;

                /* DNS Tunneling: analisa queries com subdomains suspeitos */
                if (!is_response) {
                    attack = detect_dns_tunnel(s, dns_payload, dns_len);
                }

                /* DDoS Amplification: compara volume de response vs request */
                if (!attack) {
                    attack = detect_amplification(s, length, is_response);
                }
            }
        }

        publish_packet(inet_ntoa(ip_header->ip_src), dst_port, "UDP", length,
                       attack ? 1 : 0, attack);
        return attack ? 1 : 0;
    }

    return 0;
}
