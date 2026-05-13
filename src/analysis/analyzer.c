#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#include "../include/analyzer.h"
#include "../include/publisher.h"
#include "../include/collector.h"

/* ========================================================================= *
 * HOME_NET — CIDRs ignorados no IP layer (não no ARP).                      *
 * Armazenamos addr/mask em network byte order — comparação direta com      *
 * ip_header->ip_src.s_addr (também network byte order) sem swap.            *
 * ========================================================================= */
#define MAX_HOME_CIDR 8
typedef struct { uint32_t addr_be; uint32_t mask_be; char str[20]; } HomeCidr;
static HomeCidr g_home_cidrs[MAX_HOME_CIDR];
static int      g_home_cidr_count = 0;

int analyzer_add_home_cidr(const char *cidr) {
    if (!cidr || !*cidr) return -1;
    if (g_home_cidr_count >= MAX_HOME_CIDR) return -1;

    char buf[64];
    snprintf(buf, sizeof(buf), "%s", cidr);
    char *slash = strchr(buf, '/');
    int prefix = 32;
    if (slash) { *slash = '\0'; prefix = atoi(slash + 1); }
    if (prefix < 0 || prefix > 32) return -1;

    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1) return -1;

    uint32_t mask_host = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
    uint32_t mask_be   = htonl(mask_host);
    uint32_t addr_be   = a.s_addr & mask_be;

    HomeCidr *hc = &g_home_cidrs[g_home_cidr_count++];
    hc->addr_be = addr_be;
    hc->mask_be = mask_be;
    snprintf(hc->str, sizeof(hc->str), "%s", cidr);
    return 0;
}

void analyzer_home_dump(void) {
    fprintf(stderr, "[ANALYZER] HOME_NET (%d):", g_home_cidr_count);
    for (int i = 0; i < g_home_cidr_count; i++) {
        fprintf(stderr, " %s", g_home_cidrs[i].str);
    }
    fprintf(stderr, "\n");
}

int analyzer_home_count(void) { return g_home_cidr_count; }

static inline int is_home_ip(uint32_t src_be) {
    for (int i = 0; i < g_home_cidr_count; i++) {
        if ((src_be & g_home_cidrs[i].mask_be) == g_home_cidrs[i].addr_be) return 1;
    }
    return 0;
}

/* ========================================================================= *
 * CONFIGURAÇÃO OPERACIONAL DO IDS                                           *
 * ========================================================================= */

#define MAX_SUSPECTS        100
#define CLEANUP_INTERVAL    60
#define INACTIVE_TIMEOUT    300
#define MAX_ARP_ENTRIES     256

/* Thresholds de fallback — usados apenas durante calibração EWMA             *
 * (< EWMA_CALIBRATION amostras). Após calibração, substituídos por          *
 * thresholds adaptativos calculados a partir do baseline de cada IP.        */
#define SCAN_THRESHOLD      15
#define ICMP_THRESHOLD      20
#define SYN_FLOOD_THRESHOLD 100
#define STEALTH_THRESHOLD   3
#define BRUTE_THRESHOLD     30
#define BRUTE_WINDOW_SEC    60
#define DNS_SUBDOMAIN_LEN   50
#define DNS_ENTROPY_THRESH  3.5
#define DNS_SUSPICIOUS_MAX  10
#define AMPLIFICATION_RATIO 10

/* Portas-alvo de brute force */
#define PORT_SSH  22
#define PORT_FTP  21
#define PORT_RDP  3389

/* ========================================================================= *
 * BASELINE ADAPTATIVO (EWMA)                                                *
 *                                                                           *
 * Cada IP mantém médias móveis exponencialmente ponderadas de:              *
 *   - pacotes/segundo                                                        *
 *   - portas únicas/minuto                                                   *
 *   - DNS queries/minuto                                                     *
 *                                                                           *
 * Alpha durante calibração (< 100 amostras): 0.3 — aprende rápido          *
 * Alpha após calibração:                     0.1 — adapta devagar           *
 *                                                                           *
 * Detecção de anomalia: |valor - ewma| > EWMA_SIGMA * stddev                *
 * Elimina thresholds hardcoded — cada rede aprende seus próprios limites.   *
 * ========================================================================= */

#define EWMA_ALPHA_FAST   0.3    /* alpha durante calibração */
#define EWMA_ALPHA_SLOW   0.1    /* alpha após calibração */
#define EWMA_CALIBRATION  100    /* amostras para completar calibração */
#define EWMA_SIGMA        3.0    /* desvios-padrão para threshold adaptativo */
#define EWMA_WINDOW_SEC   60     /* janela de 1 minuto para agregar métricas */

typedef struct {
    double ewma_pps;          /* pacotes/segundo — média EWMA */
    double ewma_var_pps;      /* variância EWMA da pps (para stddev) */
    double ewma_ports;        /* portas únicas/minuto — média EWMA */
    double ewma_var_ports;
    double ewma_dns;          /* DNS queries/minuto — média EWMA */
    double ewma_var_dns;

    int    sample_count;      /* janelas amostradas (0 = em calibração) */
    time_t window_start;      /* início da janela de coleta atual */
    int    pkt_in_window;     /* pacotes observados na janela atual */
    int    ports_in_window;   /* portas únicas na janela atual */
    int    dns_in_window;     /* DNS queries na janela atual */
} ip_baseline_t;

/* ========================================================================= *
 * KILL CHAIN CORRELATOR                                                     *
 *                                                                           *
 * Máquina de estados por IP: IDLE → RECON → EXPLOIT → EXFIL → COMPLETE    *
 *                                                                           *
 * RECON:   Port Scan, Stealth Scan, ARP Spoof                               *
 * EXPLOIT: SYN Flood, Brute Force                                           *
 * EXFIL:   DNS Tunnel, Amplification, ICMP Flood                            *
 *                                                                           *
 * Score 0–100: estágio atual + velocidade de progressão                     *
 * Janela de correlação: 30 minutos (reset se inativo)                       *
 * ========================================================================= */

#define KC_WINDOW_SEC  1800   /* 30 minutos para correlacionar estágios */
#define KC_MITRE_SIZE  128

typedef enum {
    KC_IDLE     = 0,
    KC_RECON    = 1,
    KC_EXPLOIT  = 2,
    KC_EXFIL    = 3,
    KC_COMPLETE = 4
} KillChainStage;

static const char *kc_stage_name[] = {
    "IDLE", "RECON", "EXPLOIT", "EXFIL", "COMPLETE"
};

/* ========================================================================= *
 * ESTRUTURA PRINCIPAL — RASTREAMENTO POR IP                                 *
 * ========================================================================= */

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

    /* Baseline EWMA (v4.0 — Etapa 2) */
    ip_baseline_t baseline;

    /* Kill Chain Correlator (v4.0 — Etapa 3) */
    KillChainStage kc_stage;
    time_t         kc_stage_entered;  /* quando entrou no estágio atual */
    time_t         kc_first_seen;     /* timestamp da primeira atividade suspeita */
    int            kc_stages_hit;     /* bitmask: bit1=RECON, bit2=EXPLOIT, bit3=EXFIL */
    int            kc_score;          /* severidade 0–100 */
    char           kc_mitre[KC_MITRE_SIZE]; /* tags MITRE acumuladas do incidente */
} Suspect;

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
 * BASELINE EWMA — implementação                                             *
 * ========================================================================= */

/**
 * @brief Atualiza o baseline EWMA de um IP a cada janela de 1 minuto.
 *
 * Coleta métricas na janela atual. Quando a janela expira, aplica a fórmula
 * EWMA sobre pps, ports/min e dns/min, e recalcula a variância EWMA.
 *
 * Variância EWMA (Welford online):
 *   V_new = (1 - alpha) * (V_old + alpha * delta^2)
 */
static void update_baseline(ip_baseline_t *b, int new_port, int is_dns, time_t now) {
    b->pkt_in_window++;
    if (new_port) b->ports_in_window++;
    if (is_dns)   b->dns_in_window++;

    double elapsed = difftime(now, b->window_start);
    if (elapsed < EWMA_WINDOW_SEC) return;

    /* Calcula métricas da janela que acabou */
    double pps   = (elapsed > 0) ? ((double)b->pkt_in_window / elapsed) : 0.0;
    double ports = (double)b->ports_in_window;
    double dns   = (double)b->dns_in_window;

    double alpha = (b->sample_count < EWMA_CALIBRATION)
                   ? EWMA_ALPHA_FAST
                   : EWMA_ALPHA_SLOW;

    if (b->sample_count == 0) {
        /* Primeira amostra: inicializa com o valor observado */
        b->ewma_pps       = pps;
        b->ewma_ports     = ports;
        b->ewma_dns       = dns;
        b->ewma_var_pps   = 0.0;
        b->ewma_var_ports = 0.0;
        b->ewma_var_dns   = 0.0;
    } else {
        double dp = pps   - b->ewma_pps;
        double dq = ports - b->ewma_ports;
        double dd = dns   - b->ewma_dns;

        b->ewma_pps   += alpha * dp;
        b->ewma_ports += alpha * dq;
        b->ewma_dns   += alpha * dd;

        /* Variância EWMA — converge para var(X) do processo estacionário */
        b->ewma_var_pps   = (1.0 - alpha) * (b->ewma_var_pps   + alpha * dp * dp);
        b->ewma_var_ports = (1.0 - alpha) * (b->ewma_var_ports + alpha * dq * dq);
        b->ewma_var_dns   = (1.0 - alpha) * (b->ewma_var_dns   + alpha * dd * dd);
    }

    b->sample_count++;
    b->window_start    = now;
    b->pkt_in_window   = 0;
    b->ports_in_window = 0;
    b->dns_in_window   = 0;
}

/**
 * @brief Retorna 1 se o valor observado é uma anomalia em relação ao baseline.
 *
 * Condição: |observed - ewma| > EWMA_SIGMA * stddev
 * Durante calibração (variância = 0), não sinaliza anomalia.
 */
static int is_anomaly(double observed, double ewma, double variance) {
    if (variance <= 0.0) return 0;
    double stddev = sqrt(variance);
    return fabs(observed - ewma) > EWMA_SIGMA * stddev;
}

/* ========================================================================= *
 * KILL CHAIN CORRELATOR — implementação                                     *
 * ========================================================================= */

/**
 * @brief Mapeia um tipo de ataque para o estágio kill chain correspondente.
 */
static KillChainStage attack_to_stage(const char *attack) {
    if (!attack) return KC_IDLE;

    if (strcmp(attack, "PORT_SCAN")    == 0 ||
        strcmp(attack, "NULL_SCAN")    == 0 ||
        strcmp(attack, "XMAS_SCAN")    == 0 ||
        strcmp(attack, "SYNFIN_SCAN")  == 0 ||
        strcmp(attack, "ARP_SPOOF")    == 0) return KC_RECON;

    if (strcmp(attack, "SYN_FLOOD")    == 0 ||
        strcmp(attack, "BRUTE_FORCE")  == 0) return KC_EXPLOIT;

    if (strcmp(attack, "DNS_TUNNEL")   == 0 ||
        strcmp(attack, "AMPLIFICATION")== 0 ||
        strcmp(attack, "ICMP_FLOOD")   == 0) return KC_EXFIL;

    return KC_IDLE;
}

/**
 * @brief Mapeia um tipo de ataque para sua(s) técnica(s) MITRE ATT&CK.
 *
 * Referência: https://attack.mitre.org/
 */
static const char *attack_to_mitre(const char *attack) {
    if (!attack) return "";
    if (strcmp(attack, "PORT_SCAN")    == 0) return "T1046";
    if (strcmp(attack, "NULL_SCAN")    == 0) return "T1046";
    if (strcmp(attack, "XMAS_SCAN")    == 0) return "T1046";
    if (strcmp(attack, "SYNFIN_SCAN")  == 0) return "T1046";
    if (strcmp(attack, "ARP_SPOOF")    == 0) return "T1557";
    if (strcmp(attack, "SYN_FLOOD")    == 0) return "T1498";
    if (strcmp(attack, "BRUTE_FORCE")  == 0) return "T1110";
    if (strcmp(attack, "DNS_TUNNEL")   == 0) return "T1071.004,T1048";
    if (strcmp(attack, "AMPLIFICATION")== 0) return "T1498";
    if (strcmp(attack, "ICMP_FLOOD")   == 0) return "T1498";
    return "";
}

/**
 * @brief Calcula score de severidade 0–100 baseado no estado da kill chain.
 *
 * Base por estágio: RECON=20, EXPLOIT=50, EXFIL=70, COMPLETE=90
 * Bônus de velocidade: +10 se EXPLOIT foi atingido em menos de 5 minutos.
 */
static int calculate_kc_score(const Suspect *s, time_t now) {
    static const int base[] = {0, 20, 50, 70, 90};
    int score = base[s->kc_stage];

    if (s->kc_first_seen > 0 && s->kc_stage >= KC_EXPLOIT) {
        double progression = difftime(now, s->kc_first_seen);
        if (progression < 300) score += 10;  /* progressão em < 5 min = crítico */
    }

    return score > 100 ? 100 : score;
}

/**
 * @brief Avança a máquina de estados da kill chain para um IP.
 *
 * Regras:
 *   1. Reseta o incidente se a janela de 30 minutos expirou.
 *   2. O estágio só avança — nunca retrocede dentro de um incidente.
 *   3. COMPLETE é atingido quando os 3 estágios (RECON+EXPLOIT+EXFIL) ocorrem.
 *   4. Tags MITRE são acumuladas sem duplicatas.
 */
static void advance_kill_chain(Suspect *s, const char *attack, time_t now) {
    if (!attack) return;

    KillChainStage target = attack_to_stage(attack);
    if (target == KC_IDLE) return;

    /* Reset se a janela de correlação expirou */
    if (s->kc_stage > KC_IDLE &&
        difftime(now, s->kc_stage_entered) > KC_WINDOW_SEC) {
        s->kc_stage         = KC_IDLE;
        s->kc_stages_hit    = 0;
        s->kc_first_seen    = 0;
        s->kc_score         = 0;
        memset(s->kc_mitre, 0, KC_MITRE_SIZE);
    }

    /* Marca timestamp da primeira atividade suspeita no incidente */
    if (s->kc_first_seen == 0) s->kc_first_seen = now;

    /* Avança estágio se o alvo é mais avançado que o atual */
    if (target > s->kc_stage) {
        s->kc_stage         = target;
        s->kc_stage_entered = now;
    }

    /* Registra o estágio atingido no bitmask */
    s->kc_stages_hit |= (1 << target);

    /* COMPLETE quando os 3 estágios foram observados (bits 1, 2 e 3) */
    if ((s->kc_stages_hit & 0xE) == 0xE) {
        s->kc_stage = KC_COMPLETE;
    }

    /* Acumula tags MITRE sem duplicatas */
    const char *mitre = attack_to_mitre(attack);
    if (mitre[0] && !strstr(s->kc_mitre, mitre)) {
        if (s->kc_mitre[0])
            strncat(s->kc_mitre, ",", KC_MITRE_SIZE - strlen(s->kc_mitre) - 1);
        strncat(s->kc_mitre, mitre, KC_MITRE_SIZE - strlen(s->kc_mitre) - 1);
    }

    s->kc_score = calculate_kc_score(s, now);
}

/* ========================================================================= *
 * FUNÇÕES AUXILIARES                                                        *
 * ========================================================================= */

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
    last_cleanup  = now;
    printf("[IDS] Limpeza de rotina. IPs rastreados: %d\n", suspect_count);
}

static Suspect *find_or_create_suspect(uint32_t ip) {
    time_t now = time(NULL);

    for (int i = 0; i < suspect_count; i++) {
        if (suspects[i].ip == ip) {
            suspects[i].last_seen = now;
            return &suspects[i];
        }
    }

    if (suspect_count >= MAX_SUSPECTS) return NULL;

    memset(&suspects[suspect_count], 0, sizeof(Suspect));
    suspects[suspect_count].ip                 = ip;
    suspects[suspect_count].last_seen          = now;
    suspects[suspect_count].brute_window_start = now;
    suspects[suspect_count].baseline.window_start = now;

    return &suspects[suspect_count++];
}

/**
 * @brief Calcula a entropia de Shannon de uma string.
 *
 * Subdomains com base64/hex encoding têm entropia alta (>3.5 bits/char)
 * comparado a nomes DNS legítimos (~2.5 bits/char).
 */
static double calculate_entropy(const unsigned char *data, int len) {
    if (len <= 0) return 0.0;

    int freq[256] = {0};
    for (int i = 0; i < len; i++) freq[(unsigned char)data[i]]++;

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
 * Formato wire DNS: cada label é precedida por um byte de tamanho.
 * [3]www[6]google[3]com[0] → "www.google.com"
 */
static int extract_dns_name(const unsigned char *dns_payload, int dns_len,
                            char *out, int out_size) {
    if (dns_len < 13) return 0;

    const unsigned char *ptr = dns_payload + 12;
    const unsigned char *end = dns_payload + dns_len;
    int pos = 0;

    while (ptr < end && *ptr != 0) {
        int label_len = *ptr++;
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
 * FUNÇÕES DE DETECÇÃO                                                       *
 * ========================================================================= */

/**
 * @brief Detecta SYN Flood: volume anormal de SYNs sem ACK.
 *
 * Threshold adaptativo quando calibrado: ewma_pps + 3*stddev * fator de burst.
 * Fallback para threshold fixo (100) durante calibração.
 */
static const char *detect_syn_flood(Suspect *s, uint8_t tcp_flags) {
    if (!((tcp_flags & TH_SYN) && !(tcp_flags & TH_ACK))) return NULL;

    s->syn_count++;

    int threshold = SYN_FLOOD_THRESHOLD;
    if (s->baseline.sample_count >= EWMA_CALIBRATION && s->baseline.ewma_var_pps > 0) {
        double stddev   = sqrt(s->baseline.ewma_var_pps);
        double adaptive = s->baseline.ewma_pps + EWMA_SIGMA * stddev;
        threshold = (int)(adaptive * 2.0);  /* burst SYN = 2x do pps normal */
        if (threshold < 10) threshold = 10;
    }

    return (s->syn_count > threshold) ? "SYN_FLOOD" : NULL;
}

/**
 * @brief Detecta Stealth Scans por combinações anômalas de TCP flags.
 *
 * Null Scan:    flags == 0x00 (nenhum flag setado)
 * Xmas Scan:    FIN + PSH + URG
 * SYN/FIN Scan: SYN + FIN simultâneos (combinação inválida pelo RFC)
 */
static const char *detect_stealth_scan(Suspect *s, uint8_t tcp_flags) {
    if (tcp_flags == 0) {
        s->null_scan_count++;
        if (s->null_scan_count >= STEALTH_THRESHOLD) return "NULL_SCAN";
    }

    if ((tcp_flags & (TH_FIN | TH_PUSH | TH_URG)) == (TH_FIN | TH_PUSH | TH_URG)) {
        s->xmas_scan_count++;
        if (s->xmas_scan_count >= STEALTH_THRESHOLD) return "XMAS_SCAN";
    }

    if ((tcp_flags & (TH_SYN | TH_FIN)) == (TH_SYN | TH_FIN)) {
        s->synfin_scan_count++;
        if (s->synfin_scan_count >= STEALTH_THRESHOLD) return "SYNFIN_SCAN";
    }

    return NULL;
}

/**
 * @brief Detecta brute force em SSH (22), FTP (21), RDP (3389).
 *
 * Conta SYNs iniciais para portas de autenticação em janela de 60 segundos.
 * Limiar: ≥30 tentativas na janela.
 */
static const char *detect_brute_force(Suspect *s, uint8_t tcp_flags, uint16_t dst_port,
                                      time_t now) {
    if (!(tcp_flags & TH_SYN) || (tcp_flags & TH_ACK)) return NULL;
    if (dst_port != PORT_SSH && dst_port != PORT_FTP && dst_port != PORT_RDP) return NULL;

    if (difftime(now, s->brute_window_start) > BRUTE_WINDOW_SEC) {
        s->brute_count        = 0;
        s->brute_window_start = now;
    }

    s->brute_count++;
    return (s->brute_count >= BRUTE_THRESHOLD) ? "BRUTE_FORCE" : NULL;
}

/**
 * @brief Detecta DNS Tunneling por análise de payload.
 *
 * Indicadores: subdomain anormalmente longo (>50 chars), entropia alta no
 * nome (base64/hex), ou volume de DNS anômalo em relação ao baseline EWMA.
 */
static const char *detect_dns_tunnel(Suspect *s, const unsigned char *dns_payload,
                                     int dns_len) {
    char domain[256];
    int name_len = extract_dns_name(dns_payload, dns_len, domain, sizeof(domain));
    if (name_len <= 0) return NULL;

    s->dns_query_count++;

    /* Tamanho do primeiro label (subdomain) */
    int first_label_len = 0;
    for (int i = 0; i < name_len && domain[i] != '.'; i++) first_label_len++;

    int suspicious = 0;

    if (first_label_len > DNS_SUBDOMAIN_LEN) suspicious = 1;

    if (calculate_entropy((const unsigned char *)domain, name_len) > DNS_ENTROPY_THRESH)
        suspicious = 1;

    /* Anomalia de baseline: volume de DNS muito acima do normal para este IP */
    if (!suspicious && s->baseline.sample_count >= EWMA_CALIBRATION) {
        if (is_anomaly((double)s->dns_query_count,
                       s->baseline.ewma_dns,
                       s->baseline.ewma_var_dns))
            suspicious = 1;
    }

    if (suspicious) {
        s->dns_suspicious_count++;
        if (s->dns_suspicious_count >= DNS_SUSPICIOUS_MAX) return "DNS_TUNNEL";
    }

    return NULL;
}

/**
 * @brief Detecta DDoS Amplification por ratio de bytes response/request.
 *
 * Quando as respostas DNS de um IP excedem 10x os requests, o IP está
 * sendo usado como refletor/amplificador.
 */
static const char *detect_amplification(Suspect *s, int bytes, int is_response) {
    if (is_response) s->dns_resp_bytes += bytes;
    else             s->dns_req_bytes  += bytes;

    if (s->dns_req_bytes < 100) return NULL;
    return (s->dns_resp_bytes > s->dns_req_bytes * AMPLIFICATION_RATIO)
           ? "AMPLIFICATION" : NULL;
}

/**
 * @brief Detecta ARP Spoofing: mesmo MAC reivindicando IPs diferentes.
 *
 * Mantém tabela MAC→IP. Alerta quando um MAC visto com IP_A aparece em
 * ARP reply reivindicando IP_B (gratuitous ARP com IP diferente).
 *
 * Layout ARP (após Ethernet 14 bytes):
 *   +8:  Sender MAC (6 bytes)
 *   +14: Sender IP  (4 bytes)
 */
static const char *detect_arp_spoof(const unsigned char *packet, int length) {
    if (length < 42) return NULL;

    const unsigned char *arp = packet + 14;

    /* Operação 2 = ARP Reply */
    uint16_t operation = (arp[6] << 8) | arp[7];
    if (operation != 2) return NULL;

    const unsigned char *sender_mac = arp + 8;
    uint32_t sender_ip;
    memcpy(&sender_ip, arp + 14, 4);

    for (int i = 0; i < arp_count; i++) {
        if (memcmp(arp_table[i].mac, sender_mac, 6) == 0) {
            if (arp_table[i].ip != sender_ip) {
                struct in_addr old_addr, new_addr;
                old_addr.s_addr = arp_table[i].ip;
                new_addr.s_addr = sender_ip;
                printf("[IDS] ARP SPOOF: MAC %02x:%02x:%02x:%02x:%02x:%02x "
                       "mudou de %s para %s!\n",
                       sender_mac[0], sender_mac[1], sender_mac[2],
                       sender_mac[3], sender_mac[4], sender_mac[5],
                       inet_ntoa(old_addr), inet_ntoa(new_addr));

                publish_packet(inet_ntoa(new_addr), 0, "ARP", length,
                               1, "ARP_SPOOF",
                               kc_stage_name[KC_RECON], 20, "T1557");
                return "ARP_SPOOF";
            }
            return NULL;
        }
    }

    if (arp_count < MAX_ARP_ENTRIES) {
        memcpy(arp_table[arp_count].mac, sender_mac, 6);
        arp_table[arp_count].ip = sender_ip;
        arp_count++;
    }

    return NULL;
}

/**
 * @brief Detecta Port Scan: ≥15 portas únicas acessadas por um mesmo IP.
 */
static const char *detect_port_scan(Suspect *s, uint16_t dst_port) {
    for (int j = 0; j < s->port_count; j++) {
        if (s->ports[j] == dst_port) return NULL;  /* porta já vista */
    }

    if (s->port_count < SCAN_THRESHOLD)
        s->ports[s->port_count++] = dst_port;

    return (s->port_count >= SCAN_THRESHOLD) ? "PORT_SCAN" : NULL;
}

/**
 * @brief Detecta ICMP Flood: volume anômalo de pacotes ICMP.
 *
 * Threshold adaptativo quando calibrado. Fallback para 20 durante calibração.
 */
static const char *detect_icmp_flood(Suspect *s) {
    s->icmp_count++;

    int threshold = ICMP_THRESHOLD;
    if (s->baseline.sample_count >= EWMA_CALIBRATION && s->baseline.ewma_var_pps > 0) {
        double stddev   = sqrt(s->baseline.ewma_var_pps);
        double adaptive = s->baseline.ewma_pps + EWMA_SIGMA * stddev;
        threshold = (int)(adaptive * 1.5);
        if (threshold < 5) threshold = 5;
    }

    return (s->icmp_count > threshold) ? "ICMP_FLOOD" : NULL;
}

/* ========================================================================= *
 * FUNÇÃO PRINCIPAL DE ANÁLISE                                               *
 * ========================================================================= */

/**
 * @brief Analisa um pacote capturado e executa todas as detecções do IDS.
 *
 * Fluxo:
 *   1. Identifica EtherType (ARP ou IPv4)
 *   2. Se ARP → verifica spoofing
 *   3. Se IPv4 → busca/cria Suspect → atualiza baseline → executa detecções
 *   4. Se ataque detectado → avança kill chain + calcula score
 *   5. Publica telemetria com kill_chain_stage, kc_score e MITRE no JSON
 *
 * @param packet Buffer bruto do pacote (inclui Ethernet header)
 * @param length Tamanho total do pacote
 * @return 1 se ataque detectado, 0 se tráfego normal
 */
int analyze_packet(const unsigned char *packet, int length) {
    cleanup_suspects();

    if (length < 14) return 0;

    /* EtherType: 0x0806 = ARP | 0x0800 = IPv4 */
    uint16_t ether_type = (packet[12] << 8) | packet[13];

    if (ether_type == 0x0806) {
        const char *arp_attack = detect_arp_spoof(packet, length);
        if (arp_attack && length >= 42) {
            /* Extrai sender IP do ARP reply (offset 14+14=28) para o collector */
            struct in_addr arp_sender;
            memcpy(&arp_sender.s_addr, packet + 28, 4);
            collector_record(arp_attack, inet_ntoa(arp_sender), time(NULL));
        }
        return arp_attack ? 1 : 0;
    }

    if (ether_type != 0x0800) return 0;

    struct ip *ip_header = (struct ip *)(packet + 14);
    uint32_t   src_ip    = ip_header->ip_src.s_addr;
    int        ip_hlen   = ip_header->ip_hl << 2;

    /* HOME_NET skip — promiscuous captura egress do próprio host. Sem skip,
     * DNS queries legítimas viram DNS_TUNNEL (subdomains longos de CDN),
     * e CDN respondendo de múltiplas portas vira PORT_SCAN. */
    if (is_home_ip(src_ip)) return 0;

    Suspect *s = find_or_create_suspect(src_ip);
    if (!s) return 0;

    time_t      now    = time(NULL);
    const char *attack = NULL;

    /* ------------------------------------------------------------------- *
     * ICMP                                                                 *
     * ------------------------------------------------------------------- */
    if (ip_header->ip_p == IPPROTO_ICMP) {
        update_baseline(&s->baseline, 0, 0, now);

        attack = detect_icmp_flood(s);
        if (attack) {
            advance_kill_chain(s, attack, now);
            collector_record(attack, inet_ntoa(ip_header->ip_src), now);
        }

        publish_packet(inet_ntoa(ip_header->ip_src), 0, "ICMP", length,
                       attack ? 1 : 0, attack,
                       kc_stage_name[s->kc_stage], s->kc_score,
                       attack ? attack_to_mitre(attack) : "");
        return attack ? 1 : 0;
    }

    /* ------------------------------------------------------------------- *
     * TCP: Stealth Scan, SYN Flood, Brute Force, Port Scan                *
     * ------------------------------------------------------------------- */
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp      = (struct tcphdr *)(packet + 14 + ip_hlen);
        uint16_t       dst_port = ntohs(tcp->th_dport);
        uint8_t        flags    = tcp->th_flags;

        /* Verifica se é porta nova para o baseline */
        int new_port = 1;
        for (int j = 0; j < s->port_count; j++) {
            if (s->ports[j] == dst_port) { new_port = 0; break; }
        }
        update_baseline(&s->baseline, new_port, 0, now);

        if (!attack) attack = detect_stealth_scan(s, flags);
        if (!attack) attack = detect_syn_flood(s, flags);
        if (!attack) attack = detect_brute_force(s, flags, dst_port, now);
        if (!attack) attack = detect_port_scan(s, dst_port);

        if (attack) {
            advance_kill_chain(s, attack, now);
            collector_record(attack, inet_ntoa(ip_header->ip_src), now);
        }

        publish_packet(inet_ntoa(ip_header->ip_src), dst_port, "TCP", length,
                       attack ? 1 : 0, attack,
                       kc_stage_name[s->kc_stage], s->kc_score,
                       attack ? attack_to_mitre(attack) : "");
        return attack ? 1 : 0;
    }

    /* ------------------------------------------------------------------- *
     * UDP: DNS Tunneling, DDoS Amplification                              *
     * ------------------------------------------------------------------- */
    if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr *udp      = (struct udphdr *)(packet + 14 + ip_hlen);
        uint16_t       src_port = ntohs(udp->uh_sport);
        uint16_t       dst_port = ntohs(udp->uh_dport);
        int            is_dns   = (src_port == 53 || dst_port == 53);

        update_baseline(&s->baseline, 0, is_dns, now);

        if (is_dns) {
            const unsigned char *dns_payload = packet + 14 + ip_hlen + 8;
            int dns_len = length - 14 - ip_hlen - 8;

            if (dns_len > 0) {
                int is_response = (dns_payload[2] & 0x80) != 0;

                if (!is_response)
                    attack = detect_dns_tunnel(s, dns_payload, dns_len);
                if (!attack)
                    attack = detect_amplification(s, length, is_response);
            }
        }

        if (attack) {
            advance_kill_chain(s, attack, now);
            collector_record(attack, inet_ntoa(ip_header->ip_src), now);
        }

        publish_packet(inet_ntoa(ip_header->ip_src), dst_port, "UDP", length,
                       attack ? 1 : 0, attack,
                       kc_stage_name[s->kc_stage], s->kc_score,
                       attack ? attack_to_mitre(attack) : "");
        return attack ? 1 : 0;
    }

    return 0;
}
