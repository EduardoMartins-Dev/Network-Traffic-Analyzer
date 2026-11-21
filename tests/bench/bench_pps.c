/* ========================================================================= *
 * B02 — Benchmark de throughput do pipeline do agente (pps)                 *
 *                                                                           *
 * Exercita o pipeline REAL de src/agent/core/pipeline.c:                    *
 *   thread de captura -> rb_pkt (SPSC) -> thread de análise (analyzer.c)    *
 *   -> rb_evt (SPSC) -> thread de publicação (batch) -> thread de métricas. *
 *                                                                           *
 * Substituído, para rodar sem rede, sem privilégio e sem RabbitMQ:          *
 *   - pcap_open_live / pcap_loop: gerador sintético de quadros Ethernet +   *
 *     IPv4 (TCP ACK, DNS query UDP, ICMP echo) que chama o packet_handler   *
 *     REAL, dentro da thread de captura. O custo do gerador entra no número.*
 *   - publish_packet: cópia do caminho live de publisher.c (sem AMQP).      *
 *   - publisher_send_batch / publisher_send_metrics: sumidouros. Contam os  *
 *     eventos e leem as amostras de profundidade/overflow que o metrics_th  *
 *     REAL publica. Serialização cJSON e envio AMQP NÃO entram na medição.  *
 *                                                                           *
 * Métricas:                                                                 *
 *   pps processados = eventos recebidos / (último evento - 1º pacote)       *
 *   pps oferecidos  = pacotes gerados / tempo de geração                    *
 *   overflow        = rb_pkt_overflow e rb_evt_overflow da última amostra   *
 *                     de métricas, tomada depois que o pipeline esvaziou    *
 *   latência de fila= Little: W = L / λ, L = média das profundidades        *
 *                     amostradas (1 Hz) e λ = taxa de entrada na fila.      *
 *                     Não é medida por item: exigiria instrumentar o pipeline.*
 *                                                                           *
 * Verificação interna: pacotes oferecidos - overflow(pkt) - overflow(evt)   *
 * tem que ser igual aos eventos recebidos (cada pacote IPv4 TCP/UDP/ICMP    *
 * gera exatamente um evento). Divergência ou drain não concluído sai com 1. *
 *                                                                           *
 * Uso:  bench_pps [--packets N] [--pps N] [--machine texto] [--json arquivo]*
 *   --pps N: taxa oferecida controlada (0/ausente = rajada). A capacidade   *
 *            sem perda é a maior taxa com overflow zero; varie N para achar.*
 * Env lidas pelo pipeline real: AGENT_BUFFER_SIZE, AGENT_BATCH_SIZE,        *
 * AGENT_BATCH_TIMEOUT_MS. O benchmark define AGENT_METRICS_INTERVAL_SEC=1   *
 * se não estiver definida (amostras de fila a 1 Hz).                        *
 * ========================================================================= */
#ifdef __linux__
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <pthread.h>
#include <pcap.h>
#include "nta_net.h"
#include "capture.h"
#include "pipeline.h"
#include "publisher.h"
#include "cJSON.h"
#ifndef _WIN32
#include <unistd.h>
#include <sys/utsname.h>
#endif

#define NTPL             64        /* quadros distintos, reaproveitados em ciclo */
#define MODEL_PPS      1000        /* taxa do tempo de pacote (pcap ts), p/ janelas do analyzer */
#define DEFAULT_PACKETS 1000000ULL
#define DRAIN_TIMEOUT_S   60
#define MAX_SAMPLES     4096

/* ------------------------------------------------------------------------- *
 * Utilitários                                                               *
 * ------------------------------------------------------------------------- */
static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void sleep_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static void set_default_env(const char *k, const char *v) {
#ifdef _WIN32
    if (!getenv(k)) _putenv_s(k, v);
#else
    setenv(k, v, 0);
#endif
}

static const char *env_or(const char *k, const char *fallback) {
    const char *v = getenv(k);
    return (v && *v) ? v : fallback;
}

/* ------------------------------------------------------------------------- *
 * Carga sintética (quadros prontos, reaproveitados)                         *
 *   64 hosts em 198.51.100.0/24 (TEST-NET-2) -> 192.0.2.10 (TEST-NET-1).    *
 *   Cada host usa um só protocolo: 5/8 TCP ACK (80/443), 3/8 DNS query      *
 *   UDP/53. Sem ICMP de propósito: o ICMP_FLOOD do analyzer conta pacotes   *
 *   por IP sem zerar na janela (só na limpeza de 300 s), então qualquer     *
 *   host ICMP com volume sustentado gera alerta (printf) a cada pacote.     *
 * ------------------------------------------------------------------------- */
static uint8_t g_tpl[NTPL][SNAP_LEN];
static int     g_tpl_len[NTPL];

static void build_templates(void) {
    static const uint8_t qname[] = {
        3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
        0, 1,   /* QTYPE A  */
        0, 1    /* QCLASS IN */
    };

    for (int t = 0; t < NTPL; t++) {
        uint8_t *f = g_tpl[t];
        memset(f, 0, SNAP_LEN);
        f[12] = 0x08; f[13] = 0x00;                       /* EtherType IPv4 */

        nta_ipv4_hdr *ip = (nta_ipv4_hdr *)(f + NTA_ETH_HLEN);
        ip->ver_ihl = 0x45;
        ip->ttl     = 64;
        ip->saddr   = htonl(0xC6336400u + (uint32_t)t + 1u);   /* 198.51.100.(t+1) */
        ip->daddr   = htonl(0xC000020Au);                      /* 192.0.2.10       */

        int total;
        if (t % 8 < 5) {                                       /* TCP ACK */
            nta_tcp_hdr *tcp = (nta_tcp_hdr *)(f + NTA_ETH_HLEN + 20);
            tcp->sport    = htons((uint16_t)(40000 + t));
            tcp->dport    = htons((t & 1) ? 443 : 80);
            tcp->data_off = 0x50;
            tcp->flags    = NTA_TH_ACK;
            tcp->window   = htons(65535);
            ip->proto = NTA_PROTO_TCP;
            total = 74;
        } else {                                               /* DNS query */
            nta_udp_hdr *udp = (nta_udp_hdr *)(f + NTA_ETH_HLEN + 20);
            uint8_t *dns = f + NTA_ETH_HLEN + 20 + 8;
            int dns_len = 12 + (int)sizeof(qname);             /* 33 bytes */
            udp->sport = htons((uint16_t)(50000 + t));
            udp->dport = htons(53);
            udp->len   = htons((uint16_t)(8 + dns_len));
            dns[0] = (uint8_t)(t >> 8);
            dns[1] = (uint8_t)(t & 0xFF);
            dns[2] = 0x01;                                     /* RD, QR=0 (query) */
            dns[5] = 0x01;                                     /* QDCOUNT = 1      */
            memcpy(dns + 12, qname, sizeof(qname));
            ip->proto = NTA_PROTO_UDP;
            total = NTA_ETH_HLEN + 20 + 8 + dns_len;           /* 75 */
        }
        ip->tot_len = htons((uint16_t)(total - NTA_ETH_HLEN));
        g_tpl_len[t] = total;
    }
}

/* ------------------------------------------------------------------------- *
 * Estado do run (escrito pela thread de captura; lido após pipeline_run)    *
 * ------------------------------------------------------------------------- */
static uint64_t g_packets   = DEFAULT_PACKETS;
static uint64_t g_pps_target = 0;      /* 0 = rajada (sem pacing)         */
static const char *g_machine = NULL;   /* descrição informada (--machine) */
static time_t   g_base_sec;
static uint64_t g_offered    = 0;
static uint64_t g_t_first    = 0;
static uint64_t g_t_gen_end  = 0;
static int      g_drain_timeout = 0;

/* ------------------------------------------------------------------------- *
 * Sumidouro de publicação e amostras de métricas (protegidos por mutex)     *
 * ------------------------------------------------------------------------- */
typedef struct {
    uint64_t t_ns;
    uint64_t pkt_depth, evt_depth;
    uint64_t pkt_ovf, evt_ovf;
    uint64_t events_sent;
} sample_t;

static _Atomic uint64_t s_events        = 0;
static _Atomic uint64_t s_alerts        = 0;
static _Atomic uint64_t s_batches       = 0;
static _Atomic uint64_t s_t_last_event  = 0;
static _Atomic uint64_t s_metric_errors = 0;

static pthread_mutex_t s_mtx = PTHREAD_MUTEX_INITIALIZER;
static sample_t g_samples[MAX_SAMPLES];   /* guardado por s_mtx */
static int      g_nsamples = 0;           /* guardado por s_mtx */

static int snapshot_count(void) {
    pthread_mutex_lock(&s_mtx);
    int n = g_nsamples;
    pthread_mutex_unlock(&s_mtx);
    return n;
}

static int snapshot_at(int idx, sample_t *out) {
    pthread_mutex_lock(&s_mtx);
    int ok = (idx >= 0 && idx < g_nsamples);
    if (ok) *out = g_samples[idx];
    pthread_mutex_unlock(&s_mtx);
    return ok;
}

/* Substitui publisher_send_batch: conta eventos e alertas, sem AMQP.        */
int publisher_send_batch(const event_slot_t *batch, int count) {
    for (int i = 0; i < count; i++)
        if (batch[i].is_scan) atomic_fetch_add_explicit(&s_alerts, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s_events,  (uint64_t)count, memory_order_relaxed);
    atomic_fetch_add_explicit(&s_batches, 1, memory_order_relaxed);
    atomic_store_explicit(&s_t_last_event, now_ns(), memory_order_release);
    return 0;
}

static uint64_t json_num(const cJSON *root, const char *key, int *ok) {
    const cJSON *it = cJSON_GetObjectItem(root, key);
    if (!cJSON_IsNumber(it)) { *ok = 0; return 0; }
    return (uint64_t)cJSON_GetNumberValue(it);
}

/* Substitui publisher_send_metrics: lê o JSON real do metrics_thread.        */
int publisher_send_metrics(const char *json_payload) {
    cJSON *root = cJSON_Parse(json_payload);
    sample_t s;
    int ok = (root != NULL);
    if (ok) {
        s.t_ns       = now_ns();
        s.pkt_depth  = json_num(root, "rb_pkt_depth", &ok);
        s.evt_depth  = json_num(root, "rb_evt_depth", &ok);
        s.pkt_ovf    = json_num(root, "rb_pkt_overflow", &ok);
        s.evt_ovf    = json_num(root, "rb_evt_overflow", &ok);
        s.events_sent = json_num(root, "events_sent", &ok);
    }
    cJSON_Delete(root);
    if (!ok) {
        atomic_fetch_add_explicit(&s_metric_errors, 1, memory_order_relaxed);
        return 0;
    }
    pthread_mutex_lock(&s_mtx);
    if (g_nsamples < MAX_SAMPLES) g_samples[g_nsamples++] = s;
    pthread_mutex_unlock(&s_mtx);
    return 0;
}

void init_queue(void) {}
void close_queue(void) {}

/* Cópia do caminho live de publish_packet (publisher.c), sem AMQP.          */
void publish_packet(const char *src_ip, int port, const char *proto, int bytes,
                    int is_scan, const char *attack_type,
                    const char *kill_chain_stage, int kc_score,
                    const char *mitre_technique) {
    const char *safe_ip     = src_ip           ? src_ip           : "0.0.0.0";
    const char *safe_proto  = proto            ? proto            : "UNKNOWN";
    const char *safe_attack = attack_type      ? attack_type      : "NONE";
    const char *safe_stage  = kill_chain_stage ? kill_chain_stage : "IDLE";
    const char *safe_mitre  = mitre_technique  ? mitre_technique  : "";

    if (is_scan) {
        printf("[IDS] Alerta: %-14s | IP: %-15s | Kill Chain: %-8s | Score: %3d | MITRE: %s\n",
               safe_attack, safe_ip, safe_stage, kc_score, safe_mitre);
    }

    event_slot_t evt;
    memset(&evt, 0, sizeof(evt));
    strncpy(evt.src_ip,           safe_ip,     sizeof(evt.src_ip)           - 1);
    evt.port    = port;
    strncpy(evt.proto,            safe_proto,  sizeof(evt.proto)            - 1);
    evt.bytes   = bytes;
    evt.is_scan = is_scan;
    strncpy(evt.attack_type,      safe_attack, sizeof(evt.attack_type)      - 1);
    strncpy(evt.kill_chain_stage, safe_stage,  sizeof(evt.kill_chain_stage) - 1);
    evt.kc_score = kc_score;
    strncpy(evt.mitre,            safe_mitre,  sizeof(evt.mitre)            - 1);

    pipeline_push_event(&evt);
}

/* ------------------------------------------------------------------------- *
 * Substitutos de libpcap (só o necessário para pipeline.c e capture.c).     *
 * pcap_loop gera os pacotes e chama o packet_handler REAL. Ignora `cnt`:    *
 * o número de pacotes vem de --packets.                                     *
 * ------------------------------------------------------------------------- */
static char g_fake_handle;   /* pcap_t é opaco; só precisa de endereço único */

pcap_t *pcap_open_live(const char *dev, int snaplen, int promisc, int to_ms, char *errbuf) {
    (void)dev; (void)snaplen; (void)promisc; (void)to_ms; (void)errbuf;
    return (pcap_t *)&g_fake_handle;
}

void pcap_breakloop(pcap_t *p) { (void)p; }
void pcap_close(pcap_t *p)     { (void)p; }

int pcap_findalldevs(pcap_if_t **alldevs, char *errbuf) {
    *alldevs = NULL;
    snprintf(errbuf, PCAP_ERRBUF_SIZE, "bench_pps: libpcap substituida");
    return -1;
}
void pcap_freealldevs(pcap_if_t *alldevs) { (void)alldevs; }

/* Espera o pipeline esvaziar: duas amostras consecutivas de métricas, tomadas
 * depois do fim da geração, com rb_pkt e rb_evt vazios e sem novos envios.  */
static void wait_drain(int base) {
    uint64_t t_start = now_ns();
    for (;;) {
        sleep_ms(100);
        int n = snapshot_count();
        if (n >= base + 2) {
            sample_t a, b;
            if (snapshot_at(n - 2, &a) && snapshot_at(n - 1, &b) &&
                a.pkt_depth == 0 && a.evt_depth == 0 &&
                b.pkt_depth == 0 && b.evt_depth == 0 &&
                a.events_sent == b.events_sent)
                return;
        }
        if (now_ns() - t_start > (uint64_t)DRAIN_TIMEOUT_S * 1000000000ULL) {
            g_drain_timeout = 1;
            return;
        }
    }
}

int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user) {
    (void)p; (void)cnt;

    int base = snapshot_count();

    struct pcap_pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    for (uint64_t i = 0; i < g_packets; i++) {
        int t = (int)(i % NTPL);
        hdr.caplen = (bpf_u_int32)g_tpl_len[t];
        hdr.len    = hdr.caplen;
        hdr.ts.tv_sec  = (long)((uint64_t)g_base_sec + i / MODEL_PPS);
        hdr.ts.tv_usec = (long)((i % MODEL_PPS) * (1000000 / MODEL_PPS));
        if (i == 0) g_t_first = now_ns();
        if (g_pps_target) {                 /* taxa oferecida controlada */
            uint64_t due = g_t_first + i * 1000000000ULL / g_pps_target;
            while (now_ns() < due) { }      /* espera ativa: nanosleep é grosso no Windows */
        }
        callback(user, &hdr, g_tpl[t]);
        g_offered++;
    }
    g_t_gen_end = now_ns();

    wait_drain(base);
    return 0;
}

/* ------------------------------------------------------------------------- *
 * Relatório                                                                 *
 * ------------------------------------------------------------------------- */
typedef struct {
    uint64_t packets_req, pps_target, offered, events, alerts, batches;
    uint64_t pkt_ovf, evt_ovf;
    uint64_t buffer_req, buffer_slots;
    uint64_t metric_errors;
    int      n_samples;
    double   gen_s, elapsed_s;
    double   pps_proc, pps_off, lambda_pkt, lambda_evt;
    double   pkt_depth_avg, evt_depth_avg;
    uint64_t pkt_depth_max, evt_depth_max;
    double   w_pkt_us, w_evt_us;          /* < 0 = não disponível          */
    int      conservation_ok, drain_ok, rc;
} report_t;

static uint64_t next_pow2(uint64_t v) {
    uint64_t p = 1;
    while (p < v) p <<= 1;
    return p;
}

static void print_machine(FILE *f) {
    if (g_machine) fprintf(f, "Máquina (informada): %s\n", g_machine);
#ifdef _WIN32
    fprintf(f, "Máquina: Windows | CPU: %s | processadores lógicos: %s\n",
            env_or("PROCESSOR_IDENTIFIER", "(desconhecida)"),
            env_or("NUMBER_OF_PROCESSORS", "?"));
#else
    struct utsname u;
    if (uname(&u) == 0)
        fprintf(f, "Máquina: %s %s (%s) | processadores lógicos: %ld\n",
                u.sysname, u.release, u.machine, sysconf(_SC_NPROCESSORS_ONLN));
    else
        fprintf(f, "Máquina: (desconhecida)\n");
#endif
}

static void print_report(FILE *f, const report_t *r) {
    fprintf(f, "\n== Resultado (B02 bench_pps) ==\n");
    print_machine(f);
    fprintf(f, "Pacotes pedidos: %llu | oferecidos: %llu | taxa: %s | buffer: %llu slots (pedido %llu)\n",
            (unsigned long long)r->packets_req, (unsigned long long)r->offered,
            r->pps_target ? "pacing" : "rajada",
            (unsigned long long)r->buffer_slots, (unsigned long long)r->buffer_req);
    fprintf(f, "Eventos publicados (sumidouro): %llu em %llu lotes | alertas: %llu\n",
            (unsigned long long)r->events, (unsigned long long)r->batches,
            (unsigned long long)r->alerts);
    fprintf(f, "Tempo: geração %.3f s | ponta a ponta %.3f s\n", r->gen_s, r->elapsed_s);
    fprintf(f, "pps processados (ponta a ponta): %.0f\n", r->pps_proc);
    fprintf(f, "pps oferecidos (geração):        %.0f\n", r->pps_off);
    fprintf(f, "Overflow rb_pkt: %llu (%.2f %% dos oferecidos)\n",
            (unsigned long long)r->pkt_ovf,
            r->offered ? 100.0 * (double)r->pkt_ovf / (double)r->offered : 0.0);
    fprintf(f, "Overflow rb_evt: %llu\n", (unsigned long long)r->evt_ovf);
    if (r->w_pkt_us >= 0) {
        fprintf(f, "Fila rb_pkt: profundidade média %.1f (máx %llu) -> W = %.1f us (Little)\n",
                r->pkt_depth_avg, (unsigned long long)r->pkt_depth_max, r->w_pkt_us);
        fprintf(f, "Fila rb_evt: profundidade média %.1f (máx %llu) -> W = %.1f us (Little)\n",
                r->evt_depth_avg, (unsigned long long)r->evt_depth_max, r->w_evt_us);
    } else {
        fprintf(f, "Fila: sem amostras de métricas (latência de fila n/d)\n");
    }
    fprintf(f, "Amostras de métricas: %d | erros de parse: %llu\n",
            r->n_samples, (unsigned long long)r->metric_errors);
    fprintf(f, "Conservação (oferecidos - ovf_pkt - ovf_evt = eventos): %s\n",
            r->conservation_ok ? "OK" : "FALHOU");
    fprintf(f, "Drain do pipeline: %s\n", r->drain_ok ? "OK" : "TIMEOUT");
    fprintf(f, "Escopo: pcap e AMQP substituídos (ver cabeçalho); cJSON e rede não medidos.\n");
}

static void write_json(const char *path, const report_t *r) {
    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "bench_pps: nao foi possivel gravar %s\n", path);
        return;
    }
    fprintf(f, "{\n");
    fprintf(f, "  \"machine\": \"%s\",\n", g_machine ? g_machine : "");
    fprintf(f, "  \"packets_requested\": %llu,\n", (unsigned long long)r->packets_req);
    fprintf(f, "  \"pps_target\": %llu,\n", (unsigned long long)r->pps_target);
    fprintf(f, "  \"offered\": %llu,\n", (unsigned long long)r->offered);
    fprintf(f, "  \"events\": %llu,\n", (unsigned long long)r->events);
    fprintf(f, "  \"alerts\": %llu,\n", (unsigned long long)r->alerts);
    fprintf(f, "  \"buffer_slots\": %llu,\n", (unsigned long long)r->buffer_slots);
    fprintf(f, "  \"gen_seconds\": %.6f,\n", r->gen_s);
    fprintf(f, "  \"end_to_end_seconds\": %.6f,\n", r->elapsed_s);
    fprintf(f, "  \"pps_processed\": %.1f,\n", r->pps_proc);
    fprintf(f, "  \"pps_offered\": %.1f,\n", r->pps_off);
    fprintf(f, "  \"overflow_rb_pkt\": %llu,\n", (unsigned long long)r->pkt_ovf);
    fprintf(f, "  \"overflow_rb_evt\": %llu,\n", (unsigned long long)r->evt_ovf);
    fprintf(f, "  \"queue_latency_us_rb_pkt\": %.2f,\n", r->w_pkt_us);
    fprintf(f, "  \"queue_latency_us_rb_evt\": %.2f,\n", r->w_evt_us);
    fprintf(f, "  \"metric_samples\": %d,\n", r->n_samples);
    fprintf(f, "  \"conservation_ok\": %s,\n", r->conservation_ok ? "true" : "false");
    fprintf(f, "  \"drain_ok\": %s\n", r->drain_ok ? "true" : "false");
    fprintf(f, "}\n");
    fclose(f);
}

/* ------------------------------------------------------------------------- *
 * main                                                                      *
 * ------------------------------------------------------------------------- */
int main(int argc, char **argv) {
    const char *json_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--packets") == 0 && i + 1 < argc) {
            g_packets = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--pps") == 0 && i + 1 < argc) {
            g_pps_target = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--machine") == 0 && i + 1 < argc) {
            g_machine = argv[++i];
        } else if (strcmp(argv[i], "--json") == 0 && i + 1 < argc) {
            json_path = argv[++i];
        } else {
            fprintf(stderr, "uso: %s [--packets N] [--pps N] [--machine texto] [--json arquivo]\n",
                    argv[0]);
            return 2;
        }
    }
    if (g_packets == 0) {
        fprintf(stderr, "bench_pps: --packets deve ser > 0\n");
        return 2;
    }

    set_default_env("AGENT_METRICS_INTERVAL_SEC", "1");
    build_templates();
    g_base_sec = time(NULL);

    uint64_t buf_req = strtoull(env_or("AGENT_BUFFER_SIZE", "4096"), NULL, 10);

    printf("== bench_pps (B02): pipeline real, sem rede, sem privilegio, sem RabbitMQ ==\n");
    print_machine(stdout);
    printf("Pacotes: %llu | tipo: TCP ACK 62,5%% / DNS query UDP 37,5%% | "
           "64 hosts (198.51.100.0/24)\n", (unsigned long long)g_packets);
    if (g_pps_target)
        printf("Taxa oferecida: %llu pps (pacing)\n", (unsigned long long)g_pps_target);
    else
        printf("Taxa oferecida: rajada (sem pacing; overflow esperado)\n");
    printf("Buffer pedido: %llu | batch: %s | timeout batch: %s ms | metricas: %s s\n",
           (unsigned long long)buf_req,
           env_or("AGENT_BATCH_SIZE", "50 (default)"),
           env_or("AGENT_BATCH_TIMEOUT_MS", "100 (default)"),
           env_or("AGENT_METRICS_INTERVAL_SEC", "1"));

    int rc = pipeline_run("bench-sintetico");

    /* Após pipeline_run (threads juntadas) os valores são estáveis.         */
    report_t r;
    memset(&r, 0, sizeof(r));
    r.rc            = rc;
    r.packets_req   = g_packets;
    r.pps_target    = g_pps_target;
    r.offered       = g_offered;
    r.events        = atomic_load(&s_events);
    r.alerts        = atomic_load(&s_alerts);
    r.batches       = atomic_load(&s_batches);
    r.metric_errors = atomic_load(&s_metric_errors);
    r.buffer_req    = buf_req;
    r.buffer_slots  = next_pow2(buf_req ? buf_req : 4096);
    r.drain_ok      = !g_drain_timeout;

    uint64_t t_last = atomic_load(&s_t_last_event);
    r.gen_s     = (g_t_gen_end > g_t_first) ? (g_t_gen_end - g_t_first) / 1e9 : 0.0;
    r.elapsed_s = (t_last > g_t_first) ? (t_last - g_t_first) / 1e9 : 0.0;
    r.pps_proc  = (r.elapsed_s > 0) ? (double)r.events / r.elapsed_s : 0.0;
    r.pps_off   = (r.gen_s > 0) ? (double)r.offered / r.gen_s : 0.0;

    pthread_mutex_lock(&s_mtx);
    r.n_samples = g_nsamples;
    sample_t last = {0};
    if (g_nsamples > 0) last = g_samples[g_nsamples - 1];
    pthread_mutex_unlock(&s_mtx);

    r.pkt_ovf = last.pkt_ovf;
    r.evt_ovf = last.evt_ovf;

    uint64_t lost = r.pkt_ovf + r.evt_ovf;
    r.conservation_ok = (r.offered >= lost) && (r.offered - lost == r.events);

    if (r.elapsed_s > 0) {
        r.lambda_pkt = (double)(r.offered - r.pkt_ovf) / r.elapsed_s;
        r.lambda_evt = (double)r.events / r.elapsed_s;
    }

    /* Little sobre as amostras da janela [1º pacote, último evento].         */
    double sum_pkt = 0, sum_evt = 0;
    int in_window = 0;
    pthread_mutex_lock(&s_mtx);
    for (int i = 0; i < g_nsamples; i++) {
        if (g_samples[i].t_ns < g_t_first || g_samples[i].t_ns > t_last) continue;
        sum_pkt += (double)g_samples[i].pkt_depth;
        sum_evt += (double)g_samples[i].evt_depth;
        if (g_samples[i].pkt_depth > r.pkt_depth_max) r.pkt_depth_max = g_samples[i].pkt_depth;
        if (g_samples[i].evt_depth > r.evt_depth_max) r.evt_depth_max = g_samples[i].evt_depth;
        in_window++;
    }
    pthread_mutex_unlock(&s_mtx);

    r.w_pkt_us = -1.0;
    r.w_evt_us = -1.0;
    if (in_window > 0 && r.lambda_pkt > 0 && r.lambda_evt > 0) {
        r.pkt_depth_avg = sum_pkt / in_window;
        r.evt_depth_avg = sum_evt / in_window;
        r.w_pkt_us = r.pkt_depth_avg / r.lambda_pkt * 1e6;
        r.w_evt_us = r.evt_depth_avg / r.lambda_evt * 1e6;
    }

    print_report(stdout, &r);
    if (json_path) write_json(json_path, &r);

    int ok = r.conservation_ok && r.drain_ok && r.rc == 0;
    return ok ? 0 : 1;
}
