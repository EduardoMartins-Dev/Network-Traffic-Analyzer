/* Linux/glibc esconde os tipos BSD (u_char/u_int) sem _GNU_SOURCE.
 * No FreeBSD, <sys/types.h> já os expõe nativamente. */
#ifdef __linux__
#define _GNU_SOURCE
#endif
#include "pipeline.h"
#include "ringbuf.h"
#include "capture.h"
#include "analyzer.h"
#include "publisher.h"
#include "dns_log.h"

#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include "netif.h"
#ifdef _WIN32
#include <windows.h>   /* SetThreadPriority */
#endif

/* ========================================================================= *
 * CONSTANTES                                                                *
 * ========================================================================= */
#define DEFAULT_BUFFER_SIZE     4096
#define DEFAULT_BATCH_SIZE        50
#define DEFAULT_BATCH_TIMEOUT_MS 100
#define DEFAULT_METRICS_INTERVAL  10
#define IDLE_SLEEP_NS         100000   /* 100 µs entre polls do ring buffer */
#define PUBLISH_RETRY_SLEEP_NS 100000000L /* 100 ms entre tentativas c/ broker fora */

/* ========================================================================= *
 * ESTADO GLOBAL                                                             *
 * ========================================================================= */
static ringbuf_t g_rb_pkt;   /* captura → análise                            */
static ringbuf_t g_rb_evt;   /* análise → publicação                         */

static pcap_t *g_pcap_handle = NULL;
static volatile sig_atomic_t g_running = 1;

/* Flags de coordenação de shutdown — propagam vazio dos buffers a jusante */
static _Atomic int g_capture_done  = 0;
static _Atomic int g_analysis_done = 0;
static _Atomic int g_capture_error = 0;   /* interface não abriu → rc != 0 */

/* Contadores observados pelas métricas */
static _Atomic uint64_t g_batches_sent = 0;
static _Atomic uint64_t g_events_sent  = 0;

/* ========================================================================= *
 * CONFIGURAÇÃO VIA ENV                                                      *
 * ========================================================================= */
static int env_int(const char *name, int fallback) {
    const char *v = getenv(name);
    if (!v || !*v) return fallback;
    int n = atoi(v);
    return (n > 0) ? n : fallback;
}

/* ========================================================================= *
 * HOOKS PÚBLICOS                                                            *
 * ========================================================================= */
int pipeline_push_packet(const pkt_slot_t *pkt) { return rb_push(&g_rb_pkt, pkt); }
int pipeline_push_event (const event_slot_t *e) { return rb_push(&g_rb_evt, e); }

void pipeline_request_stop(void) {
    g_running = 0;
    if (g_pcap_handle) pcap_breakloop(g_pcap_handle);
}

/* ========================================================================= *
 * HELPERS DE TEMPO                                                          *
 * ========================================================================= */
static void idle_sleep(long ns) {
    struct timespec ts = { 0, ns };
    nanosleep(&ts, NULL);
}

static long now_ms_monotonic(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* ========================================================================= *
 * HOME_NET init — env AGENT_HOME_NETS override OU auto-detect das redes   *
 * da interface monitorada (netif.h, por plataforma). Sem skip, tráfego    *
 * egress do host vira false-positive no analyzer (DNS_TUNNEL, PORT_SCAN). *
 * ========================================================================= */
static int parse_csv_cidrs(const char *csv) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", csv);
    int n = 0;
    char *save = NULL;
    for (char *tok = strtok_r(buf, ", \t", &save); tok;
         tok = strtok_r(NULL, ", \t", &save)) {
        if (analyzer_add_home_cidr(tok) == 0) n++;
    }
    return n;
}

static void init_home_nets(const char *iface) {
    const char *env = getenv("AGENT_HOME_NETS");
    if (env && *env) {
        int n = parse_csv_cidrs(env);
        fprintf(stderr, "[PIPE] HOME_NET via AGENT_HOME_NETS: %d CIDR(s)\n", n);
    } else {
        int n = netif_home_cidrs(iface, analyzer_add_home_cidr);
        fprintf(stderr, "[PIPE] HOME_NET auto-detect em '%s': %d CIDR(s)\n",
                iface, n);
    }
    analyzer_home_dump();
}

/* ========================================================================= *
 * THREAD 1 — CAPTURA                                                        *
 *                                                                           *
 * Abre a interface em modo promíscuo, eleva prioridade para SCHED_FIFO     *
 * (best-effort) e roda `pcap_loop` até receber `pcap_breakloop`.            *
 * ========================================================================= */
static void *capture_thread(void *arg) {
    const char *iface = (const char *)arg;

    /* Eleva prioridade — não fatal se falhar (ex.: rodando sem CAP_SYS_NICE). */
#ifdef _WIN32
    if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL)) {
        fprintf(stderr, "[PIPE] Aviso: nao foi possivel elevar a prioridade "
                        "da thread de captura.\n");
    }
#else
    struct sched_param sp = { .sched_priority = 80 };
    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp) != 0) {
        fprintf(stderr, "[PIPE] Aviso: nao foi possivel aplicar SCHED_FIFO "
                        "(continuando em SCHED_OTHER).\n");
    }
#endif

    init_home_nets(iface);

    char errbuf[PCAP_ERRBUF_SIZE];
    g_pcap_handle = pcap_open_live(iface, SNAP_LEN, 1, 1000, errbuf);
    if (!g_pcap_handle) {
        fprintf(stderr, "[PIPE] Erro ao abrir %s: %s\n", iface, errbuf);
        g_running       = 0;
        g_capture_error = 1;
        goto done;
    }

    printf("[PIPE] Captura iniciada em '%s'.\n", iface);
    pcap_loop(g_pcap_handle, -1, packet_handler, NULL);

    pcap_close(g_pcap_handle);
    g_pcap_handle = NULL;

done:
    atomic_store_explicit(&g_capture_done, 1, memory_order_release);
    printf("[PIPE] Thread de captura finalizada.\n");
    return NULL;
}

/* ========================================================================= *
 * THREAD 2 — ANÁLISE                                                        *
 *                                                                           *
 * Consome rb_pkt e dispara o pipeline IDS (EWMA + kill chain). As chamadas *
 * a `publish_packet` dentro do analyzer enfileiram eventos em rb_evt.       *
 * Sai quando captura terminou e rb_pkt está vazio.                          *
 * ========================================================================= */
static void *analysis_thread(void *arg) {
    (void)arg;
    pkt_slot_t slot;

    while (1) {
        if (rb_pop(&g_rb_pkt, &slot) == 0) {
            int64_t ts_ms = (int64_t)slot.ts.tv_sec * 1000
                          + (int64_t)(slot.ts.tv_usec / 1000);
            analyze_packet_ms(slot.data, slot.len, slot.ts.tv_sec, ts_ms);
            continue;
        }
        if (atomic_load_explicit(&g_capture_done, memory_order_acquire)) break;
        idle_sleep(IDLE_SLEEP_NS);
    }

    atomic_store_explicit(&g_analysis_done, 1, memory_order_release);
    printf("[PIPE] Thread de analise finalizada.\n");
    return NULL;
}

/* ========================================================================= *
 * THREAD 3 — PUBLICAÇÃO EM BATCH                                            *
 *                                                                           *
 * Acumula até `batch_size` eventos OU espera `batch_timeout_ms` antes de   *
 * chamar `publisher_send_batch`. Evita uma chamada AMQP por pacote.         *
 * ========================================================================= */
static void *publish_thread(void *arg) {
    (void)arg;
    int  batch_size    = env_int("AGENT_BATCH_SIZE",       DEFAULT_BATCH_SIZE);
    long batch_timeout = env_int("AGENT_BATCH_TIMEOUT_MS", DEFAULT_BATCH_TIMEOUT_MS);

    event_slot_t *batch = calloc((size_t)batch_size, sizeof(event_slot_t));
    if (!batch) {
        fprintf(stderr, "[PIPE] Falha ao alocar batch de %d eventos.\n", batch_size);
        return NULL;
    }

    int  filled      = 0;
    long batch_start = now_ms_monotonic();

    while (1) {
        if (filled < batch_size &&
            rb_pop(&g_rb_evt, &batch[filled]) == 0) {
            if (filled == 0) batch_start = now_ms_monotonic();
            filled++;
            continue;
        }

        /* Flush se: batch cheio, timeout atingido, ou análise terminou.    */
        int timed_out = (filled > 0) &&
                        (now_ms_monotonic() - batch_start >= batch_timeout);
        int drained   = atomic_load_explicit(&g_analysis_done, memory_order_acquire);

        if (filled == batch_size || timed_out || (drained && filled > 0)) {
            if (publisher_send_batch(batch, filled) != 0) {
                /* Broker fora: segura o lote e para de consumir rb_evt — os
                 * eventos acumulam a montante (overflow vira métrica). No
                 * shutdown descarta em vez de travar esperando o broker. */
                if (drained) {
                    fprintf(stderr, "[PIPE] Broker indisponivel no shutdown — "
                            "%d eventos descartados.\n", filled);
                    break;
                }
                idle_sleep(PUBLISH_RETRY_SLEEP_NS);
                continue;
            }
            atomic_fetch_add_explicit(&g_batches_sent, 1, memory_order_relaxed);
            atomic_fetch_add_explicit(&g_events_sent, (uint64_t)filled,
                                      memory_order_relaxed);
            filled = 0;
            continue;
        }

        if (drained && filled == 0) break;
        idle_sleep(IDLE_SLEEP_NS);
    }

    free(batch);
    printf("[PIPE] Thread de publicacao finalizada.\n");
    return NULL;
}

/* ========================================================================= *
 * THREAD DE LOGS DE PROTOCOLO (B16, PR a) — só com AGENT_PROTO_LOGS=dns.    *
 *                                                                           *
 * Consome o ring próprio do dns_log e publica em AGENT_PROTO_QUEUE. Não usa  *
 * rb_evt: um pico de logs nunca tira alerta do pipeline. Descarte no ring de *
 * logs aparece em proto_overflow (métricas).                                 *
 * ========================================================================= */
static void *proto_thread(void *arg) {
    (void)arg;
    int  batch_size    = env_int("AGENT_BATCH_SIZE",       DEFAULT_BATCH_SIZE);
    long batch_timeout = env_int("AGENT_BATCH_TIMEOUT_MS", DEFAULT_BATCH_TIMEOUT_MS);

    DnsEvent *batch    = calloc((size_t)batch_size, sizeof(DnsEvent));
    size_t    json_cap = (size_t)batch_size * DNS_LOG_JSON_MAX + 3;
    char     *json     = malloc(json_cap);
    if (!batch || !json) {
        fprintf(stderr, "[PIPE] Falha ao alocar buffers do log de protocolo.\n");
        free(batch);
        free(json);
        return NULL;
    }

    int  filled      = 0;
    long batch_start = now_ms_monotonic();

    while (1) {
        /* `drained` é lido ANTES do pop: se a análise já terminou, um pop que
         * falha de fato quer dizer fila vazia (sem corrida com o último push). */
        int drained = atomic_load_explicit(&g_analysis_done, memory_order_acquire);

        if (filled < batch_size && dns_log_pop(&batch[filled]) == 0) {
            if (filled == 0) batch_start = now_ms_monotonic();
            filled++;
            continue;
        }

        int timed_out = (filled > 0) &&
                        (now_ms_monotonic() - batch_start >= batch_timeout);
        if (filled == batch_size || timed_out || (drained && filled > 0)) {
            int len = dns_log_render_json(batch, filled, json, json_cap);
            if (len < 0) {               /* não deve ocorrer: json_cap cobre o lote */
                filled = 0;
                continue;
            }
            if (publisher_send_protocol(json) != 0) {
                /* Broker fora: segura o lote; o ring enche e conta descarte. No
                 * shutdown descarta em vez de travar. */
                if (drained) {
                    fprintf(stderr, "[PIPE] Broker indisponivel no shutdown — "
                            "%d registros DNS descartados.\n", filled);
                    break;
                }
                idle_sleep(PUBLISH_RETRY_SLEEP_NS);
                continue;
            }
            filled = 0;
            continue;
        }

        if (drained && filled == 0) break;
        idle_sleep(IDLE_SLEEP_NS);
    }

    free(batch);
    free(json);
    printf("[PIPE] Thread de logs de protocolo finalizada.\n");
    return NULL;
}

/* ========================================================================= *
 * THREAD 4 — MÉTRICAS                                                      *
 *                                                                           *
 * A cada N segundos publica um JSON numa routing key separada com o estado *
 * atual do pipeline: profundidade dos buffers, overflows, throughput.       *
 * ========================================================================= */
static void *metrics_thread(void *arg) {
    (void)arg;
    int interval = env_int("AGENT_METRICS_INTERVAL_SEC", DEFAULT_METRICS_INTERVAL);

    uint64_t last_events  = 0;
    long     last_ts_ms   = now_ms_monotonic();

    while (g_running) {
        /* Sleep em fatias pequenas para responder rápido ao shutdown.      */
        for (int i = 0; i < interval * 10 && g_running; i++) idle_sleep(100000000L);
        if (!g_running) break;

        uint64_t events_now = atomic_load_explicit(&g_events_sent,
                                                    memory_order_relaxed);
        long     now_ms     = now_ms_monotonic();
        double   dt         = (now_ms - last_ts_ms) / 1000.0;
        double   eps        = (dt > 0) ? (events_now - last_events) / dt : 0.0;

        analyzer_stats_t as;
        analyzer_get_stats(&as);

        /* proto_overflow (B16) só existe com o log de DNS ligado: desligado, o
         * payload sai igual ao de antes. */
        char proto_field[48] = "";
        if (g_dns_log_on)
            snprintf(proto_field, sizeof(proto_field), ",\"proto_overflow\":%llu",
                     (unsigned long long)dns_log_overflow());

        char payload[512];
        snprintf(payload, sizeof(payload),
            "{\"rb_pkt_depth\":%zu,\"rb_evt_depth\":%zu,"
             "\"rb_pkt_overflow\":%llu,\"rb_evt_overflow\":%llu,"
             "\"batches_sent\":%llu,\"events_sent\":%llu,"
             "\"events_per_sec\":%.2f,"
             "\"vlan_frames\":%llu,\"frag_seen\":%llu,\"frag_discarded\":%llu%s}",
            rb_size(&g_rb_pkt), rb_size(&g_rb_evt),
            (unsigned long long)rb_overflow(&g_rb_pkt),
            (unsigned long long)rb_overflow(&g_rb_evt),
            (unsigned long long)atomic_load_explicit(&g_batches_sent,
                                                     memory_order_relaxed),
            (unsigned long long)events_now,
            eps,
            (unsigned long long)as.vlan_frames,
            (unsigned long long)as.frag_seen,
            (unsigned long long)as.frag_discarded,
            proto_field);

        publisher_send_metrics(payload);

        last_events = events_now;
        last_ts_ms  = now_ms;
    }

    printf("[PIPE] Thread de metricas finalizada.\n");
    return NULL;
}

/* ========================================================================= *
 * ORQUESTRAÇÃO                                                              *
 * ========================================================================= */
int pipeline_run(const char *iface) {
    int buf_size = env_int("AGENT_BUFFER_SIZE", DEFAULT_BUFFER_SIZE);

    if (rb_init(&g_rb_pkt, (size_t)buf_size, sizeof(pkt_slot_t)) != 0) {
        fprintf(stderr, "[PIPE] Falha ao alocar rb_pkt (%d slots).\n", buf_size);
        return -1;
    }
    if (rb_init(&g_rb_evt, (size_t)buf_size, sizeof(event_slot_t)) != 0) {
        fprintf(stderr, "[PIPE] Falha ao alocar rb_evt (%d slots).\n", buf_size);
        rb_destroy(&g_rb_pkt);
        return -1;
    }

    printf("[PIPE] Ring buffers prontos — %zu slots (%d solicitados).\n",
           g_rb_pkt.capacity, buf_size);

    /* Log de DNS (B16) só com AGENT_PROTO_LOGS=dns: ring próprio e fila nova.
     * Antes do init_queue, que declara as filas no primeiro connect. */
    if (g_dns_log_on) {
        if (dns_log_start((size_t)buf_size) != 0) {
            fprintf(stderr, "[PIPE] Falha ao alocar ring de logs de protocolo (%d slots).\n",
                    buf_size);
            rb_destroy(&g_rb_pkt);
            rb_destroy(&g_rb_evt);
            return -1;
        }
        publisher_enable_proto_queue();
    }

    init_queue();

    pthread_t th_cap, th_ana, th_pub, th_met, th_prt;
    pthread_create(&th_cap, NULL, capture_thread,  (void *)iface);
    pthread_create(&th_ana, NULL, analysis_thread, NULL);
    pthread_create(&th_pub, NULL, publish_thread,  NULL);
    pthread_create(&th_met, NULL, metrics_thread,  NULL);
    int prt_ok = 0;
    if (g_dns_log_on) {
        prt_ok = (pthread_create(&th_prt, NULL, proto_thread, NULL) == 0);
        if (!prt_ok) fprintf(stderr, "[PIPE] pthread_create (logs de protocolo) falhou\n");
    }

    /* Ordem de join: captura → análise → publicação → métricas.           *
     * Cada thread downstream observa a flag _done da anterior.            */
    pthread_join(th_cap, NULL);
    pthread_join(th_ana, NULL);
    pthread_join(th_pub, NULL);
    if (prt_ok) pthread_join(th_prt, NULL);
    g_running = 0;              /* força saída da thread de métricas        */
    pthread_join(th_met, NULL);

    printf("[PIPE] Descartes — rb_pkt: %llu · rb_evt: %llu\n",
           (unsigned long long)rb_overflow(&g_rb_pkt),
           (unsigned long long)rb_overflow(&g_rb_evt));
    if (g_dns_log_on)
        printf("[PIPE] Descartes — proto: %llu\n",
               (unsigned long long)dns_log_overflow());

    close_queue();
    rb_destroy(&g_rb_pkt);
    rb_destroy(&g_rb_evt);
    dns_log_stop();

    return g_capture_error ? -1 : 0;
}
