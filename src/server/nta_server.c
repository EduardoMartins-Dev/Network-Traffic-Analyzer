/* ========================================================================= *
 *  nta-server — servidor central em C (substituto do data_ingestor.py).     *
 *                                                                           *
 *  Responsabilidades (completas na v7.0):                                   *
 *    1. Consome traffic_queue (N workers, 1 conn AMQP cada)                 *
 *    2. Enriquece com GeoIP offline via libmaxminddb                        *
 *    3. Grava line protocol no InfluxDB via libcurl                         *
 *    4. Republica eventos críticos (kc_score >= N) em narrator_queue        *
 *    5. Consome traffic_metrics (worker dedicado → pipeline_metrics)        *
 *                                                                           *
 *  Esta etapa (1) entrega APENAS o esqueleto: parse de config + signal      *
 *  handling + shutdown limpo. Lógica AMQP/Influx/GeoIP vem nas etapas       *
 *  seguintes.                                                               *
 * ========================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include "../../include/nta_server.h"
#include "../../include/nta_consumer.h"
#include "../../include/nta_influx.h"
#include "../../include/nta_geoip.h"

atomic_int g_nta_stop = 0;

/* -------------------------------------------------------------------------- *
 * Helpers de env var                                                         *
 * -------------------------------------------------------------------------- */
static const char *env_or(const char *name, const char *fallback) {
    const char *v = getenv(name);
    return (v && *v) ? v : fallback;
}

static int env_int(const char *name, int fallback) {
    const char *v = getenv(name);
    if (!v || !*v) return fallback;
    char *end = NULL;
    long n = strtol(v, &end, 10);
    if (end == v || n < 0) return fallback;
    return (int)n;
}

/* -------------------------------------------------------------------------- *
 * Config                                                                     *
 * -------------------------------------------------------------------------- */
void nta_config_load(NtaConfig *cfg) {
    cfg->influx_url    = env_or("INFLUX_URL",    "http://localhost:8086");
    cfg->influx_token  = env_or("INFLUX_TOKEN",  "my-super-secret-auth-token");
    cfg->influx_org    = env_or("INFLUX_ORG",    "cybersecurity");
    cfg->influx_bucket = env_or("INFLUX_BUCKET", "network_traffic");

    cfg->rabbit_host     = env_or("RABBIT_HOST",     "localhost");
    cfg->rabbit_port     = env_int("RABBIT_PORT",    5674);
    cfg->rabbit_user     = env_or("RABBIT_USER",     "guest");
    cfg->rabbit_pass     = env_or("RABBIT_PASS",     "guest");
    cfg->rabbit_vhost    = env_or("RABBIT_VHOST",    "/");
    cfg->queue_name      = env_or("QUEUE_NAME",      "traffic_queue");
    cfg->metrics_queue   = env_or("METRICS_QUEUE",   "traffic_metrics");
    cfg->narrator_queue  = env_or("NARRATOR_QUEUE",  "narrator_queue");

    cfg->narrator_min_score = env_int("NARRATOR_MIN_SCORE", 80);

    cfg->geoip_db_path = env_or("GEOIP_DB_PATH", "./GeoLite2-City.mmdb");

    cfg->num_workers = env_int("NTA_WORKERS", 4);
    if (cfg->num_workers < 1) cfg->num_workers = 1;
    if (cfg->num_workers > 32) cfg->num_workers = 32;
}

void nta_config_print(const NtaConfig *cfg) {
    /* Mascara o token pra não vazar em logs. */
    const char *tok = cfg->influx_token ? cfg->influx_token : "";
    size_t tlen = strlen(tok);
    char tok_masked[16];
    if (tlen <= 4) {
        snprintf(tok_masked, sizeof(tok_masked), "****");
    } else {
        snprintf(tok_masked, sizeof(tok_masked), "****%s", tok + tlen - 4);
    }

    fprintf(stderr,
        "▶ nta-server config:\n"
        "    InfluxDB  url=%s org=%s bucket=%s token=%s\n"
        "    RabbitMQ  host=%s port=%d user=%s vhost=%s\n"
        "    Queues    traffic=%s metrics=%s narrator=%s\n"
        "    Narrator  min_score=%d\n"
        "    GeoIP     db=%s\n"
        "    Workers   %d\n",
        cfg->influx_url, cfg->influx_org, cfg->influx_bucket, tok_masked,
        cfg->rabbit_host, cfg->rabbit_port, cfg->rabbit_user, cfg->rabbit_vhost,
        cfg->queue_name, cfg->metrics_queue, cfg->narrator_queue,
        cfg->narrator_min_score,
        cfg->geoip_db_path,
        cfg->num_workers);
}

/* -------------------------------------------------------------------------- *
 * Signal handling                                                            *
 * -------------------------------------------------------------------------- */
static void on_signal(int sig) {
    (void)sig;
    atomic_store_explicit(&g_nta_stop, 1, memory_order_relaxed);
}

/* -------------------------------------------------------------------------- *
 * Handler de traffic_queue (etapas 4–5): parse → GeoIP → InfluxDB.           *
 * Etapa 7 adiciona republish em narrator_queue.                              *
 * -------------------------------------------------------------------------- */
typedef struct {
    NtaInflux *inf;
    NtaGeo    *geo;   /* pode ser NULL se mmdb ausente */
} TrafficCtx;

static void traffic_handler(const char *body, size_t len,
                            const char *agent_id, void *user_ctx) {
    TrafficCtx *ctx = (TrafficCtx *)user_ctx;
    if (nta_influx_write_traffic(ctx->inf, ctx->geo, body, len, agent_id) != 0) {
        fprintf(stderr, "[MSG] descarte agent=%s len=%zu (escrita falhou)\n",
                agent_id, len);
    }
}

/* -------------------------------------------------------------------------- *
 * Worker — 1 thread = 1 conn AMQP + 1 handle libcurl.                       *
 * NtaGeo é compartilhado entre workers (thread-safe internamente).          *
 * -------------------------------------------------------------------------- */
typedef struct {
    int             worker_id;
    const NtaConfig *cfg;
    NtaGeo         *geo;       /* shared */
    NtaAmqp         amqp;      /* per-worker */
    NtaInflux       influx;    /* per-worker */
} Worker;

static void *worker_main(void *arg) {
    Worker *w = (Worker *)arg;

    if (nta_influx_open(&w->influx, w->cfg) != 0) {
        fprintf(stderr, "[W-%d] InfluxDB open falhou\n", w->worker_id);
        return NULL;
    }

    /* Prefetch baixo por worker pra distribuir trabalho de forma justa.
     * Total em flight: NTA_WORKERS * prefetch = 4 * 20 = 80. */
    if (nta_amqp_open(&w->amqp, w->cfg, w->cfg->queue_name, 20) != 0) {
        fprintf(stderr, "[W-%d] AMQP open falhou\n", w->worker_id);
        nta_influx_close(&w->influx);
        return NULL;
    }

    fprintf(stderr, "[W-%d] pronto.\n", w->worker_id);

    TrafficCtx ctx = { .inf = &w->influx, .geo = w->geo };
    nta_amqp_consume_loop(&w->amqp, w->cfg->queue_name,
                           traffic_handler, &ctx);

    nta_amqp_close(&w->amqp);
    nta_influx_close(&w->influx);
    fprintf(stderr, "[W-%d] encerrado.\n", w->worker_id);
    return NULL;
}

/* -------------------------------------------------------------------------- *
 * main                                                                       *
 * -------------------------------------------------------------------------- */
int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    NtaConfig cfg;
    nta_config_load(&cfg);
    nta_config_print(&cfg);

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN); /* libcurl/AMQP podem receber EPIPE sem drama. */

    /* ---------------------------------------------------------------- *
     * Pool de workers (etapa 6).                                       *
     *                                                                  *
     * Cada worker tem sua PRÓPRIA conn AMQP e seu PRÓPRIO handle curl  *
     * (libcurl easy não é thread-safe; librabbitmq tampouco compartilha *
     * connections). NtaGeo é compartilhado — o módulo já tem mutex.    *
     * ---------------------------------------------------------------- */
    if (nta_influx_global_init() != 0) {
        fprintf(stderr, "✗ falha ao inicializar libcurl — abortando\n");
        return 1;
    }

    NtaGeo *geo = nta_geo_open(cfg.geoip_db_path);
    if (!geo) {
        fprintf(stderr, "⚠ GeoIP indisponível (db=%s) — eventos sem lat/lon. "
                "Veja data/GeoLite2-City.mmdb.README.md\n",
                cfg.geoip_db_path);
    }

    /* Bloqueia SIGINT/SIGTERM ANTES de spawnar — workers herdam a máscara
     * e ficam imunes. Signal vai sempre pra main, que seta o stop flag.   */
    sigset_t block_set, prev_set;
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGINT);
    sigaddset(&block_set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &block_set, &prev_set);

    Worker *workers = calloc((size_t)cfg.num_workers, sizeof(Worker));
    pthread_t *tids = calloc((size_t)cfg.num_workers, sizeof(pthread_t));
    if (!workers || !tids) {
        fprintf(stderr, "✗ alocação de workers falhou\n");
        free(workers); free(tids);
        nta_geo_close(geo);
        nta_influx_global_cleanup();
        return 1;
    }

    int spawned = 0;
    for (int i = 0; i < cfg.num_workers; i++) {
        workers[i].worker_id = i;
        workers[i].cfg       = &cfg;
        workers[i].geo       = geo;
        if (pthread_create(&tids[i], NULL, worker_main, &workers[i]) != 0) {
            fprintf(stderr, "[W-%d] pthread_create falhou — abortando spawn\n", i);
            atomic_store(&g_nta_stop, 1);
            break;
        }
        spawned++;
    }

    /* Restaura máscara na main pra receber SIGINT/SIGTERM. */
    pthread_sigmask(SIG_SETMASK, &prev_set, NULL);

    fprintf(stderr, "▶ %d worker(s) consumindo '%s' → InfluxDB%s (Ctrl+C p/ parar)\n",
            spawned, cfg.queue_name, geo ? " (+GeoIP)" : "");

    /* Espera workers terminarem (eles saem ao detectar g_nta_stop). */
    for (int i = 0; i < spawned; i++) {
        pthread_join(tids[i], NULL);
    }

    free(workers);
    free(tids);
    nta_geo_close(geo);
    nta_influx_global_cleanup();

    fprintf(stderr, "✓ nta-server encerrado.\n");
    return 0;
}
