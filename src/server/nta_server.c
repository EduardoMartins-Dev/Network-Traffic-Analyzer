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
#include "../../include/nta_ioc.h"
#include "../../include/nta_narrator.h"
#include "../../include/nta_scaler.h"
#include "../../include/cJSON.h"

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

    cfg->geoip_db_path     = env_or("GEOIP_DB_PATH",     "./GeoLite2-City.mmdb");
    cfg->geoip_asn_db_path = env_or("GEOIP_ASN_DB_PATH", "./GeoLite2-ASN.mmdb");

    cfg->ioc_path = env_or("IOC_PATH", "./deploy/ioc/blocklist.json");

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
        "    GeoIP     city=%s asn=%s\n"
        "    IoC       path=%s\n"
        "    Workers   %d\n",
        cfg->influx_url, cfg->influx_org, cfg->influx_bucket, tok_masked,
        cfg->rabbit_host, cfg->rabbit_port, cfg->rabbit_user, cfg->rabbit_vhost,
        cfg->queue_name, cfg->metrics_queue, cfg->narrator_queue,
        cfg->narrator_min_score,
        cfg->geoip_db_path, cfg->geoip_asn_db_path,
        cfg->ioc_path,
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
 * Handler de traffic_queue: parse → GeoIP → InfluxDB → republish narrator.  *
 *                                                                            *
 * Republish: para cada evento individual com kc_score >= min_score, publica *
 * o objeto JSON em narrator_queue. Header `x-agent-id` carrega identidade   *
 * original. Reusa o mesmo channel AMQP do consumer (librabbitmq permite     *
 * publish e consume no mesmo channel — auto_ack mantém ordem).              *
 * -------------------------------------------------------------------------- */
typedef struct {
    NtaInflux  *inf;
    NtaGeo     *geo;            /* shared, pode ser NULL */
    NtaIoc     *ioc;            /* shared, pode ser NULL (v8.0 M3) */
    NtaAmqp    *amqp;           /* per-worker, mesmo do consumer */
    const char *narrator_queue;
    int         min_score;      /* 0 desabilita republish */
} TrafficCtx;

static void republish_if_high(TrafficCtx *ctx, const cJSON *evt,
                              const char *agent_id) {
    if (!ctx->amqp || !ctx->narrator_queue || ctx->min_score <= 0) return;
    const cJSON *score = cJSON_GetObjectItemCaseSensitive(evt, "kc_score");
    if (!cJSON_IsNumber(score) || score->valuedouble < ctx->min_score) return;

    char *s = cJSON_PrintUnformatted(evt);
    if (!s) return;
    if (nta_amqp_publish(ctx->amqp, ctx->narrator_queue, agent_id,
                         s, strlen(s)) == 0) {
        const cJSON *ip = cJSON_GetObjectItemCaseSensitive(evt, "src_ip");
        fprintf(stderr, "[NARR] republish agent=%s src=%s score=%.0f\n",
                agent_id,
                (cJSON_IsString(ip) && ip->valuestring) ? ip->valuestring : "?",
                score->valuedouble);
    }
    free(s);
}

static void traffic_handler(const char *body, size_t len,
                            const char *agent_id, void *user_ctx) {
    TrafficCtx *ctx = (TrafficCtx *)user_ctx;
    if (nta_influx_write_traffic(ctx->inf, ctx->geo, ctx->ioc,
                                  body, len, agent_id) != 0) {
        fprintf(stderr, "[MSG] descarte agent=%s len=%zu (escrita falhou)\n",
                agent_id, len);
        return;
    }

    if (ctx->min_score <= 0) return;

    cJSON *root = cJSON_ParseWithLength(body, len);
    if (!root) return;

    if (cJSON_IsArray(root)) {
        const cJSON *item = NULL;
        cJSON_ArrayForEach(item, root) {
            if (cJSON_IsObject(item)) republish_if_high(ctx, item, agent_id);
        }
    } else if (cJSON_IsObject(root)) {
        republish_if_high(ctx, root, agent_id);
    }
    cJSON_Delete(root);
}

/* -------------------------------------------------------------------------- *
 * Handler de traffic_metrics: grava measurement pipeline_metrics.            *
 * -------------------------------------------------------------------------- */
typedef struct {
    NtaInflux *inf;
} MetricsCtx;

static void metrics_handler(const char *body, size_t len,
                            const char *agent_id, void *user_ctx) {
    MetricsCtx *ctx = (MetricsCtx *)user_ctx;
    if (nta_influx_write_metrics(ctx->inf, body, len, agent_id) != 0) {
        fprintf(stderr, "[METRICS] descarte agent=%s len=%zu\n", agent_id, len);
    }
}

/* -------------------------------------------------------------------------- *
 * Handler de narrator_queue: chama Groq → grava incident_narrative.         *
 * -------------------------------------------------------------------------- */
typedef struct {
    NtaInflux  *inf;
    NtaNarrator *nar;
    const NtaNarratorCfg *ncfg;
} NarratorCtx;

static void narrator_handler(const char *body, size_t len,
                             const char *agent_id, void *user_ctx) {
    NarratorCtx *ctx = (NarratorCtx *)user_ctx;
    char *narrative = nta_narrator_call(ctx->nar, body, len, agent_id);
    if (!narrative) return;
    nta_influx_write_narrative(ctx->inf, body, len, narrative,
                               agent_id, nta_narrator_backend(ctx->ncfg));
    free(narrative);
}

/* -------------------------------------------------------------------------- *
 * Worker — 1 thread = 1 conn AMQP + 1 handle libcurl.                       *
 * NtaGeo é compartilhado entre workers (thread-safe internamente).          *
 * -------------------------------------------------------------------------- */
typedef struct {
    int             worker_id;
    const NtaConfig *cfg;
    NtaGeo         *geo;       /* shared */
    NtaIoc         *ioc;       /* shared (v8.0 M3) */
    NtaAmqp         amqp;      /* per-worker */
    NtaInflux       influx;    /* per-worker */
    const NtaNarratorCfg *ncfg;  /* só pro narrator worker */
    atomic_int      stop;      /* per-worker (0=run, 1=drain). Usado pelo scaler */
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

    /* Pré-declara narrator_queue no mesmo canal — idempotente. Se falhar,
     * desabilita republish neste worker (min_score=0) mas segue consumindo. */
    int can_narrate = 1;
    if (w->cfg->narrator_min_score > 0 && w->cfg->narrator_queue) {
        if (nta_amqp_declare_queue(&w->amqp, w->cfg->narrator_queue) != 0) {
            fprintf(stderr, "[W-%d] declare narrator_queue falhou — sem republish\n",
                    w->worker_id);
            can_narrate = 0;
        }
    }

    fprintf(stderr, "[W-%d] pronto%s.\n", w->worker_id,
            can_narrate ? " (+narrator republish)" : "");

    TrafficCtx ctx = {
        .inf            = &w->influx,
        .geo            = w->geo,
        .ioc            = w->ioc,
        .amqp           = &w->amqp,
        .narrator_queue = w->cfg->narrator_queue,
        .min_score      = can_narrate ? w->cfg->narrator_min_score : 0,
    };
    nta_amqp_consume_loop(&w->amqp, w->cfg->queue_name,
                           traffic_handler, &ctx, &w->stop);

    nta_amqp_close(&w->amqp);
    nta_influx_close(&w->influx);
    fprintf(stderr, "[W-%d] encerrado.\n", w->worker_id);
    return NULL;
}

/* -------------------------------------------------------------------------- *
 * Worker dedicado da fila de métricas. Conn AMQP separada, prefetch baixo.  *
 * -------------------------------------------------------------------------- */
static void *metrics_worker_main(void *arg) {
    Worker *w = (Worker *)arg;

    if (nta_influx_open(&w->influx, w->cfg) != 0) {
        fprintf(stderr, "[METRICS] InfluxDB open falhou\n");
        return NULL;
    }
    if (nta_amqp_open(&w->amqp, w->cfg, w->cfg->metrics_queue, 5) != 0) {
        fprintf(stderr, "[METRICS] AMQP open falhou\n");
        nta_influx_close(&w->influx);
        return NULL;
    }

    fprintf(stderr, "[METRICS] pronto (queue=%s).\n", w->cfg->metrics_queue);

    MetricsCtx ctx = { .inf = &w->influx };
    nta_amqp_consume_loop(&w->amqp, w->cfg->metrics_queue,
                           metrics_handler, &ctx, NULL);

    nta_amqp_close(&w->amqp);
    nta_influx_close(&w->influx);
    fprintf(stderr, "[METRICS] encerrado.\n");
    return NULL;
}

/* -------------------------------------------------------------------------- *
 * Worker dedicado de narrator_queue: Groq → InfluxDB. Thread única,         *
 * prefetch=1 (chamada LLM é cara — não acumula backlog em memória).          *
 * -------------------------------------------------------------------------- */
static void *narrator_worker_main(void *arg) {
    Worker *w = (Worker *)arg;

    if (nta_influx_open(&w->influx, w->cfg) != 0) {
        fprintf(stderr, "[NARR] InfluxDB open falhou\n");
        return NULL;
    }
    NtaNarrator nar;
    if (nta_narrator_open(&nar, w->ncfg) != 0) {
        fprintf(stderr, "[NARR] narrator open falhou (api_key ausente?)\n");
        nta_influx_close(&w->influx);
        return NULL;
    }
    if (nta_amqp_open(&w->amqp, w->cfg, w->cfg->narrator_queue, 1) != 0) {
        fprintf(stderr, "[NARR] AMQP open falhou\n");
        nta_narrator_close(&nar);
        nta_influx_close(&w->influx);
        return NULL;
    }

    fprintf(stderr, "[NARR] pronto (queue=%s backend=%s).\n",
            w->cfg->narrator_queue, nta_narrator_backend(w->ncfg));

    NarratorCtx ctx = { .inf = &w->influx, .nar = &nar, .ncfg = w->ncfg };
    nta_amqp_consume_loop(&w->amqp, w->cfg->narrator_queue,
                           narrator_handler, &ctx, NULL);

    nta_amqp_close(&w->amqp);
    nta_narrator_close(&nar);
    nta_influx_close(&w->influx);
    fprintf(stderr, "[NARR] encerrado.\n");
    return NULL;
}

/* -------------------------------------------------------------------------- *
 * Traffic pool — array dinâmico de slots gerenciado pelo scaler.            *
 * Slots inativos podem ser preenchidos por scale_up; ativos são drenados   *
 * via per-worker stop flag em scale_down (pthread_join no scaler thread).  *
 * -------------------------------------------------------------------------- */
typedef struct {
    Worker         *slots;       /* array[max] */
    pthread_t      *tids;
    int            *active;      /* 0/1 por slot */
    int             max;
    int             count;       /* slots ativos */
    pthread_mutex_t mu;
    const NtaConfig *cfg;
    NtaGeo         *geo;
    NtaIoc         *ioc;         /* shared (v8.0 M3) */
    int             next_id;     /* contador monotônico p/ worker_id */
} TrafficPool;

static int pool_init(TrafficPool *p, const NtaConfig *cfg, NtaGeo *geo,
                     NtaIoc *ioc, int max) {
    memset(p, 0, sizeof(*p));
    p->slots  = calloc((size_t)max, sizeof(Worker));
    p->tids   = calloc((size_t)max, sizeof(pthread_t));
    p->active = calloc((size_t)max, sizeof(int));
    if (!p->slots || !p->tids || !p->active) return -1;
    p->max = max;
    p->cfg = cfg;
    p->geo = geo;
    p->ioc = ioc;
    pthread_mutex_init(&p->mu, NULL);
    return 0;
}

static int pool_spawn_one_locked(TrafficPool *p) {
    int idx = -1;
    for (int i = 0; i < p->max; i++) {
        if (!p->active[i]) { idx = i; break; }
    }
    if (idx < 0) return -1;
    Worker *w = &p->slots[idx];
    memset(w, 0, sizeof(*w));
    w->worker_id = p->next_id++;
    w->cfg       = p->cfg;
    w->geo       = p->geo;
    w->ioc       = p->ioc;
    atomic_init(&w->stop, 0);
    if (pthread_create(&p->tids[idx], NULL, worker_main, w) != 0) {
        fprintf(stderr, "[POOL] pthread_create slot=%d falhou\n", idx);
        return -1;
    }
    p->active[idx] = 1;
    p->count++;
    atomic_store_explicit(&g_nta_pool_size, p->count, memory_order_relaxed);
    return p->count;
}

/* Callbacks p/ scaler. */
static int pool_size_cb(void *u) {
    TrafficPool *p = (TrafficPool *)u;
    pthread_mutex_lock(&p->mu);
    int n = p->count;
    pthread_mutex_unlock(&p->mu);
    return n;
}

static int pool_up_cb(void *u) {
    TrafficPool *p = (TrafficPool *)u;
    pthread_mutex_lock(&p->mu);
    int n = p->count;
    if (n < p->max) {
        int r = pool_spawn_one_locked(p);
        if (r > 0) n = r;
    }
    pthread_mutex_unlock(&p->mu);
    return n;
}

static int pool_down_cb(void *u) {
    TrafficPool *p = (TrafficPool *)u;
    /* Pega LIFO: último slot ativo. Marca stop sob lock; join fora do lock. */
    pthread_mutex_lock(&p->mu);
    int idx = -1;
    for (int i = p->max - 1; i >= 0; i--) {
        if (p->active[i]) { idx = i; break; }
    }
    if (idx < 0) { pthread_mutex_unlock(&p->mu); return 0; }
    atomic_store_explicit(&p->slots[idx].stop, 1, memory_order_relaxed);
    pthread_t tid = p->tids[idx];
    pthread_mutex_unlock(&p->mu);

    pthread_join(tid, NULL);

    pthread_mutex_lock(&p->mu);
    p->active[idx] = 0;
    p->count--;
    int n = p->count;
    atomic_store_explicit(&g_nta_pool_size, n, memory_order_relaxed);
    pthread_mutex_unlock(&p->mu);
    return n;
}

static void pool_join_all(TrafficPool *p) {
    /* Shutdown global: g_nta_stop já está setado. Só joina slots ativos. */
    for (int i = 0; i < p->max; i++) {
        pthread_mutex_lock(&p->mu);
        int active = p->active[i];
        pthread_t tid = p->tids[i];
        pthread_mutex_unlock(&p->mu);
        if (active) pthread_join(tid, NULL);
    }
    pthread_mutex_lock(&p->mu);
    for (int i = 0; i < p->max; i++) p->active[i] = 0;
    p->count = 0;
    pthread_mutex_unlock(&p->mu);
}

static void pool_destroy(TrafficPool *p) {
    pthread_mutex_destroy(&p->mu);
    free(p->slots);
    free(p->tids);
    free(p->active);
    memset(p, 0, sizeof(*p));
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

    NtaGeo *geo = nta_geo_open(cfg.geoip_db_path, cfg.geoip_asn_db_path);
    if (!geo) {
        fprintf(stderr, "⚠ GeoIP indisponível (city=%s asn=%s) — eventos "
                "sem lat/lon/asn. Veja data/GeoLite2-*.mmdb.README.md\n",
                cfg.geoip_db_path, cfg.geoip_asn_db_path);
    }

    NtaIoc *ioc = nta_ioc_load(cfg.ioc_path);
    if (!ioc) {
        fprintf(stderr, "⚠ IoC desabilitado (path=%s) — sem tags ioc_hit. "
                "Veja deploy/ioc/blocklist.json.example\n", cfg.ioc_path);
    }

    /* Narrator config — repo_root = cwd (assume script up.sh ou make rodando
     * a partir da raiz). Se GROQ_API_KEY ausente, narrator worker não sobe. */
    NtaNarratorCfg ncfg;
    nta_narrator_load(&ncfg, ".");
    if (!ncfg.enabled) {
        fprintf(stderr, "⚠ GROQ_API_KEY ausente — narrator worker desabilitado.\n");
    }

    /* Carrega config do scaler. Se enabled=0, pool fica fixo em num_workers. */
    NtaScalerCtx sctx;
    nta_scaler_load(&sctx.cfg, &cfg);

    /* Pool max = max(scaler.max, cfg.num_workers). Garante que initial cabe. */
    int pool_max = sctx.cfg.max_workers;
    if (pool_max < cfg.num_workers) pool_max = cfg.num_workers;

    TrafficPool pool;
    if (pool_init(&pool, &cfg, geo, ioc, pool_max) != 0) {
        fprintf(stderr, "✗ pool_init falhou\n");
        nta_ioc_close(ioc);
        nta_geo_close(geo);
        nta_influx_global_cleanup();
        return 1;
    }

    /* Bloqueia SIGINT/SIGTERM ANTES de spawnar — workers herdam a máscara
     * e ficam imunes. Signal vai sempre pra main, que seta o stop flag.   */
    sigset_t block_set, prev_set;
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGINT);
    sigaddset(&block_set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &block_set, &prev_set);

    /* Initial spawn = cfg.num_workers traffic workers. */
    pthread_mutex_lock(&pool.mu);
    for (int i = 0; i < cfg.num_workers; i++) {
        if (pool_spawn_one_locked(&pool) < 0) {
            atomic_store(&g_nta_stop, 1);
            break;
        }
    }
    pthread_mutex_unlock(&pool.mu);

    /* Metrics worker (thread fixa, fora do pool). */
    Worker metrics_w = { .worker_id = -1, .cfg = &cfg, .geo = NULL };
    pthread_t metrics_tid;
    int metrics_ok = (pthread_create(&metrics_tid, NULL,
                                      metrics_worker_main, &metrics_w) == 0);
    if (!metrics_ok) fprintf(stderr, "[METRICS] pthread_create falhou\n");

    /* Narrator worker (thread fixa, fora do pool, opcional). */
    Worker narrator_w = { .worker_id = -2, .cfg = &cfg, .geo = NULL, .ncfg = &ncfg };
    pthread_t narrator_tid;
    int narrator_ok = 0;
    if (ncfg.enabled) {
        narrator_ok = (pthread_create(&narrator_tid, NULL,
                                       narrator_worker_main, &narrator_w) == 0);
        if (!narrator_ok) fprintf(stderr, "[NARR] pthread_create falhou\n");
    }

    /* Scaler thread (opcional). */
    pthread_t scaler_tid;
    int scaler_ok = 0;
    if (sctx.cfg.enabled) {
        sctx.base      = &cfg;
        sctx.pool_user = &pool;
        sctx.pool_size = pool_size_cb;
        sctx.pool_up   = pool_up_cb;
        sctx.pool_down = pool_down_cb;
        scaler_ok = (pthread_create(&scaler_tid, NULL,
                                     nta_scaler_thread_main, &sctx) == 0);
        if (!scaler_ok) fprintf(stderr, "[SCALER] pthread_create falhou\n");
    }

    /* Restaura máscara na main pra receber SIGINT/SIGTERM. */
    pthread_sigmask(SIG_SETMASK, &prev_set, NULL);

    fprintf(stderr, "▶ %d traffic + %d metrics + %d narrator + %d scaler — '%s' → InfluxDB%s%s (Ctrl+C p/ parar)\n",
            pool_size_cb(&pool), metrics_ok ? 1 : 0, narrator_ok ? 1 : 0,
            scaler_ok ? 1 : 0, cfg.queue_name,
            geo ? " (+GeoIP)" : "",
            ioc ? " (+IoC)" : "");

    /* Espera todos terminarem ao receber stop global. */
    pool_join_all(&pool);
    if (metrics_ok)  pthread_join(metrics_tid,  NULL);
    if (narrator_ok) pthread_join(narrator_tid, NULL);
    if (scaler_ok)   pthread_join(scaler_tid,   NULL);

    pool_destroy(&pool);
    nta_ioc_close(ioc);
    nta_geo_close(geo);
    nta_influx_global_cleanup();

    fprintf(stderr, "✓ nta-server encerrado.\n");
    return 0;
}
