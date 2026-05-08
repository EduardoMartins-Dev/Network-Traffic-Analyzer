/* ========================================================================= *
 *  nta_scaler.c — thread de auto-scaling do pool de traffic workers.        *
 *                                                                           *
 *  Poll RabbitMQ Mgmt API a cada N segundos. Se backlog (messages_ready)   *
 *  > threshold, pede pool_up. Se backlog ficar zerado por idle_sec consec, *
 *  pede pool_down. Respeita min/max workers.                                *
 * ========================================================================= */

#include "../../include/nta_scaler.h"
#include "../../include/nta_influx.h"
#include "../../include/cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <curl/curl.h>

atomic_int g_nta_pool_size    = 0;
atomic_int g_nta_pool_backlog = 0;

/* -------------------------------------------------------------------------- *
 * env helpers (locais — não puxa de nta_server.c)                            *
 * -------------------------------------------------------------------------- */
static const char *env_or(const char *k, const char *fb) {
    const char *v = getenv(k);
    return (v && *v) ? v : fb;
}

static int env_int(const char *k, int fb) {
    const char *v = getenv(k);
    if (!v || !*v) return fb;
    char *end = NULL;
    long n = strtol(v, &end, 10);
    if (end == v) return fb;
    return (int)n;
}

/* URL-encode mínimo: substitui '/' por %2F (suficiente p/ vhost). */
static void url_encode_vhost(char *out, size_t cap, const char *in) {
    size_t w = 0;
    for (const char *p = in; *p && w + 4 < cap; p++) {
        if (*p == '/') {
            out[w++] = '%'; out[w++] = '2'; out[w++] = 'F';
        } else {
            out[w++] = *p;
        }
    }
    out[w] = '\0';
}

/* -------------------------------------------------------------------------- *
 * Load                                                                       *
 * -------------------------------------------------------------------------- */
int nta_scaler_load(NtaScalerCfg *cfg, const NtaConfig *base) {
    memset(cfg, 0, sizeof(*cfg));

    const char *mhost = env_or("RABBIT_MGMT_HOST", base->rabbit_host);
    int   mport       = env_int("RABBIT_MGMT_PORT", 15673);

    snprintf(cfg->user, sizeof(cfg->user), "%s", base->rabbit_user);
    snprintf(cfg->pass, sizeof(cfg->pass), "%s", base->rabbit_pass);
    snprintf(cfg->queue, sizeof(cfg->queue), "%s", base->queue_name);

    char vhost_enc[64];
    url_encode_vhost(vhost_enc, sizeof(vhost_enc), base->rabbit_vhost);

    snprintf(cfg->mgmt_url, sizeof(cfg->mgmt_url),
             "http://%s:%d/api/queues/%s/%s",
             mhost, mport, vhost_enc, base->queue_name);

    cfg->poll_sec            = env_int("SCALER_POLL_SEC",            10);
    cfg->min_workers         = env_int("SCALER_MIN_WORKERS",         2);
    cfg->max_workers         = env_int("SCALER_MAX_WORKERS",         16);
    cfg->scale_up_backlog    = env_int("SCALER_SCALE_UP_BACKLOG",    1000);
    cfg->scale_down_idle_sec = env_int("SCALER_SCALE_DOWN_IDLE_SEC", 60);

    if (cfg->min_workers < 1) cfg->min_workers = 1;
    if (cfg->max_workers < cfg->min_workers) cfg->max_workers = cfg->min_workers;

    cfg->enabled = (cfg->poll_sec > 0 && cfg->max_workers > cfg->min_workers);
    return 0;
}

/* -------------------------------------------------------------------------- *
 * Query Mgmt API                                                             *
 * -------------------------------------------------------------------------- */
typedef struct { char *data; size_t len, cap; } RespBuf;

static size_t resp_cb(char *p, size_t sz, size_t nm, void *u) {
    RespBuf *b = (RespBuf *)u;
    size_t add = sz * nm;
    if (b->len + add + 1 > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 4096;
        while (nc < b->len + add + 1) nc *= 2;
        char *nd = realloc(b->data, nc);
        if (!nd) return 0;
        b->data = nd; b->cap = nc;
    }
    memcpy(b->data + b->len, p, add);
    b->len += add; b->data[b->len] = '\0';
    return add;
}

int nta_scaler_query(const NtaScalerCfg *cfg, NtaQueueStats *out) {
    memset(out, 0, sizeof(*out));
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    RespBuf buf = {0};
    char userpass[160];
    snprintf(userpass, sizeof(userpass), "%s:%s", cfg->user, cfg->pass);

    curl_easy_setopt(curl, CURLOPT_URL,            cfg->mgmt_url);
    curl_easy_setopt(curl, CURLOPT_USERPWD,        userpass);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH,       CURLAUTH_BASIC);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  resp_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &buf);

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK || http_code < 200 || http_code >= 300 || !buf.data) {
        free(buf.data);
        return -1;
    }

    cJSON *root = cJSON_ParseWithLength(buf.data, buf.len);
    free(buf.data);
    if (!cJSON_IsObject(root)) {
        if (root) cJSON_Delete(root);
        return -1;
    }

    const cJSON *v;
    v = cJSON_GetObjectItemCaseSensitive(root, "messages_ready");
    if (cJSON_IsNumber(v)) out->messages_ready = (int)v->valuedouble;
    v = cJSON_GetObjectItemCaseSensitive(root, "messages_unacknowledged");
    if (cJSON_IsNumber(v)) out->messages_unacked = (int)v->valuedouble;
    v = cJSON_GetObjectItemCaseSensitive(root, "consumers");
    if (cJSON_IsNumber(v)) out->consumers = (int)v->valuedouble;

    cJSON_Delete(root);
    return 0;
}

/* -------------------------------------------------------------------------- *
 * Thread main                                                                *
 * -------------------------------------------------------------------------- */
void *nta_scaler_thread_main(void *arg) {
    NtaScalerCtx *ctx = (NtaScalerCtx *)arg;
    if (!ctx || !ctx->cfg.enabled) {
        fprintf(stderr, "[SCALER] desabilitado.\n");
        return NULL;
    }

    fprintf(stderr, "[SCALER] poll=%ds min=%d max=%d up_at=%dmsg down_after=%ds url=%s\n",
            ctx->cfg.poll_sec, ctx->cfg.min_workers, ctx->cfg.max_workers,
            ctx->cfg.scale_up_backlog, ctx->cfg.scale_down_idle_sec,
            ctx->cfg.mgmt_url);

    /* Handle InfluxDB próprio (libcurl easy não é thread-safe). */
    NtaInflux inf;
    int inf_ok = (ctx->base && nta_influx_open(&inf, ctx->base) == 0);
    if (!inf_ok) fprintf(stderr, "[SCALER] InfluxDB open falhou — métricas off\n");

    time_t idle_since = 0;

    while (!nta_should_stop()) {
        NtaQueueStats st;
        if (nta_scaler_query(&ctx->cfg, &st) != 0) {
            fprintf(stderr, "[SCALER] query falhou\n");
        } else {
            atomic_store_explicit(&g_nta_pool_backlog, st.messages_ready,
                                   memory_order_relaxed);
            int cur = ctx->pool_size(ctx->pool_user);

            if (inf_ok) {
                nta_influx_write_pool(&inf, cur, st.messages_ready,
                                       st.messages_unacked, st.consumers);
            }

            /* Scale up: backlog acima do threshold E pool < max. */
            if (st.messages_ready >= ctx->cfg.scale_up_backlog &&
                cur < ctx->cfg.max_workers) {
                int n = ctx->pool_up(ctx->pool_user);
                fprintf(stderr, "[SCALER] UP backlog=%d → pool=%d\n",
                        st.messages_ready, n);
                idle_since = 0;
            }
            /* Scale down: backlog zerado por idle_sec consecutivos E pool > min. */
            else if (st.messages_ready == 0 && cur > ctx->cfg.min_workers) {
                if (idle_since == 0) idle_since = time(NULL);
                else if (time(NULL) - idle_since >= ctx->cfg.scale_down_idle_sec) {
                    int n = ctx->pool_down(ctx->pool_user);
                    fprintf(stderr, "[SCALER] DOWN idle=%lds → pool=%d\n",
                            (long)(time(NULL) - idle_since), n);
                    idle_since = time(NULL);   /* reseta janela */
                }
            } else {
                idle_since = 0;
            }
        }

        /* Sleep com checagem periódica de stop (1s steps). */
        for (int i = 0; i < ctx->cfg.poll_sec && !nta_should_stop(); i++) {
            sleep(1);
        }
    }

    if (inf_ok) nta_influx_close(&inf);
    fprintf(stderr, "[SCALER] encerrado.\n");
    return NULL;
}
