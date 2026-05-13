/* ========================================================================= *
 *  nta_abuse.c — enricher AbuseIPDB via libcurl + cache TTL.                *
 *                                                                           *
 *  Single shared instance: 1 curl handle + 1 hashtable, todas operações    *
 *  sob 1 mutex. Rate limit free tier (1000 checks/dia) torna serialização  *
 *  irrelevante — bottleneck é a API, não o lock.                            *
 *                                                                           *
 *  Cache: chained hash, 4096 buckets. TTL positivo (86400s) ≠ negativo     *
 *  (300s) pra não martelar API em falha temporária. Eviction lazy on get.  *
 * ========================================================================= */

#include "../../include/nta_abuse.h"
#include "../../include/cJSON.h"

#include <curl/curl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CACHE_BUCKETS  4096
#define IP_KEY_MAX     46
#define DEFAULT_URL    "https://api.abuseipdb.com/api/v2/check"
#define DEFAULT_TIMEOUT      5
#define DEFAULT_MAX_AGE_DAYS 90
#define DEFAULT_TTL          86400
#define DEFAULT_NEG_TTL      300
#define DEFAULT_MIN_REPUB    75

typedef struct CacheEntry {
    char     ip[IP_KEY_MAX];
    int      score;            /* -1 = negative cache (HTTP/parse fail) */
    time_t   expires_at;
    struct CacheEntry *next;
} CacheEntry;

struct NtaAbuse {
    CURL              *curl;
    struct curl_slist *headers;
    NtaAbuseCfg        cfg;
    pthread_mutex_t    mtx;
    CacheEntry        *buckets[CACHE_BUCKETS];
};

/* -------------------------------------------------------------------------- *
 * Helpers de env                                                             *
 * -------------------------------------------------------------------------- */
static const char *env_or(const char *k, const char *d) {
    const char *v = getenv(k);
    return (v && *v) ? v : d;
}
static int env_int(const char *k, int d) {
    const char *v = getenv(k);
    if (!v || !*v) return d;
    char *end = NULL;
    long n = strtol(v, &end, 10);
    if (end == v) return d;
    return (int)n;
}

/* -------------------------------------------------------------------------- *
 * .env loader (mesmo formato KEY=VALUE do groq.env)                          *
 * -------------------------------------------------------------------------- */
static char *strip_inplace(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == '\n' || e[-1] == '\r' ||
                     e[-1] == ' '  || e[-1] == '\t')) *--e = '\0';
    return s;
}

static void load_env_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *p = strip_inplace(line);
        if (!*p || *p == '#') continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = strip_inplace(p);
        char *v = strip_inplace(eq + 1);
        if (*k && !getenv(k)) setenv(k, v, 0);
    }
    fclose(fp);
}

/* -------------------------------------------------------------------------- *
 * IP privado — mesma lista do nta_geoip.c                                    *
 * -------------------------------------------------------------------------- */
static int is_private_ip(const char *ip) {
    if (!ip || !*ip) return 1;
    if (strncmp(ip, "127.",     4) == 0) return 1;
    if (strncmp(ip, "192.168.", 8) == 0) return 1;
    if (strncmp(ip, "10.",      3) == 0) return 1;
    if (strncmp(ip, "172.",     4) == 0) return 1;
    return 0;
}

/* FNV-1a 32-bit */
static unsigned hash_ip(const char *s) {
    unsigned h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h;
}

/* -------------------------------------------------------------------------- *
 * Cache                                                                      *
 * -------------------------------------------------------------------------- */
static int cache_get_locked(NtaAbuse *a, const char *ip, time_t now,
                            int *out_score) {
    unsigned h = hash_ip(ip) % CACHE_BUCKETS;
    for (CacheEntry *e = a->buckets[h]; e; e = e->next) {
        if (strcmp(e->ip, ip) != 0) continue;
        if (e->expires_at < now) return 0;   /* expirado — miss */
        *out_score = e->score;
        return 1;
    }
    return 0;
}

static void cache_put_locked(NtaAbuse *a, const char *ip, int score,
                             time_t expires_at) {
    if (strlen(ip) >= IP_KEY_MAX) return;
    unsigned h = hash_ip(ip) % CACHE_BUCKETS;
    /* Atualiza se já existe (mesmo IP cached antes, agora expirado). */
    for (CacheEntry *e = a->buckets[h]; e; e = e->next) {
        if (strcmp(e->ip, ip) == 0) {
            e->score      = score;
            e->expires_at = expires_at;
            return;
        }
    }
    CacheEntry *e = calloc(1, sizeof(*e));
    if (!e) return;
    strncpy(e->ip, ip, IP_KEY_MAX - 1);
    e->score      = score;
    e->expires_at = expires_at;
    e->next       = a->buckets[h];
    a->buckets[h] = e;
}

/* -------------------------------------------------------------------------- *
 * Load cfg                                                                   *
 * -------------------------------------------------------------------------- */
int nta_abuse_load(NtaAbuseCfg *cfg, const char *repo_root) {
    memset(cfg, 0, sizeof(*cfg));

    if (repo_root) {
        char path[1024];
        snprintf(path, sizeof(path), "%s/deploy/secrets/abuseipdb.env",
                 repo_root);
        load_env_file(path);
    }

    snprintf(cfg->api_key, sizeof(cfg->api_key), "%s",
             env_or("ABUSEIPDB_API_KEY", ""));
    snprintf(cfg->url, sizeof(cfg->url), "%s",
             env_or("ABUSEIPDB_URL", DEFAULT_URL));

    cfg->timeout_sec         = env_int("ABUSEIPDB_TIMEOUT",         DEFAULT_TIMEOUT);
    cfg->max_age_days        = env_int("ABUSEIPDB_MAX_AGE_DAYS",    DEFAULT_MAX_AGE_DAYS);
    cfg->ttl_sec             = env_int("ABUSEIPDB_TTL",             DEFAULT_TTL);
    cfg->neg_ttl_sec         = env_int("ABUSEIPDB_NEG_TTL",         DEFAULT_NEG_TTL);
    cfg->min_republish_score = env_int("ABUSEIPDB_MIN_REPUBLISH_SCORE",
                                       DEFAULT_MIN_REPUB);
    cfg->enabled = (cfg->api_key[0] != '\0');
    return 0;
}

/* -------------------------------------------------------------------------- *
 * Open / close                                                               *
 * -------------------------------------------------------------------------- */
NtaAbuse *nta_abuse_open(const NtaAbuseCfg *cfg) {
    if (!cfg || !cfg->enabled) return NULL;
    NtaAbuse *a = calloc(1, sizeof(*a));
    if (!a) return NULL;
    a->cfg = *cfg;

    a->curl = curl_easy_init();
    if (!a->curl) { free(a); return NULL; }

    char key_hdr[256];
    snprintf(key_hdr, sizeof(key_hdr), "Key: %s", cfg->api_key);
    a->headers = curl_slist_append(NULL, key_hdr);
    a->headers = curl_slist_append(a->headers, "Accept: application/json");

    curl_easy_setopt(a->curl, CURLOPT_HTTPHEADER,     a->headers);
    curl_easy_setopt(a->curl, CURLOPT_TIMEOUT,        (long)cfg->timeout_sec);
    curl_easy_setopt(a->curl, CURLOPT_CONNECTTIMEOUT, 3L);
    curl_easy_setopt(a->curl, CURLOPT_HTTPGET,        1L);

    pthread_mutex_init(&a->mtx, NULL);
    fprintf(stderr, "[ABUSE] habilitado: ttl=%ds neg_ttl=%ds republish>=%d\n",
            cfg->ttl_sec, cfg->neg_ttl_sec, cfg->min_republish_score);
    return a;
}

void nta_abuse_close(NtaAbuse *a) {
    if (!a) return;
    if (a->headers) curl_slist_free_all(a->headers);
    if (a->curl)    curl_easy_cleanup(a->curl);
    for (int i = 0; i < CACHE_BUCKETS; i++) {
        CacheEntry *e = a->buckets[i];
        while (e) { CacheEntry *n = e->next; free(e); e = n; }
    }
    pthread_mutex_destroy(&a->mtx);
    free(a);
}

/* -------------------------------------------------------------------------- *
 * HTTP                                                                       *
 * -------------------------------------------------------------------------- */
typedef struct { char *buf; size_t len; size_t cap; } RespBuf;

static size_t resp_write_cb(char *p, size_t sz, size_t n, void *u) {
    RespBuf *r = (RespBuf *)u;
    size_t add = sz * n;
    if (r->len + add + 1 > r->cap) {
        size_t nc = r->cap ? r->cap * 2 : 1024;
        while (nc < r->len + add + 1) nc *= 2;
        if (nc > 64 * 1024) return 0;   /* hard cap p/ defesa */
        char *nb = realloc(r->buf, nc);
        if (!nb) return 0;
        r->buf = nb;
        r->cap = nc;
    }
    memcpy(r->buf + r->len, p, add);
    r->len += add;
    r->buf[r->len] = '\0';
    return add;
}

/* Faz HTTP GET sob lock. Retorna score 0-100 ou -1. */
static int http_query_locked(NtaAbuse *a, const char *ip) {
    char url[512];
    snprintf(url, sizeof(url), "%s?ipAddress=%s&maxAgeInDays=%d",
             a->cfg.url, ip, a->cfg.max_age_days);

    RespBuf r = {0};
    curl_easy_setopt(a->curl, CURLOPT_URL,           url);
    curl_easy_setopt(a->curl, CURLOPT_WRITEFUNCTION, resp_write_cb);
    curl_easy_setopt(a->curl, CURLOPT_WRITEDATA,     &r);

    CURLcode rc = curl_easy_perform(a->curl);
    if (rc != CURLE_OK) {
        fprintf(stderr, "[ABUSE] curl %s: %s\n", ip, curl_easy_strerror(rc));
        free(r.buf);
        return -1;
    }
    long http_code = 0;
    curl_easy_getinfo(a->curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code < 200 || http_code >= 300) {
        fprintf(stderr, "[ABUSE] HTTP %ld para %s\n", http_code, ip);
        free(r.buf);
        return -1;
    }

    cJSON *root = cJSON_ParseWithLength(r.buf, r.len);
    free(r.buf);
    if (!cJSON_IsObject(root)) { if (root) cJSON_Delete(root); return -1; }

    const cJSON *data = cJSON_GetObjectItemCaseSensitive(root, "data");
    const cJSON *sc   = data ? cJSON_GetObjectItemCaseSensitive(
                                  data, "abuseConfidenceScore") : NULL;
    int score = -1;
    if (cJSON_IsNumber(sc)) {
        score = (int)sc->valuedouble;
        if (score < 0) score = 0;
        if (score > 100) score = 100;
    }
    cJSON_Delete(root);
    return score;
}

/* -------------------------------------------------------------------------- *
 * Public lookup                                                              *
 * -------------------------------------------------------------------------- */
int nta_abuse_score(NtaAbuse *a, const char *ip) {
    if (!a || !ip || !*ip)   return -1;
    if (is_private_ip(ip))   return -1;

    time_t now = time(NULL);

    pthread_mutex_lock(&a->mtx);
    int cached = 0;
    int score  = -1;
    cached = cache_get_locked(a, ip, now, &score);
    if (cached) {
        pthread_mutex_unlock(&a->mtx);
        return score;
    }

    /* Miss: HTTP sob o mesmo lock. Outras threads bloqueiam — aceitável dado
     * o rate limit da API. */
    score = http_query_locked(a, ip);
    time_t exp = (score >= 0)
                 ? now + a->cfg.ttl_sec
                 : now + a->cfg.neg_ttl_sec;
    cache_put_locked(a, ip, score, exp);
    pthread_mutex_unlock(&a->mtx);
    return score;
}
