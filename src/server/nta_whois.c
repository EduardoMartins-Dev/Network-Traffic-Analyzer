/* ========================================================================= *
 *  nta_whois.c — cliente WHOIS nativo (TCP socket port 43).                 *
 *                                                                           *
 *  Sem libs externas. BSD sockets + parser linha-a-linha.                   *
 *                                                                           *
 *  Fluxo padrão:                                                            *
 *    1. Connect whois.iana.org:43 → query "<ip>\r\n"                        *
 *    2. Resposta contém `refer: whois.<rir>.net` (ARIN/RIPE/APNIC/...)      *
 *    3. Connect ao refer server → repete query → resposta final             *
 *    4. Extrai OrgName | descr | owner | netname + country                  *
 *                                                                           *
 *  Cada RIR usa keys diferentes — scan canônico cobrindo todos:             *
 *    - ARIN:    OrgName, Country, NetName                                    *
 *    - RIPE:    descr,   country, netname                                    *
 *    - APNIC:   descr,   country, netname                                    *
 *    - LACNIC:  owner,   country, ownerid                                    *
 *    - AFRINIC: descr,   country, netname                                    *
 *                                                                           *
 *  Cache 24h chained hashtable. Mutex interno — workers compartilham 1     *
 *  instância. Latência WHOIS é alta (~200ms-2s) → cache aggressive crucial. *
 * ========================================================================= */

#include "../../include/nta_whois.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <strings.h>   /* strncasecmp */

#define CACHE_BUCKETS  2048
#define IP_KEY_MAX     46
#define WHOIS_IANA     "whois.iana.org"
#define WHOIS_PORT     "43"
#define WHOIS_RESP_MAX (32 * 1024)
#define WHOIS_REFER_MAX 128

typedef struct CacheEntry {
    char     ip[IP_KEY_MAX];
    NtaWhoisInfo info;
    time_t   expires_at;
    struct CacheEntry *next;
} CacheEntry;

struct NtaWhois {
    pthread_mutex_t mtx;
    int             timeout_sec;
    int             ttl_sec;
    CacheEntry     *buckets[CACHE_BUCKETS];
};

/* -------------------------------------------------------------------------- *
 * Helpers                                                                    *
 * -------------------------------------------------------------------------- */
static int is_private_ip(const char *ip) {
    if (!ip || !*ip) return 1;
    if (strncmp(ip, "127.",     4) == 0) return 1;
    if (strncmp(ip, "192.168.", 8) == 0) return 1;
    if (strncmp(ip, "10.",      3) == 0) return 1;
    if (strncmp(ip, "172.",     4) == 0) return 1;
    return 0;
}

static unsigned hash_ip(const char *s) {
    unsigned h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h;
}

static void copy_trim(char *dst, size_t cap, const char *src, size_t n) {
    while (n && (*src == ' ' || *src == '\t')) { src++; n--; }
    while (n && (src[n-1] == ' ' || src[n-1] == '\t' ||
                 src[n-1] == '\r' || src[n-1] == '\n')) n--;
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* -------------------------------------------------------------------------- *
 * TCP query                                                                  *
 * Faz socket → connect → send "<ip>\r\n" → read até EOF (peer fecha).        *
 * out_buf é alocado dinamicamente (caller free). Retorna len em bytes ou -1. *
 * -------------------------------------------------------------------------- */
static ssize_t whois_query(const char *server, const char *ip,
                           int timeout_sec, char **out_buf) {
    *out_buf = NULL;

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(server, WHOIS_PORT, &hints, &res) != 0 || !res) return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);

    char query[64];
    int qlen = snprintf(query, sizeof(query), "%s\r\n", ip);
    if (send(fd, query, (size_t)qlen, 0) != qlen) { close(fd); return -1; }

    char *buf = malloc(WHOIS_RESP_MAX);
    if (!buf) { close(fd); return -1; }
    size_t total = 0;
    while (total < WHOIS_RESP_MAX - 1) {
        ssize_t r = recv(fd, buf + total, WHOIS_RESP_MAX - 1 - total, 0);
        if (r <= 0) break;
        total += (size_t)r;
    }
    close(fd);
    buf[total] = '\0';
    *out_buf = buf;
    return (ssize_t)total;
}

/* -------------------------------------------------------------------------- *
 * Parsing                                                                    *
 * line_starts_with: compara case-insensitive até ':'. Retorna ponteiro       *
 * pro valor (após ':' + skip ws) ou NULL.                                    *
 * -------------------------------------------------------------------------- */
static const char *line_match_key(const char *line, size_t line_len,
                                  const char *key) {
    size_t klen = strlen(key);
    if (line_len < klen + 1) return NULL;
    if (strncasecmp(line, key, klen) != 0) return NULL;
    const char *p = line + klen;
    while (p < line + line_len && (*p == ' ' || *p == '\t')) p++;
    if (p >= line + line_len || *p != ':') return NULL;
    p++;
    while (p < line + line_len && (*p == ' ' || *p == '\t')) p++;
    return p;
}

/* Procura `refer: <host>` no buffer IANA. Retorna 1 + escreve host em out. */
static int parse_refer(const char *buf, size_t len, char *out_host,
                       size_t out_cap) {
    const char *p = buf;
    const char *end = buf + len;
    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t)(end - p));
        size_t llen = eol ? (size_t)(eol - p) : (size_t)(end - p);
        const char *v = line_match_key(p, llen, "refer");
        if (v) {
            size_t vlen = (p + llen) - v;
            while (vlen && (v[vlen-1] == '\r' || v[vlen-1] == ' ')) vlen--;
            if (vlen > 0 && vlen < out_cap) {
                memcpy(out_host, v, vlen);
                out_host[vlen] = '\0';
                return 1;
            }
        }
        if (!eol) break;
        p = eol + 1;
    }
    return 0;
}

/* Parse regional response. Estratégia: scan completo, primeiro valor não
 * vazio vence pra cada campo canônico. */
static void parse_regional(const char *buf, size_t len, NtaWhoisInfo *out) {
    static const char *org_keys[] = {
        "OrgName", "owner", "descr", "org-name", "organisation", NULL
    };
    static const char *country_keys[] = {
        "Country", "country", NULL
    };
    static const char *netname_keys[] = {
        "NetName", "netname", NULL
    };

    const char *p = buf;
    const char *end = buf + len;
    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t)(end - p));
        size_t llen = eol ? (size_t)(eol - p) : (size_t)(end - p);

        if (!*out->org) {
            for (int i = 0; org_keys[i]; i++) {
                const char *v = line_match_key(p, llen, org_keys[i]);
                if (v) {
                    copy_trim(out->org, sizeof(out->org), v,
                              (p + llen) - v);
                    break;
                }
            }
        }
        if (!*out->country) {
            for (int i = 0; country_keys[i]; i++) {
                const char *v = line_match_key(p, llen, country_keys[i]);
                if (v) {
                    copy_trim(out->country, sizeof(out->country), v,
                              (p + llen) - v);
                    break;
                }
            }
        }
        if (!*out->netname) {
            for (int i = 0; netname_keys[i]; i++) {
                const char *v = line_match_key(p, llen, netname_keys[i]);
                if (v) {
                    copy_trim(out->netname, sizeof(out->netname), v,
                              (p + llen) - v);
                    break;
                }
            }
        }
        if (!eol) break;
        p = eol + 1;
    }
    if (*out->org || *out->country) out->has_data = 1;
}

/* -------------------------------------------------------------------------- *
 * Cache (locked)                                                             *
 * -------------------------------------------------------------------------- */
static int cache_get_locked(NtaWhois *w, const char *ip, time_t now,
                            NtaWhoisInfo *out) {
    unsigned h = hash_ip(ip) % CACHE_BUCKETS;
    for (CacheEntry *e = w->buckets[h]; e; e = e->next) {
        if (strcmp(e->ip, ip) != 0) continue;
        if (e->expires_at < now) return 0;
        *out = e->info;
        return 1;
    }
    return 0;
}

static void cache_put_locked(NtaWhois *w, const char *ip,
                             const NtaWhoisInfo *info, time_t expires_at) {
    if (strlen(ip) >= IP_KEY_MAX) return;
    unsigned h = hash_ip(ip) % CACHE_BUCKETS;
    for (CacheEntry *e = w->buckets[h]; e; e = e->next) {
        if (strcmp(e->ip, ip) == 0) {
            e->info       = *info;
            e->expires_at = expires_at;
            return;
        }
    }
    CacheEntry *e = calloc(1, sizeof(*e));
    if (!e) return;
    strncpy(e->ip, ip, IP_KEY_MAX - 1);
    e->info       = *info;
    e->expires_at = expires_at;
    e->next       = w->buckets[h];
    w->buckets[h] = e;
}

/* -------------------------------------------------------------------------- *
 * Public                                                                     *
 * -------------------------------------------------------------------------- */
NtaWhois *nta_whois_open(int timeout_sec, int ttl_sec) {
    NtaWhois *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->timeout_sec = (timeout_sec > 0) ? timeout_sec : 5;
    w->ttl_sec     = (ttl_sec     > 0) ? ttl_sec     : 86400;
    pthread_mutex_init(&w->mtx, NULL);
    fprintf(stderr, "[WHOIS] habilitado: timeout=%ds ttl=%ds\n",
            w->timeout_sec, w->ttl_sec);
    return w;
}

int nta_whois_lookup(NtaWhois *w, const char *ip, NtaWhoisInfo *out) {
    if (!w || !out)        return 0;
    memset(out, 0, sizeof(*out));
    if (is_private_ip(ip)) return 0;

    time_t now = time(NULL);
    pthread_mutex_lock(&w->mtx);
    if (cache_get_locked(w, ip, now, out)) {
        pthread_mutex_unlock(&w->mtx);
        return out->has_data ? 1 : 0;
    }
    pthread_mutex_unlock(&w->mtx);

    /* Queries fora do lock — TCP I/O é lento, não trava cache. */
    char *iana_buf = NULL;
    ssize_t iana_len = whois_query(WHOIS_IANA, ip, w->timeout_sec, &iana_buf);
    if (iana_len <= 0) {
        free(iana_buf);
        pthread_mutex_lock(&w->mtx);
        cache_put_locked(w, ip, out, now + 300);   /* neg cache 5min */
        pthread_mutex_unlock(&w->mtx);
        return 0;
    }

    char refer_host[WHOIS_REFER_MAX] = {0};
    if (parse_refer(iana_buf, (size_t)iana_len, refer_host,
                    sizeof(refer_host))) {
        char *reg_buf = NULL;
        ssize_t reg_len = whois_query(refer_host, ip, w->timeout_sec, &reg_buf);
        if (reg_len > 0) parse_regional(reg_buf, (size_t)reg_len, out);
        free(reg_buf);
    }
    /* Fallback: se IANA respondeu mas sem refer, parse no próprio IANA. */
    if (!out->has_data) parse_regional(iana_buf, (size_t)iana_len, out);
    free(iana_buf);

    time_t exp = out->has_data ? now + w->ttl_sec : now + 300;
    pthread_mutex_lock(&w->mtx);
    cache_put_locked(w, ip, out, exp);
    pthread_mutex_unlock(&w->mtx);
    return out->has_data ? 1 : 0;
}

void nta_whois_close(NtaWhois *w) {
    if (!w) return;
    for (int i = 0; i < CACHE_BUCKETS; i++) {
        CacheEntry *e = w->buckets[i];
        while (e) { CacheEntry *n = e->next; free(e); e = n; }
    }
    pthread_mutex_destroy(&w->mtx);
    free(w);
}
