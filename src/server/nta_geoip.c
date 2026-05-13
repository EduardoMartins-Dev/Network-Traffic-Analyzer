/* ========================================================================= *
 *  nta_geoip.c — lookup GeoIP (City + ASN) via libmaxminddb + cache próprio. *
 *                                                                           *
 *  Cache: chained hash de bucket fixo (4096), entradas alocadas dinamica-  *
 *  mente. Sem eviction (footprint ínfimo: cada entry ~180B; cap full < 3MB  *
 *  pra ~14k IPs distintos). Negative cache também — IP não encontrado vai  *
 *  pra mesma tabela com flags=0 pra evitar hit repetido no mmdb.            *
 *                                                                           *
 *  v8.0 M1: cada entry comporta resultado dos DOIS bancos (city + asn).   *
 *  Um único cache_get cobre ambos — evitamos lookup duplicado.              *
 *                                                                           *
 *  libmaxminddb é thread-safe pra MMDB_lookup_string com handle compartil- *
 *  hado. O mutex aqui protege APENAS a tabela hash.                        *
 * ========================================================================= */

#include "../../include/nta_geoip.h"

#include <maxminddb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CACHE_BUCKETS  4096
#define IP_KEY_MAX     46   /* IPv6 textual max = 45 + \0 */

typedef struct CacheEntry {
    char               ip[IP_KEY_MAX];
    NtaGeoResult       res;
    struct CacheEntry *next;
} CacheEntry;

struct NtaGeo {
    MMDB_s          mmdb_city;
    MMDB_s          mmdb_asn;
    int             city_open;
    int             asn_open;
    pthread_mutex_t mtx;
    CacheEntry     *buckets[CACHE_BUCKETS];
};

/* -------------------------------------------------------------------------- *
 * Hash + IP privado                                                          *
 * -------------------------------------------------------------------------- */

/* FNV-1a 32-bit — boa distribuição pra strings curtas. */
static unsigned hash_ip(const char *s) {
    unsigned h = 2166136261u;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 16777619u;
    }
    return h;
}

/* Mantém EXATAMENTE a lista do data_ingestor.py:
 *   ip.startswith(("127.", "192.168.", "10.", "172."))
 * Sim, "172." pega 172.32+ que tecnicamente é público — mantemos pra
 * paridade de schema com Python. */
static int is_private_ip(const char *ip) {
    if (!ip || !*ip) return 1;
    if (strncmp(ip, "127.",     4) == 0) return 1;
    if (strncmp(ip, "192.168.", 8) == 0) return 1;
    if (strncmp(ip, "10.",      3) == 0) return 1;
    if (strncmp(ip, "172.",     4) == 0) return 1;
    return 0;
}

/* -------------------------------------------------------------------------- *
 * Cache                                                                      *
 * Retorna:  1 = hit (positivo ou negativo — `out` preenchido com flags)     *
 *           0 = miss                                                         *
 * -------------------------------------------------------------------------- */
static int cache_get(NtaGeo *g, const char *ip, NtaGeoResult *out) {
    unsigned h = hash_ip(ip) % CACHE_BUCKETS;
    pthread_mutex_lock(&g->mtx);
    for (CacheEntry *e = g->buckets[h]; e; e = e->next) {
        if (strcmp(e->ip, ip) == 0) {
            *out = e->res;
            pthread_mutex_unlock(&g->mtx);
            return 1;
        }
    }
    pthread_mutex_unlock(&g->mtx);
    return 0;
}

static void cache_put(NtaGeo *g, const char *ip, const NtaGeoResult *res) {
    if (strlen(ip) >= IP_KEY_MAX) return;
    CacheEntry *e = calloc(1, sizeof(*e));
    if (!e) return;
    strncpy(e->ip, ip, IP_KEY_MAX - 1);
    e->res = *res;

    unsigned h = hash_ip(ip) % CACHE_BUCKETS;
    pthread_mutex_lock(&g->mtx);
    /* Race: outro worker pode ter inserido o mesmo IP entre cache_get e este
     * put. Não é problema — get retorna o primeiro match na lista. */
    e->next = g->buckets[h];
    g->buckets[h] = e;
    pthread_mutex_unlock(&g->mtx);
}

/* -------------------------------------------------------------------------- *
 * Open                                                                       *
 * -------------------------------------------------------------------------- */
static int try_open(MMDB_s *db, const char *path, const char *label) {
    if (!path || !*path) return 0;
    int s = MMDB_open(path, MMDB_MODE_MMAP, db);
    if (s != MMDB_SUCCESS) return 0;
    fprintf(stderr, "[GEOIP] %s carregado: %s (%s)\n",
            label, path, db->metadata.database_type);
    return 1;
}

NtaGeo *nta_geo_open(const char *city_db_path, const char *asn_db_path) {
    NtaGeo *g = calloc(1, sizeof(*g));
    if (!g) return NULL;

    g->city_open = try_open(&g->mmdb_city, city_db_path, "city");
    g->asn_open  = try_open(&g->mmdb_asn,  asn_db_path,  "asn");

    if (!g->city_open && !g->asn_open) {
        free(g);
        return NULL;
    }

    pthread_mutex_init(&g->mtx, NULL);
    return g;
}

/* -------------------------------------------------------------------------- *
 * Lookup                                                                     *
 * -------------------------------------------------------------------------- */
static void lookup_city(NtaGeo *g, const char *ip, NtaGeoResult *out) {
    if (!g->city_open) return;

    int gai_err = 0, mmdb_err = MMDB_SUCCESS;
    MMDB_lookup_result_s r =
        MMDB_lookup_string(&g->mmdb_city, ip, &gai_err, &mmdb_err);
    if (gai_err != 0 || mmdb_err != MMDB_SUCCESS || !r.found_entry) return;

    MMDB_entry_data_s lat_d, lon_d;
    int s1 = MMDB_get_value(&r.entry, &lat_d, "location", "latitude",  NULL);
    int s2 = MMDB_get_value(&r.entry, &lon_d, "location", "longitude", NULL);
    if (s1 != MMDB_SUCCESS || s2 != MMDB_SUCCESS ||
        !lat_d.has_data || !lon_d.has_data) return;

    out->lat = lat_d.double_value;
    out->lon = lon_d.double_value;
    out->has_geo = 1;
}

static void lookup_asn(NtaGeo *g, const char *ip, NtaGeoResult *out) {
    if (!g->asn_open) return;

    int gai_err = 0, mmdb_err = MMDB_SUCCESS;
    MMDB_lookup_result_s r =
        MMDB_lookup_string(&g->mmdb_asn, ip, &gai_err, &mmdb_err);
    if (gai_err != 0 || mmdb_err != MMDB_SUCCESS || !r.found_entry) return;

    MMDB_entry_data_s num_d, org_d;
    int s1 = MMDB_get_value(&r.entry, &num_d,
                            "autonomous_system_number", NULL);
    int s2 = MMDB_get_value(&r.entry, &org_d,
                            "autonomous_system_organization", NULL);

    int got = 0;
    if (s1 == MMDB_SUCCESS && num_d.has_data &&
        num_d.type == MMDB_DATA_TYPE_UINT32) {
        out->asn_number = num_d.uint32;
        got = 1;
    }
    if (s2 == MMDB_SUCCESS && org_d.has_data &&
        org_d.type == MMDB_DATA_TYPE_UTF8_STRING) {
        size_t n = org_d.data_size;
        if (n >= NTA_ASN_ORG_MAX) n = NTA_ASN_ORG_MAX - 1;
        memcpy(out->asn_org, org_d.utf8_string, n);
        out->asn_org[n] = '\0';
        got = 1;
    }
    if (got) out->has_asn = 1;
}

int nta_geo_lookup(NtaGeo *g, const char *ip, NtaGeoResult *out) {
    if (!g || !out)          return 0;
    memset(out, 0, sizeof(*out));
    if (is_private_ip(ip))   return 0;

    if (cache_get(g, ip, out)) return (out->has_geo || out->has_asn) ? 1 : 0;

    lookup_city(g, ip, out);
    lookup_asn (g, ip, out);
    cache_put(g, ip, out);

    return (out->has_geo || out->has_asn) ? 1 : 0;
}

/* -------------------------------------------------------------------------- *
 * Close                                                                      *
 * -------------------------------------------------------------------------- */
void nta_geo_close(NtaGeo *g) {
    if (!g) return;
    if (g->city_open) MMDB_close(&g->mmdb_city);
    if (g->asn_open)  MMDB_close(&g->mmdb_asn);
    for (int i = 0; i < CACHE_BUCKETS; i++) {
        CacheEntry *e = g->buckets[i];
        while (e) {
            CacheEntry *n = e->next;
            free(e);
            e = n;
        }
    }
    pthread_mutex_destroy(&g->mtx);
    free(g);
}
