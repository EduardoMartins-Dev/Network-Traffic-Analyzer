/* ========================================================================= *
 *  nta_geoip.c — lookup GeoIP via libmaxminddb + cache hashtable própria.   *
 *                                                                           *
 *  Cache: chained hash de bucket fixo (4096), entradas alocadas dinamica-  *
 *  mente. Sem eviction (footprint ínfimo: cada entry ~70B; cap full < 1MB  *
 *  pra ~14k IPs distintos). Negative cache também — IP não encontrado vai  *
 *  pra mesma tabela com found=0 pra evitar hit repetido no mmdb.            *
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
    double             lat;
    double             lon;
    int                found;   /* 0 = negative cache, 1 = positive */
    struct CacheEntry *next;
} CacheEntry;

struct NtaGeo {
    MMDB_s          mmdb;
    int             mmdb_open;
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
 * paridade de schema com Python (etapa 11 vai diff). */
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
 * Retorna:  1 = hit positivo (lat/lon preenchidos)                           *
 *          -1 = hit negativo (já sabemos que não tem)                        *
 *           0 = miss                                                         *
 * -------------------------------------------------------------------------- */
static int cache_get(NtaGeo *g, const char *ip, double *lat, double *lon) {
    unsigned h = hash_ip(ip) % CACHE_BUCKETS;
    pthread_mutex_lock(&g->mtx);
    for (CacheEntry *e = g->buckets[h]; e; e = e->next) {
        if (strcmp(e->ip, ip) == 0) {
            int found = e->found;
            if (found) { *lat = e->lat; *lon = e->lon; }
            pthread_mutex_unlock(&g->mtx);
            return found ? 1 : -1;
        }
    }
    pthread_mutex_unlock(&g->mtx);
    return 0;
}

static void cache_put(NtaGeo *g, const char *ip, int found,
                      double lat, double lon) {
    if (strlen(ip) >= IP_KEY_MAX) return;
    CacheEntry *e = calloc(1, sizeof(*e));
    if (!e) return;
    strncpy(e->ip, ip, IP_KEY_MAX - 1);
    e->found = found;
    e->lat   = lat;
    e->lon   = lon;

    unsigned h = hash_ip(ip) % CACHE_BUCKETS;
    pthread_mutex_lock(&g->mtx);
    /* Race: outro worker pode ter inserido o mesmo IP entre o cache_get e
     * este put. Não é problema — get vai retornar o primeiro match na lista. */
    e->next = g->buckets[h];
    g->buckets[h] = e;
    pthread_mutex_unlock(&g->mtx);
}

/* -------------------------------------------------------------------------- *
 * Open                                                                       *
 * -------------------------------------------------------------------------- */
NtaGeo *nta_geo_open(const char *db_path) {
    if (!db_path || !*db_path) return NULL;

    NtaGeo *g = calloc(1, sizeof(*g));
    if (!g) return NULL;

    int s = MMDB_open(db_path, MMDB_MODE_MMAP, &g->mmdb);
    if (s != MMDB_SUCCESS) {
        /* Não loga aqui — caller decide se é erro de config ou esperado. */
        free(g);
        return NULL;
    }

    g->mmdb_open = 1;
    pthread_mutex_init(&g->mtx, NULL);
    fprintf(stderr, "[GEOIP] banco carregado: %s (%s)\n",
            db_path, g->mmdb.metadata.database_type);
    return g;
}

/* -------------------------------------------------------------------------- *
 * Lookup                                                                     *
 * -------------------------------------------------------------------------- */
int nta_geo_lookup(NtaGeo *g, const char *ip, double *lat, double *lon) {
    if (!g || !lat || !lon)   return 0;
    if (is_private_ip(ip))    return 0;

    int c = cache_get(g, ip, lat, lon);
    if (c == 1)  return 1;
    if (c == -1) return 0;

    /* Cache miss: consulta mmdb. */
    int gai_err = 0, mmdb_err = MMDB_SUCCESS;
    MMDB_lookup_result_s r =
        MMDB_lookup_string(&g->mmdb, ip, &gai_err, &mmdb_err);

    if (gai_err != 0 || mmdb_err != MMDB_SUCCESS || !r.found_entry) {
        cache_put(g, ip, 0, 0, 0);
        return 0;
    }

    MMDB_entry_data_s lat_d, lon_d;
    int s1 = MMDB_get_value(&r.entry, &lat_d, "location", "latitude",  NULL);
    int s2 = MMDB_get_value(&r.entry, &lon_d, "location", "longitude", NULL);
    if (s1 != MMDB_SUCCESS || s2 != MMDB_SUCCESS ||
        !lat_d.has_data || !lon_d.has_data) {
        cache_put(g, ip, 0, 0, 0);
        return 0;
    }

    *lat = lat_d.double_value;
    *lon = lon_d.double_value;
    cache_put(g, ip, 1, *lat, *lon);
    return 1;
}

/* -------------------------------------------------------------------------- *
 * Close                                                                      *
 * -------------------------------------------------------------------------- */
void nta_geo_close(NtaGeo *g) {
    if (!g) return;
    if (g->mmdb_open) MMDB_close(&g->mmdb);
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
