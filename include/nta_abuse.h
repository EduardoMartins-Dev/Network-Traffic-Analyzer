#ifndef NTA_ABUSE_H
#define NTA_ABUSE_H

#include <stddef.h>

/* AbuseIPDB enricher — v8.0 M4.
 *
 * Consulta https://api.abuseipdb.com/api/v2/check?ipAddress=...&maxAgeInDays=90
 * Header `Key: <ABUSEIPDB_API_KEY>` + `Accept: application/json`.
 *
 * Single shared instance (mutex interno). Cache 24h positivo, 5min negativo.
 * Skip private IPs. Rate limit free tier: 1000 checks/dia — cache aggressive.
 *
 * Endpoint retorna data.abuseConfidenceScore (0-100). Score < 0 = unknown
 * (key ausente, IP privado, HTTP fail, ou parsing fail). */
typedef struct NtaAbuse NtaAbuse;

typedef struct {
    char api_key[128];
    char url[256];               /* default api.abuseipdb.com endpoint */
    int  timeout_sec;            /* default 5 */
    int  max_age_days;           /* parâmetro maxAgeInDays — default 90 */
    int  ttl_sec;                /* cache TTL positivo — default 86400 */
    int  neg_ttl_sec;            /* cache TTL negativo (falha) — default 300 */
    int  min_republish_score;    /* threshold p/ disparar narrator — 0 disabled */
    int  enabled;                /* 1 se api_key não vazia */
} NtaAbuseCfg;

/* Carrega config: lê deploy/secrets/abuseipdb.env (se existir), depois env
 * vars (ABUSEIPDB_API_KEY, ABUSEIPDB_URL, ABUSEIPDB_TIMEOUT, ABUSEIPDB_TTL,
 * ABUSEIPDB_NEG_TTL, ABUSEIPDB_MAX_AGE_DAYS, ABUSEIPDB_MIN_REPUBLISH_SCORE).
 * Retorna 0 sempre — caller checa cfg->enabled. */
int  nta_abuse_load(NtaAbuseCfg *cfg, const char *repo_root);

/* Init curl handle + cache. Retorna NULL se cfg->enabled=0 ou alloc falha. */
NtaAbuse *nta_abuse_open(const NtaAbuseCfg *cfg);

/* Lookup com cache. Retorna 0-100 (abuseConfidenceScore) em sucesso, -1 em:
 *  - a == NULL, ip privado/vazio, key ausente, HTTP fail, JSON inválido.
 * Cache hit é O(1) sem rede. Cache miss faz HTTP síncrono — chamadores
 * sensíveis a latência devem ter cache morno antes. */
int  nta_abuse_score(NtaAbuse *a, const char *ip);

void nta_abuse_close(NtaAbuse *a);

#endif /* NTA_ABUSE_H */
