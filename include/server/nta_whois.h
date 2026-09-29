#ifndef NTA_WHOIS_H
#define NTA_WHOIS_H

#include <stddef.h>

/* WHOIS nativo via TCP socket — v8.0 M5.
 *
 * Conexão port 43 raw. Fluxo: query whois.iana.org → parse `refer:` →
 * 2ª query no servidor regional. Sem libs externas (BSD sockets).
 *
 * Usado pelo narrator p/ enriquecer prompt LLM com contexto de origem
 * do IP (organização + país). Não emitido como tag InfluxDB.
 *
 * Cache 24h, mutex interno — single shared instance. */
typedef struct NtaWhois NtaWhois;

typedef struct {
    char org[256];       /* OrgName | descr | owner | netname */
    char country[8];     /* "BR", "US", "DE" — vazio se desconhecido */
    char netname[128];
    int  has_data;       /* 1 se org OR country preenchidos */
} NtaWhoisInfo;

/* timeout_sec por hop (default 5). ttl_sec cache (default 86400). */
NtaWhois *nta_whois_open(int timeout_sec, int ttl_sec);

/* Lookup com cache. Skip private IPs. Retorna 1 se preencheu `out` com algo,
 * 0 se: w NULL, ip privado/inválido, ou todas as queries falharam.
 * Sempre zera `out` antes. */
int nta_whois_lookup(NtaWhois *w, const char *ip, NtaWhoisInfo *out);

void nta_whois_close(NtaWhois *w);

#endif /* NTA_WHOIS_H */
