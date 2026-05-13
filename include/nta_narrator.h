#ifndef NTA_NARRATOR_H
#define NTA_NARRATOR_H

#include <stddef.h>
#include <curl/curl.h>
#include "nta_whois.h"

/* Config Groq carregado de env vars + deploy/secrets/groq.env. */
typedef struct {
    char  api_key[256];
    char  model[128];           /* default llama-3.3-70b-versatile */
    char  url[256];             /* default Groq chat completions */
    int   timeout_sec;          /* default 8 */
    int   min_score;            /* default 80 */
    int   enabled;              /* 1 se api_key != "" */
} NtaNarratorCfg;

/* Lê NARRATOR_*, GROQ_API_KEY/MODEL. Faz fallback p/ deploy/secrets/groq.env
 * relativo a `repo_root` (tipicamente cwd). Retorna 0 sempre — `enabled=0` se
 * api_key ausente (caller decide se aborta). */
int nta_narrator_load(NtaNarratorCfg *cfg, const char *repo_root);

/* Handle por-thread: libcurl handle + slist headers (Authorization). */
typedef struct {
    CURL              *curl;
    struct curl_slist *headers;
    const NtaNarratorCfg *cfg;
    int                ready;
} NtaNarrator;

/* Open: curl_easy_init + monta headers Authorization/Content-Type.
 * Caller deve ter chamado curl_global_init antes (nta_influx_global_init basta). */
int  nta_narrator_open(NtaNarrator *n, const NtaNarratorCfg *cfg);
void nta_narrator_close(NtaNarrator *n);

/* POST Groq + extrai choices[0].message.content. Aloca string (caller free).
 * Se `whois` != NULL: faz lookup do src_ip e prepende "Origem: <org>, <country>"
 * ao user prompt — enriquece contexto LLM com atribuição da origem (v8.0 M5).
 * Retorna NULL em falha (HTTP, JSON malformado, timeout). */
char *nta_narrator_call(NtaNarrator *n, NtaWhois *whois,
                        const char *event_json, size_t event_len,
                        const char *agent_id);

/* "groq:<model>" pra tag backend no InfluxDB. Buffer estático. */
const char *nta_narrator_backend(const NtaNarratorCfg *cfg);

#endif /* NTA_NARRATOR_H */
