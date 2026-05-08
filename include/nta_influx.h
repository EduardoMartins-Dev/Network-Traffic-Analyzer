#ifndef NTA_INFLUX_H
#define NTA_INFLUX_H

#include <stddef.h>
#include <curl/curl.h>
#include "nta_server.h"
#include "nta_geoip.h"

/* Cliente InfluxDB v2 por worker. libcurl mantém keepalive da conexão HTTP. */
typedef struct {
    CURL               *curl;
    char                endpoint[512];   /* URL completa com ?org=&bucket= */
    struct curl_slist  *headers;         /* Content-Type + Authorization   */
    int                 ready;
} NtaInflux;

/* Chama curl_global_init (idempotente via flag). */
int  nta_influx_global_init(void);
void nta_influx_global_cleanup(void);

/* Abre handle por-worker. Não faz I/O — só monta URL/headers/curl handle. */
int  nta_influx_open(NtaInflux *inf, const NtaConfig *cfg);

/* Parse JSON (array ou objeto) em `body` e escreve como measurement
 * "traffic" no bucket. `agent_id` vira tag. Se `geo` != NULL, faz lookup
 * do src_ip e adiciona fields lat/lon quando IP é público + encontrado.
 * Retorna 0 em sucesso. */
int  nta_influx_write_traffic(NtaInflux *inf, NtaGeo *geo,
                              const char *body, size_t len,
                              const char *agent_id);

/* Parse JSON (objeto único) em `body` e escreve como measurement
 * "pipeline_metrics". Cada chave numérica vira um field. `agent_id` vira tag.
 * Mantém paridade com data_ingestor.py._on_metrics. Retorna 0 em sucesso. */
int  nta_influx_write_metrics(NtaInflux *inf,
                              const char *body, size_t len,
                              const char *agent_id);

/* Grava measurement "incident_narrative" pra narrativa LLM.
 * tags  : agent_id, src_ip, attack_type, kill_chain_stage, backend
 * fields: narrative (string), kc_score (float)
 * `event_json` é o JSON do evento original (extrai tags). `narrative` já é
 * a string final retornada pelo modelo. Retorna 0 em sucesso. */
int  nta_influx_write_narrative(NtaInflux *inf,
                                const char *event_json, size_t event_len,
                                const char *narrative,
                                const char *agent_id,
                                const char *backend);

/* Grava measurement "nta_pool" (status do pool de traffic workers).
 * fields: pool_size, backlog, unacked, consumers (todos int).
 * Sem tags — métrica global do server. Retorna 0 sucesso. */
int  nta_influx_write_pool(NtaInflux *inf,
                           int pool_size, int backlog,
                           int unacked, int consumers);

void nta_influx_close(NtaInflux *inf);

#endif /* NTA_INFLUX_H */
