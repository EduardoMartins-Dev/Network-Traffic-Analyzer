#ifndef NTA_INFLUX_H
#define NTA_INFLUX_H

#include <stddef.h>
#include <curl/curl.h>
#include "cJSON.h"
#include "nta_server.h"
#include "nta_geoip.h"
#include "nta_ioc.h"
#include "nta_abuse.h"

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
 * "traffic" no bucket. `agent_id` vira tag.
 *  - Se `geo`   != NULL: lookup src_ip → fields lat/lon + tags asn/asn_org.
 *  - Se `ioc`   != NULL: lookup src_ip → tags ioc_hit + ioc_source.
 *  - Se `abuse` != NULL: lookup src_ip → field abuse_score (0-100).
 * Retorna 0 em sucesso. */
int  nta_influx_write_traffic(NtaInflux *inf, NtaGeo *geo, NtaIoc *ioc,
                              NtaAbuse *abuse,
                              const char *body, size_t len,
                              const char *agent_id);

/* Parse JSON (objeto único) em `body` e escreve como measurement
 * "pipeline_metrics". Cada chave numérica vira um field. `agent_id` vira tag.
 * Retorna 0 em sucesso. */
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

/* Logs de DNS do agente (B16, PR a), vindos da protocol_queue. Um array (ou um
 * objeto) com registros `event_type:"dns"`, `schema_version:1`. Grava o
 * measurement "proto_dns" com:
 *   tags   : agent_id, protocol (UDP|TCP), qtype (mnemônico ou OTHER), rcode (0..15)
 *   fields : qname, src_ip, dst_ip (string); resp, bytes, qtype_num (int);
 *            qname_hashed (bool)
 *   tempo  : ts do agente (ms no JSON, ns no line protocol), não a hora de chegada.
 * qname e IP nunca são tags (cardinalidade). Itens com tipo/versão desconhecidos
 * ou campos inválidos são pulados e contados em *skipped (pode ser NULL).
 * Retorna 0 em sucesso, -1 em erro de parse ou de envio. */
int  nta_influx_write_proto(NtaInflux *inf, const char *body, size_t len,
                            const char *agent_id, unsigned *skipped);

/* Renderiza um registro DNS (objeto JSON) como uma linha de line protocol do
 * proto_dns, terminada em \n. Retorna o tamanho, ou 0 se o item é inválido ou
 * não cabe em `cap`. Exposta para teste. */
size_t nta_influx_proto_line(const cJSON *evt, const char *agent_id,
                             char *out, size_t cap);

void nta_influx_close(NtaInflux *inf);

#endif /* NTA_INFLUX_H */
