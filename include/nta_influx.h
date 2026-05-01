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

void nta_influx_close(NtaInflux *inf);

#endif /* NTA_INFLUX_H */
