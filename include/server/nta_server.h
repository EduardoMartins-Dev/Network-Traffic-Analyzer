#ifndef NTA_SERVER_H
#define NTA_SERVER_H

#include <stdatomic.h>

/* -------------------------------------------------------------------------- *
 * Configuração do nta-server — carregada via env vars no startup.           *
 * Mesmas vars do data_ingestor.py (compat) + NTA_WORKERS / NARRATOR_QUEUE / *
 * GEOIP_DB_PATH (novas na v7.0).                                            *
 * -------------------------------------------------------------------------- */
typedef struct {
    /* InfluxDB */
    const char *influx_url;
    const char *influx_token;
    const char *influx_org;
    const char *influx_bucket;

    /* RabbitMQ */
    const char *rabbit_host;
    int         rabbit_port;
    const char *rabbit_user;
    const char *rabbit_pass;
    const char *rabbit_vhost;
    const char *queue_name;
    const char *metrics_queue;
    const char *narrator_queue;

    /* Narrator */
    int narrator_min_score;

    /* GeoIP */
    const char *geoip_db_path;       /* GeoLite2-City.mmdb */
    const char *geoip_asn_db_path;   /* GeoLite2-ASN.mmdb  (v8.0 M1) */

    /* IoC framework (v8.0 M3) */
    const char *ioc_path;            /* JSON com listas de IPs maliciosos */

    /* Pool */
    int num_workers;
} NtaConfig;

/* Flag global de shutdown, setado pelo signal handler. Workers devem checar
 * periodicamente para sair do consume loop de forma limpa. */
extern atomic_int g_nta_stop;

static inline int nta_should_stop(void) {
    return atomic_load_explicit(&g_nta_stop, memory_order_relaxed);
}

/* Carrega env vars. Aplica defaults compatíveis com o data_ingestor.py. */
void nta_config_load(NtaConfig *cfg);

/* Imprime a config (mascarando token) — útil pra debug de deploy. */
void nta_config_print(const NtaConfig *cfg);

#endif /* NTA_SERVER_H */
