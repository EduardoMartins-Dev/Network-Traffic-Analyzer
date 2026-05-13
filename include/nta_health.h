#ifndef NTA_HEALTH_H
#define NTA_HEALTH_H

#include <pthread.h>
#include <stdatomic.h>

/* Healthcheck HTTP endpoint — v8.1.
 *
 * Servidor TCP raw (sem libs externas) numa thread dedicada. Rotas:
 *   GET /health     → 200 JSON {status, uptime_s, workers, backlog, version}
 *   GET /metrics    → 200 text/plain Prometheus exposition format
 *   GET /           → 200 HTML banner com links
 *   *               → 404
 *
 * Sem auth — bind defaul 127.0.0.1 (localhost-only). Pra expor externamente,
 * setar NTA_HEALTH_BIND=0.0.0.0 + colocar reverse proxy com TLS na frente. */
typedef struct {
    int             port;
    char            bind_addr[64];
    int             enabled;
    pthread_t       tid;
    atomic_int      ready;
    int             srv_fd;
} NtaHealth;

int  nta_health_start(NtaHealth *h);
void nta_health_stop(NtaHealth *h);

#endif /* NTA_HEALTH_H */
