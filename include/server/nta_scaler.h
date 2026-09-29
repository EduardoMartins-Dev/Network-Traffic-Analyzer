#ifndef NTA_SCALER_H
#define NTA_SCALER_H

#include <stdatomic.h>
#include "nta_server.h"

/* Config carregada de SCALER_* + RABBIT_MGMT_*. */
typedef struct {
    char  mgmt_url[512];          /* http://host:mport/api/queues/<vhost-enc>/<queue> */
    char  user[64];
    char  pass[64];
    char  queue[128];             /* nome da fila monitorada (= QUEUE_NAME) */
    int   poll_sec;               /* SCALER_POLL_SEC default 10 */
    int   min_workers;            /* SCALER_MIN_WORKERS default 2 */
    int   max_workers;            /* SCALER_MAX_WORKERS default 16 */
    int   scale_up_backlog;       /* SCALER_SCALE_UP_BACKLOG default 1000 */
    int   scale_down_idle_sec;    /* SCALER_SCALE_DOWN_IDLE_SEC default 60 */
    int   enabled;                /* 0 desliga thread (poll_sec<=0 ou min==max) */
} NtaScalerCfg;

typedef struct {
    int messages_ready;
    int messages_unacked;
    int consumers;
} NtaQueueStats;

/* Callbacks fornecidos pelo nta_server p/ controlar pool. */
typedef int (*nta_pool_size_fn)(void *u);
typedef int (*nta_pool_scale_up_fn)(void *u);    /* retorna novo size, -1 erro */
typedef int (*nta_pool_scale_down_fn)(void *u);  /* idem */

typedef struct {
    NtaScalerCfg            cfg;
    const NtaConfig        *base;             /* p/ abrir NtaInflux na thread */
    nta_pool_size_fn        pool_size;
    nta_pool_scale_up_fn    pool_up;
    nta_pool_scale_down_fn  pool_down;
    void                   *pool_user;
} NtaScalerCtx;

/* Carrega env vars + monta mgmt_url. Retorna 0 sempre (enabled=0 se inválido). */
int nta_scaler_load(NtaScalerCfg *cfg, const NtaConfig *base);

/* Faz GET /api/queues/<vhost>/<queue> e popula stats. Retorna 0 sucesso. */
int nta_scaler_query(const NtaScalerCfg *cfg, NtaQueueStats *out);

/* Thread main: loop de poll + decide scale up/down via callbacks. arg = NtaScalerCtx*. */
void *nta_scaler_thread_main(void *arg);

/* Métricas globais expostas (lidas pelo metrics worker p/ pipeline_metrics). */
extern atomic_int g_nta_pool_size;
extern atomic_int g_nta_pool_backlog;

#endif /* NTA_SCALER_H */
