#ifndef NTA_PIPELINE_H
#define NTA_PIPELINE_H

#include <stdint.h>
#include <sys/time.h>
#include "capture.h"   /* SNAP_LEN */

/* ========================================================================= *
 * PIPELINE MULTI-THREAD (v5.0)                                              *
 *                                                                           *
 *   ┌──────────────┐   rb_pkt    ┌──────────────┐   rb_evt   ┌───────────┐ *
 *   │  capture_th  │ ─────────►  │  analysis_th │ ─────────► │ publish_th│ *
 *   │ (SCHED_FIFO) │  pkt_slot_t │  (analyzer)  │ event_slot │ (batch)   │ *
 *   └──────────────┘             └──────────────┘            └───────────┘ *
 *                                                                           *
 *                                               ┌───────────────┐           *
 *                                               │  metrics_th   │ ─► AMQP   *
 *                                               └───────────────┘           *
 *                                                                           *
 * Configuração via variáveis de ambiente:                                  *
 *   AGENT_BUFFER_SIZE          — slots por ring buffer (default 4096)      *
 *   AGENT_BATCH_SIZE           — eventos por publish (default 50)          *
 *   AGENT_BATCH_TIMEOUT_MS     — flush mesmo se batch < N (default 100)    *
 *   AGENT_METRICS_INTERVAL_SEC — frequência das métricas (default 10)      *
 * ========================================================================= */

/* Slot de pacote cru copiado da interface para o ring buffer de entrada.  */
typedef struct {
    struct timeval ts;
    int            len;
    uint8_t        data[SNAP_LEN];
} pkt_slot_t;

/* Slot de evento parseado pelo analyzer, pronto para serialização JSON.   */
typedef struct {
    char src_ip[16];
    int  port;
    char proto[8];
    int  bytes;
    int  is_scan;
    char attack_type[32];
    char kill_chain_stage[16];
    int  kc_score;
    char mitre[48];
} event_slot_t;

/* ---------------------------------------------------------------------- *
 * Ciclo de vida do pipeline                                                *
 * ---------------------------------------------------------------------- */

/* Inicializa ring buffers e inicia as 4 threads (captura, análise,        *
 * publicação e métricas). Bloqueia até `pipeline_request_stop()` ser      *
 * chamado — tipicamente via SIGINT/SIGTERM.                                */
int  pipeline_run(const char *iface);

/* Sinaliza shutdown gracioso. Seguro para chamar de signal handler.      */
void pipeline_request_stop(void);

/* ---------------------------------------------------------------------- *
 * Hooks usados pelos módulos (não chame diretamente)                      *
 * ---------------------------------------------------------------------- */

/* Empurra pacote cru — usado pelo packet_handler em modo live.            *
 * Retorna 0 se enfileirado, -1 se overflow.                                */
int  pipeline_push_packet(const pkt_slot_t *pkt);

/* Empurra evento parseado — usado pelo publish_packet em modo live.       *
 * Retorna 0 se enfileirado, -1 se overflow.                                */
int  pipeline_push_event (const event_slot_t *evt);

#endif /* NTA_PIPELINE_H */
