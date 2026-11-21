#ifndef NTA_EVE_AGG_H
#define NTA_EVE_AGG_H

#include <stdint.h>
#include "eve_map.h"

/* ========================================================================= *
 * nta-eve-bridge — controle de volume (B17, ADR regra 3).                    *
 *                                                                           *
 * Alertas são agregados por (signature_id, src_ip) numa janela curta. Ao     *
 * fechar a janela, o grupo vira um registro com `count`. Registros passam    *
 * por um limite de taxa (token bucket) antes de entrar na fila de publicação.*
 * Tudo que é descartado é contado. Sem relógio interno: o chamador passa     *
 * `now_ms`, então o módulo é determinístico nos testes.                      *
 *                                                                           *
 * Invariante (testado): alerts == published + dropped_* + pendentes + abertos*
 * ========================================================================= */

#define EVE_AGG_MAX_SLOTS  1024   /* grupos abertos ao mesmo tempo            */
#define EVE_PENDING_MAX    1024   /* registros esperando publicação           */

typedef struct {
    eve_event_t ev;       /* campos do primeiro alerta do grupo               */
    unsigned    count;    /* alertas agregados                                */
    int64_t     t0_ms;    /* abertura da janela                               */
} eve_rec_t;

typedef struct {
    uint64_t alerts;          /* alertas válidos recebidos                    */
    uint64_t dropped_table;   /* descartados: tabela de grupos cheia         */
    uint64_t dropped_rate;    /* descartados: limite de taxa                 */
    uint64_t dropped_pending; /* descartados: fila de publicação cheia       */
    uint64_t dropped_broker;  /* descartados: broker fora no encerramento    */
    uint64_t published;       /* alertas publicados (soma de count)          */
    uint64_t records;         /* registros publicados                        */
} eve_counters_t;

typedef struct {
    int             window_ms;     /* 0 desliga a agregação (count sempre 1)  */
    int             rate_per_sec;  /* 0 desliga o limite de taxa              */
    double          tokens;
    int64_t         last_ms;
    int             n_slots;
    eve_rec_t       slots[EVE_AGG_MAX_SLOTS];
    int             n_pend;
    eve_rec_t       pend[EVE_PENDING_MAX];
    eve_counters_t  c;
} eve_agg_t;

void eve_agg_init(eve_agg_t *a, int window_ms, int rate_per_sec, int64_t now_ms);

/* Registra um alerta. Com janela > 0 agrega; com janela 0 emite já (count=1). */
void eve_agg_add(eve_agg_t *a, const eve_event_t *e, int64_t now_ms);

/* Fecha grupos cuja janela venceu (ou todos, se force != 0) e os envia para a
 * fila de publicação, respeitando o limite de taxa. */
void eve_agg_tick(eve_agg_t *a, int64_t now_ms, int force);

int             eve_agg_pending(const eve_agg_t *a);
const eve_rec_t *eve_agg_peek(const eve_agg_t *a, int i);

/* Remove os n primeiros pendentes depois de publicados (atualiza contadores). */
void eve_agg_consume(eve_agg_t *a, int n);

/* Encerramento sem broker: pendentes viram dropped_broker. */
void eve_agg_abandon_pending(eve_agg_t *a);

#endif /* NTA_EVE_AGG_H */
