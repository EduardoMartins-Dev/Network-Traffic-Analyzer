#include "eve_agg.h"

#include <string.h>

void eve_agg_init(eve_agg_t *a, int window_ms, int rate_per_sec, int64_t now_ms) {
    memset(a, 0, sizeof *a);
    a->window_ms    = window_ms > 0 ? window_ms : 0;
    a->rate_per_sec = rate_per_sec > 0 ? rate_per_sec : 0;
    a->tokens       = (double)a->rate_per_sec;   /* balde cheio: rajada de 1 s */
    a->last_ms      = now_ms;
}

/* Um token por registro publicado. Sem limite: sempre sim. */
static int take_token(eve_agg_t *a, int64_t now_ms) {
    if (a->rate_per_sec == 0) return 1;
    if (now_ms > a->last_ms) {
        a->tokens += (double)(now_ms - a->last_ms) * a->rate_per_sec / 1000.0;
        if (a->tokens > a->rate_per_sec) a->tokens = a->rate_per_sec;
        a->last_ms = now_ms;
    }
    if (a->tokens >= 1.0) {
        a->tokens -= 1.0;
        return 1;
    }
    return 0;
}

/* Coloca um grupo fechado na fila de publicação, ou conta o descarte. */
static void emit(eve_agg_t *a, const eve_rec_t *r, int64_t now_ms) {
    if (a->n_pend >= EVE_PENDING_MAX) { a->c.dropped_pending += r->count; return; }
    if (!take_token(a, now_ms))       { a->c.dropped_rate    += r->count; return; }
    a->pend[a->n_pend++] = *r;
}

void eve_agg_add(eve_agg_t *a, const eve_event_t *e, int64_t now_ms) {
    a->c.alerts++;

    if (a->window_ms == 0) {
        eve_rec_t r;
        memset(&r, 0, sizeof r);
        r.ev = *e;
        r.count = 1;
        r.t0_ms = now_ms;
        emit(a, &r, now_ms);
        return;
    }

    eve_agg_tick(a, now_ms, 0);

    for (int i = 0; i < a->n_slots; i++) {
        eve_rec_t *s = &a->slots[i];
        if (s->ev.signature_id == e->signature_id &&
            strcmp(s->ev.src_ip, e->src_ip) == 0) {
            s->count++;
            return;
        }
    }

    if (a->n_slots >= EVE_AGG_MAX_SLOTS) { a->c.dropped_table++; return; }

    eve_rec_t *s = &a->slots[a->n_slots++];
    memset(s, 0, sizeof *s);
    s->ev = *e;
    s->count = 1;
    s->t0_ms = now_ms;
}

void eve_agg_tick(eve_agg_t *a, int64_t now_ms, int force) {
    int i = 0;
    while (i < a->n_slots) {
        eve_rec_t *s = &a->slots[i];
        if (!force && now_ms - s->t0_ms < a->window_ms) { i++; continue; }

        eve_rec_t r = *s;
        /* Remove preservando a ordem de abertura (saída determinística). */
        memmove(&a->slots[i], &a->slots[i + 1],
                (size_t)(a->n_slots - i - 1) * sizeof a->slots[0]);
        a->n_slots--;
        emit(a, &r, now_ms);
    }
}

int eve_agg_pending(const eve_agg_t *a) {
    return a->n_pend;
}

const eve_rec_t *eve_agg_peek(const eve_agg_t *a, int i) {
    return (i >= 0 && i < a->n_pend) ? &a->pend[i] : NULL;
}

void eve_agg_consume(eve_agg_t *a, int n) {
    if (n <= 0) return;
    if (n > a->n_pend) n = a->n_pend;
    for (int i = 0; i < n; i++) {
        a->c.published += a->pend[i].count;
        a->c.records++;
    }
    memmove(&a->pend[0], &a->pend[n], (size_t)(a->n_pend - n) * sizeof a->pend[0]);
    a->n_pend -= n;
}

void eve_agg_abandon_pending(eve_agg_t *a) {
    for (int i = 0; i < a->n_pend; i++) a->c.dropped_broker += a->pend[i].count;
    a->n_pend = 0;
}
