#ifndef NTA_RINGBUF_H
#define NTA_RINGBUF_H

#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

/* ========================================================================= *
 * RING BUFFER SPSC LOCK-FREE (v5.0)                                         *
 *                                                                           *
 * Implementação Single-Producer / Single-Consumer sem mutex, baseada em     *
 * C11 atomics (<stdatomic.h>). Adequada para pipelines lineares:            *
 *                                                                           *
 *   captura (producer)  ─►  rb_pkt  ─►  análise (consumer)                  *
 *   análise (producer)  ─►  rb_evt  ─►  publicação (consumer)               *
 *                                                                           *
 * Capacidade é arredondada internamente para a próxima potência de 2 para   *
 * permitir wrap via máscara de bits (`head & mask`), eliminando o custo de  *
 * `%` no caminho crítico.                                                    *
 *                                                                           *
 * Modelo de memory ordering (Lamport / acquire-release):                    *
 *   - Producer: load(tail) com ACQUIRE · store(head) com RELEASE             *
 *   - Consumer: load(head) com ACQUIRE · store(tail) com RELEASE             *
 *   Isso garante que o slot escrito antes do store(head) é visível ao       *
 *   consumidor após o load(head) correspondente.                             *
 *                                                                           *
 * Overflow: quando o buffer está cheio, `rb_push` incrementa um contador    *
 * atômico e devolve -1. O chamador decide se descarta o item ou trata.      *
 * ========================================================================= */

typedef struct {
    size_t            slot_size;       /* bytes por slot                     */
    size_t            capacity;        /* sempre potência de 2               */
    size_t            mask;            /* capacity - 1                       */
    uint8_t          *slots;           /* buffer contíguo (capacity * sz)    */

    /* head = próxima posição a escrever ; tail = próxima posição a ler     */
    _Atomic size_t    head;
    _Atomic size_t    tail;

    _Atomic uint64_t  overflow_count;  /* itens descartados por buffer cheio */
} ringbuf_t;

/* Inicializa. `capacity` é arredondado para a próxima potência de 2.
 * Retorna 0 se sucesso, -1 se alocação falhou.                              */
int      rb_init(ringbuf_t *rb, size_t capacity, size_t slot_size);

/* Libera o buffer interno. Não libera o ringbuf_t em si.                   */
void     rb_destroy(ringbuf_t *rb);

/* Empurra um item (copia slot_size bytes). 0 sucesso · -1 buffer cheio.    */
int      rb_push(ringbuf_t *rb, const void *item);

/* Lê e remove o próximo item (copia em `out`). 0 sucesso · -1 buffer vazio.*/
int      rb_pop (ringbuf_t *rb, void *out);

/* Quantos itens estão na fila no momento (aproximado; SPSC lê atomic).    */
size_t   rb_size(const ringbuf_t *rb);

/* Total acumulado de overflows desde `rb_init`.                           */
uint64_t rb_overflow(const ringbuf_t *rb);

#endif /* NTA_RINGBUF_H */
