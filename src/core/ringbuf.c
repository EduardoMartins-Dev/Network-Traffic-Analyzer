#include "../../include/ringbuf.h"
#include <stdlib.h>
#include <string.h>

/* Arredonda n para a próxima potência de 2. Mínimo: 2. */
static size_t next_pow2(size_t n) {
    if (n < 2) return 2;
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
#if SIZE_MAX > 0xFFFFFFFFu
    n |= n >> 32;
#endif
    return n + 1;
}

int rb_init(ringbuf_t *rb, size_t capacity, size_t slot_size) {
    size_t cap = next_pow2(capacity);

    rb->slots = (uint8_t *)calloc(cap, slot_size);
    if (!rb->slots) return -1;

    rb->slot_size = slot_size;
    rb->capacity  = cap;
    rb->mask      = cap - 1;

    atomic_store_explicit(&rb->head,           0, memory_order_relaxed);
    atomic_store_explicit(&rb->tail,           0, memory_order_relaxed);
    atomic_store_explicit(&rb->overflow_count, 0, memory_order_relaxed);

    return 0;
}

void rb_destroy(ringbuf_t *rb) {
    free(rb->slots);
    rb->slots = NULL;
}

int rb_push(ringbuf_t *rb, const void *item) {
    size_t head = atomic_load_explicit(&rb->head, memory_order_relaxed);
    size_t tail = atomic_load_explicit(&rb->tail, memory_order_acquire);

    /* Unsigned wrap: (head - tail) é a ocupação corrente. */
    if ((head - tail) >= rb->capacity) {
        atomic_fetch_add_explicit(&rb->overflow_count, 1, memory_order_relaxed);
        return -1;
    }

    memcpy(rb->slots + (head & rb->mask) * rb->slot_size,
           item, rb->slot_size);

    /* Release: slot deve estar visível antes do novo head. */
    atomic_store_explicit(&rb->head, head + 1, memory_order_release);
    return 0;
}

int rb_pop(ringbuf_t *rb, void *out) {
    size_t tail = atomic_load_explicit(&rb->tail, memory_order_relaxed);
    size_t head = atomic_load_explicit(&rb->head, memory_order_acquire);

    if (tail == head) return -1; /* vazio */

    memcpy(out, rb->slots + (tail & rb->mask) * rb->slot_size,
           rb->slot_size);

    atomic_store_explicit(&rb->tail, tail + 1, memory_order_release);
    return 0;
}

size_t rb_size(const ringbuf_t *rb) {
    size_t head = atomic_load_explicit(&rb->head, memory_order_acquire);
    size_t tail = atomic_load_explicit(&rb->tail, memory_order_acquire);
    return head - tail; /* unsigned wrap */
}

uint64_t rb_overflow(const ringbuf_t *rb) {
    return atomic_load_explicit(&rb->overflow_count, memory_order_relaxed);
}
