/* Testes do ring buffer SPSC lock-free (src/core/ringbuf.c). */
#include "test.h"
#include "../../include/ringbuf.h"

#include <pthread.h>
#include <stdint.h>

static void test_capacidade_potencia_de_2(void) {
    ringbuf_t rb;
    CHECK(rb_init(&rb, 5, sizeof(int)) == 0);
    CHECK(rb.capacity == 8);
    CHECK(rb.mask == 7);
    rb_destroy(&rb);

    CHECK(rb_init(&rb, 4096, sizeof(int)) == 0);
    CHECK(rb.capacity == 4096);
    rb_destroy(&rb);

    CHECK(rb_init(&rb, 0, sizeof(int)) == 0);   /* mínimo 2 */
    CHECK(rb.capacity == 2);
    rb_destroy(&rb);
}

static void test_fifo_e_vazio(void) {
    ringbuf_t rb;
    rb_init(&rb, 8, sizeof(int));
    int out = -1;
    CHECK(rb_pop(&rb, &out) == -1);             /* vazio */

    for (int i = 1; i <= 5; i++) CHECK(rb_push(&rb, &i) == 0);
    CHECK(rb_size(&rb) == 5);
    for (int i = 1; i <= 5; i++) {
        CHECK(rb_pop(&rb, &out) == 0);
        CHECK(out == i);
    }
    CHECK(rb_pop(&rb, &out) == -1);
    CHECK(rb_size(&rb) == 0);
    rb_destroy(&rb);
}

static void test_cheio_conta_overflow(void) {
    ringbuf_t rb;
    rb_init(&rb, 4, sizeof(int));
    for (int i = 0; i < 4; i++) CHECK(rb_push(&rb, &i) == 0);   /* usa a capacidade toda */
    int x = 99;
    CHECK(rb_push(&rb, &x) == -1);
    CHECK(rb_push(&rb, &x) == -1);
    CHECK(rb_overflow(&rb) == 2);
    int out;
    CHECK(rb_pop(&rb, &out) == 0 && out == 0);  /* item descartado não entrou */
    CHECK(rb_push(&rb, &x) == 0);               /* liberou 1 slot */
    rb_destroy(&rb);
}

static void test_wrap_around(void) {
    ringbuf_t rb;
    rb_init(&rb, 4, sizeof(int));
    int out, ok = 1;
    for (int i = 0; i < 1000; i++) {            /* dá centenas de voltas no array */
        if (rb_push(&rb, &i) != 0 || rb_pop(&rb, &out) != 0 || out != i) ok = 0;
    }
    CHECK(ok);
    CHECK(rb_overflow(&rb) == 0);
    rb_destroy(&rb);
}

/* Produtor e consumidor em threads reais: valida acquire/release — o
 * consumidor tem que ver todos os itens, em ordem, sem corrupção. */
#define STRESS_N 2000000u
typedef struct { uint32_t seq; uint32_t check; } item_t;

static void *producer(void *arg) {
    ringbuf_t *rb = arg;
    for (uint32_t i = 0; i < STRESS_N; ) {
        item_t it = { i, ~i };
        if (rb_push(rb, &it) == 0) i++;         /* cheio: tenta de novo */
    }
    return NULL;
}

static void test_spsc_duas_threads(void) {
    ringbuf_t rb;
    rb_init(&rb, 1024, sizeof(item_t));
    pthread_t th;
    pthread_create(&th, NULL, producer, &rb);

    uint32_t expected = 0, bad = 0;
    item_t it;
    while (expected < STRESS_N) {
        if (rb_pop(&rb, &it) != 0) continue;
        if (it.seq != expected || it.check != ~expected) bad++;
        expected++;
    }
    pthread_join(th, NULL);
    CHECK(bad == 0);
    CHECK(expected == STRESS_N);
    CHECK(rb_size(&rb) == 0);
    rb_destroy(&rb);
}

int main(void) {
    RUN(test_capacidade_potencia_de_2);
    RUN(test_fifo_e_vazio);
    RUN(test_cheio_conta_overflow);
    RUN(test_wrap_around);
    RUN(test_spsc_duas_threads);
    TEST_EXIT();
}
