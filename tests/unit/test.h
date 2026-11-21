#ifndef NTA_TEST_H
#define NTA_TEST_H

/* Harness mínimo de testes unitários — sem dependências externas.
 * Cada teste é um executável; CTest trata exit != 0 como falha. */

#include <stdio.h>
#include <string.h>

static int t_checks = 0, t_failures = 0;

#define CHECK(cond) do {                                                    \
    t_checks++;                                                             \
    if (!(cond)) {                                                          \
        t_failures++;                                                       \
        fprintf(stderr, "%s:%d: FALHOU: %s\n", __FILE__, __LINE__, #cond);  \
    }                                                                       \
} while (0)

#define CHECK_STR(a, b) do {                                                \
    const char *a_ = (a), *b_ = (b);                                        \
    t_checks++;                                                             \
    if (!a_ || !b_ || strcmp(a_, b_) != 0) {                                \
        t_failures++;                                                       \
        fprintf(stderr, "%s:%d: FALHOU: %s == \"%s\" (obtido \"%s\")\n",    \
                __FILE__, __LINE__, #a, b_ ? b_ : "(null)", a_ ? a_ : "(null)"); \
    }                                                                       \
} while (0)

#define RUN(test_fn) do {                                                   \
    int before_ = t_failures;                                               \
    test_fn();                                                              \
    printf("%s %s\n", t_failures == before_ ? "[ OK ]" : "[FAIL]", #test_fn); \
} while (0)

#define TEST_EXIT() do {                                                    \
    printf("%d/%d checks ok\n", t_checks - t_failures, t_checks);           \
    return t_failures ? 1 : 0;                                              \
} while (0)

#endif /* NTA_TEST_H */
