#include "rules.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

/* ========================================================================= *
 * TABELA DE CAMPOS                                                          *
 *                                                                           *
 * Uma linha por campo de NtaRules: nome da chave JSON (o mesmo do campo),    *
 * tipo, deslocamento na struct e faixa inclusiva. A faixa é o contrato: fora  *
 * dela o arquivo é rejeitado. Os limites ficam em rules.h (comentários).      *
 * ========================================================================= */

typedef enum { F_INT, F_DBL } FieldKind;

typedef struct {
    const char *key;
    FieldKind   kind;
    size_t      off;
    double      min, max;
} RuleField;

#define FLD_INT(name, lo, hi) { #name, F_INT, offsetof(NtaRules, name), (lo), (hi) }
#define FLD_DBL(name, lo, hi) { #name, F_DBL, offsetof(NtaRules, name), (lo), (hi) }

static const RuleField FIELDS[] = {
    FLD_INT(scan_threshold,      2,    NTA_RULES_SCAN_MAX),
    FLD_INT(icmp_threshold,      5,    100000),
    FLD_INT(syn_flood_threshold, 10,   1000000),
    FLD_INT(stealth_threshold,   2,    1000),
    FLD_INT(brute_threshold,     5,    100000),
    FLD_INT(brute_window_sec,    10,   3600),
    FLD_INT(dns_subdomain_len,   1,    63),
    FLD_DBL(dns_entropy_thresh,  1.0,  8.0),
    FLD_INT(dns_suspicious_max,  1,    100000),
    FLD_INT(amplification_ratio, 2,    10000),
    FLD_INT(kc_window_sec,       60,   86400),
    FLD_INT(ewma_calibration,    2,    100000),
    FLD_DBL(ewma_alpha_fast,     0.01, 1.0),
    FLD_DBL(ewma_alpha_slow,     0.01, 1.0),
    FLD_DBL(ewma_sigma,          1.0,  10.0),
    FLD_INT(ewma_window_sec,     10,   3600),
};

#define N_FIELDS ((int)(sizeof(FIELDS) / sizeof(FIELDS[0])))
#define VERSAO_KEY "versao"
#define VERSAO_BIT (1u << N_FIELDS)   /* bit extra da máscara de chaves vistas */

/* ========================================================================= *
 * ERROS                                                                     *
 * ========================================================================= */

static int fail(char *err, size_t errlen, const char *fmt, ...) {
    if (err && errlen > 0) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, errlen, fmt, ap);
        va_end(ap);
    }
    return -1;
}

/* Mensagem com chaves (`%s` = nome da chave) e depois liberação da árvore. A
 * ordem importa: as chaves apontam para memória do cJSON, e liberar antes da
 * mensagem é use-after-free (achado pelo ASan e pelo fuzz no Linux). */
static int fail_tree(cJSON *root, char *err, size_t errlen, const char *fmt, ...) {
    if (err && errlen > 0) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, errlen, fmt, ap);
        va_end(ap);
    }
    cJSON_Delete(root);
    return -1;
}

/* ========================================================================= *
 * PADRÕES                                                                   *
 * ========================================================================= */

void rules_defaults(NtaRules *r) {
    NtaRules d = NTA_RULES_DEFAULT;
    *r = d;
}

/* ========================================================================= *
 * VALIDAÇÃO ESTRUTURAL (antes do cJSON)                                     *
 *                                                                           *
 * Rejeita profundidade acima de NTA_RULES_MAX_DEPTH. Conta só colchetes     *
 * fora de strings, então o cJSON nunca recursiona além do limite.           *
 * ========================================================================= */

static int check_shape(const char *s, size_t len, char *err, size_t errlen) {
    int depth = 0;
    int in_str = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (in_str) {
            if (c == '\\')      i++;          /* pula o caractere escapado */
            else if (c == '"')  in_str = 0;
            continue;
        }
        if (c == '"') {
            in_str = 1;
        } else if (c == '{' || c == '[') {
            if (++depth > NTA_RULES_MAX_DEPTH)
                return fail(err, errlen, "aninhamento acima de %d níveis",
                            NTA_RULES_MAX_DEPTH);
        } else if (c == '}' || c == ']') {
            if (depth > 0) depth--;
        }
    }
    return 0;
}

static const RuleField *find_field(const char *key) {
    for (int i = 0; i < N_FIELDS; i++) {
        if (strcmp(FIELDS[i].key, key) == 0) return &FIELDS[i];
    }
    return NULL;
}

/* ========================================================================= *
 * PARSE                                                                     *
 * ========================================================================= */

int rules_parse(const char *json, size_t len, NtaRules *out,
                char *err, size_t errlen) {
    if (len == 0) return fail(err, errlen, "arquivo vazio");
    if (len > NTA_RULES_MAX_BYTES)
        return fail(err, errlen, "arquivo com %zu bytes; o máximo é %d",
                    len, NTA_RULES_MAX_BYTES);
    if (memchr(json, '\0', len))
        return fail(err, errlen, "bytes nulos: o arquivo não é JSON de texto");
    if (check_shape(json, len, err, errlen) != 0) return -1;

    /* cJSON exige terminador NUL: copia para um buffer com o NUL no fim. */
    char *copy = malloc(len + 1);
    if (!copy) return fail(err, errlen, "sem memória");
    memcpy(copy, json, len);
    copy[len] = '\0';

    /* require_null_terminated: qualquer coisa depois do JSON é erro. */
    const char *end = NULL;
    cJSON *root = cJSON_ParseWithLengthOpts(copy, len + 1, &end, 1);
    if (!root) {
        const char *at = cJSON_GetErrorPtr();
        long pos = at ? (long)(at - copy) : (long)len;
        free(copy);
        return fail(err, errlen, "JSON inválido perto do byte %ld", pos);
    }
    free(copy);

    if (!cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return fail(err, errlen, "a raiz deve ser um objeto JSON { ... }");
    }

    NtaRules tmp;
    rules_defaults(&tmp);

    uint32_t seen = 0;
    for (const cJSON *it = root->child; it; it = it->next) {
        const char *k = it->string ? it->string : "";

        if (strcmp(k, VERSAO_KEY) == 0) {
            if (seen & VERSAO_BIT)
                return fail_tree(root, err, errlen, "chave repetida: '%s'", k);
            seen |= VERSAO_BIT;
            if (!cJSON_IsNumber(it) || it->valuedouble != 1.0)
                return fail_tree(root, err, errlen, "'versao' deve ser 1 (formato atual)");
            continue;
        }

        const RuleField *f = find_field(k);
        if (!f)
            return fail_tree(root, err, errlen, "chave desconhecida: '%s'", k);
        uint32_t bit = 1u << (f - FIELDS);
        if (seen & bit)
            return fail_tree(root, err, errlen, "chave repetida: '%s'", k);
        seen |= bit;

        if (!cJSON_IsNumber(it))
            return fail_tree(root, err, errlen, "'%s' deve ser um número", k);
        double v = it->valuedouble;
        /* Comparação com a faixa vem antes do cast, e a forma positiva
         * (!(v >= min && v <= max)) também pega NaN. */
        if (!(v >= f->min && v <= f->max))
            return fail_tree(root, err, errlen, "'%s' fora da faixa %g..%g (obtido %g)",
                             k, f->min, f->max, v);
        if (f->kind == F_INT) {
            if (v != (double)(int)v)
                return fail_tree(root, err, errlen, "'%s' deve ser inteiro (obtido %g)", k, v);
            *(int *)((char *)&tmp + f->off) = (int)v;
        } else {
            *(double *)((char *)&tmp + f->off) = v;
        }
    }
    cJSON_Delete(root);

    if (!(seen & VERSAO_BIT))
        return fail(err, errlen, "falta a chave 'versao' (use 1)");

    *out = tmp;
    return 0;
}

/* ========================================================================= *
 * ARQUIVO                                                                   *
 * ========================================================================= */

int rules_load_file(const char *path, NtaRules *out, char *err, size_t errlen) {
    FILE *f = fopen(path, "rb");
    if (!f) return fail(err, errlen, "não foi possível abrir o arquivo");

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return fail(err, errlen, "não foi possível ler o tamanho do arquivo");
    }
    long n = ftell(f);
    rewind(f);

    if (n < 0) {
        fclose(f);
        return fail(err, errlen, "não foi possível ler o tamanho do arquivo");
    }
    /* Tamanho checado antes de alocar ou ler: arquivo gigante não entra. */
    if (n == 0) {
        fclose(f);
        return fail(err, errlen, "arquivo vazio");
    }
    if (n > NTA_RULES_MAX_BYTES) {
        fclose(f);
        return fail(err, errlen, "arquivo com %ld bytes; o máximo é %d",
                    n, NTA_RULES_MAX_BYTES);
    }

    char *buf = malloc((size_t)n);
    if (!buf) {
        fclose(f);
        return fail(err, errlen, "sem memória");
    }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    if (got != (size_t)n) {
        free(buf);
        return fail(err, errlen, "leitura incompleta");
    }

    int rc = rules_parse(buf, (size_t)n, out, err, errlen);
    free(buf);
    return rc;
}
