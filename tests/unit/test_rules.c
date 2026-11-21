/* Testes do carregador de limiares (src/agent/analysis/rules.c, B18 fase 1).
 * Cobre: padrões iguais aos #define antigos, faixa inclusiva por campo, tipo,
 * chave desconhecida ou repetida, versão, raiz, JSON truncado ou com lixo,
 * profundidade, NUL, arquivo vazio, gigante ou ausente, e mutações aleatórias
 * determinísticas (com ASan/UBSan no CI, roda como fuzz leve). */
#include "test.h"
#include "rules.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TMP_RULES "test_rules_tmp.json"

static char err[256];

static int parse(const char *s, NtaRules *r) {
    return rules_parse(s, strlen(s), r, err, sizeof(err));
}

static int contem(const char *sub) {
    return strstr(err, sub) != NULL;
}

static void write_file(const void *data, size_t len) {
    FILE *f = fopen(TMP_RULES, "wb");
    if (f) {
        if (len) fwrite(data, 1, len, f);
        fclose(f);
    }
}

/* Compara todos os campos (doubles por ==: valores vêm de literais iguais). */
static int same(const NtaRules *a, const NtaRules *b) {
    return a->scan_threshold == b->scan_threshold &&
           a->icmp_threshold == b->icmp_threshold &&
           a->syn_flood_threshold == b->syn_flood_threshold &&
           a->stealth_threshold == b->stealth_threshold &&
           a->brute_threshold == b->brute_threshold &&
           a->brute_window_sec == b->brute_window_sec &&
           a->dns_subdomain_len == b->dns_subdomain_len &&
           a->dns_entropy_thresh == b->dns_entropy_thresh &&
           a->dns_suspicious_max == b->dns_suspicious_max &&
           a->amplification_ratio == b->amplification_ratio &&
           a->kc_window_sec == b->kc_window_sec &&
           a->ewma_calibration == b->ewma_calibration &&
           a->ewma_alpha_fast == b->ewma_alpha_fast &&
           a->ewma_alpha_slow == b->ewma_alpha_slow &&
           a->ewma_sigma == b->ewma_sigma &&
           a->ewma_window_sec == b->ewma_window_sec;
}

/* ------------------------------------------------------------------------- *
 * Padrões = #define antigos do analyzer.c (valores de origin/main)          *
 * ------------------------------------------------------------------------- */
static void test_padrao_igual_ao_codigo_antigo(void) {
    NtaRules r;
    rules_defaults(&r);
    CHECK(r.scan_threshold == 15);        /* SCAN_THRESHOLD */
    CHECK(r.icmp_threshold == 20);        /* ICMP_THRESHOLD */
    CHECK(r.syn_flood_threshold == 100);  /* SYN_FLOOD_THRESHOLD */
    CHECK(r.stealth_threshold == 3);      /* STEALTH_THRESHOLD */
    CHECK(r.brute_threshold == 30);       /* BRUTE_THRESHOLD */
    CHECK(r.brute_window_sec == 60);      /* BRUTE_WINDOW_SEC */
    CHECK(r.dns_subdomain_len == 50);     /* DNS_SUBDOMAIN_LEN */
    CHECK(r.dns_entropy_thresh == 3.5);   /* DNS_ENTROPY_THRESH */
    CHECK(r.dns_suspicious_max == 10);    /* DNS_SUSPICIOUS_MAX */
    CHECK(r.amplification_ratio == 10);   /* AMPLIFICATION_RATIO */
    CHECK(r.kc_window_sec == 1800);       /* KC_WINDOW_SEC */
    CHECK(r.ewma_calibration == 100);     /* EWMA_CALIBRATION */
    CHECK(r.ewma_alpha_fast == 0.3);      /* EWMA_ALPHA_FAST */
    CHECK(r.ewma_alpha_slow == 0.1);      /* EWMA_ALPHA_SLOW */
    CHECK(r.ewma_sigma == 3.0);           /* EWMA_SIGMA */
    CHECK(r.ewma_window_sec == 60);       /* EWMA_WINDOW_SEC */

    NtaRules c = NTA_RULES_DEFAULT;       /* padrão compilado = o da função */
    CHECK(same(&c, &r));
}

static void test_exemplo_versionado_e_padrao(void) {
    char path[512];
    snprintf(path, sizeof(path), "%s/deploy/rules/limiares.example.json",
             NTA_SOURCE_DIR);
    NtaRules ex, d;
    rules_defaults(&d);
    CHECK(rules_load_file(path, &ex, err, sizeof(err)) == 0);
    CHECK(same(&ex, &d));
}

/* ------------------------------------------------------------------------- *
 * Válidos                                                                   *
 * ------------------------------------------------------------------------- */
static void test_parcial_usa_padrao_no_resto(void) {
    NtaRules r;
    CHECK(parse("{\"versao\":1,\"scan_threshold\":5}", &r) == 0);
    CHECK(r.scan_threshold == 5);
    CHECK(r.brute_threshold == 30);
    CHECK(r.ewma_alpha_fast == 0.3);
}

static void test_valores_em_formato_livre(void) {
    NtaRules r;
    /* 1.0 é inteiro aceito em campo inteiro; 3e0 e -0 também são JSON válido */
    CHECK(parse("{\"versao\": 1.0, \"stealth_threshold\": 4.0,"
                " \"dns_entropy_thresh\": 4, \"ewma_alpha_slow\": 1e-1}", &r) == 0);
    CHECK(r.stealth_threshold == 4);
    CHECK(r.dns_entropy_thresh == 4.0);
    CHECK(r.ewma_alpha_slow == 0.1);
}

/* ------------------------------------------------------------------------- *
 * Faixa: cada campo aceita o mínimo e o máximo, e rejeita um passo fora      *
 * ------------------------------------------------------------------------- */
typedef struct { const char *key, *below, *lo, *hi, *above; } Faixa;

static const Faixa FAIXAS[] = {
    { "scan_threshold",      "1",     "2",    "32",     "33" },
    { "icmp_threshold",      "4",     "5",    "100000", "100001" },
    { "syn_flood_threshold", "9",     "10",   "1000000", "1000001" },
    { "stealth_threshold",   "1",     "2",    "1000",   "1001" },
    { "brute_threshold",     "4",     "5",    "100000", "100001" },
    { "brute_window_sec",    "9",     "10",   "3600",   "3601" },
    { "dns_subdomain_len",   "0",     "1",    "63",     "64" },
    { "dns_entropy_thresh",  "0.99",  "1.0",  "8.0",    "8.01" },
    { "dns_suspicious_max",  "0",     "1",    "100000", "100001" },
    { "amplification_ratio", "1",     "2",    "10000",  "10001" },
    { "kc_window_sec",       "59",    "60",   "86400",  "86401" },
    { "ewma_calibration",    "1",     "2",    "100000", "100001" },
    { "ewma_alpha_fast",     "0.009", "0.01", "1.0",    "1.01" },
    { "ewma_alpha_slow",     "0.009", "0.01", "1.0",    "1.01" },
    { "ewma_sigma",          "0.99",  "1.0",  "10.0",   "10.01" },
    { "ewma_window_sec",     "9",     "10",   "3600",   "3601" },
};

static void test_faixa_por_campo(void) {
    /* A tabela cobre os 16 campos de NtaRules. */
    CHECK(sizeof(FAIXAS) / sizeof(FAIXAS[0]) == 16);

    char json[256];
    for (size_t i = 0; i < sizeof(FAIXAS) / sizeof(FAIXAS[0]); i++) {
        const Faixa *f = &FAIXAS[i];
        NtaRules r;

        snprintf(json, sizeof(json), "{\"versao\":1,\"%s\":%s}", f->key, f->lo);
        CHECK(parse(json, &r) == 0);

        snprintf(json, sizeof(json), "{\"versao\":1,\"%s\":%s}", f->key, f->hi);
        CHECK(parse(json, &r) == 0);

        snprintf(json, sizeof(json), "{\"versao\":1,\"%s\":%s}", f->key, f->below);
        CHECK(parse(json, &r) == -1);
        CHECK(contem(f->key) && contem("faixa"));

        snprintf(json, sizeof(json), "{\"versao\":1,\"%s\":%s}", f->key, f->above);
        CHECK(parse(json, &r) == -1);
        CHECK(contem(f->key) && contem("faixa"));
    }
}

/* ------------------------------------------------------------------------- *
 * Tipo, chaves e versão                                                     *
 * ------------------------------------------------------------------------- */
static void test_tipo_errado(void) {
    NtaRules r;
    CHECK(parse("{\"versao\":1,\"scan_threshold\":\"15\"}", &r) == -1);
    CHECK(contem("scan_threshold") && contem("número"));

    CHECK(parse("{\"versao\":1,\"scan_threshold\":true}", &r) == -1);
    CHECK(contem("número"));

    CHECK(parse("{\"versao\":1,\"scan_threshold\":null}", &r) == -1);
    CHECK(contem("número"));

    CHECK(parse("{\"versao\":1,\"scan_threshold\":[15]}", &r) == -1);
    CHECK(contem("número"));

    CHECK(parse("{\"versao\":1,\"scan_threshold\":{\"a\":1}}", &r) == -1);
    CHECK(contem("número"));

    CHECK(parse("{\"versao\":1,\"scan_threshold\":15.5}", &r) == -1);
    CHECK(contem("inteiro"));

    CHECK(parse("{\"versao\":1,\"scan_threshold\":1e400}", &r) == -1);
    CHECK(contem("faixa"));

    CHECK(parse("{\"versao\":\"1\"}", &r) == -1);
    CHECK(contem("versao"));
}

static void test_chave_desconhecida(void) {
    NtaRules r;
    CHECK(parse("{\"versao\":1,\"scan_treshold\":5}", &r) == -1);   /* typo */
    CHECK(contem("desconhecida") && contem("scan_treshold"));

    CHECK(parse("{\"versao\":1,\"regras\":[]}", &r) == -1);         /* fase 2 */
    CHECK(contem("desconhecida") && contem("regras"));
}

static void test_chave_repetida(void) {
    NtaRules r;
    CHECK(parse("{\"versao\":1,\"scan_threshold\":5,\"scan_threshold\":6}", &r) == -1);
    CHECK(contem("repetida") && contem("scan_threshold"));

    CHECK(parse("{\"versao\":1,\"versao\":1}", &r) == -1);
    CHECK(contem("repetida") && contem("versao"));
}

static void test_versao(void) {
    NtaRules r;
    CHECK(parse("{\"scan_threshold\":5}", &r) == -1);
    CHECK(contem("falta") && contem("versao"));

    CHECK(parse("{\"versao\":2}", &r) == -1);
    CHECK(contem("'versao' deve ser 1"));
}

static void test_raiz_nao_objeto(void) {
    NtaRules r;
    CHECK(parse("[1]", &r) == -1);      CHECK(contem("raiz"));
    CHECK(parse("1", &r) == -1);        CHECK(contem("raiz"));
    CHECK(parse("\"x\"", &r) == -1);    CHECK(contem("raiz"));
    CHECK(parse("null", &r) == -1);     CHECK(contem("raiz"));
}

/* ------------------------------------------------------------------------- *
 * Texto quebrado, lixo e profundidade                                       *
 * ------------------------------------------------------------------------- */
static void test_vazio_e_nul(void) {
    NtaRules r;
    CHECK(rules_parse("", 0, &r, err, sizeof(err)) == -1);
    CHECK(contem("vazio"));

    static const char nul[] = "{\"versao\":1}\0 lixo";
    CHECK(rules_parse(nul, sizeof(nul) - 1, &r, err, sizeof(err)) == -1);
    CHECK(contem("nulos"));
}

static void test_lixo_binario(void) {
    uint8_t buf[300];
    NtaRules r;
    for (size_t i = 0; i < sizeof(buf); i++)
        buf[i] = (uint8_t)(0x01 + (i * 37) % 255);   /* nenhum byte nulo */
    CHECK(rules_parse((const char *)buf, sizeof(buf), &r, err, sizeof(err)) == -1);
    CHECK(contem("JSON inválido"));
}

static void test_truncado_em_todo_byte(void) {
    static const char base[] =
        "{\"versao\":1,\"scan_threshold\":5,\"brute_threshold\":30}";
    size_t len = strlen(base);
    NtaRules r;
    /* Qualquer prefixo sem o '}' final não é JSON completo. */
    for (size_t n = 1; n < len; n++)
        CHECK(rules_parse(base, n, &r, err, sizeof(err)) == -1);
    CHECK(rules_parse(base, len, &r, err, sizeof(err)) == 0);
}

static void test_lixo_depois_do_json(void) {
    NtaRules r;
    CHECK(parse("{\"versao\":1}x", &r) == -1);
    CHECK(parse("{\"versao\":1} {}", &r) == -1);
    CHECK(parse("{\"versao\":1}   \n\t", &r) == 0);   /* espaço é permitido */
}

static void test_profundidade(void) {
    NtaRules r;
    /* 4 níveis (chaves e colchetes) passam a validação de forma e chegam à
     * chave desconhecida. */
    CHECK(parse("{\"versao\":1,\"x\":[[[1]]]}", &r) == -1);
    CHECK(contem("desconhecida"));

    /* 5 níveis: rejeitado antes do cJSON recursionar. */
    CHECK(parse("{\"versao\":1,\"x\":[[[[1]]]]}", &r) == -1);
    CHECK(contem("aninhamento"));

    CHECK(parse("{\"versao\":1,\"x\":\"[[[[[[[[[[[[\"}", &r) == -1);
    CHECK(contem("desconhecida"));       /* colchetes dentro de string não contam */
}

static void test_tamanho_maximo(void) {
    NtaRules r;
    /* Exatamente o máximo: aceito. */
    char *big = malloc(NTA_RULES_MAX_BYTES + 1);
    CHECK(big != NULL);
    if (!big) return;
    memset(big, ' ', NTA_RULES_MAX_BYTES);
    memcpy(big, "{\"versao\":1", 11);
    big[NTA_RULES_MAX_BYTES - 1] = '}';
    CHECK(rules_parse(big, NTA_RULES_MAX_BYTES, &r, err, sizeof(err)) == 0);

    /* Um byte a mais: recusado pelo tamanho, sem parsear. */
    CHECK(rules_parse(big, NTA_RULES_MAX_BYTES + 1, &r, err, sizeof(err)) == -1);
    CHECK(contem("bytes"));
    free(big);
}

static void test_erro_nao_altera_saida(void) {
    NtaRules r;
    rules_defaults(&r);
    r.scan_threshold = 77;                       /* sentinela */
    CHECK(parse("{\"versao\":1,\"scan_threshold\":5,\"brute_threshold\":1}", &r) == -1);
    CHECK(r.scan_threshold == 77);               /* válido até o erro, mas não gravou */
}

static void test_mensagem_cabe_no_buffer(void) {
    char pequeno[8];
    NtaRules r;
    static const char ruim[] = "{\"versao\":1,\"chave_muito_longa\":1}";
    CHECK(rules_parse(ruim, strlen(ruim), &r, pequeno, sizeof(pequeno)) == -1);
    CHECK(strlen(pequeno) < sizeof(pequeno));
    /* err NULL também não pode derrubar o processo */
    CHECK(rules_parse(ruim, strlen(ruim), &r, NULL, 0) == -1);
}

/* ------------------------------------------------------------------------- *
 * Arquivo                                                                   *
 * ------------------------------------------------------------------------- */
static void test_arquivo(void) {
    NtaRules r;

    CHECK(rules_load_file("arquivo_que_nao_existe.json", &r, err, sizeof(err)) == -1);
    CHECK(contem("abrir"));

    write_file("", 0);
    CHECK(rules_load_file(TMP_RULES, &r, err, sizeof(err)) == -1);
    CHECK(contem("vazio"));

    /* Gigante: recusado pelo tamanho antes de qualquer leitura para memória. */
    char *big = malloc(NTA_RULES_MAX_BYTES + 100);
    CHECK(big != NULL);
    if (big) {
        memset(big, ' ', NTA_RULES_MAX_BYTES + 100);
        write_file(big, NTA_RULES_MAX_BYTES + 100);
        CHECK(rules_load_file(TMP_RULES, &r, err, sizeof(err)) == -1);
        CHECK(contem("bytes"));
        free(big);
    }

    /* Truncado no disco (JSON cortado no meio). */
    write_file("{\"versao\":1,\"scan_thr", 20);
    CHECK(rules_load_file(TMP_RULES, &r, err, sizeof(err)) == -1);

    /* Lixo binário em arquivo. */
    uint8_t lixo[64];
    for (size_t i = 0; i < sizeof(lixo); i++) lixo[i] = (uint8_t)(i * 91 + 1);
    write_file(lixo, sizeof(lixo));
    CHECK(rules_load_file(TMP_RULES, &r, err, sizeof(err)) == -1);

    /* Válido. */
    write_file("{\"versao\":1,\"ewma_sigma\":2.5}\n", 29);
    CHECK(rules_load_file(TMP_RULES, &r, err, sizeof(err)) == 0);
    CHECK(r.ewma_sigma == 2.5);

    remove(TMP_RULES);
}

/* ------------------------------------------------------------------------- *
 * Mutação determinística: flipa bytes de um arquivo válido. Não pode travar  *
 * nem ler fora do buffer (ASan no CI). Resultado é 0 ou -1, nunca outra coisa.*
 * ------------------------------------------------------------------------- */
static void test_mutacoes_deterministicas(void) {
    static const char base[] =
        "{\"versao\":1,\"scan_threshold\":15,\"icmp_threshold\":20,"
        "\"dns_entropy_thresh\":3.5,\"ewma_alpha_fast\":0.3}";
    size_t len = strlen(base);
    char buf[sizeof(base)];
    uint32_t s = 12345u;
    int bad = 0;
    for (int it = 0; it < 4000; it++) {
        memcpy(buf, base, len);
        int flips = 1 + (int)((s >> 3) % 3);
        for (int k = 0; k < flips; k++) {
            s = s * 1103515245u + 12345u;
            size_t pos = (size_t)((s >> 8) % len);
            s = s * 1103515245u + 12345u;
            char c = (char)((s >> 16) & 0x7F);
            if (c == '\0') c = '?';            /* NUL já é rejeitado à parte */
            buf[pos] = c;
        }
        NtaRules r;
        int rc = rules_parse(buf, len, &r, err, sizeof(err));
        if (rc != 0 && rc != -1) bad++;
    }
    CHECK(bad == 0);
}

int main(void) {
    RUN(test_padrao_igual_ao_codigo_antigo);
    RUN(test_exemplo_versionado_e_padrao);
    RUN(test_parcial_usa_padrao_no_resto);
    RUN(test_valores_em_formato_livre);
    RUN(test_faixa_por_campo);
    RUN(test_tipo_errado);
    RUN(test_chave_desconhecida);
    RUN(test_chave_repetida);
    RUN(test_versao);
    RUN(test_raiz_nao_objeto);
    RUN(test_vazio_e_nul);
    RUN(test_lixo_binario);
    RUN(test_truncado_em_todo_byte);
    RUN(test_lixo_depois_do_json);
    RUN(test_profundidade);
    RUN(test_tamanho_maximo);
    RUN(test_erro_nao_altera_saida);
    RUN(test_mensagem_cabe_no_buffer);
    RUN(test_arquivo);
    RUN(test_mutacoes_deterministicas);
    TEST_EXIT();
}
