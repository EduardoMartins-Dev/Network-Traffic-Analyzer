/* Testes do armazenamento de IoC do nta-server (src/server/nta_ioc.c), B31:
 *   1. parser: IPv4 e IPv6, entrada que não é IP, lista vazia, JSON truncado,
 *      arquivo ausente;
 *   2. recarga (NtaIocStore): troca válida; arquivo truncado e lista sem IP
 *      válido são rejeitados e a tabela anterior continua ativa; carga inicial
 *      sem arquivo seguida de reload válido liga o IoC;
 *   3. concorrência: leitores fazem acquire/match/release enquanto a thread
 *      principal recarrega, com rejeições intercaladas. Cada tabela observada
 *      tem de ser uma geração inteira e consistente. Uso de tabela liberada é
 *      pego pelo ASan (heap-use-after-free).
 * Só Linux/POSIX, como o test_whois: nta_ioc.c usa <arpa/inet.h>. Sem rede. */
#include "test.h"
#include "nta_ioc.h"

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARQ          "test_ioc_blocklist.json"  /* relativo ao diretório de build */
#define N_LEITORES   6
#define RODADAS      300
#define IPS_GERACAO  32
#define IP_COMUM     "192.0.2.1"                /* presente em toda geração */

static const char *LISTA_A =
    "{\"version\":1,\"lists\":[{\"name\":\"lista-a\","
    "\"ips\":[\"1.1.1.1\",\"2.2.2.2\"]}]}";
static const char *LISTA_B =
    "{\"version\":1,\"lists\":[{\"name\":\"lista-b\","
    "\"ips\":[\"3.3.3.3\",\"2001:db8::7\"]}]}";
static const char *SO_LIXO =
    "{\"version\":1,\"lists\":[{\"name\":\"ruim\","
    "\"ips\":[\"lixo\",\"999.1.1.1\",\"1.2.3\"]}]}";

static int escreve(const char *path, const char *dados, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t w = fwrite(dados, 1, n, f);
    fclose(f);
    return w == n ? 0 : -1;
}

/* Copia o nome da lista que casa com `ip` ("" se não casa). Copiar é
 * obrigatório: o ponteiro devolvido pela tabela só vale até o release. */
static void nome_de(NtaIocStore *s, const char *ip, char *out, size_t n) {
    int slot;
    NtaIoc *t = nta_ioc_store_acquire(s, &slot);
    const char *m = nta_ioc_match_ip(t, ip);
    snprintf(out, n, "%s", m ? m : "");
    nta_ioc_store_release(s, slot);
}

/* ------------------------------------------------------------------------ *
 * 1. Parser                                                                *
 * ------------------------------------------------------------------------ */
static void test_parser_ipv4_e_ipv6(void) {
    static const char *v4v6 =
        "{\"version\":1,\"lists\":[{\"name\":\"v4\",\"ips\":[\"1.2.3.4\"]},"
        "{\"name\":\"v6\",\"ips\":[\"2001:db8::1\"]}]}";
    CHECK(escreve(ARQ, v4v6, strlen(v4v6)) == 0);
    NtaIoc *ioc = nta_ioc_load(ARQ);
    CHECK(ioc != NULL);
    if (!ioc) return;
    CHECK(nta_ioc_size(ioc) == 2);
    CHECK_STR(nta_ioc_match_ip(ioc, "1.2.3.4"), "v4");
    CHECK_STR(nta_ioc_match_ip(ioc, "2001:db8::1"), "v6");
    CHECK(nta_ioc_match_ip(ioc, "1.2.3.5") == NULL);
    nta_ioc_close(ioc);
}

static void test_parser_descarta_nao_ip(void) {
    /* Só entram IPs de verdade; o IP válido do meio continua carregado. */
    static const char *mix =
        "{\"version\":1,\"lists\":[{\"name\":\"mix\",\"ips\":"
        "[\"lixo\",\"999.1.1.1\",\"1.2.3\",\"\",\"8.8.8.8\"]}]}";
    CHECK(escreve(ARQ, mix, strlen(mix)) == 0);
    NtaIoc *ioc = nta_ioc_load(ARQ);
    CHECK(ioc != NULL);
    if (ioc) {
        CHECK(nta_ioc_size(ioc) == 1);
        CHECK_STR(nta_ioc_match_ip(ioc, "8.8.8.8"), "mix");
        CHECK(nta_ioc_match_ip(ioc, "lixo") == NULL);
        nta_ioc_close(ioc);
    }

    /* Só lixo = zero IoCs = IoC desabilitado. */
    CHECK(escreve(ARQ, SO_LIXO, strlen(SO_LIXO)) == 0);
    CHECK(nta_ioc_load(ARQ) == NULL);
}

static void test_parser_lista_vazia(void) {
    static const char *vazia = "{\"version\":1,\"lists\":[]}";
    static const char *sem_ips =
        "{\"version\":1,\"lists\":[{\"name\":\"x\",\"ips\":[]}]}";
    static const char *sem_lists = "{\"version\":1}";
    CHECK(escreve(ARQ, vazia, strlen(vazia)) == 0);
    CHECK(nta_ioc_load(ARQ) == NULL);

    CHECK(escreve(ARQ, sem_ips, strlen(sem_ips)) == 0);
    CHECK(nta_ioc_load(ARQ) == NULL);

    CHECK(escreve(ARQ, sem_lists, strlen(sem_lists)) == 0);   /* sem 'lists' */
    CHECK(nta_ioc_load(ARQ) == NULL);
}

static void test_parser_json_truncado(void) {
    size_t n = strlen(LISTA_A) / 2;                    /* corta no meio */
    CHECK(escreve(ARQ, LISTA_A, n) == 0);
    CHECK(nta_ioc_load(ARQ) == NULL);
}

static void test_parser_arquivo_ausente(void) {
    remove(ARQ);
    CHECK(nta_ioc_load(ARQ) == NULL);
    CHECK(nta_ioc_load("") == NULL);
    CHECK(nta_ioc_load(NULL) == NULL);
}

/* ------------------------------------------------------------------------ *
 * 2. Recarga                                                               *
 * ------------------------------------------------------------------------ */
static void test_recarga_troca_valida(void) {
    char nm[64];
    CHECK(escreve(ARQ, LISTA_A, strlen(LISTA_A)) == 0);
    NtaIocStore *s = nta_ioc_store_open(ARQ);
    CHECK(s != NULL);
    if (!s) return;

    CHECK(nta_ioc_store_size(s) == 2);
    nome_de(s, "1.1.1.1", nm, sizeof nm);
    CHECK_STR(nm, "lista-a");

    CHECK(escreve(ARQ, LISTA_B, strlen(LISTA_B)) == 0);
    CHECK(nta_ioc_store_reload(s) == 0);
    CHECK(nta_ioc_store_size(s) == 2);
    nome_de(s, "1.1.1.1", nm, sizeof nm);
    CHECK_STR(nm, "");                                  /* saiu da tabela */
    nome_de(s, "3.3.3.3", nm, sizeof nm);
    CHECK_STR(nm, "lista-b");
    nome_de(s, "2001:db8::7", nm, sizeof nm);
    CHECK_STR(nm, "lista-b");

    nta_ioc_store_close(s);
}

static void test_recarga_rejeita_e_mantem_anterior(void) {
    char nm[64];
    size_t meio = strlen(LISTA_A) / 2;
    CHECK(escreve(ARQ, LISTA_B, strlen(LISTA_B)) == 0);
    NtaIocStore *s = nta_ioc_store_open(ARQ);
    CHECK(s != NULL);
    if (!s) return;

    CHECK(escreve(ARQ, LISTA_A, meio) == 0);            /* truncado */
    CHECK(nta_ioc_store_reload(s) == -1);
    CHECK(nta_ioc_store_size(s) == 2);
    nome_de(s, "3.3.3.3", nm, sizeof nm);
    CHECK_STR(nm, "lista-b");

    CHECK(escreve(ARQ, SO_LIXO, strlen(SO_LIXO)) == 0); /* sem IP válido */
    CHECK(nta_ioc_store_reload(s) == -1);
    CHECK(nta_ioc_store_size(s) == 2);
    nome_de(s, "3.3.3.3", nm, sizeof nm);
    CHECK_STR(nm, "lista-b");

    static const char *vazia = "{\"version\":1,\"lists\":[]}";
    CHECK(escreve(ARQ, vazia, strlen(vazia)) == 0);
    CHECK(nta_ioc_store_reload(s) == -1);               /* lista vazia */
    CHECK(nta_ioc_store_size(s) == 2);

    remove(ARQ);                                        /* arquivo sumiu */
    CHECK(nta_ioc_store_reload(s) == -1);
    CHECK(nta_ioc_store_size(s) == 2);
    nome_de(s, "3.3.3.3", nm, sizeof nm);
    CHECK_STR(nm, "lista-b");

    nta_ioc_store_close(s);
}

static void test_recarga_carga_inicial_sem_arquivo(void) {
    char nm[64];
    remove(ARQ);
    NtaIocStore *s = nta_ioc_store_open(ARQ);
    CHECK(s != NULL);             /* sempre devolve store, mesmo sem carga */
    if (!s) return;
    CHECK(nta_ioc_store_size(s) == 0);
    nome_de(s, "1.1.1.1", nm, sizeof nm);
    CHECK_STR(nm, "");

    CHECK(escreve(ARQ, LISTA_A, strlen(LISTA_A)) == 0);
    CHECK(nta_ioc_store_reload(s) == 0);
    CHECK(nta_ioc_store_size(s) == 2);
    nome_de(s, "1.1.1.1", nm, sizeof nm);
    CHECK_STR(nm, "lista-a");

    nta_ioc_store_close(s);
}

/* ------------------------------------------------------------------------ *
 * 3. Concorrência                                                          *
 * ------------------------------------------------------------------------ */

/* Geração k: uma única lista "gen<k>" com IP_COMUM e IPS_GERACAO IPs 10.x.y.i
 * que só existem nessa geração. */
static void gen_json(char *buf, size_t n, int k) {
    size_t len = (size_t)snprintf(buf, n,
        "{\"version\":1,\"lists\":[{\"name\":\"gen%d\",\"ips\":[\"%s\"", k, IP_COMUM);
    for (int i = 1; i <= IPS_GERACAO; i++)
        len += (size_t)snprintf(buf + len, n - len, ",\"10.%d.%d.%d\"",
                                k / 256, k % 256, i);
    snprintf(buf + len, n - len, "]}]}");
}

typedef struct {
    NtaIocStore *s;
    atomic_int  *parar;
    long         usadas;   /* tabelas adquiridas e conferidas */
    long         falhas;   /* inconsistências vistas */
} Leitor;

static void *leitor_main(void *arg) {
    Leitor *L = arg;
    while (!atomic_load(L->parar)) {
        int slot;
        NtaIoc *t = nta_ioc_store_acquire(L->s, &slot);
        if (!t) {                       /* a tabela ativa nunca fica NULL aqui */
            L->falhas++;
        } else {
            const char *nm = nta_ioc_match_ip(t, IP_COMUM);
            int k = -1;
            if (!nm || sscanf(nm, "gen%d", &k) != 1 || k < 0) {
                L->falhas++;
            } else {
                /* Segura a tabela e confere a geração inteira: tamanho, e cada
                 * IP da geração casa com o mesmo nome. Tabela mista ou já
                 * liberada/reaproveitada diverge aqui. */
                if (nta_ioc_size(t) != IPS_GERACAO + 1) L->falhas++;
                for (int i = 1; i <= IPS_GERACAO; i++) {
                    char ip[32];
                    snprintf(ip, sizeof ip, "10.%d.%d.%d", k / 256, k % 256, i);
                    const char *m = nta_ioc_match_ip(t, ip);
                    if (!m || strcmp(m, nm) != 0) L->falhas++;
                    if (i % 8 == 0) sched_yield();   /* alarga a janela de uso */
                }
            }
        }
        nta_ioc_store_release(L->s, slot);
        L->usadas++;
    }
    return NULL;
}

static void test_concorrencia_leitores_x_recarga(void) {
    char buf[4096], nm[64], esperado[64];
    atomic_int parar;
    Leitor L[N_LEITORES];
    pthread_t th[N_LEITORES];
    int criado[N_LEITORES] = {0};
    int ultimo = 0, aceitas = 0, rejeitadas = 0, erros_rc = 0, erros_visao = 0;

    gen_json(buf, sizeof buf, ultimo);
    CHECK(escreve(ARQ, buf, strlen(buf)) == 0);
    NtaIocStore *s = nta_ioc_store_open(ARQ);
    CHECK(s != NULL);
    if (!s) return;

    atomic_init(&parar, 0);
    for (int i = 0; i < N_LEITORES; i++) {
        L[i].s = s;
        L[i].parar = &parar;
        L[i].usadas = 0;
        L[i].falhas = 0;
        criado[i] = pthread_create(&th[i], NULL, leitor_main, &L[i]) == 0;
        CHECK(criado[i]);
    }

    for (int r = 1; r <= RODADAS; r++) {
        int rc_esperado;
        if (r % 5 == 0) {                       /* truncado: rejeitado */
            gen_json(buf, sizeof buf, ultimo + 1);
            escreve(ARQ, buf, strlen(buf) / 2);
            rc_esperado = -1;
        } else if (r % 7 == 0) {                /* sem IP válido: rejeitado */
            escreve(ARQ, SO_LIXO, strlen(SO_LIXO));
            rc_esperado = -1;
        } else {                                /* geração nova: aceita */
            ultimo++;
            gen_json(buf, sizeof buf, ultimo);
            escreve(ARQ, buf, strlen(buf));
            rc_esperado = 0;
        }

        int rc = nta_ioc_store_reload(s);
        if (rc != rc_esperado) erros_rc++;
        if (rc == 0) aceitas++; else rejeitadas++;

        /* A thread de recarga é a única que publica: depois de cada rodada a
         * tabela ativa tem de ser a última aceita, mesmo após rejeições. */
        snprintf(esperado, sizeof esperado, "gen%d", ultimo);
        nome_de(s, IP_COMUM, nm, sizeof nm);
        if (strcmp(nm, esperado) != 0) erros_visao++;
    }

    atomic_store(&parar, 1);
    long usadas = 0, falhas = 0;
    for (int i = 0; i < N_LEITORES; i++) {
        if (!criado[i]) continue;
        pthread_join(th[i], NULL);
        usadas += L[i].usadas;
        falhas += L[i].falhas;
    }

    CHECK(erros_rc == 0);
    CHECK(erros_visao == 0);
    CHECK(aceitas > 0);
    CHECK(rejeitadas > 0);
    CHECK(usadas > 0);                      /* leitores realmente rodaram */
    CHECK(falhas == 0);
    nta_ioc_store_close(s);
}

int main(void) {
    remove(ARQ);
    RUN(test_parser_ipv4_e_ipv6);
    RUN(test_parser_descarta_nao_ip);
    RUN(test_parser_lista_vazia);
    RUN(test_parser_json_truncado);
    RUN(test_parser_arquivo_ausente);
    RUN(test_recarga_troca_valida);
    RUN(test_recarga_rejeita_e_mantem_anterior);
    RUN(test_recarga_carga_inicial_sem_arquivo);
    RUN(test_concorrencia_leitores_x_recarga);
    remove(ARQ);
    TEST_EXIT();
}
