/* Testes do nta-eve-bridge (B17): parser EVE, leitor de linhas, tabela de
 * mapeamento, agregação/limite de taxa e seguimento do arquivo (rotação e
 * truncamento). Uso: test_eve_bridge <caminho do mapping padrão>. */
#include "test.h"
#include "eve_agg.h"
#include "eve_map.h"
#include "eve_parse.h"
#include "eve_tail.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- *
 * Coletor de linhas (para o leitor e o seguidor de arquivo)                 *
 * ------------------------------------------------------------------------- */
#define MAX_COLLECT 64
#define COLLECT_LEN 512

typedef struct {
    char lines[MAX_COLLECT][COLLECT_LEN];
    int  n;
} collector_t;

static void collect(const char *line, size_t len, void *vctx) {
    collector_t *c = (collector_t *)vctx;
    if (c->n >= MAX_COLLECT || len >= COLLECT_LEN) { c->n = MAX_COLLECT + 1; return; }
    memcpy(c->lines[c->n], line, len);
    c->lines[c->n][len] = '\0';
    c->n++;
}

/* Só conta (para linhas grandes, sem copiar). */
typedef struct {
    int    n;
    size_t last_len;
} count_t;

static void count_lines(const char *line, size_t len, void *vctx) {
    (void)line;
    count_t *c = (count_t *)vctx;
    c->n++;
    c->last_len = len;
}

/* ------------------------------------------------------------------------- *
 * Parser                                                                    *
 * ------------------------------------------------------------------------- */
static const char ALERT_OK[] =
    "{\"timestamp\":\"2026-11-21T10:00:00.000001+0000\",\"flow_id\":1,"
    "\"event_type\":\"alert\",\"src_ip\":\"203.0.113.50\",\"src_port\":40001,"
    "\"dest_ip\":\"192.168.1.10\",\"dest_port\":22,\"proto\":\"tcp\","
    "\"direction\":\"to_server\",\"alert\":{\"gid\":1,\"signature_id\":2000001,"
    "\"signature\":\"x\",\"category\":\"Detection of a Network Scan\",\"severity\":3,"
    "\"metadata\":{\"mitre_technique_id\":[\"T1595\",\"lixo\",\"T1190.001\"]}}}";

static void test_parse_alerta_completo(void) {
    eve_alert_t a;
    eve_kind_t k = eve_parse_line(ALERT_OK, strlen(ALERT_OK), "mitre_technique_id", &a);
    CHECK(k == EVE_ALERT);
    CHECK_STR(a.src_ip, "203.0.113.50");
    CHECK_STR(a.dst_ip, "192.168.1.10");
    CHECK(a.src_port == 40001);
    CHECK(a.dst_port == 22);
    CHECK_STR(a.proto, "tcp");
    CHECK_STR(a.direction, "to_server");
    CHECK_STR(a.category, "Detection of a Network Scan");
    CHECK(a.signature_id == 2000001);
    CHECK(a.severity == 3);
    CHECK_STR(a.mitre, "T1595,T1190.001");   /* "lixo" descartado */
}

static void test_parse_outro_event_type(void) {
    const char *flow = "{\"event_type\":\"flow\",\"src_ip\":\"10.0.0.1\"}";
    eve_alert_t a;
    CHECK(eve_parse_line(flow, strlen(flow), "mitre_technique_id", &a) == EVE_OTHER);
}

static void test_parse_invalidas(void) {
    eve_alert_t a;
    const char *casos[] = {
        "",                                                        /* vazia      */
        "{ nao e json",                                            /* JSON ruim  */
        "{\"event_type\":\"alert\",\"src_ip\":\"10.0.0.1\"",       /* truncada   */
        "[1,2,3]",                                                 /* não objeto */
        "{\"src_ip\":\"10.0.0.1\",\"alert\":{\"signature_id\":1}}", /* sem event_type */
        "{\"event_type\":7,\"src_ip\":\"10.0.0.1\",\"alert\":{\"signature_id\":1}}",
        "{\"event_type\":\"alert\",\"src_ip\":\"10.0.0.1\",\"alert\":{}}",   /* sem sig */
        "{\"event_type\":\"alert\",\"src_ip\":\"999.1.1.1\",\"alert\":{\"signature_id\":1}}",
        "{\"event_type\":\"alert\",\"alert\":{\"signature_id\":1}}",         /* sem src */
        "{\"event_type\":\"alert\",\"src_ip\":\"10.0.0.1\",\"alert\":{\"signature_id\":-5}}",
        "{\"event_type\":\"alert\",\"src_ip\":\"10.0.0.1\",\"alert\":{\"signature_id\":1.5}}",
        "{\"event_type\":\"alert\",\"src_ip\":\"10.0.0.1\",\"alert\":\"texto\"}",
    };
    for (size_t i = 0; i < sizeof casos / sizeof casos[0]; i++) {
        CHECK(eve_parse_line(casos[i], strlen(casos[i]), "mitre_technique_id", &a) == EVE_INVALID);
    }
}

static void test_parse_linha_grande(void) {
    /* Linha no limite: rejeitada por tamanho antes de chegar ao cJSON. */
    char *big = malloc(EVE_MAX_LINE + 1);
    memset(big, ' ', EVE_MAX_LINE);
    big[EVE_MAX_LINE] = '\0';
    eve_alert_t a;
    CHECK(eve_parse_line(big, EVE_MAX_LINE, "mitre_technique_id", &a) == EVE_INVALID);
    free(big);
}

static void test_parse_portas_e_opcionais(void) {
    const char *l =
        "{\"event_type\":\"alert\",\"src_ip\":\"2001:db8::5\",\"src_port\":70000,"
        "\"dest_ip\":\"nao-ip\",\"alert\":{\"signature_id\":9,\"severity\":\"alta\"}}";
    eve_alert_t a;
    CHECK(eve_parse_line(l, strlen(l), "mitre_technique_id", &a) == EVE_ALERT);
    CHECK_STR(a.src_ip, "2001:db8::5");           /* IPv6 válido */
    CHECK(a.src_port == -1);                      /* fora de faixa */
    CHECK(a.dst_port == -1);                      /* ausente */
    CHECK(a.dst_ip[0] == '\0');                   /* inválido: ignorado */
    CHECK(a.severity == -1);                      /* não numérico */
    CHECK_STR(a.mitre, "");
}

static void test_parse_chave_mitre_configuravel(void) {
    const char *l =
        "{\"event_type\":\"alert\",\"src_ip\":\"10.0.0.1\","
        "\"alert\":{\"signature_id\":9,\"metadata\":{\"outra\":\"T1046\","
        "\"mitre_technique_id\":\"T1190\"}}}";
    eve_alert_t a;
    eve_parse_line(l, strlen(l), "outra", &a);
    CHECK_STR(a.mitre, "T1046");
    eve_parse_line(l, strlen(l), "mitre_technique_id", &a);
    CHECK_STR(a.mitre, "T1190");
    eve_parse_line(l, strlen(l), "ausente", &a);
    CHECK_STR(a.mitre, "");
}

/* ------------------------------------------------------------------------- *
 * Leitor de linhas                                                          *
 * ------------------------------------------------------------------------- */
static void test_linebuf_pedacos(void) {
    eve_linebuf_t lb; memset(&lb, 0, sizeof lb);
    collector_t c; memset(&c, 0, sizeof c);
    eve_linebuf_feed(&lb, "ab", 2, collect, &c);
    eve_linebuf_feed(&lb, "c\nde", 4, collect, &c);
    eve_linebuf_feed(&lb, "f\n\n", 3, collect, &c);   /* linha vazia não sai */
    CHECK(c.n == 2);
    CHECK_STR(c.lines[0], "abc");
    CHECK_STR(c.lines[1], "def");
}

static void test_linebuf_crlf_e_flush(void) {
    eve_linebuf_t lb; memset(&lb, 0, sizeof lb);
    collector_t c; memset(&c, 0, sizeof c);
    eve_linebuf_feed(&lb, "x\r\ny", 4, collect, &c);
    CHECK(c.n == 1);
    CHECK_STR(c.lines[0], "x");
    eve_linebuf_flush(&lb, collect, &c);             /* "y" sem '\n' no fim */
    CHECK(c.n == 2);
    CHECK_STR(c.lines[1], "y");
}

static void test_linebuf_oversized(void) {
    eve_linebuf_t lb; memset(&lb, 0, sizeof lb);
    collector_t c; memset(&c, 0, sizeof c);
    /* Linha de EVE_MAX_LINE + 10 bytes em pedaços de 4096: descartada inteira. */
    size_t total = EVE_MAX_LINE + 10;
    char *big = malloc(total);
    memset(big, 'a', total);
    for (size_t off = 0; off < total; off += 4096) {
        size_t n = (total - off) < 4096 ? total - off : 4096;
        eve_linebuf_feed(&lb, big + off, n, collect, &c);
    }
    eve_linebuf_feed(&lb, "\nok\n", 4, collect, &c);
    CHECK(lb.oversized == 1);
    CHECK(c.n == 1);
    CHECK_STR(c.lines[0], "ok");
    free(big);

    /* Exatamente o limite (EVE_MAX_LINE - 1 bytes + '\n') passa. */
    eve_linebuf_t lb2; memset(&lb2, 0, sizeof lb2);
    count_t cnt; memset(&cnt, 0, sizeof cnt);
    char *edge = malloc(EVE_MAX_LINE);
    memset(edge, 'b', EVE_MAX_LINE - 1);
    edge[EVE_MAX_LINE - 1] = '\n';
    eve_linebuf_feed(&lb2, edge, EVE_MAX_LINE, count_lines, &cnt);
    CHECK(lb2.oversized == 0);
    CHECK(cnt.n == 1);
    CHECK(cnt.last_len == EVE_MAX_LINE - 1);
    free(edge);
}

/* ------------------------------------------------------------------------- *
 * Mapeamento                                                                *
 * ------------------------------------------------------------------------- */
static void test_attack_type(void) {
    char out[EVE_ATTACK_MAX];
    eve_attack_type("Potentially Bad Traffic", out, sizeof out);
    CHECK_STR(out, "SURICATA_POTENTIALLY_BAD_TRAFFIC");
    eve_attack_type("  a--b  ", out, sizeof out);
    CHECK_STR(out, "SURICATA_A_B");
    eve_attack_type("", out, sizeof out);
    CHECK_STR(out, "SURICATA_UNKNOWN");
    eve_attack_type("!!!", out, sizeof out);
    CHECK_STR(out, "SURICATA_UNKNOWN");
    eve_attack_type("a\x01" "b\n", out, sizeof out);      /* controle → '_' */
    CHECK_STR(out, "SURICATA_A_B");
    eve_attack_type("Ação rápida", out, sizeof out);        /* não-ASCII → '_' */
    CHECK_STR(out, "SURICATA_A_O_R_PIDA");
    char longa[300];
    memset(longa, 'z', sizeof longa - 1);
    longa[sizeof longa - 1] = '\0';
    eve_attack_type(longa, out, sizeof out);
    CHECK(strlen(out) <= EVE_ATTACK_MAX - 1);
    CHECK(strlen(out) == strlen("SURICATA_") + EVE_ATTACK_BODY_MAX);
}

/* Invariante de segurança: categoria RECON nunca chega ao NARRATOR_MIN_SCORE
 * (80) só pelo Suricata. Severidade 1 de EXPLOIT chega, para o critério de
 * aceite (o narrator dispara com esses eventos). Lê o mapping padrão do repo. */
static void test_mapa_padrao_invariantes(const char *path) {
    eve_map_t m;
    CHECK(eve_map_load(&m, path) == 0);
    CHECK(m.def_max < 80);
    CHECK(strcmp(m.def_stage, "RECON") == 0);
    for (int i = 0; i < m.n_rules; i++) {
        if (strcmp(m.rules[i].stage, "RECON") == 0) CHECK(m.rules[i].max_score < 80);
    }
    CHECK(m.sev_score[0] >= 80);            /* severidade 1 */
    CHECK(m.sev_score[1] < 80 && m.sev_score[2] < 80);
    CHECK(m.n_rules >= 20);
    CHECK_STR(m.mitre_key, "mitre_technique_id");
}

static void test_mapa_rejeita_invalidos(void) {
    eve_map_t m;
    const char *ruins[] = {
        "{}",                                                         /* sem nada   */
        "[]",                                                         /* não objeto */
        "{\"severity_score\":{\"1\":85,\"2\":55},\"default\":{\"stage\":\"RECON\"},\"categories\":[]}",
        "{\"severity_score\":{\"1\":85,\"2\":55,\"3\":30},\"default\":{\"stage\":\"FOO\"},\"categories\":[]}",
        "{\"severity_score\":{\"1\":101,\"2\":55,\"3\":30},\"default\":{\"stage\":\"RECON\"},\"categories\":[]}",
        "{\"severity_score\":{\"1\":85,\"2\":55,\"3\":30},\"default\":{\"stage\":\"RECON\"},"
          "\"categories\":[{\"category\":\"X\",\"stage\":\"IDLE\"}]}",
        "{\"severity_score\":{\"1\":85,\"2\":55,\"3\":30},\"default\":{\"stage\":\"RECON\"},"
          "\"categories\":[{\"category\":\"X\",\"stage\":\"RECON\"},{\"category\":\"x\",\"stage\":\"RECON\"}]}",
        "{\"severity_score\":{\"1\":85,\"2\":55,\"3\":30},\"default\":{\"stage\":\"RECON\"},"
          "\"categories\":[{\"category\":\"X\",\"stage\":\"RECON\",\"mitre\":\"T12\"}]}",
        "{\"severity_score\":{\"1\":85,\"2\":55,\"3\":30},\"default\":{\"stage\":\"RECON\"},"
          "\"categories\":[{\"category\":\"X\",\"stage\":\"RECON\",\"max_score\":150}]}",
        "{\"severity_score\":{\"1\":85,\"2\":55,\"3\":30},\"default\":{\"stage\":\"RECON\"},"
          "\"categories\":[{\"stage\":\"RECON\"}]}",
        "{ quebrado",
    };
    for (size_t i = 0; i < sizeof ruins / sizeof ruins[0]; i++) {
        CHECK(eve_map_parse(&m, ruins[i], strlen(ruins[i])) == -1);
    }
    /* E um válido mínimo passa e aplica o padrão de mitre_metadata_key. */
    const char *ok = "{\"severity_score\":{\"1\":85,\"2\":55,\"3\":30},"
                     "\"default\":{\"stage\":\"RECON\"},\"categories\":[]}";
    CHECK(eve_map_parse(&m, ok, strlen(ok)) == 0);
    CHECK_STR(m.mitre_key, "mitre_technique_id");
    CHECK(m.def_max == 100);
}

static void test_mapa_traducao(void) {
    const char *mapa = "{\"severity_score\":{\"1\":85,\"2\":55,\"3\":30},"
        "\"default\":{\"stage\":\"RECON\",\"max_score\":40},"
        "\"categories\":[{\"category\":\"Web Application Attack\",\"stage\":\"EXPLOIT\",\"mitre\":\"T1190\"},"
        "{\"category\":\"Potentially Bad Traffic\",\"stage\":\"RECON\",\"max_score\":40}]}";
    eve_map_t m;
    CHECK(eve_map_parse(&m, mapa, strlen(mapa)) == 0);

    /* Regra da tabela, severidade 1, sem MITRE no alerta: técnica da tabela. */
    eve_alert_t a; memset(&a, 0, sizeof a);
    strcpy(a.src_ip, "198.51.100.7"); strcpy(a.dst_ip, "192.168.1.20");
    a.src_port = 51000; a.dst_port = 80; strcpy(a.proto, "tcp");
    strcpy(a.category, "web application attack"); a.severity = 1;
    eve_event_t e;
    eve_map_alert(&m, &a, EVE_SIDE_SRC, &e);
    CHECK_STR(e.src_ip, "198.51.100.7");
    CHECK(e.port == 80);
    CHECK_STR(e.proto, "TCP");
    CHECK_STR(e.attack_type, "SURICATA_WEB_APPLICATION_ATTACK");   /* ci */
    CHECK_STR(e.stage, "EXPLOIT");
    CHECK(e.score == 85);
    CHECK_STR(e.mitre, "T1190");

    /* MITRE do alerta tem prioridade sobre a tabela. */
    strcpy(a.mitre, "T1210");
    eve_map_alert(&m, &a, EVE_SIDE_SRC, &e);
    CHECK_STR(e.mitre, "T1210");

    /* Categoria da tabela com teto: sev 1 vira 40. */
    memset(&a, 0, sizeof a);
    strcpy(a.src_ip, "10.0.0.9"); a.dst_port = 53; strcpy(a.proto, "udp");
    strcpy(a.category, "Potentially Bad Traffic"); a.severity = 1;
    eve_map_alert(&m, &a, EVE_SIDE_SRC, &e);
    CHECK_STR(e.stage, "RECON");
    CHECK(e.score == 40);
    CHECK_STR(e.proto, "UDP");

    /* Proto só com [A-Z0-9], até 7 caracteres (texto do EVE não é confiável). */
    memset(&a, 0, sizeof a);
    strcpy(a.src_ip, "10.0.0.9"); strcpy(a.proto, "t-c\"p\\x\x01longo");
    eve_map_alert(&m, &a, EVE_SIDE_SRC, &e);
    CHECK_STR(e.proto, "TCPXLON");

    /* Categoria fora da tabela: default RECON com teto 40. */
    memset(&a, 0, sizeof a);
    strcpy(a.src_ip, "10.0.0.9"); strcpy(a.category, "Nunca Vista"); a.severity = 2;
    eve_map_alert(&m, &a, EVE_SIDE_SRC, &e);
    CHECK_STR(e.attack_type, "SURICATA_NUNCA_VISTA");
    CHECK_STR(e.stage, "RECON");
    CHECK(e.score == 40);
    CHECK(e.port == 0);                           /* sem porta: 0 */
    CHECK_STR(e.proto, "UNKNOWN");

    /* Severidade fora de 1..3 vira a menor (score 30 com este mapa). */
    memset(&a, 0, sizeof a);
    strcpy(a.src_ip, "10.0.0.9"); strcpy(a.category, "Web Application Attack"); a.severity = 4;
    eve_map_alert(&m, &a, EVE_SIDE_SRC, &e);
    CHECK(e.score == 30);
    a.severity = -1;
    eve_map_alert(&m, &a, EVE_SIDE_SRC, &e);
    CHECK(e.score == 30);
}

static void test_direcao(void) {
    const char *mapa = "{\"severity_score\":{\"1\":85,\"2\":55,\"3\":30},"
        "\"default\":{\"stage\":\"RECON\",\"max_score\":40},\"categories\":[]}";
    eve_map_t m;
    CHECK(eve_map_parse(&m, mapa, strlen(mapa)) == 0);

    eve_alert_t a; memset(&a, 0, sizeof a);
    strcpy(a.src_ip, "203.0.113.50"); strcpy(a.dst_ip, "192.168.1.10");
    a.src_port = 80; a.dst_port = 51000; strcpy(a.category, "Misc activity");
    eve_event_t e;

    /* SRC (padrão): atacante é src_ip, porta é dest_port. */
    strcpy(a.direction, "to_client");
    eve_map_alert(&m, &a, EVE_SIDE_SRC, &e);
    CHECK_STR(e.src_ip, "203.0.113.50");
    CHECK(e.port == 51000);

    /* RESPONSE + to_client: troca para dest_ip, porta do outro lado (src_port). */
    eve_map_alert(&m, &a, EVE_SIDE_RESPONSE, &e);
    CHECK_STR(e.src_ip, "192.168.1.10");
    CHECK(e.port == 80);

    /* RESPONSE + to_server: não troca. */
    strcpy(a.direction, "to_server");
    eve_map_alert(&m, &a, EVE_SIDE_RESPONSE, &e);
    CHECK_STR(e.src_ip, "203.0.113.50");
    CHECK(e.port == 51000);

    /* RESPONSE + to_client sem dest_ip: não troca (não há para onde). */
    strcpy(a.direction, "to_client");
    a.dst_ip[0] = '\0';
    eve_map_alert(&m, &a, EVE_SIDE_RESPONSE, &e);
    CHECK_STR(e.src_ip, "203.0.113.50");
}

/* ------------------------------------------------------------------------- *
 * Agregação, limite de taxa e contadores                                    *
 * ------------------------------------------------------------------------- */
static eve_event_t ev(const char *src, long sid, int port) {
    eve_event_t e; memset(&e, 0, sizeof e);
    strcpy(e.src_ip, src);
    e.signature_id = sid;
    e.port = port;
    strcpy(e.proto, "TCP");
    strcpy(e.attack_type, "SURICATA_X");
    strcpy(e.stage, "RECON");
    e.score = 30;
    return e;
}

/* Invariante: todo alerta recebido está em exatamente um lugar. */
static uint64_t open_alerts(const eve_agg_t *a) {
    uint64_t n = 0;
    for (int i = 0; i < a->n_slots; i++) n += a->slots[i].count;
    return n;
}

static uint64_t pending_alerts(const eve_agg_t *a) {
    uint64_t n = 0;
    for (int i = 0; i < eve_agg_pending(a); i++) n += eve_agg_peek(a, i)->count;
    return n;
}

static int invariante(const eve_agg_t *a) {
    const eve_counters_t *c = &a->c;
    uint64_t soma = c->published + c->dropped_table + c->dropped_rate +
                    c->dropped_pending + c->dropped_broker +
                    pending_alerts(a) + open_alerts(a);
    return soma == c->alerts;
}

static void test_agregacao_por_janela(void) {
    eve_agg_t a; eve_agg_init(&a, 1000, 0, 0);
    eve_event_t e = ev("203.0.113.50", 2000001, 22);
    eve_agg_add(&a, &e, 0);
    e.port = 23; eve_agg_add(&a, &e, 100);
    e.port = 80; eve_agg_add(&a, &e, 200);
    CHECK(a.n_slots == 1);                     /* três alertas, um grupo */
    CHECK(eve_agg_pending(&a) == 0);
    CHECK(invariante(&a));

    eve_agg_tick(&a, 999, 0);                  /* ainda dentro da janela */
    CHECK(eve_agg_pending(&a) == 0);
    eve_agg_tick(&a, 1000, 0);                 /* janela venceu */
    CHECK(eve_agg_pending(&a) == 1);
    CHECK(eve_agg_peek(&a, 0)->count == 3);
    CHECK(eve_agg_peek(&a, 0)->ev.port == 22); /* porta do primeiro alerta */
    CHECK(invariante(&a));
}

static void test_agregacao_chaves_e_janela_nova(void) {
    eve_agg_t a; eve_agg_init(&a, 1000, 0, 0);
    eve_event_t e1 = ev("203.0.113.50", 2000001, 22);
    eve_event_t e2 = ev("203.0.113.51", 2000001, 22);   /* outro src */
    eve_event_t e3 = ev("203.0.113.50", 2000002, 22);   /* outra assinatura */
    eve_agg_add(&a, &e1, 0);
    eve_agg_add(&a, &e2, 0);
    eve_agg_add(&a, &e3, 0);
    CHECK(a.n_slots == 3);

    /* Mesmo grupo depois da janela: abre um novo, o antigo vai para pendentes. */
    eve_agg_add(&a, &e1, 1500);
    CHECK(eve_agg_pending(&a) == 3);
    CHECK(eve_agg_peek(&a, 0)->count == 1);
    CHECK(a.n_slots == 1);
    CHECK(invariante(&a));
}

static void test_agregacao_desligada(void) {
    /* Janela 0: cada alerta sai sozinho com count=1 (sem agregar). */
    eve_agg_t a; eve_agg_init(&a, 0, 0, 0);
    eve_event_t e = ev("203.0.113.50", 2000001, 22);
    for (int i = 0; i < 5; i++) eve_agg_add(&a, &e, 0);
    CHECK(a.n_slots == 0);
    CHECK(eve_agg_pending(&a) == 5);
    for (int i = 0; i < 5; i++) CHECK(eve_agg_peek(&a, i)->count == 1);
    CHECK(invariante(&a));
}

static void test_limite_de_taxa(void) {
    /* 2 registros/s: balde cheio com 2 fichas. */
    eve_agg_t a; eve_agg_init(&a, 0, 2, 0);
    eve_event_t e = ev("203.0.113.50", 2000001, 22);
    for (int i = 0; i < 5; i++) eve_agg_add(&a, &e, 0);
    CHECK(eve_agg_pending(&a) == 2);
    CHECK(a.c.dropped_rate == 3);              /* descarte contado, não silencioso */
    CHECK(invariante(&a));

    /* Meio segundo depois: ~1 ficha. */
    eve_agg_add(&a, &e, 500);
    CHECK(eve_agg_pending(&a) == 3);
    CHECK(invariante(&a));

    /* Sem limite (0): nada é descartado por taxa. */
    eve_agg_t b; eve_agg_init(&b, 0, 0, 0);
    for (int i = 0; i < 200; i++) eve_agg_add(&b, &e, 0);
    CHECK(b.c.dropped_rate == 0);
    CHECK(eve_agg_pending(&b) == 200);
}

static void test_fila_cheia_e_tabela_cheia(void) {
    eve_agg_t a; eve_agg_init(&a, 0, 0, 0);
    eve_event_t e = ev("203.0.113.50", 2000001, 22);
    for (int i = 0; i < EVE_PENDING_MAX + 5; i++) eve_agg_add(&a, &e, 0);
    CHECK(eve_agg_pending(&a) == EVE_PENDING_MAX);
    CHECK(a.c.dropped_pending == 5);
    CHECK(invariante(&a));

    eve_agg_t b; eve_agg_init(&b, 60000, 0, 0);
    for (int i = 0; i < EVE_AGG_MAX_SLOTS + 7; i++) {
        char src[46];
        snprintf(src, sizeof src, "10.1.%d.%d", i / 250, i % 250);
        eve_event_t e2 = ev(src, 2000001, 22);
        eve_agg_add(&b, &e2, 0);
    }
    CHECK(b.n_slots == EVE_AGG_MAX_SLOTS);
    CHECK(b.c.dropped_table == 7);
    CHECK(invariante(&b));
}

static void test_publicacao_e_abandono(void) {
    eve_agg_t a; eve_agg_init(&a, 0, 0, 0);
    eve_event_t e = ev("203.0.113.50", 2000001, 22);
    for (int i = 0; i < 4; i++) eve_agg_add(&a, &e, 0);
    eve_agg_consume(&a, 3);
    CHECK(a.c.published == 3);
    CHECK(a.c.records == 3);
    CHECK(eve_agg_pending(&a) == 1);
    CHECK(invariante(&a));
    eve_agg_abandon_pending(&a);
    CHECK(a.c.dropped_broker == 1);
    CHECK(eve_agg_pending(&a) == 0);
    CHECK(invariante(&a));
}

/* ------------------------------------------------------------------------- *
 * Arquivo: tail, rotação e truncamento                                      *
 * ------------------------------------------------------------------------- */
#define TMP_EVE "test_eve_bridge.tmp.json"
#define TMP_ROT "test_eve_bridge.tmp.json.1"

static void write_file(const char *path, const char *content, const char *mode) {
    FILE *f = fopen(path, mode);
    if (!f) return;
    fputs(content, f);
    fclose(f);
}

static void test_tail_segue_novas_linhas(void) {
    remove(TMP_EVE);
    write_file(TMP_EVE, "antiga\n", "wb");
    eve_file_t f; eve_linebuf_t lb; collector_t c;
    memset(&lb, 0, sizeof lb); memset(&c, 0, sizeof c);
    CHECK(eve_file_open(&f, TMP_EVE, 0) == 0);      /* modo tail: fim do arquivo */

    eve_file_poll(&f, &lb, collect, &c, 1);
    CHECK(c.n == 0);                                /* a antiga não é relida */

    write_file(TMP_EVE, "nova\n", "ab");
    eve_file_poll(&f, &lb, collect, &c, 1);
    CHECK(c.n == 1);
    CHECK_STR(c.lines[0], "nova");
    eve_file_close(&f);
    remove(TMP_EVE);
}

static void test_tail_rotacao(void) {
    remove(TMP_EVE); remove(TMP_ROT);
    write_file(TMP_EVE, "x1\n", "wb");
    eve_file_t f; eve_linebuf_t lb; collector_t c;
    memset(&lb, 0, sizeof lb); memset(&c, 0, sizeof c);
    CHECK(eve_file_open(&f, TMP_EVE, 1) == 0);      /* lê desde o início */
    eve_file_poll(&f, &lb, collect, &c, 1);
    CHECK(c.n == 1);

    /* Rotação: o antigo vai para .1 e um novo nasce no caminho original. */
    CHECK(rename(TMP_EVE, TMP_ROT) == 0);
    write_file(TMP_EVE, "y1\ny2\n", "wb");
    eve_file_poll(&f, &lb, collect, &c, 1);
    CHECK(f.rotations == 1);
    CHECK(c.n == 3);
    CHECK_STR(c.lines[1], "y1");
    CHECK_STR(c.lines[2], "y2");
    eve_file_close(&f);
    remove(TMP_EVE); remove(TMP_ROT);
}

static void test_tail_truncamento(void) {
    remove(TMP_EVE);
    write_file(TMP_EVE, "1\n2\n", "wb");
    eve_file_t f; eve_linebuf_t lb; collector_t c;
    memset(&lb, 0, sizeof lb); memset(&c, 0, sizeof c);
    CHECK(eve_file_open(&f, TMP_EVE, 1) == 0);
    eve_file_poll(&f, &lb, collect, &c, 1);
    CHECK(c.n == 2);

    /* copytruncate: mesmo inode, tamanho menor. */
    write_file(TMP_EVE, "3\n", "wb");
    eve_file_poll(&f, &lb, collect, &c, 1);
    CHECK(f.truncations == 1);
    CHECK(c.n == 3);
    CHECK_STR(c.lines[2], "3");
    eve_file_close(&f);
    remove(TMP_EVE);
}

static void test_tail_linha_parcial_na_rotacao(void) {
    remove(TMP_EVE); remove(TMP_ROT);
    write_file(TMP_EVE, "fim-sem-newline", "wb");
    eve_file_t f; eve_linebuf_t lb; collector_t c;
    memset(&lb, 0, sizeof lb); memset(&c, 0, sizeof c);
    CHECK(eve_file_open(&f, TMP_EVE, 1) == 0);
    eve_file_poll(&f, &lb, collect, &c, 1);
    CHECK(c.n == 0);                               /* parcial fica no buffer */

    rename(TMP_EVE, TMP_ROT);
    write_file(TMP_EVE, "novo\n", "wb");
    eve_file_poll(&f, &lb, collect, &c, 1);
    CHECK(lb.discarded == 1);                      /* parcial do arquivo antigo */
    CHECK(c.n == 1);
    CHECK_STR(c.lines[0], "novo");                 /* sem colar com o antigo */
    eve_file_close(&f);
    remove(TMP_EVE); remove(TMP_ROT);
}

static void test_tail_arquivo_ausente(void) {
    remove(TMP_EVE);
    eve_file_t f; eve_linebuf_t lb; collector_t c;
    memset(&lb, 0, sizeof lb); memset(&c, 0, sizeof c);
    CHECK(eve_file_open(&f, TMP_EVE, 0) == -1);
    CHECK(eve_file_poll(&f, &lb, collect, &c, 1) == 0);   /* ainda não existe */
    write_file(TMP_EVE, "chegou\n", "wb");
    eve_file_poll(&f, &lb, collect, &c, 1);               /* aparece: lê do início */
    CHECK(c.n == 1);
    CHECK_STR(c.lines[0], "chegou");
    eve_file_close(&f);
    remove(TMP_EVE);
}

int main(int argc, char **argv) {
    const char *mapping = argc > 1 ? argv[1] : "deploy/eve-bridge.mapping.json";

    test_parse_alerta_completo();
    test_parse_outro_event_type();
    test_parse_invalidas();
    test_parse_linha_grande();
    test_parse_portas_e_opcionais();
    test_parse_chave_mitre_configuravel();
    test_linebuf_pedacos();
    test_linebuf_crlf_e_flush();
    test_linebuf_oversized();
    test_attack_type();
    test_mapa_padrao_invariantes(mapping);
    test_mapa_rejeita_invalidos();
    test_mapa_traducao();
    test_direcao();
    test_agregacao_por_janela();
    test_agregacao_chaves_e_janela_nova();
    test_agregacao_desligada();
    test_limite_de_taxa();
    test_fila_cheia_e_tabela_cheia();
    test_publicacao_e_abandono();
    test_tail_segue_novas_linhas();
    test_tail_rotacao();
    test_tail_truncamento();
    test_tail_linha_parcial_na_rotacao();
    test_tail_arquivo_ausente();

    TEST_EXIT();
}
