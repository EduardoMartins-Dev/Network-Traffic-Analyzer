/* ========================================================================= *
 * nta-eve-bridge — lê alertas do eve.json do Suricata e publica eventos NTA  *
 * na traffic_queue (B17, ADR "Contrato da ponte EVE do Suricata", opção A).  *
 *                                                                           *
 * Processo auxiliar ao lado do agente: usa o mesmo publisher AMQP e as       *
 * mesmas credenciais (AGENT_*, inclusive mTLS). Não toca no pipeline de      *
 * captura nem no servidor.                                                  *
 *                                                                           *
 * Configuração: --config <arq> (mesmo formato do agente; o ambiente vence)   *
 *   BRIDGE_EVE_PATH               eve.json a seguir (obrigatório)            *
 *   BRIDGE_MAPPING_FILE           tabela de mapeamento JSON (obrigatório)    *
 *   BRIDGE_AGG_WINDOW_MS          janela de agregação; 0 desliga (10000)     *
 *   BRIDGE_RATE_PER_SEC           registros publicados por segundo; 0 = sem    *
 *                                 limite (100)                                *
 *   BRIDGE_ATTACKER_SIDE          src | response (src)                      *
 *   BRIDGE_STATS_INTERVAL_SEC     intervalo dos contadores no log (10)       *
 * Flags: --once (lê até o fim e sai), --dry-run (imprime JSON, sem AMQP),    *
 *        --from-start (no modo seguir, lê o arquivo desde o início).         *
 * ========================================================================= */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "publisher.h"
#include "cJSON.h"
#include "eve_agg.h"
#include "eve_map.h"
#include "eve_tail.h"

#define BATCH_MAX        50        /* registros por mensagem AMQP (= agente)  */
#define POLL_SLEEP_NS    200000000L
#define DEFAULT_WINDOW_MS 10000
#define DEFAULT_RATE      100
#define DEFAULT_STATS_S   10

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static int64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "uso: %s [--config <arq>] [--once] [--dry-run] [--from-start]\n"
        "  variaveis: BRIDGE_EVE_PATH, BRIDGE_MAPPING_FILE (obrigatorias),\n"
        "             BRIDGE_AGG_WINDOW_MS, BRIDGE_RATE_PER_SEC,\n"
        "             BRIDGE_ATTACKER_SIDE (src|response), BRIDGE_STATS_INTERVAL_SEC\n"
        "  AMQP: AGENT_SERVER_HOST, AGENT_SERVER_PORT, AGENT_ID, AGENT_TOKEN, ...\n",
        prog);
}

/* Inteiro de ambiente dentro de [min, max]; ausente: fallback; inválido: sai. */
static int env_int(const char *name, int fallback, int min, int max) {
    const char *v = getenv(name);
    if (!v || !*v) return fallback;
    char *end = NULL;
    long n = strtol(v, &end, 10);
    if (*end != '\0' || n < min || n > max) {
        fprintf(stderr, "[EVE] %s invalido: '%s' (esperado %d..%d)\n", name, v, min, max);
        exit(2);
    }
    return (int)n;
}

/* ------------------------------------------------------------------------- *
 * Linha → alerta → agregação                                                *
 * ------------------------------------------------------------------------- */
typedef struct {
    const eve_map_t *map;
    eve_side_t       side;
    eve_agg_t       *agg;
    int64_t          now_ms;
    uint64_t         lines;      /* linhas recebidas (não vazias)              */
    uint64_t         other;      /* JSON válido de outro event_type            */
    uint64_t         invalid;    /* JSON inválido ou alerta incompleto         */
} run_ctx_t;

static void on_line(const char *line, size_t len, void *vctx) {
    run_ctx_t *c = (run_ctx_t *)vctx;
    c->lines++;

    eve_alert_t a;
    eve_kind_t k = eve_parse_line(line, len, c->map->mitre_key, &a);
    if (k == EVE_OTHER) { c->other++; return; }
    if (k == EVE_INVALID) { c->invalid++; return; }

    eve_event_t e;
    eve_map_alert(c->map, &a, c->side, &e);
    eve_agg_add(c->agg, &e, c->now_ms);
}

/* ------------------------------------------------------------------------- *
 * Publicação                                                                *
 * ------------------------------------------------------------------------- */

/* Array JSON no formato do evento NTA. bytes = 0 (alerta não tem contagem de
 * bytes); is_scan = 1 (o alerta disparou detecção). count e signature_id são
 * campos extras: o nta-server ignora chaves que não conhece (Influx, republish
 * e export lêem só as suas). */
static char *build_json(const eve_rec_t *r, int n) {
    cJSON *arr = cJSON_CreateArray();
    if (!arr) return NULL;
    for (int i = 0; i < n; i++) {
        cJSON *o = cJSON_CreateObject();
        if (!o) { cJSON_Delete(arr); return NULL; }
        cJSON_AddStringToObject(o, "src_ip",           r[i].ev.src_ip);
        cJSON_AddNumberToObject(o, "port",             r[i].ev.port);
        cJSON_AddStringToObject(o, "proto",            r[i].ev.proto);
        cJSON_AddNumberToObject(o, "bytes",            0);
        cJSON_AddNumberToObject(o, "is_scan",          1);
        cJSON_AddStringToObject(o, "attack_type",      r[i].ev.attack_type);
        cJSON_AddStringToObject(o, "kill_chain_stage", r[i].ev.stage);
        cJSON_AddNumberToObject(o, "kc_score",         r[i].ev.score);
        cJSON_AddStringToObject(o, "mitre",            r[i].ev.mitre);
        cJSON_AddNumberToObject(o, "count",            r[i].count);
        cJSON_AddNumberToObject(o, "signature_id",     (double)r[i].ev.signature_id);
        cJSON_AddItemToArray(arr, o);
    }
    char *s = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return s;
}

/* Publica os pendentes em lotes. Retorna -1 na primeira falha: os registros
 * não publicados continuam pendentes e a próxima rodada tenta de novo. */
static int publish_pending(eve_agg_t *a, int dry_run) {
    while (eve_agg_pending(a) > 0) {
        int n = eve_agg_pending(a);
        if (n > BATCH_MAX) n = BATCH_MAX;
        char *json = build_json(eve_agg_peek(a, 0), n);
        if (!json) return -1;

        int rc = 0;
        if (dry_run) {
            printf("%s\n", json);
            fflush(stdout);
        } else {
            rc = publisher_send_json(json);
        }
        free(json);
        if (rc != 0) return -1;
        eve_agg_consume(a, n);
    }
    return 0;
}

/* ------------------------------------------------------------------------- *
 * Contadores                                                                *
 * ------------------------------------------------------------------------- */
static void print_stats(const char *tag, const eve_agg_t *a, const run_ctx_t *c,
                        const eve_linebuf_t *lb, const eve_file_t *f) {
    const eve_counters_t *k = &a->c;
    fprintf(stderr,
        "[EVE] %s lidas=%llu alertas=%llu outros=%llu invalidas=%llu "
        "grandes=%llu parciais=%llu rotacoes=%llu truncamentos=%llu | "
        "publicados=%llu registros=%llu | descartados: tabela=%llu taxa=%llu "
        "fila=%llu broker=%llu | pendentes=%d abertos=%d\n",
        tag,
        (unsigned long long)c->lines, (unsigned long long)k->alerts,
        (unsigned long long)c->other, (unsigned long long)c->invalid,
        (unsigned long long)lb->oversized, (unsigned long long)lb->discarded,
        (unsigned long long)f->rotations, (unsigned long long)f->truncations,
        (unsigned long long)k->published, (unsigned long long)k->records,
        (unsigned long long)k->dropped_table, (unsigned long long)k->dropped_rate,
        (unsigned long long)k->dropped_pending, (unsigned long long)k->dropped_broker,
        eve_agg_pending(a), a->n_slots);
    fflush(stderr);
}

int main(int argc, char **argv) {
    const char *config = NULL;
    int once = 0, dry_run = 0, from_start = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) config = argv[++i];
        else if (strcmp(argv[i], "--once") == 0) once = 1;
        else if (strcmp(argv[i], "--dry-run") == 0) dry_run = 1;
        else if (strcmp(argv[i], "--from-start") == 0) from_start = 1;
        else { usage(argv[0]); return 2; }
    }

    if (config && config_load_file(config) < 0) {
        fprintf(stderr, "[EVE] config nao abre: %s\n", config);
        return 2;
    }

    const char *eve_path = getenv("BRIDGE_EVE_PATH");
    const char *map_path = getenv("BRIDGE_MAPPING_FILE");
    if (!eve_path || !*eve_path || !map_path || !*map_path) {
        usage(argv[0]);
        return 2;
    }

    eve_map_t map;
    if (eve_map_load(&map, map_path) != 0) return 2;

    int window_ms = env_int("BRIDGE_AGG_WINDOW_MS", DEFAULT_WINDOW_MS, 0, 3600000);
    int rate      = env_int("BRIDGE_RATE_PER_SEC", DEFAULT_RATE, 0, 1000000);
    int stats_s   = env_int("BRIDGE_STATS_INTERVAL_SEC", DEFAULT_STATS_S, 1, 3600);

    eve_side_t side = EVE_SIDE_SRC;
    const char *sv = getenv("BRIDGE_ATTACKER_SIDE");
    if (sv && *sv) {
        if (strcmp(sv, "src") == 0) side = EVE_SIDE_SRC;
        else if (strcmp(sv, "response") == 0) side = EVE_SIDE_RESPONSE;
        else {
            fprintf(stderr, "[EVE] BRIDGE_ATTACKER_SIDE invalido: '%s' (src|response)\n", sv);
            return 2;
        }
    }

    eve_file_t f;
    if (strlen(eve_path) >= sizeof f.path) {
        fprintf(stderr, "[EVE] caminho do eve.json longo demais\n");
        return 2;
    }

    if (!dry_run) init_queue();   /* mesmas credenciais AMQP do agente */

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int64_t now = mono_ms();
    /* Estáticos: agg e lb somam ~0,5 MB; fora da pilha da main. */
    static eve_agg_t agg;
    eve_agg_init(&agg, window_ms, rate, now);

    run_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.map = &map;
    ctx.side = side;
    ctx.agg = &agg;
    ctx.now_ms = now;

    static eve_linebuf_t lb;
    memset(&lb, 0, sizeof lb);

    /* --once lê desde o início; no modo seguir, o padrão é o fim (tail). */
    if (eve_file_open(&f, eve_path, once || from_start) != 0) {
        if (once) {
            fprintf(stderr, "[EVE] nao abre %s\n", eve_path);
            if (!dry_run) close_queue();
            return 1;
        }
        fprintf(stderr, "[EVE] aguardando %s\n", eve_path);
    }

    if (once) {
        ssize_t n = eve_file_poll(&f, &lb, on_line, &ctx, 0);
        if (n < 0) {
            fprintf(stderr, "[EVE] erro ao ler %s\n", eve_path);
            eve_file_close(&f);
            if (!dry_run) close_queue();
            return 1;
        }
        eve_linebuf_flush(&lb, on_line, &ctx);
        eve_agg_tick(&agg, now, 1);
        if (publish_pending(&agg, dry_run) != 0) eve_agg_abandon_pending(&agg);
        print_stats("fim", &agg, &ctx, &lb, &f);
        eve_file_close(&f);
        if (!dry_run) close_queue();
        return agg.c.dropped_broker > 0 ? 1 : 0;
    }

    int64_t last_stats = now;
    fprintf(stderr, "[EVE] seguindo %s | lado=%s janela=%dms taxa=%d/s\n", eve_path,
            side == EVE_SIDE_RESPONSE ? "response" : "src", window_ms, rate);

    while (!g_stop) {
        now = mono_ms();
        ctx.now_ms = now;
        ssize_t n = eve_file_poll(&f, &lb, on_line, &ctx, 1);
        if (n < 0) fprintf(stderr, "[EVE] erro de leitura em %s; nova tentativa\n", eve_path);

        eve_agg_tick(&agg, now, 0);
        publish_pending(&agg, dry_run);

        if (now - last_stats >= (int64_t)stats_s * 1000) {
            print_stats("status", &agg, &ctx, &lb, &f);
            last_stats = now;
        }
        if (n <= 0) {
            struct timespec ts = { 0, POLL_SLEEP_NS };
            nanosleep(&ts, NULL);
        }
    }

    /* Encerramento: fecha os grupos abertos e tenta publicar o que sobrou. */
    now = mono_ms();
    ctx.now_ms = now;
    eve_agg_tick(&agg, now, 1);
    if (publish_pending(&agg, dry_run) != 0) eve_agg_abandon_pending(&agg);
    print_stats("parada", &agg, &ctx, &lb, &f);
    eve_file_close(&f);
    if (!dry_run) close_queue();
    return agg.c.dropped_broker > 0 ? 1 : 0;
}
