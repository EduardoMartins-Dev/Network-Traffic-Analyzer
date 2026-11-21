/* Harness de fuzzing do nta-eve-bridge (B17): parser EVE, tradução e leitor de
 * linhas. A entrada é o eve.json, que o Suricata escreve e que pode vir de rede
 * (tráfego hostil refletido em campos de alerta). O alvo: leitura fora do buffer,
 * UB e crescimento sem limite.
 *
 * Os dois primeiros bytes escolhem o tamanho dos pedaços alimentados ao leitor de
 * linhas (eve_linebuf_feed), para exercitar a montagem de linhas em fronteiras
 * arbitrárias. O restante é tratado como uma linha do eve.json.
 *
 * Usa uma tabela de mapeamento embutida só aqui (o fuzz não lê arquivo). */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "eve_map.h"
#include "eve_parse.h"
#include "eve_tail.h"

static const char MAP_JSON[] =
    "{\"severity_score\":{\"1\":85,\"2\":55,\"3\":30},"
    "\"default\":{\"stage\":\"RECON\",\"max_score\":40},"
    "\"categories\":[{\"category\":\"Web Application Attack\",\"stage\":\"EXPLOIT\",\"mitre\":\"T1190\"}]}";

static eve_map_t g_map;
static int g_map_ready = 0;

static void count_line(const char *line, size_t len, void *ctx) {
    (void)line;
    (void)len;
    (void)ctx;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_map_ready) {
        eve_map_parse(&g_map, MAP_JSON, strlen(MAP_JSON));
        g_map_ready = 1;
    }
    if (size == 0) return 0;

    /* 1. Leitor de linhas, com pedaços de tamanho variável. */
    size_t chunk = (size_t)(data[0] % 17) + 1;
    eve_linebuf_t lb;
    memset(&lb, 0, sizeof lb);
    for (size_t off = 1; off < size; off += chunk) {
        size_t n = size - off < chunk ? size - off : chunk;
        eve_linebuf_feed(&lb, (const char *)data + off, n, count_line, NULL);
    }
    eve_linebuf_flush(&lb, count_line, NULL);

    /* 2. Parser e tradução sobre a entrada inteira, como uma linha. */
    if (size >= EVE_MAX_LINE) return 0;
    eve_alert_t a;
    if (eve_parse_line((const char *)data, size, g_map.mitre_key, &a) == EVE_ALERT) {
        eve_event_t e;
        eve_map_alert(&g_map, &a, EVE_SIDE_RESPONSE, &e);
        char attack[EVE_ATTACK_MAX];
        eve_attack_type(a.category, attack, sizeof attack);
    }
    return 0;
}
