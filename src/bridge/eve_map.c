#include "eve_map.h"
#include "cJSON.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAP_FILE_MAX (256 * 1024)  /* tabela de mapeamento: limite de tamanho */
#define NORMALIZE_SCAN_MAX 256     /* categoria: só os primeiros bytes contam */

/* ------------------------------------------------------------------------- *
 * Helpers                                                                   *
 * ------------------------------------------------------------------------- */
static void copy_trunc(char *dst, size_t dstsz, const char *src) {
    if (dstsz == 0) return;
    strncpy(dst, src, dstsz - 1);
    dst[dstsz - 1] = '\0';
}

/* Comparação ASCII sem diferenciar maiúsculas (categorias do Suricata). */
static int eq_ci(const char *a, const char *b) {
    for (; *a && *b; a++, b++) {
        if (toupper((unsigned char)*a) != toupper((unsigned char)*b)) return 0;
    }
    return *a == *b;
}

static int valid_stage(const char *s) {
    return strcmp(s, "RECON") == 0 || strcmp(s, "EXPLOIT") == 0 ||
           strcmp(s, "EXFIL") == 0;
}

static int get_str(const cJSON *o, const char *key, const char **out) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    if (!cJSON_IsString(v) || !v->valuestring) return 0;
    *out = v->valuestring;
    return 1;
}

static int get_score(const cJSON *o, const char *key, int *out) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    if (!cJSON_IsNumber(v)) return 0;
    double d = v->valuedouble;
    if (d < 0.0 || d > 100.0 || d != (double)(int)d) return 0;
    *out = (int)d;
    return 1;
}

static int fail_map(cJSON *root, const char *msg) {
    fprintf(stderr, "[EVE] mapeamento invalido: %s\n", msg);
    cJSON_Delete(root);
    return -1;
}

/* ------------------------------------------------------------------------- *
 * Carregamento                                                              *
 * ------------------------------------------------------------------------- */
int eve_map_parse(eve_map_t *m, const char *json, size_t len) {
    memset(m, 0, sizeof *m);

    cJSON *root = cJSON_ParseWithLength(json, len);
    if (!cJSON_IsObject(root)) return fail_map(root, "JSON invalido ou nao e objeto");

    /* severity_score: {"1": score, "2": score, "3": score} */
    const cJSON *ss = cJSON_GetObjectItemCaseSensitive(root, "severity_score");
    if (!cJSON_IsObject(ss)) return fail_map(root, "falta severity_score");
    for (int s = 1; s <= 3; s++) {
        char key[2] = { (char)('0' + s), '\0' };
        if (!get_score(ss, key, &m->sev_score[s - 1]))
            return fail_map(root, "severity_score precisa de 1, 2 e 3 com valor 0..100");
    }

    /* default: categoria fora da tabela */
    const cJSON *def = cJSON_GetObjectItemCaseSensitive(root, "default");
    const char *st = NULL;
    if (!cJSON_IsObject(def) || !get_str(def, "stage", &st) || !valid_stage(st))
        return fail_map(root, "default.stage precisa ser RECON, EXPLOIT ou EXFIL");
    copy_trunc(m->def_stage, sizeof m->def_stage, st);
    m->def_max = 100;
    if (cJSON_GetObjectItemCaseSensitive(def, "max_score") &&
        !get_score(def, "max_score", &m->def_max))
        return fail_map(root, "default.max_score precisa ser 0..100");

    /* chave de alert.metadata com a técnica ATT&CK (padrão: convenção ET) */
    const char *mk = NULL;
    if (get_str(root, "mitre_metadata_key", &mk)) {
        if (mk[0] == '\0') return fail_map(root, "mitre_metadata_key vazia");
        copy_trunc(m->mitre_key, sizeof m->mitre_key, mk);
    } else {
        copy_trunc(m->mitre_key, sizeof m->mitre_key, "mitre_technique_id");
    }

    /* categories: lista de regras */
    const cJSON *cats = cJSON_GetObjectItemCaseSensitive(root, "categories");
    if (!cJSON_IsArray(cats)) return fail_map(root, "falta a lista categories");
    const cJSON *it = NULL;
    cJSON_ArrayForEach(it, cats) {
        if (m->n_rules >= EVE_MAP_MAX_RULES) return fail_map(root, "categorias demais");
        if (!cJSON_IsObject(it)) return fail_map(root, "item de categories nao e objeto");

        eve_rule_t *r = &m->rules[m->n_rules];
        const char *name = NULL;
        if (!get_str(it, "category", &name) || name[0] == '\0' || strlen(name) >= sizeof r->category)
            return fail_map(root, "categoria sem nome ou nome longo demais");
        copy_trunc(r->category, sizeof r->category, name);

        const char *rs = NULL;
        if (!get_str(it, "stage", &rs) || !valid_stage(rs))
            return fail_map(root, "stage da categoria precisa ser RECON, EXPLOIT ou EXFIL");
        copy_trunc(r->stage, sizeof r->stage, rs);

        r->max_score = 100;   /* sem teto, salvo max_score explícito */
        if (cJSON_GetObjectItemCaseSensitive(it, "max_score") &&
            !get_score(it, "max_score", &r->max_score))
            return fail_map(root, "max_score da categoria precisa ser 0..100");

        const char *tech = NULL;
        if (cJSON_GetObjectItemCaseSensitive(it, "mitre")) {
            if (!get_str(it, "mitre", &tech) || !eve_is_mitre_token(tech))
                return fail_map(root, "mitre da categoria precisa ser TNNNN ou TNNNN.NNN");
            copy_trunc(r->mitre, sizeof r->mitre, tech);
        }

        for (int j = 0; j < m->n_rules; j++) {
            if (eq_ci(m->rules[j].category, r->category))
                return fail_map(root, "categoria duplicada");
        }
        m->n_rules++;
    }

    cJSON_Delete(root);
    return 0;
}

int eve_map_load(eve_map_t *m, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[EVE] mapeamento nao abre: %s\n", path);
        return -1;
    }
    char *buf = malloc(MAP_FILE_MAX + 1);
    if (!buf) { fclose(f); return -1; }
    size_t n = fread(buf, 1, MAP_FILE_MAX + 1, f);
    int too_big = (n > MAP_FILE_MAX);
    fclose(f);
    if (too_big) {
        fprintf(stderr, "[EVE] mapeamento maior que %d bytes: %s\n", MAP_FILE_MAX, path);
        free(buf);
        return -1;
    }
    int rc = eve_map_parse(m, buf, n);
    free(buf);
    return rc;
}

/* ------------------------------------------------------------------------- *
 * Tradução                                                                  *
 * ------------------------------------------------------------------------- */
void eve_attack_type(const char *category, char *out, size_t outsz) {
    char body[EVE_ATTACK_BODY_MAX + 1];
    size_t n = 0;
    int last_us = 1;  /* 1 evita '_' inicial */

    for (size_t i = 0; category[i] && i < NORMALIZE_SCAN_MAX && n < EVE_ATTACK_BODY_MAX; i++) {
        unsigned char c = (unsigned char)category[i];
        if (c >= 'a' && c <= 'z') c = (unsigned char)(c - 'a' + 'A');
        if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
            body[n++] = (char)c;
            last_us = 0;
        } else if (!last_us) {
            body[n++] = '_';
            last_us = 1;
        }
    }
    if (n > 0 && body[n - 1] == '_') n--;
    body[n] = '\0';

    if (n == 0) copy_trunc(out, outsz, "SURICATA_UNKNOWN");
    else snprintf(out, outsz, "SURICATA_%s", body);
}

void eve_map_alert(const eve_map_t *m, const eve_alert_t *a, eve_side_t side,
                   eve_event_t *out) {
    memset(out, 0, sizeof *out);

    /* Atacante: src_ip por padrão. Em RESPONSE, um to_client troca para dest_ip
     * e a porta passa a ser a do lado não atacante (src_port). */
    if (side == EVE_SIDE_RESPONSE && strcmp(a->direction, "to_client") == 0 &&
        a->dst_ip[0] != '\0') {
        copy_trunc(out->src_ip, sizeof out->src_ip, a->dst_ip);
        out->port = a->src_port;
    } else {
        copy_trunc(out->src_ip, sizeof out->src_ip, a->src_ip);
        out->port = a->dst_port;
    }
    if (out->port < 0) out->port = 0;

    /* Proto: só [A-Z0-9], até 7 caracteres (sai no JSON; o texto do EVE não é confiável). */
    if (a->proto[0] != '\0') {
        size_t n = 0;
        for (size_t i = 0; a->proto[i] && n < sizeof out->proto - 1; i++) {
            unsigned char c = (unsigned char)a->proto[i];
            if (isalnum(c)) out->proto[n++] = (char)toupper(c);
        }
        out->proto[n] = '\0';
    }
    if (out->proto[0] == '\0') {
        copy_trunc(out->proto, sizeof out->proto, "UNKNOWN");
    }

    eve_attack_type(a->category, out->attack_type, sizeof out->attack_type);

    /* Regra da categoria (se houver); senão, padrão conservador. */
    const eve_rule_t *rule = NULL;
    if (a->category[0] != '\0') {
        for (int i = 0; i < m->n_rules; i++) {
            if (eq_ci(m->rules[i].category, a->category)) { rule = &m->rules[i]; break; }
        }
    }

    copy_trunc(out->stage, sizeof out->stage, rule ? rule->stage : m->def_stage);
    int cap = rule ? rule->max_score : m->def_max;

    /* Severidade EVE 1..3 indexa a tabela; qualquer outro valor vira a menor. */
    int idx = (a->severity >= 1 && a->severity <= 3) ? a->severity - 1 : 2;
    int score = m->sev_score[idx];
    out->score = score > cap ? cap : score;

    /* MITRE: metadata do alerta tem prioridade; senão, a tabela. */
    copy_trunc(out->mitre, sizeof out->mitre,
               a->mitre[0] != '\0' ? a->mitre : (rule ? rule->mitre : ""));

    out->signature_id = a->signature_id;
}
