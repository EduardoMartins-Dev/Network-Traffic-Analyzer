#include "eve_parse.h"
#include "cJSON.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>

/* signature_id e severity cabem em int do Suricata; limite conservador. */
#define MAX_ID_VALUE 2147483647.0

/* Copia com terminador garantido (trunca). */
static void copy_trunc(char *dst, size_t dstsz, const char *src) {
    if (dstsz == 0) return;
    strncpy(dst, src, dstsz - 1);
    dst[dstsz - 1] = '\0';
}

static int valid_ip(const char *s) {
    unsigned char buf[16];
    return strlen(s) < 46 &&
           (inet_pton(AF_INET, s, buf) == 1 || inet_pton(AF_INET6, s, buf) == 1);
}

static int get_str(const cJSON *o, const char *key, const char **out) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    if (!cJSON_IsString(v) || !v->valuestring) return 0;
    *out = v->valuestring;
    return 1;
}

/* Inteiro não negativo dentro de [0, max]. Qualquer outra coisa: 0. */
static int get_int_in(const cJSON *v, double max, long *out) {
    if (!cJSON_IsNumber(v)) return 0;
    double d = v->valuedouble;
    if (d < 0.0 || d > max || d != (double)(long)d) return 0;
    *out = (long)d;
    return 1;
}

/* Porta: 0..65535, ausente/inválida: -1. */
static int get_port(const cJSON *o, const char *key) {
    long p = -1;
    if (!get_int_in(cJSON_GetObjectItemCaseSensitive(o, key), 65535.0, &p)) return -1;
    return (int)p;
}

int eve_is_mitre_token(const char *s) {
    size_t i = 0;
    if (s[i++] != 'T') return 0;
    int d = 0;
    while (isdigit((unsigned char)s[i])) { i++; d++; }
    if (d != 4) return 0;
    if (s[i] == '.') {
        i++;
        d = 0;
        while (isdigit((unsigned char)s[i])) { i++; d++; }
        if (d != 3) return 0;
    }
    return s[i] == '\0';
}

/* Acrescenta um token válido em lista separada por vírgula, sem estourar. */
static void add_mitre(char *out, size_t sz, const char *tok) {
    if (!eve_is_mitre_token(tok)) return;
    size_t n = strlen(out), t = strlen(tok);
    size_t need = (n ? 1 : 0) + t;
    if (n + need >= sz) return;
    if (n) out[n++] = ',';
    memcpy(out + n, tok, t + 1);
}

static void extract_mitre(const cJSON *alert, const char *key,
                          char *out, size_t sz) {
    out[0] = '\0';
    const cJSON *meta = cJSON_GetObjectItemCaseSensitive(alert, "metadata");
    if (!cJSON_IsObject(meta)) return;
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(meta, key);
    if (cJSON_IsString(v) && v->valuestring) {
        add_mitre(out, sz, v->valuestring);
    } else if (cJSON_IsArray(v)) {
        const cJSON *it = NULL;
        cJSON_ArrayForEach(it, v) {
            if (cJSON_IsString(it) && it->valuestring) add_mitre(out, sz, it->valuestring);
        }
    }
}

static eve_kind_t fill_alert(const cJSON *root, const char *mitre_key,
                             eve_alert_t *out) {
    const cJSON *alert = cJSON_GetObjectItemCaseSensitive(root, "alert");
    if (!cJSON_IsObject(alert)) return EVE_INVALID;

    const char *s = NULL;
    if (!get_str(root, "src_ip", &s) || !valid_ip(s)) return EVE_INVALID;
    copy_trunc(out->src_ip, sizeof out->src_ip, s);

    long sid = 0;
    if (!get_int_in(cJSON_GetObjectItemCaseSensitive(alert, "signature_id"),
                    MAX_ID_VALUE, &sid)) return EVE_INVALID;
    out->signature_id = sid;

    /* Campos opcionais: ausentes ou inválidos viram vazio / -1, sem rejeitar. */
    out->dst_ip[0] = '\0';
    if (get_str(root, "dest_ip", &s) && valid_ip(s))
        copy_trunc(out->dst_ip, sizeof out->dst_ip, s);
    out->src_port = get_port(root, "src_port");
    out->dst_port = get_port(root, "dest_port");

    out->proto[0] = '\0';
    if (get_str(root, "proto", &s)) copy_trunc(out->proto, sizeof out->proto, s);
    out->direction[0] = '\0';
    if (get_str(root, "direction", &s))
        copy_trunc(out->direction, sizeof out->direction, s);

    out->category[0] = '\0';
    if (get_str(alert, "category", &s)) copy_trunc(out->category, sizeof out->category, s);

    long sev = -1;
    out->severity = get_int_in(cJSON_GetObjectItemCaseSensitive(alert, "severity"),
                               1000.0, &sev) ? (int)sev : -1;

    extract_mitre(alert, mitre_key, out->mitre, sizeof out->mitre);
    return EVE_ALERT;
}

eve_kind_t eve_parse_line(const char *line, size_t len, const char *mitre_key,
                          eve_alert_t *out) {
    if (!line || !mitre_key || !out || len == 0 || len >= EVE_MAX_LINE)
        return EVE_INVALID;

    memset(out, 0, sizeof *out);
    out->src_port = -1;
    out->dst_port = -1;
    out->signature_id = -1;
    out->severity = -1;

    cJSON *root = cJSON_ParseWithLength(line, len);
    if (!root) return EVE_INVALID;

    eve_kind_t kind = EVE_INVALID;
    if (cJSON_IsObject(root)) {
        const char *et = NULL;
        if (get_str(root, "event_type", &et)) {
            kind = (strcmp(et, "alert") == 0) ? fill_alert(root, mitre_key, out)
                                              : EVE_OTHER;
        }
    }
    cJSON_Delete(root);
    return kind;
}
