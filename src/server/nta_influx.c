/* ========================================================================= *
 *  nta_influx.c — writer InfluxDB v2 via libcurl (line protocol).           *
 *                                                                           *
 *  Schema do measurement "traffic", escrito por nta_influx_write_traffic:   *
 *    tags   (sempre): agent_id, src_ip, protocol                            *
 *    tags   (opt)   : attack_type, kill_chain_stage, mitre, ioc_hit,        *
 *                     ioc_source, asn, asn_org                              *
 *    fields (sempre): port (int), bytes (float), is_scan (float)            *
 *    fields (opt)   : kc_score, abuse_score, lat, lon (float)               *
 *                                                                           *
 *  Escape helpers internos — não puxamos lib externa. Tag keys/values e    *
 *  field keys precisam escapar vírgula, espaço e '='. String fields (não  *
 *  usado aqui) precisariam de aspas + escape de '\\' e '"'.                 *
 * ========================================================================= */

#include "nta_influx.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define LP_BUF_SIZE   16384   /* comporta ~50 events por batch v5.0 */
#define LP_FLOAT_BUF     32   /* cabe o maior "%.17g" (24 chars) */
#define MAX_TAG_LEN     128
#define MAX_URL_LEN     512

/* -------------------------------------------------------------------------- *
 * Global init (libcurl)                                                      *
 * -------------------------------------------------------------------------- */
static int g_curl_inited = 0;

int nta_influx_global_init(void) {
    if (g_curl_inited) return 0;
    CURLcode r = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (r != CURLE_OK) {
        fprintf(stderr, "[INFLUX] curl_global_init falhou: %s\n",
                curl_easy_strerror(r));
        return -1;
    }
    g_curl_inited = 1;
    return 0;
}

void nta_influx_global_cleanup(void) {
    if (g_curl_inited) {
        curl_global_cleanup();
        g_curl_inited = 0;
    }
}

/* -------------------------------------------------------------------------- *
 * Line protocol escape                                                       *
 * Escapa ',' '=' e ' ' em tag keys/values e field keys. Escreve até `cap-1` *
 * bytes em `out` e null-termina. Retorna nº de bytes escritos (sem o \0).   *
 * -------------------------------------------------------------------------- */
static size_t lp_escape(char *out, size_t cap, const char *in) {
    if (!out || cap == 0) return 0;
    if (!in) { out[0] = '\0'; return 0; }

    size_t w = 0;
    for (const char *p = in; *p && w + 2 < cap; p++) {
        if (*p == ',' || *p == '=' || *p == ' ') {
            out[w++] = '\\';
            if (w + 1 >= cap) break;
        }
        out[w++] = *p;
    }
    out[w] = '\0';
    return w;
}

/* -------------------------------------------------------------------------- *
 * cJSON helpers                                                              *
 * -------------------------------------------------------------------------- */
/* Formata um double para line protocol sem perder precisão. Tenta "%.15g"
 * (forma curta: 0.1 sai "0.1") e usa "%.17g" só quando a forma curta não volta
 * ao mesmo double (12345678.5 sai inteiro, não "1.23457e+07"). nan/inf saem
 * como antes ("nan"/"inf"): o código nunca tratou esses casos. */
static void fmt_lp_float(char *out, size_t cap, double v) {
    int n = snprintf(out, cap, "%.15g", v);
    if (n < 0 || (size_t)n >= cap || strtod(out, NULL) != v)
        snprintf(out, cap, "%.17g", v);
}

static const char *json_get_str(const cJSON *obj, const char *key,
                                const char *fallback) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    return (cJSON_IsString(v) && v->valuestring) ? v->valuestring : fallback;
}

static bool json_get_num(const cJSON *obj, const char *key, double *out) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsNumber(v)) return false;
    *out = v->valuedouble;
    return true;
}

/* -------------------------------------------------------------------------- *
 * Monta uma linha de line protocol para um único evento.                     *
 * Retorna bytes escritos em `out` (sem \0), ou 0 em erro.                    *
 * -------------------------------------------------------------------------- */
static int build_traffic_point(char *out, size_t cap,
                               const cJSON *evt, const char *agent_id,
                               NtaGeo *geo, NtaIoc *ioc, NtaAbuse *abuse) {
    if (cap < 64) return 0;

    char esc_agent[MAX_TAG_LEN];
    char esc_ip[MAX_TAG_LEN];
    char esc_proto[MAX_TAG_LEN];
    char esc_attack[MAX_TAG_LEN];
    char esc_stage[MAX_TAG_LEN];
    char esc_mitre[MAX_TAG_LEN];
    char esc_asn[MAX_TAG_LEN];
    char esc_asn_org[MAX_TAG_LEN];
    char esc_ioc_src[MAX_TAG_LEN];

    const char *src_ip = json_get_str(evt, "src_ip", "0.0.0.0");

    lp_escape(esc_agent, sizeof(esc_agent), agent_id ? agent_id : "unknown");
    lp_escape(esc_ip,    sizeof(esc_ip),    src_ip);
    lp_escape(esc_proto, sizeof(esc_proto), json_get_str(evt, "proto",  "UNKNOWN"));

    const char *attack = json_get_str(evt, "attack_type",      NULL);
    const char *stage  = json_get_str(evt, "kill_chain_stage", NULL);
    const char *mitre  = json_get_str(evt, "mitre",            NULL);

    /* GeoIP lookup único: cobre city (lat/lon → fields) + ASN (asn/asn_org →
     * tags). 1 hit no cache serve os dois. Skip se geo é NULL ou IP privado. */
    NtaGeoResult gr = {0};
    if (geo) nta_geo_lookup(geo, src_ip, &gr);

    /* Fields */
    double port_d = 0, bytes_d = 0, is_scan_d = 0;
    json_get_num(evt, "port",    &port_d);
    json_get_num(evt, "bytes",   &bytes_d);
    json_get_num(evt, "is_scan", &is_scan_d);

    double kc_score = 0;
    bool has_kc = json_get_num(evt, "kc_score", &kc_score);

    char f_bytes[LP_FLOAT_BUF], f_scan[LP_FLOAT_BUF], f_kc[LP_FLOAT_BUF];

    /* Nota: `port` vai como inteiro (sufixo 'i') pra bater com o client Python
     * que usa Point.field("port", int(...)). bytes/is_scan vão como float. */
    int n = snprintf(out, cap,
        "traffic,agent_id=%s,src_ip=%s,protocol=%s",
        esc_agent, esc_ip, esc_proto);
    if (n <= 0 || (size_t)n >= cap) return 0;
    size_t w = (size_t)n;

    if (attack && *attack) {
        lp_escape(esc_attack, sizeof(esc_attack), attack);
        n = snprintf(out + w, cap - w, ",attack_type=%s", esc_attack);
        if (n <= 0 || (size_t)n >= cap - w) return 0;
        w += n;
    }
    if (stage && *stage) {
        lp_escape(esc_stage, sizeof(esc_stage), stage);
        n = snprintf(out + w, cap - w, ",kill_chain_stage=%s", esc_stage);
        if (n <= 0 || (size_t)n >= cap - w) return 0;
        w += n;
    }
    if (mitre && *mitre) {
        lp_escape(esc_mitre, sizeof(esc_mitre), mitre);
        n = snprintf(out + w, cap - w, ",mitre=%s", esc_mitre);
        if (n <= 0 || (size_t)n >= cap - w) return 0;
        w += n;
    }

    /* IoC match — v8.0 M3. Tag ioc_hit (cardinality=1) + ioc_source (lista que
     * cassou). Lookup O(1). Skip se ioc é NULL. */
    if (ioc) {
        const char *src = nta_ioc_match_ip(ioc, src_ip);
        if (src) {
            lp_escape(esc_ioc_src, sizeof(esc_ioc_src), src);
            n = snprintf(out + w, cap - w, ",ioc_hit=1,ioc_source=%s",
                         esc_ioc_src);
            if (n <= 0 || (size_t)n >= cap - w) return 0;
            w += n;
        }
    }

    /* ASN tags — v8.0 M1. Cardinalidade baixa (~100s típico). asn como string
     * "AS<num>" pra evitar query Flux com cast de número→string em filtros. */
    if (gr.has_asn) {
        char asn_str[16];
        snprintf(asn_str, sizeof(asn_str), "AS%u", gr.asn_number);
        lp_escape(esc_asn, sizeof(esc_asn), asn_str);
        n = snprintf(out + w, cap - w, ",asn=%s", esc_asn);
        if (n <= 0 || (size_t)n >= cap - w) return 0;
        w += n;

        if (gr.asn_org[0]) {
            lp_escape(esc_asn_org, sizeof(esc_asn_org), gr.asn_org);
            n = snprintf(out + w, cap - w, ",asn_org=%s", esc_asn_org);
            if (n <= 0 || (size_t)n >= cap - w) return 0;
            w += n;
        }
    }

    fmt_lp_float(f_bytes, sizeof(f_bytes), bytes_d);
    fmt_lp_float(f_scan, sizeof(f_scan), is_scan_d);
    n = snprintf(out + w, cap - w,
        " port=%lldi,bytes=%s,is_scan=%s",
        (long long)port_d, f_bytes, f_scan);
    if (n <= 0 || (size_t)n >= cap - w) return 0;
    w += n;

    if (has_kc) {
        fmt_lp_float(f_kc, sizeof(f_kc), kc_score);
        n = snprintf(out + w, cap - w, ",kc_score=%s", f_kc);
        if (n <= 0 || (size_t)n >= cap - w) return 0;
        w += n;
    }

    /* lat/lon como fields (não tags). Reusa o lookup já feito acima (gr). */
    if (gr.has_geo) {
        n = snprintf(out + w, cap - w, ",lat=%.6f,lon=%.6f", gr.lat, gr.lon);
        if (n <= 0 || (size_t)n >= cap - w) return 0;
        w += n;
    }

    /* abuse_score — v8.0 M4. Field numérico (0-100). Skip se -1 (key ausente,
     * IP privado, ou API fail). Lookup sob mutex interno — cache hits são
     * instantâneos; cache miss bloqueia até HTTP (5s timeout). */
    if (abuse) {
        int abuse_s = nta_abuse_score(abuse, src_ip);
        if (abuse_s >= 0) {
            n = snprintf(out + w, cap - w, ",abuse_score=%d", abuse_s);
            if (n <= 0 || (size_t)n >= cap - w) return 0;
            w += n;
        }
    }

    n = snprintf(out + w, cap - w, "\n");
    if (n <= 0 || (size_t)n >= cap - w) return 0;
    w += n;

    return (int)w;
}

/* -------------------------------------------------------------------------- *
 * Open                                                                       *
 * -------------------------------------------------------------------------- */
int nta_influx_open(NtaInflux *inf, const NtaConfig *cfg) {
    /* IMPORTANTE: caller deve ter chamado nta_influx_global_init() ANTES.
     * libcurl exige curl_global_init em ambiente single-thread, antes de
     * qualquer easy_init em outras threads. */
    memset(inf, 0, sizeof(*inf));

    int n = snprintf(inf->endpoint, sizeof(inf->endpoint),
        "%s/api/v2/write?org=%s&bucket=%s&precision=ns",
        cfg->influx_url, cfg->influx_org, cfg->influx_bucket);
    if (n <= 0 || (size_t)n >= sizeof(inf->endpoint)) {
        fprintf(stderr, "[INFLUX] URL excede buffer\n");
        return -1;
    }

    inf->curl = curl_easy_init();
    if (!inf->curl) {
        fprintf(stderr, "[INFLUX] curl_easy_init falhou\n");
        return -1;
    }

    char auth_hdr[256];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Token %s",
             cfg->influx_token);

    inf->headers = curl_slist_append(NULL, "Content-Type: text/plain; charset=utf-8");
    inf->headers = curl_slist_append(inf->headers, auth_hdr);
    inf->headers = curl_slist_append(inf->headers, "Accept: application/json");

    curl_easy_setopt(inf->curl, CURLOPT_URL,         inf->endpoint);
    curl_easy_setopt(inf->curl, CURLOPT_POST,        1L);
    curl_easy_setopt(inf->curl, CURLOPT_HTTPHEADER,  inf->headers);
    curl_easy_setopt(inf->curl, CURLOPT_TIMEOUT,     10L);
    curl_easy_setopt(inf->curl, CURLOPT_CONNECTTIMEOUT, 5L);
    /* Descartamos corpo da resposta (só HTTP code importa). */
    curl_easy_setopt(inf->curl, CURLOPT_NOBODY,      0L);
    curl_easy_setopt(inf->curl, CURLOPT_WRITEFUNCTION, NULL);

    inf->ready = 1;
    return 0;
}

/* -------------------------------------------------------------------------- *
 * Write                                                                      *
 * -------------------------------------------------------------------------- */
static size_t null_write_cb(char *p, size_t sz, size_t n, void *u) {
    (void)p; (void)u; return sz * n;
}

static int influx_post(NtaInflux *inf, const char *body, size_t len) {
    curl_easy_setopt(inf->curl, CURLOPT_POSTFIELDS,    body);
    curl_easy_setopt(inf->curl, CURLOPT_POSTFIELDSIZE, (long)len);
    curl_easy_setopt(inf->curl, CURLOPT_WRITEFUNCTION, null_write_cb);

    CURLcode rc = curl_easy_perform(inf->curl);
    if (rc != CURLE_OK) {
        fprintf(stderr, "[INFLUX] POST falhou: %s\n", curl_easy_strerror(rc));
        return -1;
    }

    long http_code = 0;
    curl_easy_getinfo(inf->curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code < 200 || http_code >= 300) {
        fprintf(stderr, "[INFLUX] HTTP %ld (payload %zuB)\n", http_code, len);
        return -1;
    }
    return 0;
}

int nta_influx_write_traffic(NtaInflux *inf, NtaGeo *geo, NtaIoc *ioc,
                             NtaAbuse *abuse,
                             const char *body, size_t len,
                             const char *agent_id) {
    if (!inf->ready || !body || len == 0) return -1;

    cJSON *root = cJSON_ParseWithLength(body, len);
    if (!root) {
        fprintf(stderr, "[INFLUX] JSON inválido (%zuB)\n", len);
        return -1;
    }

    char lp[LP_BUF_SIZE];
    size_t lp_len = 0;
    int n_events = 0;

    /* Payload aceita array (batch v5.0) ou objeto único (compat v4). */
    if (cJSON_IsArray(root)) {
        const cJSON *item = NULL;
        cJSON_ArrayForEach(item, root) {
            if (!cJSON_IsObject(item)) continue;
            int w = build_traffic_point(lp + lp_len, sizeof(lp) - lp_len,
                                         item, agent_id, geo, ioc, abuse);
            if (w > 0) { lp_len += w; n_events++; }
        }
    } else if (cJSON_IsObject(root)) {
        int w = build_traffic_point(lp, sizeof(lp), root, agent_id, geo, ioc,
                                     abuse);
        if (w > 0) { lp_len = w; n_events = 1; }
    }

    cJSON_Delete(root);

    if (lp_len == 0) return 0;  /* nada a escrever — não é erro */

    /* Escape hatch de debug: NTA_DEBUG_LP=1 dumpa o line protocol no stderr. */
    if (getenv("NTA_DEBUG_LP")) {
        fprintf(stderr, "[INFLUX DEBUG LP >>>]\n%.*s[<<< DEBUG LP]\n",
                (int)lp_len, lp);
    }

    int rc = influx_post(inf, lp, lp_len);
    if (rc == 0) {
        fprintf(stderr, "[INFLUX] traffic: %d evt(s) / %zuB OK\n",
                n_events, lp_len);
    }
    return rc;
}

/* -------------------------------------------------------------------------- *
 * Write metrics — measurement "pipeline_metrics".                           *
 * Schema:                                                                   *
 *   tags  : agent_id                                                         *
 *   fields: cada chave numérica do JSON (rb_pkt_depth, eps, etc) como float *
 * -------------------------------------------------------------------------- */
int nta_influx_write_metrics(NtaInflux *inf, const char *body, size_t len,
                             const char *agent_id) {
    if (!inf->ready || !body || len == 0) return -1;

    cJSON *root = cJSON_ParseWithLength(body, len);
    if (!cJSON_IsObject(root)) {
        if (root) cJSON_Delete(root);
        fprintf(stderr, "[METRICS] payload não é objeto JSON\n");
        return -1;
    }

    char esc_agent[MAX_TAG_LEN];
    lp_escape(esc_agent, sizeof(esc_agent), agent_id ? agent_id : "unknown");

    char lp[LP_BUF_SIZE];
    int n = snprintf(lp, sizeof(lp), "pipeline_metrics,agent_id=%s ", esc_agent);
    if (n <= 0 || (size_t)n >= sizeof(lp)) {
        cJSON_Delete(root);
        return -1;
    }
    size_t w = (size_t)n;

    int field_count = 0;
    char esc_key[MAX_TAG_LEN];
    char f_val[LP_FLOAT_BUF];
    cJSON *iter = NULL;
    cJSON_ArrayForEach(iter, root) {
        if (!cJSON_IsNumber(iter) || !iter->string) continue;
        lp_escape(esc_key, sizeof(esc_key), iter->string);
        fmt_lp_float(f_val, sizeof(f_val), iter->valuedouble);
        n = snprintf(lp + w, sizeof(lp) - w, "%s%s=%s",
                     field_count == 0 ? "" : ",", esc_key, f_val);
        if (n <= 0 || (size_t)n >= sizeof(lp) - w) break;
        w += (size_t)n;
        field_count++;
    }
    cJSON_Delete(root);

    if (field_count == 0) return 0;  /* nada numérico — não é erro */

    n = snprintf(lp + w, sizeof(lp) - w, "\n");
    if (n <= 0 || (size_t)n >= sizeof(lp) - w) return -1;
    w += (size_t)n;

    int rc = influx_post(inf, lp, w);
    if (rc == 0) {
        fprintf(stderr, "[INFLUX] metrics: %d field(s) / %zuB OK\n",
                field_count, w);
    }
    return rc;
}

/* -------------------------------------------------------------------------- *
 * Write narrative — measurement "incident_narrative".                        *
 * Schema espelha narrator.py._on_message:                                    *
 *   tags  : agent_id, src_ip, attack_type, kill_chain_stage, backend         *
 *   fields: narrative (string), kc_score (float)                             *
 * String fields no line protocol vão entre aspas com escape de '\\' e '"'.   *
 * -------------------------------------------------------------------------- */
static size_t lp_escape_str_field(char *out, size_t cap, const char *in) {
    if (!out || cap == 0) return 0;
    if (!in) { out[0] = '\0'; return 0; }
    size_t w = 0;
    for (const char *p = in; *p && w + 2 < cap; p++) {
        if (*p == '\\' || *p == '"') {
            out[w++] = '\\';
            if (w + 1 >= cap) break;
        }
        if (*p == '\n') {
            out[w++] = '\\';
            if (w + 1 >= cap) break;
            out[w++] = 'n';
            continue;
        }
        if (*p == '\r') continue;
        out[w++] = *p;
    }
    out[w] = '\0';
    return w;
}

int nta_influx_write_narrative(NtaInflux *inf,
                               const char *event_json, size_t event_len,
                               const char *narrative,
                               const char *agent_id,
                               const char *backend) {
    if (!inf->ready || !narrative || !*narrative) return -1;

    cJSON *root = NULL;
    if (event_json && event_len > 0) {
        root = cJSON_ParseWithLength(event_json, event_len);
    }

    const char *src_ip = "0.0.0.0";
    const char *attack = "UNKNOWN";
    const char *stage  = "UNKNOWN";
    double kc_score = 0;

    if (cJSON_IsObject(root)) {
        const cJSON *v;
        v = cJSON_GetObjectItemCaseSensitive(root, "src_ip");
        if (cJSON_IsString(v) && v->valuestring) src_ip = v->valuestring;
        v = cJSON_GetObjectItemCaseSensitive(root, "attack_type");
        if (cJSON_IsString(v) && v->valuestring) attack = v->valuestring;
        v = cJSON_GetObjectItemCaseSensitive(root, "kill_chain_stage");
        if (cJSON_IsString(v) && v->valuestring) stage = v->valuestring;
        v = cJSON_GetObjectItemCaseSensitive(root, "kc_score");
        if (cJSON_IsNumber(v)) kc_score = v->valuedouble;
    }

    /* Copia tags pra buffers locais — `src_ip`/`attack`/`stage` apontam pra
     * cJSON que vai ser destruído logo após. */
    char src_ip_buf[MAX_TAG_LEN], attack_buf[MAX_TAG_LEN], stage_buf[MAX_TAG_LEN];
    snprintf(src_ip_buf, sizeof(src_ip_buf), "%s", src_ip);
    snprintf(attack_buf, sizeof(attack_buf), "%s", attack);
    snprintf(stage_buf,  sizeof(stage_buf),  "%s", stage);

    char esc_agent[MAX_TAG_LEN], esc_ip[MAX_TAG_LEN], esc_attack[MAX_TAG_LEN];
    char esc_stage[MAX_TAG_LEN], esc_backend[MAX_TAG_LEN];
    lp_escape(esc_agent,   sizeof(esc_agent),   agent_id ? agent_id : "unknown");
    lp_escape(esc_ip,      sizeof(esc_ip),      src_ip_buf);
    lp_escape(esc_attack,  sizeof(esc_attack),  attack_buf);
    lp_escape(esc_stage,   sizeof(esc_stage),   stage_buf);
    lp_escape(esc_backend, sizeof(esc_backend), backend ? backend : "unknown");

    /* Campo string narrative pode ser longo (~1KB). Aloca buffer dinâmico. */
    size_t narr_cap = strlen(narrative) * 2 + 16;
    char *esc_narr = malloc(narr_cap);
    if (!esc_narr) { if (root) cJSON_Delete(root); return -1; }
    lp_escape_str_field(esc_narr, narr_cap, narrative);

    size_t lp_cap = narr_cap + 1024;
    char *lp = malloc(lp_cap);
    if (!lp) { free(esc_narr); if (root) cJSON_Delete(root); return -1; }

    char f_kc[LP_FLOAT_BUF];
    fmt_lp_float(f_kc, sizeof(f_kc), kc_score);
    int n = snprintf(lp, lp_cap,
        "incident_narrative,agent_id=%s,src_ip=%s,attack_type=%s,"
        "kill_chain_stage=%s,backend=%s narrative=\"%s\",kc_score=%s\n",
        esc_agent, esc_ip, esc_attack, esc_stage, esc_backend,
        esc_narr, f_kc);

    free(esc_narr);
    if (root) cJSON_Delete(root);

    if (n <= 0 || (size_t)n >= lp_cap) {
        free(lp);
        return -1;
    }

    int rc = influx_post(inf, lp, (size_t)n);
    if (rc == 0) {
        fprintf(stderr, "[NARR] write %s | %s | %d chars\n",
                src_ip_buf, attack_buf, (int)strlen(narrative));
    }
    free(lp);
    return rc;
}

/* -------------------------------------------------------------------------- *
 * Write pool status — measurement "nta_pool".                               *
 * -------------------------------------------------------------------------- */
int nta_influx_write_pool(NtaInflux *inf,
                          int pool_size, int backlog,
                          int unacked, int consumers) {
    if (!inf->ready) return -1;
    char lp[256];
    int n = snprintf(lp, sizeof(lp),
        "nta_pool pool_size=%di,backlog=%di,unacked=%di,consumers=%di\n",
        pool_size, backlog, unacked, consumers);
    if (n <= 0 || (size_t)n >= sizeof(lp)) return -1;
    return influx_post(inf, lp, (size_t)n);
}

/* -------------------------------------------------------------------------- *
 * proto_dns (B16, PR a): logs de DNS do agente, vindos da protocol_queue.    *
 * Ver nta_influx.h para o schema. qname/IP são fields, nunca tags.           *
 * -------------------------------------------------------------------------- */
#define PROTO_LINE_MAX  1536            /* um registro: qname (≤512 escapado) + IPs + tags */
#define PROTO_ACC_CAP   65536           /* um POST junta vários registros até este tamanho */
#define PROTO_TS_MAX    9000000000000.0 /* ms: além disso o ns estoura int64 */

static const char *proto_qtype_name(long qt) {
    switch (qt) {
    case 1:   return "A";
    case 2:   return "NS";
    case 5:   return "CNAME";
    case 6:   return "SOA";
    case 12:  return "PTR";
    case 15:  return "MX";
    case 16:  return "TXT";
    case 28:  return "AAAA";
    case 33:  return "SRV";
    case 64:  return "SVCB";
    case 65:  return "HTTPS";
    case 255: return "ANY";
    default:  return "OTHER";   /* tipo fora da lista: tag com cardinalidade fixa */
    }
}

/* Inteiro JSON dentro de [lo, hi]. NaN e fracionário são rejeitados. */
static int json_int_in(const cJSON *obj, const char *key, double lo, double hi,
                       long *out) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsNumber(v)) return 0;
    double d = v->valuedouble;
    if (!(d >= lo && d <= hi)) return 0;   /* também pega NaN */
    if (d != (double)(long)d) return 0;
    *out = (long)d;
    return 1;
}

/* Campo string de line protocol: \ e " escapados; qualquer byte fora de
 * 0x20..0x7E vira '?' (nem quebra de linha nem UTF-8 inválido chega ao Influx).
 * Retorna o tamanho escrito ou -1 se não couber. */
static int lp_field_str(char *out, size_t cap, const char *in) {
    if (cap < 3) return -1;
    size_t w = 0;
    out[w++] = '"';
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        char e[2];
        size_t n = 1;
        if (*p == '"' || *p == '\\') {
            e[0] = '\\'; e[1] = (char)*p; n = 2;
        } else if (*p < 0x20 || *p > 0x7E) {
            e[0] = '?';
        } else {
            e[0] = (char)*p;
        }
        if (w + n + 2 > cap) return -1;     /* +2: aspa final e NUL */
        memcpy(out + w, e, n);
        w += n;
    }
    out[w++] = '"';
    out[w] = '\0';
    return (int)w;
}

size_t nta_influx_proto_line(const cJSON *evt, const char *agent_id,
                             char *out, size_t cap) {
    if (!out || cap < 64 || !cJSON_IsObject(evt)) return 0;

    /* Discriminador e versão: só aceita o que o schema 1 define. */
    const cJSON *et = cJSON_GetObjectItemCaseSensitive(evt, "event_type");
    const cJSON *sv = cJSON_GetObjectItemCaseSensitive(evt, "schema_version");
    if (!cJSON_IsString(et) || strcmp(et->valuestring, "dns") != 0) return 0;
    if (!cJSON_IsNumber(sv) || sv->valuedouble != 1.0) return 0;

    const char *proto = json_get_str(evt, "proto",  NULL);
    const char *src   = json_get_str(evt, "src_ip", NULL);
    const char *dst   = json_get_str(evt, "dst_ip", NULL);
    const char *qname = json_get_str(evt, "qname",  NULL);
    if (!proto || !src || !dst || !qname) return 0;
    if (strcmp(proto, "UDP") != 0 && strcmp(proto, "TCP") != 0) return 0;
    if (strlen(src) > 45 || strlen(dst) > 45 || strlen(qname) > 255) return 0;

    long qtype = 0, rcode = 0, resp = 0, bytes = 0, hashed = 0;
    if (!json_int_in(evt, "qtype", 0, 65535, &qtype)) return 0;
    if (!json_int_in(evt, "rcode", 0, 15, &rcode))    return 0;
    if (!json_int_in(evt, "resp",  0, 1, &resp))     return 0;
    if (!json_int_in(evt, "bytes", 0, 65535, &bytes)) return 0;
    if (cJSON_GetObjectItemCaseSensitive(evt, "qname_hashed") &&
        !json_int_in(evt, "qname_hashed", 0, 1, &hashed)) return 0;

    const cJSON *ts = cJSON_GetObjectItemCaseSensitive(evt, "ts");
    if (!cJSON_IsNumber(ts) || !(ts->valuedouble >= 0 && ts->valuedouble <= PROTO_TS_MAX))
        return 0;
    long long ts_ns = (long long)ts->valuedouble * 1000000LL;

    char esc_agent[MAX_TAG_LEN];
    char f_qn[2 * 256 + 8], f_src[2 * 46 + 8], f_dst[2 * 46 + 8];
    lp_escape(esc_agent, sizeof(esc_agent), agent_id ? agent_id : "unknown");
    if (lp_field_str(f_qn,  sizeof(f_qn),  qname) < 0 ||
        lp_field_str(f_src, sizeof(f_src), src)   < 0 ||
        lp_field_str(f_dst, sizeof(f_dst), dst)   < 0) return 0;

    /* Tags (baixa cardinalidade): agent_id, protocol, qtype, rcode. O resto é
     * field. Timestamp é o do agente, em ns. */
    int n = snprintf(out, cap,
        "proto_dns,agent_id=%s,protocol=%s,qtype=%s,rcode=%ld "
        "qname=%s,src_ip=%s,dst_ip=%s,resp=%ldi,bytes=%ldi,qtype_num=%ldi,"
        "qname_hashed=%s %lld\n",
        esc_agent, proto, proto_qtype_name(qtype), rcode,
        f_qn, f_src, f_dst, resp, bytes, qtype,
        hashed ? "true" : "false", ts_ns);
    if (n <= 0 || (size_t)n >= cap) return 0;
    return (size_t)n;
}

int nta_influx_write_proto(NtaInflux *inf, const char *body, size_t len,
                           const char *agent_id, unsigned *skipped) {
    if (skipped) *skipped = 0;
    if (!inf->ready || !body || len == 0) return -1;

    cJSON *root = cJSON_ParseWithLength(body, len);
    if (!root) {
        fprintf(stderr, "[PROTO] JSON invalido (%zuB)\n", len);
        return -1;
    }
    int is_arr = cJSON_IsArray(root);
    if (!is_arr && !cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return -1;
    }

    char *acc = malloc(PROTO_ACC_CAP);
    if (!acc) { cJSON_Delete(root); return -1; }

    char   line[PROTO_LINE_MAX];
    size_t w = 0;
    unsigned n_pts = 0, n_skip = 0;
    int rc = 0;

    /* Junta registros num bloco e envia; bloco cheio é enviado antes de
     * continuar, então um lote grande não estoura o buffer. */
    const cJSON *item = is_arr ? root->child : root;
    while (item) {
        size_t l = nta_influx_proto_line(item, agent_id, line, sizeof(line));
        if (l == 0) {
            n_skip++;
        } else {
            if (w + l >= PROTO_ACC_CAP) {
                rc = influx_post(inf, acc, w);
                w = 0;
                if (rc != 0) break;
            }
            memcpy(acc + w, line, l);
            w += l;
            n_pts++;
        }
        item = is_arr ? item->next : NULL;
    }
    if (rc == 0 && w > 0) rc = influx_post(inf, acc, w);

    free(acc);
    cJSON_Delete(root);
    if (skipped) *skipped = n_skip;
    if (rc == 0 && n_pts > 0)
        fprintf(stderr, "[PROTO] proto_dns: %u ponto(s) OK\n", n_pts);
    return rc;
}

/* -------------------------------------------------------------------------- *
 * Close                                                                      *
 * -------------------------------------------------------------------------- */
void nta_influx_close(NtaInflux *inf) {
    if (!inf) return;
    if (inf->headers) { curl_slist_free_all(inf->headers); inf->headers = NULL; }
    if (inf->curl)    { curl_easy_cleanup(inf->curl);      inf->curl    = NULL; }
    inf->ready = 0;
}
