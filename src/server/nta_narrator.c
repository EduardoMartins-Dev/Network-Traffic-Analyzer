/* ========================================================================= *
 *  nta_narrator.c — chama Groq Cloud (OpenAI-compatible) p/ gerar narrativa *
 *  de incidente. Substitui src/ingestor/narrator.py em C puro (libcurl).    *
 * ========================================================================= */

#include "../../include/nta_narrator.h"
#include "../../include/cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define DEFAULT_URL     "https://api.groq.com/openai/v1/chat/completions"
#define DEFAULT_MODEL   "llama-3.3-70b-versatile"
#define DEFAULT_TIMEOUT 8
#define DEFAULT_MIN     80
#define MAX_RESP_BYTES  (256 * 1024)   /* 256KB cap p/ resposta Groq */

static const char *SYSTEM_PROMPT =
    "Você é um analista de SOC sênior. Recebe um JSON de incidente do IDS "
    "e devolve uma narrativa concisa em PT-BR no formato EXATO abaixo "
    "(sem markdown, sem bullets):\n\n"
    "INCIDENT | Severidade: <Crítica|Alta|Média> (<score>/100)\n\n"
    "O QUE ACONTECEU:\n"
    "<máx 4 linhas técnicas>\n\n"
    "POR QUE É CRÍTICO:\n"
    "<máx 2 linhas, citando técnica MITRE>\n\n"
    "AÇÃO RECOMENDADA:\n"
    "<um comando concreto: iptables, nft, ip route ou similar>\n\n"
    "MITRE ATT&CK: <techniques separadas por vírgula>\n\n"
    "Não invente dados além do JSON. Seja direto.";

/* -------------------------------------------------------------------------- *
 * env helpers                                                                *
 * -------------------------------------------------------------------------- */
static const char *env_or(const char *k, const char *fb) {
    const char *v = getenv(k);
    return (v && *v) ? v : fb;
}

static int env_int(const char *k, int fb) {
    const char *v = getenv(k);
    if (!v || !*v) return fb;
    char *end = NULL;
    long n = strtol(v, &end, 10);
    if (end == v || n < 0) return fb;
    return (int)n;
}

static char *strip_inplace(char *s) {
    if (!s) return s;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t'))
        *--e = '\0';
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

/* Lê arquivo KEY=VALUE estilo .env e injeta em getenv() via setenv(..., 0). */
static void load_env_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *p = strip_inplace(line);
        if (!*p || *p == '#') continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = strip_inplace(p);
        char *v = strip_inplace(eq + 1);
        if (*k && !getenv(k)) setenv(k, v, 0);
    }
    fclose(fp);
}

/* -------------------------------------------------------------------------- *
 * Load                                                                       *
 * -------------------------------------------------------------------------- */
int nta_narrator_load(NtaNarratorCfg *cfg, const char *repo_root) {
    memset(cfg, 0, sizeof(*cfg));

    /* Tenta .env file relativo ao repo_root. */
    if (repo_root) {
        char path[1024];
        snprintf(path, sizeof(path), "%s/deploy/secrets/groq.env", repo_root);
        load_env_file(path);
    }

    snprintf(cfg->url,   sizeof(cfg->url),   "%s", env_or("GROQ_URL",   DEFAULT_URL));
    snprintf(cfg->model, sizeof(cfg->model), "%s", env_or("GROQ_MODEL", DEFAULT_MODEL));
    snprintf(cfg->api_key, sizeof(cfg->api_key), "%s", env_or("GROQ_API_KEY", ""));

    cfg->timeout_sec = env_int("NARRATOR_TIMEOUT",   DEFAULT_TIMEOUT);
    cfg->min_score   = env_int("NARRATOR_MIN_SCORE", DEFAULT_MIN);
    cfg->enabled     = (cfg->api_key[0] != '\0');

    return 0;
}

const char *nta_narrator_backend(const NtaNarratorCfg *cfg) {
    static char buf[160];
    snprintf(buf, sizeof(buf), "groq:%s", cfg->model);
    return buf;
}

/* -------------------------------------------------------------------------- *
 * Open / close                                                               *
 * -------------------------------------------------------------------------- */
int nta_narrator_open(NtaNarrator *n, const NtaNarratorCfg *cfg) {
    memset(n, 0, sizeof(*n));
    n->cfg = cfg;
    if (!cfg->enabled) return -1;

    n->curl = curl_easy_init();
    if (!n->curl) return -1;

    char auth[320];
    snprintf(auth, sizeof(auth), "Authorization: Bearer %s", cfg->api_key);
    n->headers = curl_slist_append(NULL, auth);
    n->headers = curl_slist_append(n->headers, "Content-Type: application/json");
    n->headers = curl_slist_append(n->headers, "Accept: application/json");

    curl_easy_setopt(n->curl, CURLOPT_URL,            cfg->url);
    curl_easy_setopt(n->curl, CURLOPT_POST,           1L);
    curl_easy_setopt(n->curl, CURLOPT_HTTPHEADER,     n->headers);
    curl_easy_setopt(n->curl, CURLOPT_TIMEOUT,        (long)cfg->timeout_sec);
    curl_easy_setopt(n->curl, CURLOPT_CONNECTTIMEOUT, 5L);

    n->ready = 1;
    return 0;
}

void nta_narrator_close(NtaNarrator *n) {
    if (!n) return;
    if (n->headers) { curl_slist_free_all(n->headers); n->headers = NULL; }
    if (n->curl)    { curl_easy_cleanup(n->curl);      n->curl    = NULL; }
    n->ready = 0;
}

/* -------------------------------------------------------------------------- *
 * Resposta — buffer dinâmico                                                 *
 * -------------------------------------------------------------------------- */
typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} RespBuf;

static size_t resp_write_cb(char *ptr, size_t sz, size_t nm, void *u) {
    RespBuf *b = (RespBuf *)u;
    size_t add = sz * nm;
    if (b->len + add > MAX_RESP_BYTES) return 0;   /* aborta — corpo grande demais */
    if (b->len + add + 1 > b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 4096;
        while (ncap < b->len + add + 1) ncap *= 2;
        char *nd = realloc(b->data, ncap);
        if (!nd) return 0;
        b->data = nd; b->cap = ncap;
    }
    memcpy(b->data + b->len, ptr, add);
    b->len += add;
    b->data[b->len] = '\0';
    return add;
}

/* -------------------------------------------------------------------------- *
 * Build prompt body — JSON request p/ Groq                                   *
 * -------------------------------------------------------------------------- */
static char *build_request_body(const char *model, const char *event_json,
                                size_t event_len, const char *agent_id,
                                const NtaWhoisInfo *whois_info) {
    /* user prompt = ["Origem: ...\n"]? + "Incidente:\n" + JSON original.
     * Reparseia evento p/ injetar agent_id sem confiar em concat de strings. */
    cJSON *evt = cJSON_ParseWithLength(event_json, event_len);
    if (!evt) evt = cJSON_CreateObject();
    if (cJSON_IsObject(evt) && agent_id && *agent_id &&
        !cJSON_HasObjectItem(evt, "agent_id")) {
        cJSON_AddStringToObject(evt, "agent_id", agent_id);
    }
    char *evt_str = cJSON_PrintUnformatted(evt);
    cJSON_Delete(evt);
    if (!evt_str) return NULL;

    char whois_line[512] = {0};
    if (whois_info && whois_info->has_data) {
        snprintf(whois_line, sizeof(whois_line),
                 "Origem (WHOIS): %s%s%s%s%s\n",
                 whois_info->org[0]     ? whois_info->org     : "",
                 (whois_info->org[0] && whois_info->country[0]) ? " (" : "",
                 whois_info->country[0] ? whois_info->country : "",
                 (whois_info->org[0] && whois_info->country[0]) ? ")"  : "",
                 whois_info->netname[0] ? " — netname: "      : "");
        if (whois_info->netname[0]) {
            size_t l = strlen(whois_line);
            snprintf(whois_line + l, sizeof(whois_line) - l, "%s\n",
                     whois_info->netname);
        }
    }

    size_t up_cap = strlen(evt_str) + strlen(whois_line) + 32;
    char *user_prompt = malloc(up_cap);
    if (!user_prompt) { free(evt_str); return NULL; }
    snprintf(user_prompt, up_cap, "%sIncidente:\n%s", whois_line, evt_str);
    free(evt_str);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "model", model);
    cJSON *msgs = cJSON_AddArrayToObject(root, "messages");
    cJSON *m1 = cJSON_CreateObject();
    cJSON_AddStringToObject(m1, "role", "system");
    cJSON_AddStringToObject(m1, "content", SYSTEM_PROMPT);
    cJSON_AddItemToArray(msgs, m1);
    cJSON *m2 = cJSON_CreateObject();
    cJSON_AddStringToObject(m2, "role", "user");
    cJSON_AddStringToObject(m2, "content", user_prompt);
    cJSON_AddItemToArray(msgs, m2);

    free(user_prompt);

    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

/* -------------------------------------------------------------------------- *
 * Call                                                                       *
 * -------------------------------------------------------------------------- */
char *nta_narrator_call(NtaNarrator *n, NtaWhois *whois,
                        const char *event_json, size_t event_len,
                        const char *agent_id) {
    if (!n || !n->ready || !event_json) return NULL;

    /* WHOIS opcional — só pra enriquecer prompt. Falha não bloqueia narrator. */
    NtaWhoisInfo wi = {0};
    if (whois) {
        cJSON *evt = cJSON_ParseWithLength(event_json, event_len);
        if (cJSON_IsObject(evt)) {
            const cJSON *ip = cJSON_GetObjectItemCaseSensitive(evt, "src_ip");
            if (cJSON_IsString(ip) && ip->valuestring) {
                nta_whois_lookup(whois, ip->valuestring, &wi);
            }
        }
        if (evt) cJSON_Delete(evt);
    }

    char *req = build_request_body(n->cfg->model, event_json, event_len,
                                    agent_id, wi.has_data ? &wi : NULL);
    if (!req) return NULL;
    size_t req_len = strlen(req);

    RespBuf resp = {0};
    curl_easy_setopt(n->curl, CURLOPT_POSTFIELDS,    req);
    curl_easy_setopt(n->curl, CURLOPT_POSTFIELDSIZE, (long)req_len);
    curl_easy_setopt(n->curl, CURLOPT_WRITEFUNCTION, resp_write_cb);
    curl_easy_setopt(n->curl, CURLOPT_WRITEDATA,     &resp);

    CURLcode rc = curl_easy_perform(n->curl);
    free(req);

    if (rc != CURLE_OK) {
        fprintf(stderr, "[NARR] curl falhou: %s\n", curl_easy_strerror(rc));
        free(resp.data);
        return NULL;
    }
    long http_code = 0;
    curl_easy_getinfo(n->curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code < 200 || http_code >= 300) {
        fprintf(stderr, "[NARR] HTTP %ld (%zuB)\n", http_code, resp.len);
        free(resp.data);
        return NULL;
    }
    if (!resp.data || resp.len == 0) {
        free(resp.data);
        return NULL;
    }

    cJSON *root = cJSON_ParseWithLength(resp.data, resp.len);
    free(resp.data);
    if (!root) {
        fprintf(stderr, "[NARR] JSON resposta malformado\n");
        return NULL;
    }

    char *narrative = NULL;
    const cJSON *choices = cJSON_GetObjectItemCaseSensitive(root, "choices");
    if (cJSON_IsArray(choices)) {
        const cJSON *c0 = cJSON_GetArrayItem(choices, 0);
        if (cJSON_IsObject(c0)) {
            const cJSON *msg = cJSON_GetObjectItemCaseSensitive(c0, "message");
            if (cJSON_IsObject(msg)) {
                const cJSON *content = cJSON_GetObjectItemCaseSensitive(msg, "content");
                if (cJSON_IsString(content) && content->valuestring) {
                    narrative = strdup(strip_inplace(content->valuestring));
                }
            }
        }
    }
    cJSON_Delete(root);
    return narrative;
}
