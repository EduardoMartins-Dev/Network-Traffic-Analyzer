/* ========================================================================= *
 *  nta_export.c — exportação de alertas para SIEM (B11).                    *
 *                                                                           *
 *  Mapeamento fixo: ECS 8.11.0 (JSON) e CEF v0 com cabeçalho versão "1.0".   *
 *  Sem OCSF nesta entrega (ver PR).                                         *
 *                                                                           *
 *  Alerta = attack_type não vazio e diferente de "NONE" (comparação exata).  *
 *  O agente grava attack_type "NONE" em TODO pacote benigno (publish_packet  *
 *  com attack NULL, ver publisher.c); esses pacotes não são exportados.     *
 *                                                                           *
 *  Fluxo: traffic_handler → nta_export_submit (copia o JSON do alerta para   *
 *  uma fila limitada) → thread export_main (parse, render, send). O consumer *
 *  nunca espera rede. Fila cheia → descarte contado.                        *
 * ========================================================================= */

#include "nta_export.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <strings.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef MSG_NOSIGNAL
#define NTA_SEND_FLAGS MSG_NOSIGNAL
#else
#define NTA_SEND_FLAGS 0
#endif

#define NTA_EXPORT_ECS_VERSION "8.11.0"
#define NTA_EXPORT_CEF_VERSION "1.0"
#define NTA_EXPORT_APP_NAME    "nta-server"
#define NTA_EXPORT_LINE_MAX    4096
#define NTA_EXPORT_AGENT_MAX   128
#define NTA_EXPORT_RETRY_MS    1000
#define NTA_EXPORT_DRAIN_MS    2000
#define NTA_EXPORT_LOG_EVERY   1000ULL

/* -------------------------------------------------------------------------- *
 * Helpers de env var                                                         *
 * -------------------------------------------------------------------------- */
static const char *env_str(const char *name, const char *fallback) {
    const char *v = getenv(name);
    return (v && *v) ? v : fallback;
}

static int env_int_clamp(const char *name, int fallback, int lo, int hi) {
    const char *v = getenv(name);
    if (!v || !*v) return fallback;
    char *end = NULL;
    long n = strtol(v, &end, 10);
    if (end == v || *end != '\0' || n < lo || n > hi) return fallback;
    return (int)n;
}

/* -------------------------------------------------------------------------- *
 * Buffer com escrita limitada: qualquer estouro marca err e nada é escrito.  *
 * -------------------------------------------------------------------------- */
typedef struct {
    char  *buf;
    size_t cap;
    size_t len;
    int    err;
} Buf;

static void b_putn(Buf *b, const char *s, size_t n) {
    if (b->err) return;
    if (n >= b->cap - b->len) { b->err = 1; return; }
    memcpy(b->buf + b->len, s, n);
    b->len += n;
    b->buf[b->len] = '\0';
}

static void b_puts(Buf *b, const char *s) { b_putn(b, s, strlen(s)); }

static void b_putc(Buf *b, char c) { b_putn(b, &c, 1); }

static void b_fmt(Buf *b, const char *fmt, ...) {
    if (b->err) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b->buf + b->len, b->cap - b->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= b->cap - b->len) { b->err = 1; return; }
    b->len += (size_t)n;
}

/* -------------------------------------------------------------------------- *
 * Escapes                                                                    *
 *                                                                            *
 * CEF cabeçalho: '\' → '\\', '|' → '\|'; quebras e controles → espaço.       *
 * CEF extensão : '\' → '\\', '=' → '\=', LF → '\n', CR → '\r'; outros        *
 *                controles → espaço.                                         *
 * Cabeçalho RFC 5424 (HOSTNAME, APP-NAME, MSGID): PRINTUSASCII 33..126,      *
 * o resto vira '_'; vazio vira NILVALUE '-'.                                  *
 * JSON ECS: cJSON escapa controles e aspas.                                   *
 * -------------------------------------------------------------------------- */
static void b_cef(Buf *b, const char *s, int ext) {
    for (const unsigned char *p = (const unsigned char *)s; p && *p; p++) {
        unsigned char c = *p;
        if (c == '\\')                 b_puts(b, "\\\\");
        else if (ext && c == '=')      b_puts(b, "\\=");
        else if (!ext && c == '|')     b_puts(b, "\\|");
        else if (c == '\n')            b_puts(b, ext ? "\\n" : " ");
        else if (c == '\r')            b_puts(b, ext ? "\\r" : " ");
        else if (c < 0x20 || c == 0x7f) b_putc(b, ' ');
        else                           b_putc(b, (char)c);
    }
}

static void sd_token(char *dst, size_t cap, const char *src, size_t max) {
    size_t lim = max < cap - 1 ? max : cap - 1;
    size_t w = 0;
    if (src) {
        for (const unsigned char *p = (const unsigned char *)src; *p && w < lim; p++) {
            dst[w++] = (*p >= 33 && *p <= 126) ? (char)*p : '_';
        }
    }
    if (w == 0) { dst[0] = '-'; w = 1; }
    dst[w] = '\0';
}

/* -------------------------------------------------------------------------- *
 * Leitura de campos do evento                                                *
 * -------------------------------------------------------------------------- */
static const char *json_str(const cJSON *obj, const char *key, const char *fb) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    return (cJSON_IsString(v) && v->valuestring) ? v->valuestring : fb;
}

static double json_num(const cJSON *obj, const char *key, double fb) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    return cJSON_IsNumber(v) ? v->valuedouble : fb;
}

/* Regra de alerta (única, usada em submit e render): attack_type não vazio e
 * diferente de "NONE". "NONE" é o valor gravado pelo agente em pacote benigno. */
static int attack_is_alerta(const char *a) {
    return a && *a && strcmp(a, "NONE") != 0;
}

static int is_ip_literal(const char *s) {
    struct in_addr a4;
    struct in6_addr a6;
    return s && (inet_pton(AF_INET, s, &a4) == 1 || inet_pton(AF_INET6, s, &a6) == 1);
}

/* -------------------------------------------------------------------------- *
 * CEF                                                                        *
 * CEF:0|NTA|Network Traffic Analyzer|1.0|<attack>|<attack>|<sev>|<ext>      *
 * sev = kc_score/10 (0..10). dpt = port, out = bytes, cs1 = kill chain stage,*
 * cs2 = MITRE, cn1 = kc_score, cn2 = is_scan.                                *
 * -------------------------------------------------------------------------- */
static void render_cef(Buf *b, const cJSON *evt, const char *agent_id,
                       const char *attack, double kc) {
    int sev = (int)(kc / 10.0);
    if (sev < 0) sev = 0;
    if (sev > 10) sev = 10;

    b_puts(b, "CEF:0|NTA|Network Traffic Analyzer|" NTA_EXPORT_CEF_VERSION "|");
    b_cef(b, attack, 0);
    b_putc(b, '|');
    b_cef(b, attack, 0);
    b_fmt(b, "|%d|", sev);

    b_puts(b, "deviceExternalId=");
    b_cef(b, agent_id ? agent_id : "unknown", 1);
    b_puts(b, " src=");
    b_cef(b, json_str(evt, "src_ip", ""), 1);
    b_fmt(b, " dpt=%.0f proto=", json_num(evt, "port", 0));
    b_cef(b, json_str(evt, "proto", ""), 1);
    b_fmt(b, " out=%.0f cs1=", json_num(evt, "bytes", 0));
    b_cef(b, json_str(evt, "kill_chain_stage", ""), 1);
    b_puts(b, " cs1Label=killChainStage cs2=");
    b_cef(b, json_str(evt, "mitre", ""), 1);
    b_puts(b, " cs2Label=mitreTechnique");
    b_fmt(b, " cn1=%.0f cn1Label=killChainScore", kc);
    b_fmt(b, " cn2=%.0f cn2Label=isScan", json_num(evt, "is_scan", 0));
}

/* -------------------------------------------------------------------------- *
 * ECS (JSON)                                                                 *
 * -------------------------------------------------------------------------- */
static void add_technique_ids(cJSON *arr, const char *mitre) {
    char tok[64];
    size_t t = 0;
    for (const char *p = mitre; ; p++) {
        if (*p == ',' || *p == '\0') {
            size_t s = 0, e = t;
            while (s < e && tok[s] == ' ') s++;
            while (e > s && tok[e - 1] == ' ') e--;
            if (e > s) {
                char id[64];
                memcpy(id, tok + s, e - s);
                id[e - s] = '\0';
                cJSON_AddItemToArray(arr, cJSON_CreateString(id));
            }
            t = 0;
            if (*p == '\0') break;
        } else if (t < sizeof(tok) - 1) {
            tok[t++] = *p;
        }
    }
}

static void render_ecs(Buf *b, const cJSON *evt, const char *agent_id,
                       const char *attack, const char *ts, double kc) {
    const char *src   = json_str(evt, "src_ip", "");
    const char *proto = json_str(evt, "proto", "");
    const char *stage = json_str(evt, "kill_chain_stage", "");
    const char *mitre = json_str(evt, "mitre", "");
    double port  = json_num(evt, "port", 0);
    double bytes = json_num(evt, "bytes", -1);

    cJSON *root = cJSON_CreateObject();
    if (!root) { b->err = 1; return; }

    cJSON_AddStringToObject(root, "@timestamp", ts);

    cJSON *ecs = cJSON_AddObjectToObject(root, "ecs");
    cJSON_AddStringToObject(ecs, "version", NTA_EXPORT_ECS_VERSION);

    cJSON *ev = cJSON_AddObjectToObject(root, "event");
    cJSON *cat = cJSON_AddArrayToObject(ev, "category");
    cJSON_AddItemToArray(cat, cJSON_CreateString("network"));
    cJSON_AddItemToArray(cat, cJSON_CreateString("intrusion_detection"));
    cJSON *typ = cJSON_AddArrayToObject(ev, "type");
    cJSON_AddItemToArray(typ, cJSON_CreateString("info"));
    cJSON_AddStringToObject(ev, "kind", "alert");
    cJSON_AddStringToObject(ev, "module", "nta");
    cJSON_AddStringToObject(ev, "dataset", "nta.alert");
    cJSON_AddStringToObject(ev, "action", attack);
    cJSON_AddNumberToObject(ev, "risk_score", kc);

    cJSON *rule = cJSON_AddObjectToObject(root, "rule");
    cJSON_AddStringToObject(rule, "name", attack);

    if (mitre[0]) {
        cJSON *ids = cJSON_CreateArray();
        add_technique_ids(ids, mitre);
        if (cJSON_GetArraySize(ids) > 0) {
            cJSON *threat = cJSON_AddObjectToObject(root, "threat");
            cJSON_AddStringToObject(threat, "framework", "MITRE ATT&CK");
            cJSON *tech = cJSON_AddObjectToObject(threat, "technique");
            cJSON_AddItemToObject(tech, "id", ids);
        } else {
            cJSON_Delete(ids);
        }
    }

    /* source.ip precisa ser IP válido no SIEM; texto que não é IP fica de fora
     * do campo ECS (o valor bruto segue na mensagem, escapado pelo JSON). */
    if (is_ip_literal(src)) {
        cJSON *s = cJSON_AddObjectToObject(root, "source");
        cJSON_AddStringToObject(s, "ip", src);
    }

    if (port >= 1 && port <= 65535) {
        cJSON *d = cJSON_AddObjectToObject(root, "destination");
        cJSON_AddNumberToObject(d, "port", port);
    }

    cJSON *net = cJSON_AddObjectToObject(root, "network");
    if (strcasecmp(proto, "TCP") == 0)       cJSON_AddStringToObject(net, "transport", "tcp");
    else if (strcasecmp(proto, "UDP") == 0)  cJSON_AddStringToObject(net, "transport", "udp");
    else if (strcasecmp(proto, "ICMP") == 0) cJSON_AddStringToObject(net, "transport", "icmp");
    if (bytes >= 0) cJSON_AddNumberToObject(net, "bytes", bytes);

    cJSON *ag = cJSON_AddObjectToObject(root, "agent");
    cJSON_AddStringToObject(ag, "id", agent_id ? agent_id : "unknown");

    cJSON *lb = cJSON_AddObjectToObject(root, "labels");
    cJSON_AddStringToObject(lb, "kill_chain_stage", stage);
    cJSON_AddStringToObject(lb, "proto", proto);
    cJSON_AddStringToObject(lb, "mitre", mitre);
    cJSON_AddNumberToObject(lb, "is_scan", json_num(evt, "is_scan", 0));

    char msg[512];
    snprintf(msg, sizeof msg, "NTA alert %s src=%s", attack, src);
    cJSON_AddStringToObject(root, "message", msg);

    char *s = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!s) { b->err = 1; return; }
    b_puts(b, s);
    free(s);
}

/* -------------------------------------------------------------------------- *
 * Render público                                                             *
 * -------------------------------------------------------------------------- */
size_t nta_export_render(char *out, size_t cap, NtaExportFormat fmt,
                         const char *hostname, const cJSON *evt,
                         const char *agent_id, const char *ts) {
    if (!out || cap < 2 || !ts || !evt || !cJSON_IsObject(evt)) return 0;

    const char *attack = json_str(evt, "attack_type", NULL);
    if (!attack_is_alerta(attack)) return 0;
    double kc = json_num(evt, "kc_score", 0);

    char host[256], msgid[33];
    sd_token(host, sizeof host, hostname, 255);
    sd_token(msgid, sizeof msgid, attack, 32);

    Buf b = { out, cap, 0, 0 };
    out[0] = '\0';

    /* PRI = local0 (16) * 8 + severidade: 2 (crit) se kc >= 80, senão 4 (warning). */
    b_fmt(&b, "<%d>1 %s %s " NTA_EXPORT_APP_NAME " - %s - ",
          128 + (kc >= 80 ? 2 : 4), ts, host, msgid);

    if (fmt == NTA_EXPORT_CEF)      render_cef(&b, evt, agent_id, attack, kc);
    else if (fmt == NTA_EXPORT_ECS) render_ecs(&b, evt, agent_id, attack, ts, kc);
    else return 0;

    if (b.err) return 0;
    /* Defesa em profundidade: linha com byte de controle é descartada, não
     * enviada. Os escapes acima já impedem isso. */
    for (size_t i = 0; i < b.len; i++) {
        if ((unsigned char)out[i] < 0x20) return 0;
    }
    return b.len;
}

void nta_export_now(char *out, size_t cap) {
    if (!out || cap < 25) { if (out && cap) out[0] = '\0'; return; }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);
    size_t n = strftime(out, cap, "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(out + n, cap - n, ".%03ldZ", ts.tv_nsec / 1000000L);
}

/* -------------------------------------------------------------------------- *
 * Config                                                                     *
 * -------------------------------------------------------------------------- */
void nta_export_cfg_load(NtaExportCfg *cfg) {
    memset(cfg, 0, sizeof(*cfg));

    const char *f = env_str("NTA_EXPORT_FORMAT", NULL);
    if (!f) return;   /* desligado: nada é lido nem impresso */
    if (strcmp(f, "cef") == 0)      cfg->format = NTA_EXPORT_CEF;
    else if (strcmp(f, "ecs") == 0) cfg->format = NTA_EXPORT_ECS;
    else {
        fprintf(stderr, "⚠ NTA_EXPORT_FORMAT='%s' inválido (use cef ou ecs) — exportação desligada\n", f);
        return;
    }

    cfg->syslog_host = env_str("NTA_EXPORT_SYSLOG_HOST", NULL);
    cfg->syslog_port = env_int_clamp("NTA_EXPORT_SYSLOG_PORT", 514, 1, 65535);
    cfg->use_tcp     = strcmp(env_str("NTA_EXPORT_SYSLOG_PROTO", "udp"), "tcp") == 0;
    cfg->hostname    = env_str("NTA_EXPORT_HOSTNAME", "nta-server");
    cfg->queue_max   = env_int_clamp("NTA_EXPORT_QUEUE", 1024, 16, 65536);
    cfg->timeout_ms  = env_int_clamp("NTA_EXPORT_TIMEOUT_MS", 500, 50, 10000);
}

/* -------------------------------------------------------------------------- *
 * Exportador                                                                 *
 * -------------------------------------------------------------------------- */
typedef struct {
    char *json;                       /* cJSON impresso do alerta (dono: fila) */
    char  agent[NTA_EXPORT_AGENT_MAX];
} QItem;

struct NtaExport {
    NtaExportCfg    cfg;
    pthread_t       tid;
    pthread_mutex_t mu;               /* guarda fila, qcount e stop_deadline */
    pthread_cond_t  cv;
    QItem          *q;                /* anel de tamanho qcap */
    int             qcap, qhead, qcount;
    int             stop;
    long long       stop_deadline_ms; /* monotônico; após isso, descarta */
    int             fd;               /* só a thread de envio mexe */
    long long       retry_at_ms;      /* idem */
    char           *line;             /* buffer de render, só a thread de envio */
    atomic_ullong   sent, dropped, failed;
};

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000L;
}

/* connect com prazo: não-bloqueante + select. Devolve ao modo bloqueante em
 * sucesso; o envio usa SO_SNDTIMEO. */
static int connect_with_timeout(int fd, const struct sockaddr *sa, socklen_t salen,
                                int timeout_ms) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return -1;
    if (connect(fd, sa, salen) != 0) {
        if (errno != EINPROGRESS) return -1;
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        if (select(fd + 1, NULL, &wfds, NULL, &tv) <= 0) return -1;
        int err = 0;
        socklen_t el = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) return -1;
    }
    fcntl(fd, F_SETFL, fl);
    return 0;
}

/* Abre o socket para o destino. Só a thread de envio chama. Falha → backoff. */
static int ensure_fd(NtaExport *e) {
    if (e->fd >= 0) return 0;
    long long now = mono_ms();
    if (now < e->retry_at_ms) return -1;

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = e->cfg.use_tcp ? SOCK_STREAM : SOCK_DGRAM;
    char port[8];
    snprintf(port, sizeof(port), "%d", e->cfg.syslog_port);

    int fd = -1;
    if (getaddrinfo(e->cfg.syslog_host, port, &hints, &res) == 0) {
        for (struct addrinfo *ai = res; ai && fd < 0; ai = ai->ai_next) {
            int s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (s < 0) continue;
            int ok = e->cfg.use_tcp
                ? connect_with_timeout(s, ai->ai_addr, ai->ai_addrlen, e->cfg.timeout_ms)
                : connect(s, ai->ai_addr, ai->ai_addrlen);
            if (ok == 0) fd = s; else close(s);
        }
        freeaddrinfo(res);
    }
    if (fd < 0) {
        e->retry_at_ms = now + NTA_EXPORT_RETRY_MS;
        fprintf(stderr, "[EXPORT] destino indisponível (%s:%d, %s) — nova tentativa em %d ms\n",
                e->cfg.syslog_host, e->cfg.syslog_port,
                e->cfg.use_tcp ? "tcp" : "udp", NTA_EXPORT_RETRY_MS);
        return -1;
    }

    struct timeval tv = { e->cfg.timeout_ms / 1000, (e->cfg.timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    e->fd = fd;
    return 0;
}

static int send_all(int fd, const char *p, size_t n) {
    while (n > 0) {
        ssize_t w = send(fd, p, n, NTA_SEND_FLAGS);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static int send_line(NtaExport *e, const char *line, size_t n) {
    if (ensure_fd(e) != 0) return -1;

    int ok;
    if (e->cfg.use_tcp) {
        /* RFC 6587 octet-counting: "<len> <msg>". Não depende de \n no payload. */
        char pre[24];
        int pl = snprintf(pre, sizeof(pre), "%zu ", n);
        ok = send_all(e->fd, pre, (size_t)pl) == 0 && send_all(e->fd, line, n) == 0;
    } else {
        /* RFC 5426: uma mensagem por datagrama. */
        ssize_t w = send(e->fd, line, n, NTA_SEND_FLAGS);
        ok = (w == (ssize_t)n);
    }
    if (!ok) {
        int err = errno;
        close(e->fd);
        e->fd = -1;
        e->retry_at_ms = mono_ms() + NTA_EXPORT_RETRY_MS;
        fprintf(stderr, "[EXPORT] envio falhou (%s:%d, %s): %s — nova tentativa em %d ms\n",
                e->cfg.syslog_host, e->cfg.syslog_port,
                e->cfg.use_tcp ? "tcp" : "udp", strerror(err), NTA_EXPORT_RETRY_MS);
        return -1;
    }
    return 0;
}

static void count_drop(NtaExport *e) {
    unsigned long long n = atomic_fetch_add(&e->dropped, 1) + 1;
    if (n == 1 || n % NTA_EXPORT_LOG_EVERY == 0) {
        fprintf(stderr, "[EXPORT] descartados=%llu (fila cheia ou prazo de shutdown)\n", n);
    }
}

static void *export_main(void *arg) {
    NtaExport *e = (NtaExport *)arg;
    for (;;) {
        QItem it;
        pthread_mutex_lock(&e->mu);
        while (e->qcount == 0 && !e->stop) pthread_cond_wait(&e->cv, &e->mu);
        if (e->qcount == 0) { pthread_mutex_unlock(&e->mu); break; }
        it = e->q[e->qhead];
        e->qhead = (e->qhead + 1) % e->qcap;
        e->qcount--;
        int late = e->stop && mono_ms() > e->stop_deadline_ms;
        pthread_mutex_unlock(&e->mu);

        if (late) {
            free(it.json);
            count_drop(e);
            continue;
        }

        char ts[32];
        nta_export_now(ts, sizeof(ts));
        cJSON *evt = cJSON_Parse(it.json);
        free(it.json);
        size_t n = evt ? nta_export_render(e->line, NTA_EXPORT_LINE_MAX,
                                           e->cfg.format, e->cfg.hostname,
                                           evt, it.agent, ts) : 0;
        cJSON_Delete(evt);
        if (n == 0) {
            atomic_fetch_add(&e->failed, 1);
            continue;
        }
        if (send_line(e, e->line, n) == 0) atomic_fetch_add(&e->sent, 1);
        else                               atomic_fetch_add(&e->failed, 1);
    }
    return NULL;
}

NtaExport *nta_export_open(const NtaExportCfg *cfg) {
    if (!cfg || cfg->format == 0) return NULL;
    if (!cfg->syslog_host || !*cfg->syslog_host) {
        fprintf(stderr, "⚠ NTA_EXPORT_FORMAT ligado sem NTA_EXPORT_SYSLOG_HOST — exportação desligada\n");
        return NULL;
    }

    NtaExport *e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    e->cfg = *cfg;
    e->fd = -1;
    e->qcap = cfg->queue_max > 0 ? cfg->queue_max : 1024;
    e->q = calloc((size_t)e->qcap, sizeof(QItem));
    e->line = malloc(NTA_EXPORT_LINE_MAX);
    if (!e->q || !e->line) goto fail_alloc;
    pthread_mutex_init(&e->mu, NULL);
    pthread_cond_init(&e->cv, NULL);

    if (pthread_create(&e->tid, NULL, export_main, e) != 0) {
        pthread_mutex_destroy(&e->mu);
        pthread_cond_destroy(&e->cv);
        goto fail_alloc;
    }

    fprintf(stderr, "▶ export %s → syslog %s://%s:%d (queue=%d, timeout=%dms)\n",
            cfg->format == NTA_EXPORT_CEF ? "CEF" : "ECS",
            cfg->use_tcp ? "tcp" : "udp", cfg->syslog_host, cfg->syslog_port,
            e->qcap, cfg->timeout_ms);
    return e;

fail_alloc:
    free(e->q);
    free(e->line);
    free(e);
    return NULL;
}

void nta_export_submit(NtaExport *e, const cJSON *evt, const char *agent_id) {
    if (!e || !evt || !cJSON_IsObject(evt)) return;
    const char *a = json_str(evt, "attack_type", NULL);
    if (!attack_is_alerta(a)) return;

    /* Checagem barata antes de serializar: fila cheia descarta sem custo. */
    pthread_mutex_lock(&e->mu);
    int full = e->qcount == e->qcap;
    pthread_mutex_unlock(&e->mu);
    if (full) { count_drop(e); return; }

    char *s = cJSON_PrintUnformatted(evt);
    if (!s) { count_drop(e); return; }

    pthread_mutex_lock(&e->mu);
    if (e->qcount == e->qcap || e->stop) {
        pthread_mutex_unlock(&e->mu);
        free(s);
        count_drop(e);
        return;
    }
    QItem *slot = &e->q[(e->qhead + e->qcount) % e->qcap];
    slot->json = s;
    snprintf(slot->agent, sizeof(slot->agent), "%s", agent_id ? agent_id : "unknown");
    e->qcount++;
    pthread_cond_signal(&e->cv);
    pthread_mutex_unlock(&e->mu);
}

void nta_export_close(NtaExport *e, NtaExportStats *out) {
    if (!e) return;

    pthread_mutex_lock(&e->mu);
    e->stop = 1;
    e->stop_deadline_ms = mono_ms() + NTA_EXPORT_DRAIN_MS;
    pthread_cond_broadcast(&e->cv);
    pthread_mutex_unlock(&e->mu);

    pthread_join(e->tid, NULL);

    /* A thread só sai com a fila vazia; sobra só se algo falhou antes. */
    while (e->qcount > 0) {
        free(e->q[e->qhead].json);
        e->qhead = (e->qhead + 1) % e->qcap;
        e->qcount--;
        count_drop(e);
    }
    if (e->fd >= 0) close(e->fd);

    NtaExportStats st = {
        .sent    = atomic_load(&e->sent),
        .dropped = atomic_load(&e->dropped),
        .failed  = atomic_load(&e->failed),
    };
    if (out) *out = st;
    fprintf(stderr, "[EXPORT] encerrado: enviados=%llu descartados=%llu falhas=%llu\n",
            st.sent, st.dropped, st.failed);

    pthread_mutex_destroy(&e->mu);
    pthread_cond_destroy(&e->cv);
    free(e->q);
    free(e->line);
    free(e);
}
