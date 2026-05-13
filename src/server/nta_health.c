/* ========================================================================= *
 *  nta_health.c — endpoint healthcheck HTTP (port 9091 default).            *
 *                                                                           *
 *  Servidor TCP raw em thread única. Sem libs externas. Loop accept + handle*
 *  síncrono — 1 conexão por vez, suficiente pra liveness probes.            *
 *                                                                           *
 *  Default bind 127.0.0.1 (localhost-only). NTA_HEALTH_BIND=0.0.0.0 expõe. *
 *  Em prod, colocar TLS reverse proxy (nginx/caddy) na frente.              *
 * ========================================================================= */

#include "../../include/nta_health.h"
#include "../../include/nta_server.h"
#include "../../include/nta_scaler.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define VERSION_STR    "v8.0"
#define REQ_BUF        2048
#define RESP_BUF       4096

static time_t g_start_time = 0;

/* -------------------------------------------------------------------------- *
 * Response helpers                                                           *
 * -------------------------------------------------------------------------- */
static void send_all(int fd, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t w = write(fd, buf + sent, len - sent);
        if (w <= 0) return;
        sent += (size_t)w;
    }
}

static void respond(int fd, int code, const char *ctype, const char *body) {
    char hdr[256];
    size_t blen = strlen(body);
    const char *reason = (code == 200) ? "OK"
                       : (code == 404) ? "Not Found"
                       : "Internal Server Error";
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.0 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n",
        code, reason, ctype, blen);
    if (n > 0) send_all(fd, hdr, (size_t)n);
    send_all(fd, body, blen);
}

/* -------------------------------------------------------------------------- *
 * Route handlers                                                             *
 * -------------------------------------------------------------------------- */
static void route_health(int fd) {
    int pool    = atomic_load_explicit(&g_nta_pool_size,    memory_order_relaxed);
    int backlog = atomic_load_explicit(&g_nta_pool_backlog, memory_order_relaxed);
    long uptime = (long)(time(NULL) - g_start_time);
    int stopping = atomic_load_explicit(&g_nta_stop, memory_order_relaxed);

    char body[512];
    snprintf(body, sizeof(body),
        "{\n"
        "  \"status\": \"%s\",\n"
        "  \"version\": \"%s\",\n"
        "  \"uptime_s\": %ld,\n"
        "  \"workers\": %d,\n"
        "  \"queue_backlog\": %d,\n"
        "  \"shutting_down\": %s\n"
        "}\n",
        stopping ? "draining" : "ok",
        VERSION_STR, uptime, pool, backlog,
        stopping ? "true" : "false");
    respond(fd, 200, "application/json", body);
}

static void route_metrics(int fd) {
    int pool    = atomic_load_explicit(&g_nta_pool_size,    memory_order_relaxed);
    int backlog = atomic_load_explicit(&g_nta_pool_backlog, memory_order_relaxed);
    long uptime = (long)(time(NULL) - g_start_time);
    int stopping = atomic_load_explicit(&g_nta_stop, memory_order_relaxed);

    char body[1024];
    snprintf(body, sizeof(body),
        "# HELP nta_uptime_seconds nta-server uptime in seconds\n"
        "# TYPE nta_uptime_seconds counter\n"
        "nta_uptime_seconds %ld\n"
        "# HELP nta_workers_active Current traffic worker count\n"
        "# TYPE nta_workers_active gauge\n"
        "nta_workers_active %d\n"
        "# HELP nta_queue_backlog RabbitMQ traffic_queue depth (from scaler)\n"
        "# TYPE nta_queue_backlog gauge\n"
        "nta_queue_backlog %d\n"
        "# HELP nta_shutting_down 1 if SIGTERM received\n"
        "# TYPE nta_shutting_down gauge\n"
        "nta_shutting_down %d\n",
        uptime, pool, backlog, stopping);
    respond(fd, 200, "text/plain; version=0.0.4", body);
}

static void route_index(int fd) {
    static const char *body =
        "<!doctype html><html><head><meta charset=utf-8>"
        "<title>nta-server " VERSION_STR "</title>"
        "<style>body{font-family:monospace;padding:2em;max-width:600px;}"
        "a{color:#0a7;}code{background:#eee;padding:0.1em 0.3em;}</style>"
        "</head><body>"
        "<h1>nta-server " VERSION_STR "</h1>"
        "<p>Network Traffic Analyzer — Threat Intelligence pipeline em C.</p>"
        "<ul>"
        "<li><a href=\"/health\">/health</a> — JSON liveness</li>"
        "<li><a href=\"/metrics\">/metrics</a> — Prometheus exposition</li>"
        "</ul>"
        "<p>Repo: <a href=\"https://github.com/EduardoMartins-Dev/Network-Traffic-Analyzer\">github.com/EduardoMartins-Dev/Network-Traffic-Analyzer</a></p>"
        "</body></html>\n";
    respond(fd, 200, "text/html; charset=utf-8", body);
}

static void route_404(int fd) {
    respond(fd, 404, "text/plain", "not found\n");
}

/* -------------------------------------------------------------------------- *
 * Request parsing                                                            *
 * -------------------------------------------------------------------------- */
static void handle_request(int fd) {
    char buf[REQ_BUF];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) return;
    buf[n] = '\0';

    /* Aceita só GET. Extrai path do request-line: "GET /path HTTP/1.x". */
    if (strncmp(buf, "GET ", 4) != 0) { route_404(fd); return; }
    char *path = buf + 4;
    char *end  = strpbrk(path, " \r\n");
    if (end) *end = '\0';

    if      (strcmp(path, "/health")  == 0) route_health(fd);
    else if (strcmp(path, "/metrics") == 0) route_metrics(fd);
    else if (strcmp(path, "/")        == 0) route_index(fd);
    else                                    route_404(fd);
}

/* -------------------------------------------------------------------------- *
 * Server thread                                                              *
 * -------------------------------------------------------------------------- */
static void *server_main(void *arg) {
    NtaHealth *h = (NtaHealth *)arg;

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        fprintf(stderr, "[HEALTH] socket: %s\n", strerror(errno));
        return NULL;
    }
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)h->port);
    if (inet_pton(AF_INET, h->bind_addr, &sa.sin_addr) != 1) {
        fprintf(stderr, "[HEALTH] bind addr inválido: %s\n", h->bind_addr);
        close(srv); return NULL;
    }
    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        fprintf(stderr, "[HEALTH] bind %s:%d falhou: %s\n",
                h->bind_addr, h->port, strerror(errno));
        close(srv); return NULL;
    }
    if (listen(srv, 16) != 0) {
        fprintf(stderr, "[HEALTH] listen: %s\n", strerror(errno));
        close(srv); return NULL;
    }

    h->srv_fd = srv;
    atomic_store_explicit(&h->ready, 1, memory_order_release);
    fprintf(stderr, "[HEALTH] listening %s:%d (GET /health /metrics /)\n",
            h->bind_addr, h->port);

    /* Accept loop com timeout pra responder ao stop flag. */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(srv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (!nta_should_stop()) {
        struct sockaddr_in ca;
        socklen_t cl = sizeof(ca);
        int c = accept(srv, (struct sockaddr *)&ca, &cl);
        if (c < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (errno == EINTR) continue;
            break;
        }
        struct timeval rt = { .tv_sec = 2, .tv_usec = 0 };
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &rt, sizeof(rt));
        setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &rt, sizeof(rt));
        handle_request(c);
        close(c);
    }

    close(srv);
    h->srv_fd = -1;
    fprintf(stderr, "[HEALTH] encerrado.\n");
    return NULL;
}

/* -------------------------------------------------------------------------- *
 * Public                                                                     *
 * -------------------------------------------------------------------------- */
int nta_health_start(NtaHealth *h) {
    memset(h, 0, sizeof(*h));

    const char *en = getenv("NTA_HEALTH_ENABLED");
    h->enabled = (en && strcmp(en, "0") == 0) ? 0 : 1;
    if (!h->enabled) {
        fprintf(stderr, "[HEALTH] desabilitado (NTA_HEALTH_ENABLED=0).\n");
        return 0;
    }

    const char *port_s = getenv("NTA_HEALTH_PORT");
    h->port = (port_s && *port_s) ? atoi(port_s) : 9091;
    if (h->port <= 0 || h->port > 65535) h->port = 9091;

    const char *bind_s = getenv("NTA_HEALTH_BIND");
    snprintf(h->bind_addr, sizeof(h->bind_addr), "%s",
             (bind_s && *bind_s) ? bind_s : "127.0.0.1");

    h->srv_fd = -1;
    atomic_init(&h->ready, 0);
    g_start_time = time(NULL);

    if (pthread_create(&h->tid, NULL, server_main, h) != 0) {
        fprintf(stderr, "[HEALTH] pthread_create falhou\n");
        h->enabled = 0;
        return -1;
    }
    return 0;
}

void nta_health_stop(NtaHealth *h) {
    if (!h || !h->enabled) return;
    if (h->srv_fd >= 0) shutdown(h->srv_fd, SHUT_RDWR);
    pthread_join(h->tid, NULL);
}
