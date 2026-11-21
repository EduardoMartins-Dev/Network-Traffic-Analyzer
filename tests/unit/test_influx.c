/* Precisão dos floats escritos no line protocol do InfluxDB (nta_influx.c).
 *   1. traffic: bytes > 1e6 (12345678.5) sai sem perda; is_scan 0.1 volta igual;
 *   2. traffic: inteiros comuns continuam curtos (bytes=1500, sem ponto);
 *   3. metrics: cada campo float volta idêntico ao double original (round-trip),
 *      incluindo 3.141592653589793 (exige 17 dígitos) e 1e20;
 *   4. narrative: kc_score com 9 dígitos sai inteiro (não arredondado a 6).
 * A escrita passa pela API pública real: um servidor HTTP de teste em loopback
 * recebe o POST, guarda o corpo line protocol e responde 204. */
#include "test.h"
#include "nta_influx.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_REQ  8
#define BODY_CAP 8192

typedef struct {
    int         listen_fd;
    atomic_int  n_req;
    char        bodies[MAX_REQ][BODY_CAP];
} Servidor;

static Servidor srv;
static NtaInflux inf;

/* Lê uma requisição (headers + Content-Length) do socket e copia o corpo. */
static int le_requisicao(int fd, char *corpo, size_t cap) {
    char buf[BODY_CAP + 4096];
    size_t used = 0;
    const char *sep = NULL;
    for (;;) {
        if (used >= sizeof(buf) - 1) return -1;
        ssize_t r = recv(fd, buf + used, sizeof(buf) - 1 - used, 0);
        if (r <= 0) return -1;
        used += (size_t)r;
        buf[used] = '\0';
        if ((sep = strstr(buf, "\r\n\r\n")) != NULL) break;
    }
    size_t hdr_len = (size_t)(sep - buf) + 4;
    const char *cl = strstr(buf, "Content-Length:");
    if (!cl) return -1;
    size_t clen = strtoul(cl + 15, NULL, 10);
    if (clen >= cap) return -1;

    size_t have = used - hdr_len;
    size_t got = have < clen ? have : clen;
    memcpy(corpo, buf + hdr_len, got);
    while (got < clen) {
        ssize_t r = recv(fd, corpo + got, clen - got, 0);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    corpo[clen] = '\0';
    return 0;
}

/* Atende uma conexão keep-alive: guarda cada corpo e responde 204. Sai quando
 * o cliente fecha (nta_influx_close) ou após 5 s sem dados. */
static void *serve(void *arg) {
    (void)arg;
    int conn = accept(srv.listen_fd, NULL, NULL);
    if (conn < 0) return NULL;
    struct timeval tv = {5, 0};
    setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    const char *resp = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
    while (atomic_load(&srv.n_req) < MAX_REQ) {
        int i = atomic_load(&srv.n_req);
        if (le_requisicao(conn, srv.bodies[i], BODY_CAP) != 0) break;
        atomic_fetch_add(&srv.n_req, 1);
        if (send(conn, resp, strlen(resp), 0) < 0) break;
    }
    close(conn);
    return NULL;
}

static int abre_servidor(int *porta) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    socklen_t al = sizeof(a);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(fd, 1) < 0 ||
        getsockname(fd, (struct sockaddr *)&a, &al) < 0) {
        close(fd);
        return -1;
    }
    *porta = ntohs(a.sin_port);
    srv.listen_fd = fd;
    return 0;
}

/* Corpo da última requisição recebida pelo servidor de teste. */
static const char *ultimo_corpo(void) {
    int n = atomic_load(&srv.n_req);
    return n > 0 ? srv.bodies[n - 1] : "";
}

/* Lê o valor numérico que segue "chave=" no line protocol. 0 se não achar. */
static int campo(const char *lp, const char *chave, double *out) {
    const char *p = strstr(lp, chave);
    if (!p) return 0;
    char *fim = NULL;
    *out = strtod(p + strlen(chave), &fim);
    return fim != p + strlen(chave);
}

static void teste_trafego(void) {
    const char *json =
        "{\"src_ip\":\"10.0.0.5\",\"port\":22,\"proto\":\"TCP\","
        "\"bytes\":12345678.5,\"is_scan\":0.1,\"attack_type\":\"BRUTE_FORCE\","
        "\"kill_chain_stage\":\"EXPLOIT\",\"kc_score\":85}";
    int rc = nta_influx_write_traffic(&inf, NULL, NULL, NULL,
                                      json, strlen(json), "agente-teste");
    CHECK(rc == 0);
    const char *lp = ultimo_corpo();

    double v = 0;
    CHECK(campo(lp, "bytes=", &v));
    CHECK(v == 12345678.5);
    CHECK(campo(lp, "is_scan=", &v));
    CHECK(v == 0.1);
    CHECK(strstr(lp, "port=22i,") != NULL);
    CHECK(strstr(lp, "bytes=12345678.5,is_scan=0.1") != NULL);
    CHECK(strstr(lp, ",kc_score=85") != NULL);
}

static void teste_inteiros_curtos(void) {
    const char *json =
        "{\"src_ip\":\"10.0.0.6\",\"port\":80,\"proto\":\"TCP\","
        "\"bytes\":1500,\"is_scan\":0}";
    int rc = nta_influx_write_traffic(&inf, NULL, NULL, NULL,
                                      json, strlen(json), "agente-teste");
    CHECK(rc == 0);
    const char *lp = ultimo_corpo();
    CHECK(strstr(lp, "bytes=1500,is_scan=0\n") != NULL);
}

static void teste_metricas(void) {
    const char *json =
        "{\"k_big\":12345678.5,\"k_frac\":0.1,"
        "\"k_pi\":3.141592653589793,\"k_exp\":1e20,\"k_int\":1500}";
    int rc = nta_influx_write_metrics(&inf, json, strlen(json), "agente-teste");
    CHECK(rc == 0);
    const char *lp = ultimo_corpo();

    double v = 0;
    CHECK(campo(lp, "k_big=", &v));
    CHECK(v == 12345678.5);
    CHECK(campo(lp, "k_frac=", &v));
    CHECK(v == 0.1);
    CHECK(campo(lp, "k_pi=", &v));
    CHECK(v == 3.141592653589793);
    CHECK(campo(lp, "k_exp=", &v));
    CHECK(v == 1e20);
    CHECK(strstr(lp, "k_int=1500\n") != NULL);
}

static void teste_narrativa(void) {
    const char *evt = "{\"src_ip\":\"10.0.0.7\",\"attack_type\":\"SYN_FLOOD\","
                      "\"kill_chain_stage\":\"RECON\",\"kc_score\":87.123456789}";
    int rc = nta_influx_write_narrative(&inf, evt, strlen(evt),
                                        "Texto de teste.", "agente-teste", "groq");
    CHECK(rc == 0);
    const char *lp = ultimo_corpo();
    double v = 0;
    CHECK(campo(lp, "kc_score=", &v));
    CHECK(v == 87.123456789);
}

int main(void) {
    int porta = 0;
    CHECK(abre_servidor(&porta) == 0);
    if (t_failures) return 1;

    atomic_init(&srv.n_req, 0);
    pthread_t th;
    CHECK(pthread_create(&th, NULL, serve, NULL) == 0);

    NtaConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    char url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d", porta);
    cfg.influx_url    = url;
    cfg.influx_token  = "token-teste";
    cfg.influx_org    = "org-teste";
    cfg.influx_bucket = "bucket-teste";

    CHECK(nta_influx_global_init() == 0);
    CHECK(nta_influx_open(&inf, &cfg) == 0);

    RUN(teste_trafego);
    RUN(teste_inteiros_curtos);
    RUN(teste_metricas);
    RUN(teste_narrativa);

    nta_influx_close(&inf);
    pthread_join(th, NULL);
    close(srv.listen_fd);
    TEST_EXIT();
}
