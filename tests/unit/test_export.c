/* Testes da exportação SIEM do nta-server (include/server/nta_export.h), B11.
 *   1. CEF: linha completa (cabeçalho RFC 5424 + CEF) contra texto esperado;
 *   2. CEF com entrada hostil: \ | = quebras e controles escapados ou trocados,
 *      sem LF/CR na linha;
 *   3. ECS: JSON válido com os campos mapeados (event, threat, source, network,
 *      agent, labels), MITRE múltiplo separado por vírgula;
 *   4. ECS com entrada hostil: IP inválido fica fora de source.ip; strings
 *      voltam intactas ao parsear (escape JSON correto); sem LF/CR na linha;
 *   5. cabeçalho syslog: HOSTNAME e MSGID sanitizados; sem alerta → 0;
 *      buffer pequeno → 0 (sem estouro);
 *   6. timestamp RFC 3339 com milissegundos;
 *   7. configuração por env: desligado = nada; formato inválido; porta fora da faixa;
 *   8. envio UDP real em loopback: a linha chega bem formada, alerta normal não sai;
 *   9. destino fechado: submit não bloqueia e a contabilidade fecha (enviados +
 *      descartados + falhas = submetidos). Nenhum tráfego sai para fora da máquina;
 *  10. pacote benigno do agente (attack_type "NONE") não é exportado; mistura
 *      benigno + alerta envia só o alerta. */
#include "test.h"
#include "nta_export.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TS  "2026-11-20T10:00:00.000Z"
#define OUT_CAP 4096

static int escuta_udp(int *porta);

static int contem(const char *h, const char *n) { return strstr(h, n) != NULL; }

static int tem_quebra(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) if (s[i] == '\n' || s[i] == '\r') return 1;
    return 0;
}

static long long agora_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000L;
}

/* Alerta de referência: BRUTE_FORCE em 10.0.0.5:22/TCP, 1500 bytes, kc=85. */
static cJSON *alerta_ref(void) {
    cJSON *e = cJSON_CreateObject();
    cJSON_AddStringToObject(e, "src_ip", "10.0.0.5");
    cJSON_AddNumberToObject(e, "port", 22);
    cJSON_AddStringToObject(e, "proto", "TCP");
    cJSON_AddNumberToObject(e, "bytes", 1500);
    cJSON_AddNumberToObject(e, "is_scan", 1);
    cJSON_AddStringToObject(e, "attack_type", "BRUTE_FORCE");
    cJSON_AddStringToObject(e, "kill_chain_stage", "EXPLOIT");
    cJSON_AddNumberToObject(e, "kc_score", 85);
    cJSON_AddStringToObject(e, "mitre", "T1110");
    return e;
}

/* Evento benigno exatamente como o agente publica (publish_packet com attack
 * NULL → publisher grava NONE/IDLE). Não é alerta: não pode ser exportado. */
static cJSON *evento_benigno(void) {
    cJSON *e = cJSON_CreateObject();
    cJSON_AddStringToObject(e, "src_ip", "10.0.0.5");
    cJSON_AddNumberToObject(e, "port", 53);
    cJSON_AddStringToObject(e, "proto", "UDP");
    cJSON_AddNumberToObject(e, "bytes", 512);
    cJSON_AddNumberToObject(e, "is_scan", 0);
    cJSON_AddStringToObject(e, "attack_type", "NONE");
    cJSON_AddStringToObject(e, "kill_chain_stage", "IDLE");
    cJSON_AddNumberToObject(e, "kc_score", 0);
    cJSON_AddStringToObject(e, "mitre", "");
    return e;
}

/* Alerta hostil: IP com \n e =, MSGID com \\ | \r\n, agente com = e \n. */
static cJSON *alerta_hostil(void) {
    cJSON *e = cJSON_CreateObject();
    cJSON_AddStringToObject(e, "src_ip", "10.0.0.5\nX=evil");
    cJSON_AddNumberToObject(e, "port", 0);
    cJSON_AddStringToObject(e, "proto", "TCP");
    cJSON_AddNumberToObject(e, "bytes", 1500);
    cJSON_AddNumberToObject(e, "is_scan", 0);
    cJSON_AddStringToObject(e, "attack_type", "PORT\\SCAN|x\r\nFAKE");
    cJSON_AddStringToObject(e, "kill_chain_stage", "");
    cJSON_AddNumberToObject(e, "kc_score", 10);
    cJSON_AddStringToObject(e, "mitre", "");
    return e;
}

static void test_cef_linha_completa(void) {
    cJSON *e = alerta_ref();
    char out[OUT_CAP];
    size_t n = nta_export_render(out, sizeof out, NTA_EXPORT_CEF, "host-test",
                                 e, "agent-01", TS);
    CHECK(n > 0);
    CHECK_STR(out,
        "<130>1 " TS " host-test nta-server - BRUTE_FORCE - "
        "CEF:0|NTA|Network Traffic Analyzer|1.0|BRUTE_FORCE|BRUTE_FORCE|8|"
        "deviceExternalId=agent-01 src=10.0.0.5 dpt=22 proto=TCP out=1500 "
        "cs1=EXPLOIT cs1Label=killChainStage cs2=T1110 cs2Label=mitreTechnique "
        "cn1=85 cn1Label=killChainScore cn2=1 cn2Label=isScan");
    CHECK(strlen(out) == n);
    cJSON_Delete(e);
}

static void test_cef_entrada_hostil(void) {
    cJSON *e = alerta_hostil();
    char out[OUT_CAP];
    size_t n = nta_export_render(out, sizeof out, NTA_EXPORT_CEF, "host-test",
                                 e, "ag=\n1", TS);
    CHECK(n > 0);
    /* Sem quebra de linha: não pode injetar registro novo no syslog. */
    CHECK(n > 0 && !tem_quebra(out, n));
    /* MSGID (RFC 5424) sanitizado: só controles e espaço viram '_'. \ e | são
     * PRINTUSASCII (33..126) e ficam. */
    CHECK(contem(out, " - PORT\\SCAN|x__FAKE - CEF:0|"));
    /* Cabeçalho CEF: \ → \\, | → \|, CR/LF → espaço. */
    CHECK(contem(out, "|PORT\\\\SCAN\\|x  FAKE|PORT\\\\SCAN\\|x  FAKE|1|"));
    /* Extensão: = → \=, LF → \n, agente idem. */
    CHECK(contem(out, "deviceExternalId=ag\\=\\n1 src=10.0.0.5\\nX\\=evil "));
    cJSON_Delete(e);
}

static void test_ecs_campos(void) {
    cJSON *e = alerta_ref();
    cJSON_ReplaceItemInObject(e, "mitre", cJSON_CreateString("T1071.004, T1048"));
    char out[OUT_CAP];
    size_t n = nta_export_render(out, sizeof out, NTA_EXPORT_ECS, "host-test",
                                 e, "agent-01", TS);
    CHECK(n > 0);
    CHECK(!tem_quebra(out, n));
    const char *pref = "<130>1 " TS " host-test nta-server - BRUTE_FORCE - {";
    CHECK(strncmp(out, pref, strlen(pref)) == 0);

    const char *json = strchr(out, '{');
    cJSON *r = json ? cJSON_Parse(json) : NULL;
    CHECK(r != NULL);
    if (r) {
        CHECK_STR(cJSON_GetObjectItem(r, "@timestamp")->valuestring, TS);
        CHECK_STR(cJSON_GetObjectItem(cJSON_GetObjectItem(r, "ecs"), "version")->valuestring, "8.11.0");
        const cJSON *ev = cJSON_GetObjectItem(r, "event");
        CHECK_STR(cJSON_GetObjectItem(ev, "kind")->valuestring, "alert");
        CHECK_STR(cJSON_GetObjectItem(ev, "action")->valuestring, "BRUTE_FORCE");
        CHECK(cJSON_GetObjectItem(ev, "risk_score")->valuedouble == 85);
        CHECK_STR(cJSON_GetObjectItem(cJSON_GetObjectItem(r, "rule"), "name")->valuestring, "BRUTE_FORCE");
        const cJSON *thr = cJSON_GetObjectItem(r, "threat");
        CHECK_STR(cJSON_GetObjectItem(thr, "framework")->valuestring, "MITRE ATT&CK");
        const cJSON *ids = cJSON_GetObjectItem(cJSON_GetObjectItem(thr, "technique"), "id");
        CHECK(cJSON_GetArraySize(ids) == 2);
        CHECK_STR(cJSON_GetArrayItem(ids, 0)->valuestring, "T1071.004");
        CHECK_STR(cJSON_GetArrayItem(ids, 1)->valuestring, "T1048");
        CHECK_STR(cJSON_GetObjectItem(cJSON_GetObjectItem(r, "source"), "ip")->valuestring, "10.0.0.5");
        CHECK(cJSON_GetObjectItem(cJSON_GetObjectItem(r, "destination"), "port")->valuedouble == 22);
        const cJSON *net = cJSON_GetObjectItem(r, "network");
        CHECK_STR(cJSON_GetObjectItem(net, "transport")->valuestring, "tcp");
        CHECK(cJSON_GetObjectItem(net, "bytes")->valuedouble == 1500);
        CHECK_STR(cJSON_GetObjectItem(cJSON_GetObjectItem(r, "agent"), "id")->valuestring, "agent-01");
        CHECK_STR(cJSON_GetObjectItem(cJSON_GetObjectItem(r, "labels"), "kill_chain_stage")->valuestring, "EXPLOIT");
        cJSON_Delete(r);
    }
    cJSON_Delete(e);
}

static void test_ecs_entrada_hostil(void) {
    cJSON *e = alerta_hostil();
    char out[OUT_CAP];
    size_t n = nta_export_render(out, sizeof out, NTA_EXPORT_ECS, "host-test",
                                 e, "ag=\n1", TS);
    CHECK(n > 0);
    CHECK(n > 0 && !tem_quebra(out, n));

    const char *json = strchr(out, '{');
    cJSON *r = json ? cJSON_Parse(json) : NULL;
    CHECK(r != NULL);
    if (r) {
        /* IP inválido não vai para source.ip. */
        CHECK(cJSON_GetObjectItem(r, "source") == NULL);
        /* Port 0 não é porta válida. */
        CHECK(cJSON_GetObjectItem(r, "destination") == NULL);
        /* Sem MITRE, sem bloco threat. */
        CHECK(cJSON_GetObjectItem(r, "threat") == NULL);
        /* Strings voltam exatamente como entraram (escape JSON correto). */
        CHECK_STR(cJSON_GetObjectItem(cJSON_GetObjectItem(r, "event"), "action")->valuestring,
                  "PORT\\SCAN|x\r\nFAKE");
        CHECK_STR(cJSON_GetObjectItem(cJSON_GetObjectItem(r, "agent"), "id")->valuestring, "ag=\n1");
        CHECK_STR(cJSON_GetObjectItem(r, "message")->valuestring,
                  "NTA alert PORT\\SCAN|x\r\nFAKE src=10.0.0.5\nX=evil");
        cJSON_Delete(r);
    }
    cJSON_Delete(e);
}

static void test_cabecalho_sanitizado(void) {
    cJSON *e = alerta_ref();
    char out[OUT_CAP];
    size_t n = nta_export_render(out, sizeof out, NTA_EXPORT_CEF, "evil host\n<999>",
                                 e, "agent-01", TS);
    CHECK(n > 0);
    /* HOSTNAME: espaço e LF viram '_'; '<' e '>' são PRINTUSASCII e ficam. */
    CHECK(contem(out, " " TS " evil_host_<999> nta-server - BRUTE_FORCE - "));
    cJSON_Delete(e);

    /* HOSTNAME vazio vira NILVALUE '-'. */
    e = alerta_ref();
    n = nta_export_render(out, sizeof out, NTA_EXPORT_CEF, "", e, "a", TS);
    CHECK(contem(out, " " TS " - nta-server - BRUTE_FORCE - "));
    cJSON_Delete(e);
}

static void test_render_rejeita(void) {
    char out[OUT_CAP];
    cJSON *e = alerta_ref();

    /* Sem attack_type ou com vazio: não é alerta. */
    cJSON_ReplaceItemInObject(e, "attack_type", cJSON_CreateString(""));
    CHECK(nta_export_render(out, sizeof out, NTA_EXPORT_CEF, "h", e, "a", TS) == 0);
    cJSON_DeleteItemFromObject(e, "attack_type");
    CHECK(nta_export_render(out, sizeof out, NTA_EXPORT_ECS, "h", e, "a", TS) == 0);
    cJSON_Delete(e);

    /* Entrada que não é objeto. */
    cJSON *arr = cJSON_CreateArray();
    CHECK(nta_export_render(out, sizeof out, NTA_EXPORT_CEF, "h", arr, "a", TS) == 0);
    cJSON_Delete(arr);

    /* Buffer pequeno: nada de estouro, retorna 0. */
    e = alerta_ref();
    CHECK(nta_export_render(out, 40, NTA_EXPORT_CEF, "h", e, "a", TS) == 0);
    CHECK(nta_export_render(out, 40, NTA_EXPORT_ECS, "h", e, "a", TS) == 0);
    cJSON_Delete(e);
}

/* Pacote benigno do agente (attack_type "NONE") não vira alerta: render 0 nos
 * dois formatos. Alerta real com "NONE" fora de attack_type continua válido. */
static void test_benigno_nao_renderiza(void) {
    char out[OUT_CAP];
    cJSON *b = evento_benigno();
    CHECK(nta_export_render(out, sizeof out, NTA_EXPORT_CEF, "h", b, "a", TS) == 0);
    CHECK(nta_export_render(out, sizeof out, NTA_EXPORT_ECS, "h", b, "a", TS) == 0);
    cJSON_Delete(b);

    /* Comparação exata: "none" minúsculo e "NONE " com espaço são alertas. */
    cJSON *a = alerta_ref();
    cJSON_ReplaceItemInObject(a, "attack_type", cJSON_CreateString("none"));
    CHECK(nta_export_render(out, sizeof out, NTA_EXPORT_CEF, "h", a, "a", TS) > 0);
    cJSON_Delete(a);
}

/* 200 pacotes benignos + 1 alerta PORT_SCAN no mesmo destino UDP: só o alerta
 * chega (um datagrama), e a contabilidade mostra 1 enviado e nada mais. */
static void test_mistura_benigno_alerta(void) {
    int porta = 0;
    int rx = escuta_udp(&porta);
    CHECK(rx >= 0 && porta > 0);
    struct timeval curto = { 0, 300000 };
    setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, &curto, sizeof curto);

    NtaExportCfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.format      = NTA_EXPORT_ECS;
    cfg.syslog_host = "127.0.0.1";
    cfg.syslog_port = porta;
    cfg.hostname    = "host-test";
    cfg.queue_max   = 512;
    cfg.timeout_ms  = 500;
    NtaExport *e = nta_export_open(&cfg);
    CHECK(e != NULL);

    cJSON *benigno = evento_benigno();
    for (int i = 0; i < 200; i++) nta_export_submit(e, benigno, "agent-01");
    cJSON *alerta = alerta_ref();
    cJSON_ReplaceItemInObject(alerta, "attack_type", cJSON_CreateString("PORT_SCAN"));
    cJSON_ReplaceItemInObject(alerta, "kc_score", cJSON_CreateNumber(60));
    nta_export_submit(e, alerta, "agent-01");

    char buf[OUT_CAP];
    ssize_t n = recv(rx, buf, sizeof buf - 1, 0);
    CHECK(n > 0);
    if (n > 0) {
        buf[n] = '\0';
        CHECK(contem(buf, " - PORT_SCAN - {"));
        CHECK(!contem(buf, "NONE"));
    }
    /* Nenhum segundo datagrama: os 200 benignos nunca entraram na fila. */
    CHECK(recv(rx, buf, sizeof buf, 0) < 0);

    NtaExportStats st;
    nta_export_close(e, &st);
    CHECK(st.sent == 1);
    CHECK(st.dropped == 0);
    CHECK(st.failed == 0);

    cJSON_Delete(benigno);
    cJSON_Delete(alerta);
    close(rx);
}

static void test_timestamp(void) {
    char ts[32];
    nta_export_now(ts, sizeof ts);
    CHECK(strlen(ts) == 24);
    CHECK(ts[4] == '-' && ts[7] == '-' && ts[10] == 'T');
    CHECK(ts[13] == ':' && ts[16] == ':' && ts[19] == '.');
    CHECK(ts[23] == 'Z');
}

static void test_config_env(void) {
    NtaExportCfg cfg;
    unsetenv("NTA_EXPORT_FORMAT");
    unsetenv("NTA_EXPORT_SYSLOG_HOST");
    unsetenv("NTA_EXPORT_SYSLOG_PORT");
    unsetenv("NTA_EXPORT_SYSLOG_PROTO");

    /* Padrão: desligado e sem exportador. */
    nta_export_cfg_load(&cfg);
    CHECK(cfg.format == 0);
    CHECK(nta_export_open(&cfg) == NULL);

    /* Formato desconhecido: desligado. */
    setenv("NTA_EXPORT_FORMAT", "xml", 1);
    nta_export_cfg_load(&cfg);
    CHECK(cfg.format == 0);

    /* Ligado sem destino: não abre. */
    setenv("NTA_EXPORT_FORMAT", "cef", 1);
    nta_export_cfg_load(&cfg);
    CHECK(cfg.format == NTA_EXPORT_CEF);
    CHECK(nta_export_open(&cfg) == NULL);

    /* Porta fora da faixa cai no padrão 514; proto tcp liga o modo TCP. */
    setenv("NTA_EXPORT_SYSLOG_HOST", "127.0.0.1", 1);
    setenv("NTA_EXPORT_SYSLOG_PORT", "99999", 1);
    setenv("NTA_EXPORT_SYSLOG_PROTO", "tcp", 1);
    nta_export_cfg_load(&cfg);
    CHECK(cfg.syslog_port == 514);
    CHECK(cfg.use_tcp == 1);
    CHECK(cfg.format == NTA_EXPORT_CEF);

    setenv("NTA_EXPORT_FORMAT", "ecs", 1);
    nta_export_cfg_load(&cfg);
    CHECK(cfg.format == NTA_EXPORT_ECS);

    unsetenv("NTA_EXPORT_FORMAT");
    unsetenv("NTA_EXPORT_SYSLOG_HOST");
    unsetenv("NTA_EXPORT_SYSLOG_PORT");
    unsetenv("NTA_EXPORT_SYSLOG_PROTO");
}

/* Socket UDP de escuta em loopback com porta efêmera. */
static int escuta_udp(int *porta) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    socklen_t sl = sizeof sa;
    if (s < 0 || bind(s, (struct sockaddr *)&sa, sizeof sa) != 0 ||
        getsockname(s, (struct sockaddr *)&sa, &sl) != 0) {
        if (s >= 0) close(s);
        *porta = 0;
        return -1;
    }
    struct timeval tv = { 2, 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    *porta = ntohs(sa.sin_port);
    return s;
}

static void test_udp_entrega(void) {
    int porta = 0;
    int rx = escuta_udp(&porta);
    CHECK(rx >= 0 && porta > 0);

    NtaExportCfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.format      = NTA_EXPORT_CEF;
    cfg.syslog_host = "127.0.0.1";
    cfg.syslog_port = porta;
    cfg.use_tcp     = 0;
    cfg.hostname    = "host-test";
    cfg.queue_max   = 16;
    cfg.timeout_ms  = 500;
    NtaExport *e = nta_export_open(&cfg);
    CHECK(e != NULL);

    cJSON *normal = alerta_ref();
    cJSON_ReplaceItemInObject(normal, "attack_type", cJSON_CreateString(""));
    cJSON *hostil = alerta_hostil();
    nta_export_submit(e, normal, "agent-01");   /* não é alerta: não sai */
    nta_export_submit(e, hostil, "ag=\n1");

    char buf[OUT_CAP];
    ssize_t n = (rx >= 0) ? recv(rx, buf, sizeof buf - 1, 0) : -1;
    CHECK(n > 0);
    if (n > 0) {
        buf[n] = '\0';
        CHECK(strncmp(buf, "<132>1 ", 7) == 0);
        CHECK(!tem_quebra(buf, (size_t)n));
        CHECK(contem(buf, "deviceExternalId=ag\\=\\n1 src=10.0.0.5\\nX\\=evil"));
    }

    NtaExportStats st;
    nta_export_close(e, &st);
    CHECK(st.sent == 1);
    CHECK(st.dropped == 0);
    CHECK(st.failed == 0);

    cJSON_Delete(normal);
    cJSON_Delete(hostil);
    if (rx >= 0) close(rx);
}

static void test_destino_fechado_nao_bloqueia(void) {
    /* Porta TCP livre no loopback: faz bind, pega o número e fecha. A conexão
     * sai recusada (RST) e é rápida, sem depender de timeout. */
    int porta = 0;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t sl = sizeof sa;
    if (s >= 0 && bind(s, (struct sockaddr *)&sa, sizeof sa) == 0 &&
        getsockname(s, (struct sockaddr *)&sa, &sl) == 0) {
        porta = ntohs(sa.sin_port);
    }
    if (s >= 0) close(s);
    CHECK(porta > 0);

    NtaExportCfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.format      = NTA_EXPORT_CEF;
    cfg.syslog_host = "127.0.0.1";
    cfg.syslog_port = porta;
    cfg.use_tcp     = 1;
    cfg.hostname    = "host-test";
    cfg.queue_max   = 16;
    cfg.timeout_ms  = 200;
    NtaExport *e = nta_export_open(&cfg);
    CHECK(e != NULL);

    cJSON *evt = alerta_ref();
    const int N = 5000;
    long long t0 = agora_ms();
    for (int i = 0; i < N; i++) nta_export_submit(e, evt, "agent-01");
    long long gastou = agora_ms() - t0;
    CHECK(gastou < 1000);   /* submit não espera o destino */

    NtaExportStats st;
    nta_export_close(e, &st);
    CHECK(st.sent == 0);
    CHECK(st.failed > 0);   /* o destino recusou pelo menos uma tentativa */
    CHECK(st.sent + st.dropped + st.failed == (unsigned long long)N);
    cJSON_Delete(evt);
}

int main(void) {
    RUN(test_cef_linha_completa);
    RUN(test_cef_entrada_hostil);
    RUN(test_ecs_campos);
    RUN(test_ecs_entrada_hostil);
    RUN(test_cabecalho_sanitizado);
    RUN(test_render_rejeita);
    RUN(test_benigno_nao_renderiza);
    RUN(test_mistura_benigno_alerta);
    RUN(test_timestamp);
    RUN(test_config_env);
    RUN(test_udp_entrega);
    RUN(test_destino_fechado_nao_bloqueia);
    TEST_EXIT();
}
