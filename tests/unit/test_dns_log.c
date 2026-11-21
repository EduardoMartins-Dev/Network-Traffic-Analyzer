/* Testes do log de protocolo DNS do agente (B16, PR a): src/agent/analysis/
 * protocols/dns_log.c. Entradas hostis montadas à mão, sem libpcap:
 *   - corte do pacote em cada posição (UDP e TCP);
 *   - ponteiro de compressão em laço e ponteiro para fora do pacote;
 *   - rótulo de 63 bytes aceito, byte 0x40 (rótulo reservado) rejeitado;
 *   - nome de 255 octetos aceito e 256 rejeitado;
 *   - QDCOUNT grande (usa a primeira pergunta), QDCOUNT 0 (sem pergunta);
 *   - rótulos com byte de controle, aspas, barra, ponto e UTF-8;
 *   - TCP com comprimento de prefixo errado; fragmento inicial de resposta;
 *   - render JSON, hash FNV-1a, leitura da config e ring com descarte. */
#include "test.h"
#include "dns_log.h"
#include "nta_net.h"          /* inet_pton / AF_INET, para montar os endereços */

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- *
 * Montagem de pacotes                                                       *
 * ------------------------------------------------------------------------- */

/* Nome em wire a partir de "a.b.c". Retorna o tamanho (inclui o zero final). */
static size_t wire_name(uint8_t *out, const char *dotted) {
    size_t w = 0;
    const char *p = dotted;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t n = dot ? (size_t)(dot - p) : strlen(p);
        out[w++] = (uint8_t)n;
        memcpy(out + w, p, n);
        w += n;
        if (!dot) break;
        p = dot + 1;
    }
    out[w++] = 0;
    return w;
}

/* Mensagem DNS: cabeçalho (12) + UMA pergunta com `name` em wire. */
static size_t build_msg(uint8_t *m, uint16_t flags, uint16_t qdcount,
                        const uint8_t *name, size_t nlen, uint16_t qtype) {
    memset(m, 0, 12);
    m[0] = 0x12; m[1] = 0x34;
    m[2] = (uint8_t)(flags >> 8); m[3] = (uint8_t)flags;
    m[4] = (uint8_t)(qdcount >> 8); m[5] = (uint8_t)qdcount;
    memcpy(m + 12, name, nlen);
    size_t off = 12 + nlen;
    m[off]     = (uint8_t)(qtype >> 8);
    m[off + 1] = (uint8_t)qtype;
    m[off + 2] = 0x00; m[off + 3] = 0x01;     /* QCLASS IN */
    return off + 4;
}

/* Envelopa a mensagem em UDP (cabeçalho de 8 bytes). Retorna o tamanho do L4. */
static size_t udp_wrap(uint8_t *l4, const uint8_t *msg, size_t mlen,
                       uint16_t sport, uint16_t dport) {
    uint16_t ulen = (uint16_t)(8 + mlen);
    l4[0] = (uint8_t)(sport >> 8); l4[1] = (uint8_t)sport;
    l4[2] = (uint8_t)(dport >> 8); l4[3] = (uint8_t)dport;
    l4[4] = (uint8_t)(ulen >> 8);  l4[5] = (uint8_t)ulen;
    l4[6] = 0; l4[7] = 0;
    memcpy(l4 + 8, msg, mlen);
    return 8 + mlen;
}

/* Envelopa em TCP: cabeçalho de 20 bytes (data offset 5), prefixo de 2 bytes com
 * `prefix` (comprimento declarado), depois a mensagem. */
static size_t tcp_wrap(uint8_t *l4, const uint8_t *msg, size_t mlen,
                       uint16_t prefix, uint16_t sport, uint16_t dport) {
    memset(l4, 0, 20);
    l4[0] = (uint8_t)(sport >> 8); l4[1] = (uint8_t)sport;
    l4[2] = (uint8_t)(dport >> 8); l4[3] = (uint8_t)dport;
    l4[12] = 5 << 4;
    l4[20] = (uint8_t)(prefix >> 8); l4[21] = (uint8_t)prefix;
    memcpy(l4 + 22, msg, mlen);
    return 22 + mlen;
}

static uint8_t NAME_EX[64];     /* example.com */
static size_t  NAME_EX_LEN;

static void setup_names(void) {
    NAME_EX_LEN = wire_name(NAME_EX, "example.com");
}

/* ------------------------------------------------------------------------- *
 * Parser: caminho feliz                                                     *
 * ------------------------------------------------------------------------- */
static void teste_consulta_udp(void) {
    uint8_t m[128], l4[160];
    size_t mlen = build_msg(m, 0x0100, 1, NAME_EX, NAME_EX_LEN, 1);
    size_t n = udp_wrap(l4, m, mlen, 40000, 53);

    DnsEvent e;
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, (int)n, &e) == 0);
    CHECK_STR(e.qname, "example.com");
    CHECK(e.qtype == 1);
    CHECK(e.rcode == 0);
    CHECK(e.resp == 0);
    CHECK(e.proto == DNS_PROTO_UDP);
    CHECK(e.bytes == mlen);
}

static void teste_resposta_nxdomain(void) {
    uint8_t m[128], l4[160];
    /* QR=1, RD, RA, RCODE=3 (NXDOMAIN) */
    size_t mlen = build_msg(m, 0x8183, 1, NAME_EX, NAME_EX_LEN, 28);
    size_t n = udp_wrap(l4, m, mlen, 53, 40000);

    DnsEvent e;
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, (int)n, &e) == 0);
    CHECK(e.resp == 1);
    CHECK(e.rcode == 3);
    CHECK(e.qtype == 28);            /* AAAA */
    CHECK_STR(e.qname, "example.com");
}

static void teste_tcp_correto(void) {
    uint8_t m[128], l4[160];
    size_t mlen = build_msg(m, 0x0100, 1, NAME_EX, NAME_EX_LEN, 16);
    size_t n = tcp_wrap(l4, m, mlen, (uint16_t)mlen, 40000, 53);

    DnsEvent e;
    CHECK(dns_log_parse(DNS_PROTO_TCP, l4, (int)n, &e) == 0);
    CHECK_STR(e.qname, "example.com");
    CHECK(e.qtype == 16);
    CHECK(e.proto == DNS_PROTO_TCP);
    CHECK(e.bytes == mlen);
}

static void teste_porta_nao_dns(void) {
    uint8_t m[128], l4[160];
    size_t mlen = build_msg(m, 0x0100, 1, NAME_EX, NAME_EX_LEN, 1);
    size_t n = udp_wrap(l4, m, mlen, 40000, 80);
    DnsEvent e;
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, (int)n, &e) == -1);

    size_t nt = tcp_wrap(l4, m, mlen, (uint16_t)mlen, 40000, 443);
    CHECK(dns_log_parse(DNS_PROTO_TCP, l4, (int)nt, &e) == -1);
}

static void teste_protocolo_desconhecido(void) {
    uint8_t m[128], l4[160];
    size_t mlen = build_msg(m, 0x0100, 1, NAME_EX, NAME_EX_LEN, 1);
    size_t n = udp_wrap(l4, m, mlen, 40000, 53);
    DnsEvent e;
    CHECK(dns_log_parse(1 /* ICMP */, l4, (int)n, &e) == -1);
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, 0, &e) == -1);
    CHECK(dns_log_parse(DNS_PROTO_UDP, NULL, 10, &e) == -1);
}

/* ------------------------------------------------------------------------- *
 * Entradas hostis                                                           *
 * ------------------------------------------------------------------------- */

/* Corte em cada posição: nenhum prefixo do pacote válido pode produzir registro
 * (a pergunta termina no último byte), e o pacote inteiro produz. */
static void teste_corte_em_cada_campo(void) {
    uint8_t m[128], l4[160];
    size_t mlen = build_msg(m, 0x0100, 1, NAME_EX, NAME_EX_LEN, 1);
    size_t n = udp_wrap(l4, m, mlen, 40000, 53);

    int falhas = 0;
    for (size_t cut = 0; cut < n; cut++) {
        DnsEvent e;
        if (dns_log_parse(DNS_PROTO_UDP, l4, (int)cut, &e) == 0) falhas++;
    }
    CHECK(falhas == 0);

    DnsEvent e;
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, (int)n, &e) == 0);

    /* TCP: o mesmo, com o prefixo de 2 bytes. */
    size_t nt = tcp_wrap(l4, m, mlen, (uint16_t)mlen, 40000, 53);
    falhas = 0;
    for (size_t cut = 0; cut < nt; cut++) {
        if (dns_log_parse(DNS_PROTO_TCP, l4, (int)cut, &e) == 0) falhas++;
    }
    CHECK(falhas == 0);
}

/* Ponteiro de compressão apontando para si mesmo: sai pelo limite de saltos. */
static void teste_ponteiro_em_laco(void) {
    uint8_t m[64], l4[96];
    uint8_t name[2] = { 0xC0, 0x0C };          /* aponta para o offset 12: ele mesmo */
    size_t mlen = build_msg(m, 0x0100, 1, name, 2, 1);
    size_t n = udp_wrap(l4, m, mlen, 40000, 53);
    DnsEvent e;
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, (int)n, &e) == -1);
}

/* Ponteiro para fora do pacote. */
static void teste_ponteiro_fora(void) {
    uint8_t m[64], l4[96];
    uint8_t name[2] = { 0xFF, 0xFF };          /* offset 0x3FFF, muito além do pacote */
    size_t mlen = build_msg(m, 0x0100, 1, name, 2, 1);
    size_t n = udp_wrap(l4, m, mlen, 40000, 53);
    DnsEvent e;
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, (int)n, &e) == -1);
}

/* Ponteiro válido: a pergunta aponta para um nome que está depois dela. O
 * QTYPE vem logo após o ponteiro (offset 14). */
static void teste_ponteiro_valido(void) {
    uint8_t m[64], l4[96];
    /* cabeçalho (12) + ponteiro para 18 (2) + QTYPE/QCLASS (4) + nome (13) */
    memset(m, 0, sizeof(m));
    m[4] = 0; m[5] = 1;                         /* QDCOUNT = 1 */
    m[12] = 0xC0; m[13] = 0x12;                 /* ponteiro para o offset 18 */
    m[14] = 0x00; m[15] = 0x1C;                 /* QTYPE = AAAA (28) */
    m[16] = 0x00; m[17] = 0x01;
    memcpy(m + 18, NAME_EX, NAME_EX_LEN);
    size_t mlen = 18 + NAME_EX_LEN;
    size_t n = udp_wrap(l4, m, mlen, 40000, 53);
    DnsEvent e;
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, (int)n, &e) == 0);
    CHECK_STR(e.qname, "example.com");
    CHECK(e.qtype == 28);
}

/* Rótulo de 63 bytes é o máximo; o byte 0x40 é rótulo reservado (tipo 01). */
static void teste_rotulo_63(void) {
    uint8_t name[80], m[128], l4[160];
    size_t w = 0;
    name[w++] = 63;
    memset(name + w, 'a', 63);
    w += 63;
    name[w++] = 0;
    size_t mlen = build_msg(m, 0x0100, 1, name, w, 1);
    size_t n = udp_wrap(l4, m, mlen, 40000, 53);
    DnsEvent e;
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, (int)n, &e) == 0);
    CHECK(strlen(e.qname) == 63);

    name[0] = 0x40;                              /* 64 bytes ou tipo reservado */
    mlen = build_msg(m, 0x0100, 1, name, w, 1);
    n = udp_wrap(l4, m, mlen, 40000, 53);
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, (int)n, &e) == -1);

    name[0] = 0x80;                              /* tipo reservado 10 */
    mlen = build_msg(m, 0x0100, 1, name, w, 1);
    n = udp_wrap(l4, m, mlen, 40000, 53);
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, (int)n, &e) == -1);
}

/* Nome de 255 octetos em wire (com o zero final): aceito. 256: rejeitado. */
static void teste_nome_255_e_256(void) {
    uint8_t name[300], m[400], l4[420];
    size_t w = 0;
    /* 63 + 63 + 63 + 61: wire = (1+63)*3 + (1+61) + 1 = 255 */
    const uint8_t lens[4] = { 63, 63, 63, 61 };
    for (int i = 0; i < 4; i++) {
        name[w++] = lens[i];
        memset(name + w, 'b', lens[i]);
        w += lens[i];
    }
    name[w++] = 0;
    CHECK(w == 255);
    size_t mlen = build_msg(m, 0x0100, 1, name, w, 1);
    size_t n = udp_wrap(l4, m, mlen, 40000, 53);
    DnsEvent e;
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, (int)n, &e) == 0);

    /* Último rótulo com +1 byte (62): 256 octetos em wire, rejeitado. O tamanho
     * do último rótulo fica no índice 192; o zero final passa de 254 para 255. */
    name[192] = 62;
    name[254] = 'b';
    name[255] = 0;
    w = 256;
    CHECK(w == 256);
    mlen = build_msg(m, 0x0100, 1, name, w, 1);
    n = udp_wrap(l4, m, mlen, 40000, 53);
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, (int)n, &e) == -1);
}

/* QDCOUNT grande: a implementação lê só a primeira pergunta, sem laço. */
static void teste_qdcount_grande(void) {
    uint8_t m[128], l4[160];
    size_t mlen = build_msg(m, 0x0100, 0xFFFF, NAME_EX, NAME_EX_LEN, 1);
    size_t n = udp_wrap(l4, m, mlen, 40000, 53);
    DnsEvent e;
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, (int)n, &e) == 0);
    CHECK_STR(e.qname, "example.com");
}

/* Resposta sem pergunta (QDCOUNT 0): não há qname, não há registro. */
static void teste_sem_pergunta(void) {
    uint8_t m[128], l4[160];
    size_t mlen = build_msg(m, 0x8180, 0, NAME_EX, NAME_EX_LEN, 1);
    size_t n = udp_wrap(l4, m, mlen, 53, 40000);
    DnsEvent e;
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, (int)n, &e) == -1);
}

/* Rótulo com controle, aspas, barra, ponto e UTF-8 inválido: sai escapado, em
 * ASCII imprimível. Aspas ficam (o JSON escapa depois). */
static void teste_bytes_hostis_no_rotulo(void) {
    uint8_t name[32], m[96], l4[128];
    const uint8_t label[7] = { 'a', 0x01, '"', '\\', '.', 0xC3, 0xA9 };
    size_t w = 0;
    name[w++] = (uint8_t)sizeof(label);
    memcpy(name + w, label, sizeof(label));
    w += sizeof(label);
    name[w++] = 0;
    size_t mlen = build_msg(m, 0x0100, 1, name, w, 1);
    size_t n = udp_wrap(l4, m, mlen, 40000, 53);
    DnsEvent e;
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, (int)n, &e) == 0);
    /* a \001 " \\ \. \195 \169 */
    CHECK_STR(e.qname, "a\\001\"\\\\\\.\\195\\169");
}

/* Nome da raiz (sem rótulos): texto ".". */
static void teste_raiz(void) {
    uint8_t name[1] = { 0 }, m[64], l4[96];
    size_t mlen = build_msg(m, 0x0100, 1, name, 1, 1);
    size_t n = udp_wrap(l4, m, mlen, 40000, 53);
    DnsEvent e;
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, (int)n, &e) == 0);
    CHECK_STR(e.qname, ".");
}

/* TCP com o prefixo errado: maior que o segmento, menor que o cabeçalho DNS. */
static void teste_tcp_comprimento_errado(void) {
    uint8_t m[128], l4[160];
    size_t mlen = build_msg(m, 0x0100, 1, NAME_EX, NAME_EX_LEN, 1);
    DnsEvent e;

    size_t n = tcp_wrap(l4, m, mlen, (uint16_t)(mlen + 1), 40000, 53);
    CHECK(dns_log_parse(DNS_PROTO_TCP, l4, (int)n, &e) == -1);

    n = tcp_wrap(l4, m, mlen, 11, 40000, 53);      /* menor que 12 */
    CHECK(dns_log_parse(DNS_PROTO_TCP, l4, (int)n, &e) == -1);

    n = tcp_wrap(l4, m, mlen, 0xFFFF, 40000, 53);
    CHECK(dns_log_parse(DNS_PROTO_TCP, l4, (int)n, &e) == -1);

    /* Data offset inválido (menor que 20 bytes). */
    n = tcp_wrap(l4, m, mlen, (uint16_t)mlen, 40000, 53);
    l4[12] = 4 << 4;
    CHECK(dns_log_parse(DNS_PROTO_TCP, l4, (int)n, &e) == -1);
}

/* Fragmento inicial de resposta grande: o cabeçalho UDP declara o tamanho total,
 * mas o quadro tem só o começo. A pergunta está inteira: registra, com `bytes`
 * igual ao tamanho declarado. */
static void teste_fragmento_inicial(void) {
    uint8_t m[128], l4[160];
    size_t mlen = build_msg(m, 0x8180, 1, NAME_EX, NAME_EX_LEN, 255);
    size_t n = udp_wrap(l4, m, mlen, 53, 40000);
    /* Declara 512 bytes de mensagem, mas só `n` estão no quadro. */
    l4[4] = 0x02; l4[5] = 0x08;                    /* ulen = 520 */
    DnsEvent e;
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, (int)n, &e) == 0);
    CHECK(e.bytes == 512);
    CHECK(e.qtype == 255);
    CHECK(e.resp == 1);
}

/* Cabeçalho UDP com ulen < 8: inválido. */
static void teste_udp_ulen_invalido(void) {
    uint8_t m[128], l4[160];
    size_t mlen = build_msg(m, 0x0100, 1, NAME_EX, NAME_EX_LEN, 1);
    size_t n = udp_wrap(l4, m, mlen, 40000, 53);
    l4[4] = 0; l4[5] = 4;
    DnsEvent e;
    CHECK(dns_log_parse(DNS_PROTO_UDP, l4, (int)n, &e) == -1);
}

/* ------------------------------------------------------------------------- *
 * Render, hash, config e ring                                               *
 * ------------------------------------------------------------------------- */

/* Endereço em texto para os bytes do registro (IPv4 ou IPv6). */
static void set_ip(uint8_t out[16], const char *txt, uint8_t *is_v6) {
    memset(out, 0, 16);
    if (strchr(txt, ':')) {
        inet_pton(AF_INET6, txt, out);
        *is_v6 = 1;
    } else {
        inet_pton(AF_INET, txt, out);
        *is_v6 = 0;
    }
}

static void preenche_evento(DnsEvent *e) {
    memset(e, 0, sizeof(*e));
    e->ts_ms = 1700000000123LL;
    set_ip(e->src, "10.0.0.5", &e->is_v6);
    set_ip(e->dst, "8.8.8.8", &e->is_v6);
    snprintf(e->qname, sizeof(e->qname), "example.com");
    e->qtype = 1;
    e->proto = DNS_PROTO_UDP;
    e->bytes = 29;
}

static void teste_render_json(void) {
    DnsEvent e;
    preenche_evento(&e);
    char out[DNS_LOG_JSON_MAX];
    int n = dns_log_render_json(&e, 1, out, sizeof(out));
    CHECK(n > 0);
    CHECK_STR(out,
        "[{\"event_type\":\"dns\",\"schema_version\":1,\"ts\":1700000000123,"
        "\"proto\":\"UDP\",\"src_ip\":\"10.0.0.5\",\"dst_ip\":\"8.8.8.8\","
        "\"qname\":\"example.com\",\"qtype\":1,\"rcode\":0,\"resp\":0,"
        "\"bytes\":29,\"qname_hashed\":0}]");
}

/* Aspas e barra do qname viram \" e \\ no JSON; o escape do DNS (\.) também. */
static void teste_render_escapa_json(void) {
    DnsEvent e;
    preenche_evento(&e);
    snprintf(e.qname, sizeof(e.qname), "a\"\\.b");
    char out[DNS_LOG_JSON_MAX];
    CHECK(dns_log_render_json(&e, 1, out, sizeof(out)) > 0);
    CHECK(strstr(out, "\"qname\":\"a\\\"\\\\.b\"") != NULL);
}

/* Lote de 2 registros: vírgula entre eles, colchetes fora. */
static void teste_render_lote(void) {
    DnsEvent e[2];
    preenche_evento(&e[0]);
    preenche_evento(&e[1]);
    e[1].resp = 1;
    char out[DNS_LOG_JSON_MAX * 2];
    CHECK(dns_log_render_json(e, 2, out, sizeof(out)) > 0);
    CHECK(strstr(out, "},{\"event_type\"") != NULL);
    CHECK(out[0] == '[' && out[strlen(out) - 1] == ']');
}

/* Buffer pequeno: devolve -1, sem escrever além do limite. */
static void teste_render_sem_espaco(void) {
    DnsEvent e;
    preenche_evento(&e);
    char out[32];
    CHECK(dns_log_render_json(&e, 1, out, sizeof(out)) == -1);
}

static void teste_hash(void) {
    /* Vetores de FNV-1a 64 (ASCII minúsculo). */
    char h[17];
    dns_log_hash_hex("a", h);
    CHECK_STR(h, "af63dc4c8601ec8c");
    dns_log_hash_hex("foobar", h);
    CHECK_STR(h, "85944171f73967e8");

    /* DNS não diferencia caixa: mesmo hash. */
    char h1[17], h2[17];
    dns_log_hash_hex("Example.COM", h1);
    dns_log_hash_hex("example.com", h2);
    CHECK_STR(h1, h2);
    CHECK(strlen(h1) == 16);
}

static void set_env(const char *name, const char *val) {
#ifdef _WIN32
    char buf[256];
    snprintf(buf, sizeof(buf), "%s=%s", name, val ? val : "");
    _putenv(buf);
#else
    if (val) setenv(name, val, 1);
    else     unsetenv(name);
#endif
}

static void teste_config(void) {
    char err[160];

    set_env("AGENT_PROTO_LOGS", NULL);
    set_env("AGENT_PROTO_HASH_NAMES", NULL);
    CHECK(dns_log_config_from_env(err, sizeof(err)) == 0);
    CHECK(g_dns_log_on == 0);

    set_env("AGENT_PROTO_LOGS", "dns");
    CHECK(dns_log_config_from_env(err, sizeof(err)) == 0);
    CHECK(g_dns_log_on == 1);

    set_env("AGENT_PROTO_LOGS", " DNS , dns ");
    CHECK(dns_log_config_from_env(err, sizeof(err)) == 0);
    CHECK(g_dns_log_on == 1);

    /* Tipos ainda não suportados: erro claro (rc 1 na subida). */
    set_env("AGENT_PROTO_LOGS", "dns,tls");
    CHECK(dns_log_config_from_env(err, sizeof(err)) == -1);
    CHECK(strstr(err, "tls") != NULL);
    CHECK(g_dns_log_on == 0);

    set_env("AGENT_PROTO_LOGS", "xyz");
    CHECK(dns_log_config_from_env(err, sizeof(err)) == -1);

    set_env("AGENT_PROTO_LOGS", "dns");
    set_env("AGENT_PROTO_HASH_NAMES", "1");
    CHECK(dns_log_config_from_env(err, sizeof(err)) == 0);
    CHECK(g_dns_log_on == 1);

    set_env("AGENT_PROTO_HASH_NAMES", "sim");
    CHECK(dns_log_config_from_env(err, sizeof(err)) == -1);

    set_env("AGENT_PROTO_LOGS", NULL);
    set_env("AGENT_PROTO_HASH_NAMES", NULL);
    dns_log_set_options(0, 0);
}

static void teste_ring(void) {
    /* Sem start: submit não quebra, pop falha, contadores zerados. */
    DnsEvent e;
    preenche_evento(&e);
    e.ts_ms = 1;
    dns_log_submit(&e, 0);
    CHECK(dns_log_pop(&e) == -1);
    CHECK(dns_log_overflow() == 0);

    CHECK(dns_log_start(4) == 0);
    for (int i = 0; i < 6; i++) {
        DnsEvent x;
        preenche_evento(&x);
        x.bytes = (uint32_t)i;
        x.ts_ms = 1000 + i;
        dns_log_submit(&x, 0);
    }
    /* 4 slots: 2 eventos descartados e contados. */
    CHECK(dns_log_overflow() == 2);
    CHECK(dns_log_depth() == 4);

    DnsEvent out;
    CHECK(dns_log_pop(&out) == 0);
    CHECK(out.bytes == 0);             /* FIFO: o primeiro entrou primeiro */
    CHECK(out.ts_ms == 1000);
    CHECK(dns_log_depth() == 3);
    dns_log_stop();
}

/* Com hash ligado, o JSON sai com o hash no lugar do nome e qname_hashed=1. O
 * ring guarda o texto (a formatação é da thread de logs); nada disso vai ao
 * broker com o nome em claro. */
static void teste_hash_no_json(void) {
    dns_log_set_options(1, 1);
    CHECK(dns_log_start(4) == 0);

    DnsEvent e;
    preenche_evento(&e);
    e.ts_ms = 42;
    dns_log_submit(&e, 0);

    DnsEvent out;
    CHECK(dns_log_pop(&out) == 0);
    CHECK(out.ts_ms == 42);

    char json[DNS_LOG_JSON_MAX];
    CHECK(dns_log_render_json(&out, 1, json, sizeof(json)) > 0);
    char h[17];
    dns_log_hash_hex("example.com", h);
    char esperado[64];
    snprintf(esperado, sizeof(esperado), "\"qname\":\"%s\"", h);
    CHECK(strstr(json, esperado) != NULL);
    CHECK(strstr(json, "\"qname_hashed\":1") != NULL);
    CHECK(strstr(json, "example") == NULL);
    CHECK(strstr(json, "\"src_ip\":\"10.0.0.5\"") != NULL);

    dns_log_stop();
    dns_log_set_options(0, 0);
}

int main(void) {
    setup_names();

    RUN(teste_consulta_udp);
    RUN(teste_resposta_nxdomain);
    RUN(teste_tcp_correto);
    RUN(teste_porta_nao_dns);
    RUN(teste_protocolo_desconhecido);
    RUN(teste_corte_em_cada_campo);
    RUN(teste_ponteiro_em_laco);
    RUN(teste_ponteiro_fora);
    RUN(teste_ponteiro_valido);
    RUN(teste_rotulo_63);
    RUN(teste_nome_255_e_256);
    RUN(teste_qdcount_grande);
    RUN(teste_sem_pergunta);
    RUN(teste_bytes_hostis_no_rotulo);
    RUN(teste_raiz);
    RUN(teste_tcp_comprimento_errado);
    RUN(teste_fragmento_inicial);
    RUN(teste_udp_ulen_invalido);
    RUN(teste_render_json);
    RUN(teste_render_escapa_json);
    RUN(teste_render_lote);
    RUN(teste_render_sem_espaco);
    RUN(teste_hash);
    RUN(teste_config);
    RUN(teste_ring);
    RUN(teste_hash_no_json);

    TEST_EXIT();
}
