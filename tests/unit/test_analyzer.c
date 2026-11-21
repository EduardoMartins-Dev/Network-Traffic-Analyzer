/* Testes do motor IDS (src/agent/analysis/analyzer.c) com pacotes sintéticos e
 * timestamps controlados — o analyzer usa o horário do pacote, então as
 * janelas (brute force, kill chain) são testáveis sem esperar tempo real. */
#include "test.h"
#include "analyzer.h"
#include "collector.h"
#include "nta_net.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- *
 * Stub do publisher: o analyzer publica cada pacote; guardamos o último     *
 * alerta para inspecionar estágio e score da kill chain.                    *
 * ------------------------------------------------------------------------- */
static char last_attack[32], last_stage[16];
static int  last_score;

void publish_packet(const char *src_ip, int port, const char *proto, int bytes,
                    int is_scan, const char *attack_type,
                    const char *kill_chain_stage, int kc_score,
                    const char *mitre_technique) {
    (void)src_ip; (void)port; (void)proto; (void)bytes; (void)mitre_technique;
    if (!is_scan) return;
    snprintf(last_attack, sizeof(last_attack), "%s", attack_type ? attack_type : "");
    snprintf(last_stage,  sizeof(last_stage),  "%s", kill_chain_stage ? kill_chain_stage : "");
    last_score = kc_score;
}

/* ------------------------------------------------------------------------- *
 * Construção de pacotes (Ethernet + IPv4 + TCP/ICMP)                        *
 * ------------------------------------------------------------------------- */
static int build_ip(uint8_t *buf, const char *src, uint8_t proto, int l4_len) {
    memset(buf, 0, 64);
    buf[12] = 0x08; buf[13] = 0x00;                      /* EtherType IPv4 */
    nta_ipv4_hdr *ip = (nta_ipv4_hdr *)(buf + NTA_ETH_HLEN);
    ip->ver_ihl = 0x45;
    ip->tot_len = htons((uint16_t)(20 + l4_len));
    ip->ttl     = 64;
    ip->proto   = proto;
    inet_pton(AF_INET, src, &ip->saddr);
    inet_pton(AF_INET, "192.0.2.1", &ip->daddr);
    return NTA_ETH_HLEN + 20 + l4_len;
}

static void tcp(const char *src, uint16_t dport, uint8_t flags, time_t ts) {
    uint8_t buf[64];
    int len = build_ip(buf, src, NTA_PROTO_TCP, 20);
    nta_tcp_hdr *t = (nta_tcp_hdr *)(buf + NTA_ETH_HLEN + 20);
    t->sport    = htons(40000);
    t->dport    = htons(dport);
    t->data_off = 5 << 4;
    t->flags    = flags;
    analyze_packet(buf, len, ts);
}

static void icmp(const char *src, time_t ts) {
    uint8_t buf[64];
    int len = build_ip(buf, src, NTA_PROTO_ICMP, 8);
    buf[NTA_ETH_HLEN + 20] = 8;                          /* echo request */
    analyze_packet(buf, len, ts);
}

static int detections(const char *attack, const char *ip) {
    int n = 0;
    for (int i = 0; i < collector_count(); i++) {
        const DetectedEvent *d = collector_get(i);
        if (strcmp(d->attack_type, attack) == 0 && strcmp(d->src_ip, ip) == 0) n++;
    }
    return n;
}

static void fresh(void) {
    analyzer_reset();
    collector_reset();
    last_attack[0] = last_stage[0] = '\0';
    last_score = 0;
}

#define T0 ((time_t)1700000000)

/* ------------------------------------------------------------------------- */
static void test_null_scan_no_terceiro_pacote(void) {
    fresh();
    const char *ip = "198.51.100.10";
    tcp(ip, 80, 0, T0);
    tcp(ip, 81, 0, T0);
    CHECK(detections("NULL_SCAN", ip) == 0);
    tcp(ip, 82, 0, T0);
    CHECK(detections("NULL_SCAN", ip) == 1);             /* STEALTH_THRESHOLD = 3 */
}

static void test_brute_force_dentro_da_janela(void) {
    fresh();
    const char *ip = "198.51.100.20";
    for (int i = 0; i < 29; i++) tcp(ip, 22, NTA_TH_SYN, T0 + i);
    CHECK(detections("BRUTE_FORCE", ip) == 0);
    tcp(ip, 22, NTA_TH_SYN, T0 + 29);                    /* 30ª tentativa em 29s */
    CHECK(detections("BRUTE_FORCE", ip) == 1);
}

static void test_brute_force_espalhado_nao_dispara(void) {
    fresh();
    const char *ip = "198.51.100.21";
    /* 40 SYNs para :22, um a cada 3s (117s): a janela de 60s reinicia antes
     * de acumular 30 — não é brute force. */
    for (int i = 0; i < 40; i++) tcp(ip, 22, NTA_TH_SYN, T0 + 3 * i);
    CHECK(detections("BRUTE_FORCE", ip) == 0);
}

static void test_kill_chain_completa(void) {
    fresh();
    const char *ip = "198.51.100.30";
    time_t t = T0;

    for (int p = 0; p < 15; p++) tcp(ip, (uint16_t)(1000 + p), NTA_TH_SYN, t++);
    CHECK_STR(last_attack, "PORT_SCAN");
    CHECK_STR(last_stage, "RECON");
    CHECK(last_score == 20);

    for (int i = 0; i < 30; i++) tcp(ip, 22, NTA_TH_SYN, t++);
    CHECK_STR(last_attack, "BRUTE_FORCE");
    CHECK_STR(last_stage, "EXPLOIT");
    CHECK(last_score == 60);                             /* 50 + bônus: < 5 min */

    for (int i = 0; i < 21; i++) icmp(ip, t++);
    CHECK_STR(last_attack, "ICMP_FLOOD");
    CHECK_STR(last_stage, "COMPLETE");                   /* RECON+EXPLOIT+EXFIL */
    CHECK(last_score == 100);

    /* 1h sem atividade: um novo ataque abre um incidente novo. */
    t += 3600;
    for (int i = 0; i < 3; i++) tcp(ip, (uint16_t)(2000 + i), 0, t);
    CHECK_STR(last_attack, "NULL_SCAN");
    CHECK_STR(last_stage, "RECON");
    CHECK(last_score == 20);
}

static void test_reset_limpa_estado(void) {
    fresh();
    const char *ip = "198.51.100.40";
    tcp(ip, 80, 0, T0);
    tcp(ip, 81, 0, T0);
    analyzer_reset();                                    /* zera contadores */
    tcp(ip, 82, 0, T0);
    CHECK(detections("NULL_SCAN", ip) == 0);
}

/* Entrega só os `len` primeiros bytes num buffer do heap do tamanho exato:
 * qualquer leitura além do fim vira erro do ASan (job sanitizers). */
static int feed_exact(const uint8_t *pkt, int len) {
    uint8_t *buf = malloc((size_t)len);
    memcpy(buf, pkt, (size_t)len);
    int r = analyze_packet(buf, len, T0);
    free(buf);
    return r;
}

static void test_pacotes_malformados(void) {
    fresh();
    const char *ip = "198.51.100.50";
    uint8_t pkt[128];
    nta_ipv4_hdr *iph = (nta_ipv4_hdr *)(pkt + NTA_ETH_HLEN);

    /* TCP completo = 54 bytes; flags=0 (null scan) para que qualquer
     * leitura "bem-sucedida" gerasse detecção. */
    int full = build_ip(pkt, ip, NTA_PROTO_TCP, 20);
    ((nta_tcp_hdr *)(pkt + NTA_ETH_HLEN + 20))->data_off = 5 << 4;

    for (int i = 0; i < 3; i++) {
        CHECK(feed_exact(pkt, NTA_ETH_HLEN + 10) == 0);   /* IPv4 cortado      */
        CHECK(feed_exact(pkt, NTA_ETH_HLEN + 20 + 10) == 0); /* TCP cortado    */
    }
    CHECK(feed_exact(pkt, 0) == 0);
    CHECK(feed_exact(pkt, 13) == 0);

    iph->ver_ihl = 0x4F;                         /* IHL=15 (60 bytes) > pacote */
    CHECK(feed_exact(pkt, full) == 0);
    iph->ver_ihl = 0x42;                         /* IHL=2 (8 bytes) < mínimo 20 */
    CHECK(feed_exact(pkt, full) == 0);
    iph->ver_ihl = 0x45;

    /* UDP para :53 com só 1 byte de payload DNS (flags ficam além do fim). */
    int udp_full = build_ip(pkt, ip, NTA_PROTO_UDP, 8 + 1);
    ((nta_udp_hdr *)(pkt + NTA_ETH_HLEN + 20))->dport = htons(53);
    CHECK(feed_exact(pkt, udp_full) == 0);
    CHECK(feed_exact(pkt, NTA_ETH_HLEN + 20 + 4) == 0);  /* UDP cortado */

    /* ARP menor que os 42 bytes do reply */
    uint8_t arp[30] = {0};
    arp[12] = 0x08; arp[13] = 0x06;
    CHECK(feed_exact(arp, sizeof(arp)) == 0);

    CHECK(collector_count() == 0);               /* nada malformado vira alerta */
}

/* Pacote UDP com payload DNS de `dns_len` bytes. Consulta: src=cliente, dst=
 * servidor (porta 53). Resposta: src=servidor (porta 53), dst=cliente. QR fica
 * no bit 7 do byte 2 do cabeçalho DNS. */
static void udp_dns(const char *src, const char *dst, int resp, int dns_len, time_t ts) {
    uint8_t buf[512];
    int udp_len = 8 + dns_len;
    memset(buf, 0, sizeof(buf));
    buf[12] = 0x08; buf[13] = 0x00;                      /* EtherType IPv4 */
    nta_ipv4_hdr *ip = (nta_ipv4_hdr *)(buf + NTA_ETH_HLEN);
    ip->ver_ihl = 0x45;
    ip->tot_len = htons((uint16_t)(20 + udp_len));
    ip->ttl     = 64;
    ip->proto   = NTA_PROTO_UDP;
    inet_pton(AF_INET, src, &ip->saddr);
    inet_pton(AF_INET, dst, &ip->daddr);
    nta_udp_hdr *u = (nta_udp_hdr *)(buf + NTA_ETH_HLEN + 20);
    u->sport = htons(resp ? 53 : 40000);
    u->dport = htons(resp ? 40000 : 53);
    u->len   = htons((uint16_t)udp_len);
    buf[NTA_ETH_HLEN + 20 + 8 + 2] = resp ? 0x81 : 0x01;  /* QR + RD */
    analyze_packet(buf, NTA_ETH_HLEN + 20 + udp_len, ts);
}

/* Refletor que só envia respostas: as consultas saem com o IP da vítima como
 * origem (forjada) e chegam ao refletor. O alerta tem que sair pelo IP do
 * refletor, e a vítima não pode ser marcada. */
static void test_refletor_puro_dispara(void) {
    fresh();
    const char *vit = "192.168.1.10", *ref = "203.0.113.53";
    for (int i = 0; i < 3; i++) udp_dns(vit, ref, 0, 29, T0 + i);     /* 71 B cada */
    for (int i = 0; i < 10; i++) udp_dns(ref, vit, 1, 242, T0 + 3 + i); /* 284 B cada */
    CHECK(detections("AMPLIFICATION", ref) >= 1);
    CHECK(detections("AMPLIFICATION", vit) == 0);
}

/* DNS normal: cada consulta de 71 B gera resposta de 128 B (1,8x). Nada pode
 * disparar, nem no cliente nem no resolvedor. */
static void test_dns_normal_nao_dispara(void) {
    fresh();
    const char *cli = "198.51.100.20", *res = "203.0.113.53";
    for (int i = 0; i < 20; i++) {
        udp_dns(cli, res, 0, 29, T0 + i);
        udp_dns(res, cli, 1, 86, T0 + i);
    }
    CHECK(detections("AMPLIFICATION", res) == 0);
    CHECK(detections("AMPLIFICATION", cli) == 0);
}

/* Regressão: consultas para 110 servidores distintos não podem consumir as 100
 * vagas de suspeitos. Se consumirem, o port scan que vem depois é ignorado. */
static void test_exaustao_dns_nao_cega_port_scan(void) {
    fresh();
    const char *cli = "198.51.100.20", *scan = "192.168.1.100";
    char srv[16];
    for (int i = 0; i < 110; i++) {
        snprintf(srv, sizeof(srv), "203.0.113.%d", i + 1);
        udp_dns(cli, srv, 0, 29, T0 + i);
    }
    for (int p = 0; p < 30; p++) tcp(scan, (uint16_t)(1000 + p), NTA_TH_SYN, T0 + 110 + p);
    CHECK(detections("PORT_SCAN", scan) >= 1);
}

static void test_home_net(void) {
    CHECK(analyzer_add_home_cidr("300.1.1.1/8") == -1);
    CHECK(analyzer_add_home_cidr("10.0.0.0/33") == -1);
    CHECK(analyzer_add_home_cidr("") == -1);
    CHECK(analyzer_add_home_cidr("10.0.0.0/8") == 0);

    fresh();
    for (int i = 0; i < 5; i++) tcp("10.9.9.9", (uint16_t)(80 + i), 0, T0);
    CHECK(detections("NULL_SCAN", "10.9.9.9") == 0);     /* ignorado: HOME_NET */
    for (int i = 0; i < 5; i++) tcp("11.9.9.9", (uint16_t)(80 + i), 0, T0);
    CHECK(detections("NULL_SCAN", "11.9.9.9") == 3);     /* fora do /8: 3º, 4º e 5º alertam */

    /* Limitação documentada: a vítima em HOME_NET envia consultas forjadas com
     * origem própria, e o skip de HOME_NET as descarta antes da contagem. Sem
     * request visível, o refletor fica sem denominador e não dispara. */
    fresh();
    for (int i = 0; i < 3; i++) udp_dns("10.1.1.1", "11.9.9.9", 0, 29, T0 + i);
    for (int i = 0; i < 10; i++) udp_dns("11.9.9.9", "10.1.1.1", 1, 242, T0 + 3 + i);
    CHECK(detections("AMPLIFICATION", "11.9.9.9") == 0);
}

/* ------------------------------------------------------------------------- *
 * IPv6 (B09): Ethernet (EtherType 0x86DD) + cabeçalho fixo de 40 bytes.     *
 * O L4 começa em NTA_ETH_HLEN + 40 = 54, sem extensões salvo onde o teste   *
 * pede. Todo IPv6 de teste usa endereços de documentação (RFC 3849).        *
 * ------------------------------------------------------------------------- */
#define IP6_DST  "2001:db8:2::9"
#define IP6_L4   (NTA_ETH_HLEN + NTA_IPV6_HLEN)

static int build_ip6(uint8_t *buf, const char *src, const char *dst,
                     uint8_t next_hdr, int payload_len) {
    memset(buf, 0, 128);
    buf[12] = 0x86; buf[13] = 0xDD;                      /* EtherType IPv6 */
    nta_ipv6_hdr *ip = (nta_ipv6_hdr *)(buf + NTA_ETH_HLEN);
    ip->ver_tc_flow[0] = 0x60;                           /* versão 6 */
    ip->payload_len    = htons((uint16_t)payload_len);
    ip->next_hdr       = next_hdr;
    ip->hop_limit      = 64;
    inet_pton(AF_INET6, src, ip->saddr);
    inet_pton(AF_INET6, dst, ip->daddr);
    return NTA_ETH_HLEN + NTA_IPV6_HLEN + payload_len;
}

static void tcp6(const char *src, uint16_t dport, uint8_t flags, time_t ts) {
    uint8_t buf[128];
    int len = build_ip6(buf, src, IP6_DST, NTA_PROTO_TCP, 20);
    nta_tcp_hdr *t = (nta_tcp_hdr *)(buf + IP6_L4);
    t->sport    = htons(40000);
    t->dport    = htons(dport);
    t->data_off = 5 << 4;
    t->flags    = flags;
    analyze_packet(buf, len, ts);
}

static void icmp6(const char *src, uint8_t type, time_t ts) {
    uint8_t buf[128];
    int len = build_ip6(buf, src, IP6_DST, NTA_PROTO_ICMPV6, 8);
    buf[IP6_L4] = type;
    analyze_packet(buf, len, ts);
}

/* UDP sobre IPv6 com `payload` (dns_len bytes). Consulta: src=cliente, dst=
 * servidor, porta 53. Resposta: o inverso. */
static void udp6_send(const char *src, const char *dst, int resp,
                      const uint8_t *payload, int dns_len, time_t ts) {
    uint8_t buf[512];
    int udp_len = 8 + dns_len;
    memset(buf, 0, sizeof(buf));
    int len = build_ip6(buf, src, dst, NTA_PROTO_UDP, udp_len);
    nta_udp_hdr *u = (nta_udp_hdr *)(buf + IP6_L4);
    u->sport = htons(resp ? 53 : 40000);
    u->dport = htons(resp ? 40000 : 53);
    u->len   = htons((uint16_t)udp_len);
    memcpy(buf + IP6_L4 + 8, payload, (size_t)dns_len);
    analyze_packet(buf, len, ts);
}

/* Payload DNS de `dns_len` bytes zerados, com QR no bit 7 do byte 2. */
static void udp6_dns(const char *src, const char *dst, int resp, int dns_len, time_t ts) {
    uint8_t dns[300];
    memset(dns, 0, sizeof(dns));
    dns[2] = resp ? 0x81 : 0x01;                         /* QR + RD */
    udp6_send(src, dst, resp, dns, dns_len, ts);
}

/* Consulta DNS com um nome de `label_len` caracteres no primeiro label. */
static void udp6_query_label(const char *src, const char *dst, int label_len, time_t ts) {
    uint8_t dns[200];
    memset(dns, 0, sizeof(dns));
    dns[2] = 0x01;                                       /* RD */
    dns[5] = 1;                                          /* QDCOUNT = 1 */
    int pos = 12;
    dns[pos++] = (uint8_t)label_len;
    for (int i = 0; i < label_len; i++) dns[pos++] = (uint8_t)('a' + (i % 26));
    dns[pos++] = 3; memcpy(dns + pos, "com", 3); pos += 3;
    dns[pos++] = 0;
    pos += 4;                                            /* QTYPE + QCLASS */
    udp6_send(src, dst, 0, dns, pos, ts);
}

static void test_ipv6_detectores_basicos(void) {
    fresh();
    /* Endereço longo: o texto canônico tem 35 caracteres. Com buffer de 16
     * bytes (o antigo) sairia truncado e nenhuma detecção casaria. */
    const char *scan = "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1";
    for (int p = 0; p < 15; p++) tcp6(scan, (uint16_t)(1000 + p), NTA_TH_SYN, T0 + p);
    CHECK(detections("PORT_SCAN", scan) == 1);

    const char *nul = "2001:db8:a::100", *xm = "2001:db8:a::101", *sf = "2001:db8:a::102";
    for (int i = 0; i < 3; i++) {
        tcp6(nul, (uint16_t)(80 + i), 0, T0 + i);
        tcp6(xm,  (uint16_t)(80 + i), NTA_TH_FIN | NTA_TH_PUSH | NTA_TH_URG, T0 + i);
        tcp6(sf,  (uint16_t)(80 + i), NTA_TH_SYN | NTA_TH_FIN, T0 + i);
    }
    CHECK(detections("NULL_SCAN", nul) == 1);
    CHECK(detections("XMAS_SCAN", xm) == 1);
    CHECK(detections("SYNFIN_SCAN", sf) == 1);

    const char *syn = "2001:db8:a::103", *bf = "2001:db8:a::104";
    for (int i = 0; i < 101; i++) tcp6(syn, 80, NTA_TH_SYN, T0 + i);
    CHECK(detections("SYN_FLOOD", syn) >= 1);
    for (int i = 0; i < 30; i++) tcp6(bf, 22, NTA_TH_SYN, T0 + i);
    CHECK(detections("BRUTE_FORCE", bf) == 1);
}

static void test_ipv6_dns_tunnel_e_icmp_flood(void) {
    fresh();
    const char *tun = "2001:db8:a::200";
    for (int i = 0; i < 10; i++) udp6_query_label(tun, "2001:db8:53::1", 60, T0 + i);
    CHECK(detections("DNS_TUNNEL", tun) == 1);

    const char *ping = "2001:db8:a::201";
    for (int i = 0; i < 21; i++) icmp6(ping, NTA_ICMPV6_ECHO_REQUEST, T0 + i);
    CHECK(detections("ICMP_FLOOD", ping) >= 1);

    /* Respostas de echo (129) não contam para o flood: só echo request. */
    const char *reply = "2001:db8:a::202";
    for (int i = 0; i < 30; i++) icmp6(reply, 129, T0 + i);
    CHECK(detections("ICMP_FLOOD", reply) == 0);
}

/* O número do protocolo ICMP depende da família (1 em IPv4, 58 em IPv6). Um
 * número não pode valer no outro: IPv4 com proto 58 e IPv6 com próximo cabeçalho
 * 1 não são ICMP e não podem alertar, mesmo com 30 echo requests. */
static void test_icmp_depende_da_familia(void) {
    fresh();
    const char *a = "198.51.100.61";
    for (int i = 0; i < 30; i++) {
        uint8_t buf[64];
        int len = build_ip(buf, a, NTA_PROTO_ICMPV6, 8);
        buf[NTA_ETH_HLEN + 20] = NTA_ICMPV6_ECHO_REQUEST;
        analyze_packet(buf, len, T0 + i);
    }
    CHECK(detections("ICMP_FLOOD", a) == 0);

    const char *b = "2001:db8:a::61";
    for (int i = 0; i < 30; i++) {
        uint8_t buf[128];
        int len = build_ip6(buf, b, IP6_DST, NTA_PROTO_ICMP, 8);
        buf[IP6_L4] = NTA_ICMPV6_ECHO_REQUEST;
        analyze_packet(buf, len, T0 + i);
    }
    CHECK(detections("ICMP_FLOOD", b) == 0);
}

/* Refletor IPv6 que só envia respostas; consultas saem com a vítima como origem
 * forjada. Mesmo critério do IPv4: o alerta sai pelo refletor. */
static void test_ipv6_refletor_dispara(void) {
    fresh();
    const char *vit = "2001:db8:1::10", *ref = "2001:db8:3::53";
    for (int i = 0; i < 3; i++) udp6_dns(vit, ref, 0, 29, T0 + i);
    for (int i = 0; i < 10; i++) udp6_dns(ref, vit, 1, 242, T0 + 3 + i);
    CHECK(detections("AMPLIFICATION", ref) >= 1);
    CHECK(detections("AMPLIFICATION", vit) == 0);
}

static void test_ipv6_dns_normal_nao_dispara(void) {
    fresh();
    const char *cli = "2001:db8:4::20", *res = "2001:db8:3::53";
    for (int i = 0; i < 20; i++) {
        udp6_dns(cli, res, 0, 29, T0 + i);
        udp6_dns(res, cli, 1, 86, T0 + i);
    }
    CHECK(detections("AMPLIFICATION", res) == 0);
    CHECK(detections("AMPLIFICATION", cli) == 0);
    CHECK(collector_count() == 0);
}

/* Cabeçalho de extensão Hop-by-Hop (8 bytes, next = TCP) antes do TCP. */
static void tcp6_hbh(const char *src, uint16_t dport, uint8_t flags, time_t ts) {
    uint8_t buf[128];
    int len = build_ip6(buf, src, IP6_DST, NTA_PROTO_HOPOPT, 8 + 20);
    nta_ipv6_ext_hdr *e = (nta_ipv6_ext_hdr *)(buf + IP6_L4);
    e->next_hdr   = NTA_PROTO_TCP;
    e->hdr_ext_len = 0;                                  /* 8 bytes */
    nta_tcp_hdr *t = (nta_tcp_hdr *)(buf + IP6_L4 + 8);
    t->sport    = htons(40000);
    t->dport    = htons(dport);
    t->data_off = 5 << 4;
    t->flags    = flags;
    analyze_packet(buf, len, ts);
}

static void test_ipv6_extensao_e_fragmento(void) {
    fresh();
    /* Hop-by-Hop antes do TCP: a camada superior é achada e analisada. */
    const char *hbh = "2001:db8:a::300";
    for (int i = 0; i < 3; i++) tcp6_hbh(hbh, (uint16_t)(80 + i), 0, T0 + i);
    CHECK(detections("NULL_SCAN", hbh) == 1);

    /* Fragmento inicial (offset 0): tem o L4, então é analisado. */
    uint8_t buf[128];
    const char *frag0 = "2001:db8:a::301";
    for (int i = 0; i < 3; i++) {
        int len = build_ip6(buf, frag0, IP6_DST, NTA_PROTO_FRAGMENT, 8 + 20);
        nta_ipv6_frag_hdr *f = (nta_ipv6_frag_hdr *)(buf + IP6_L4);
        f->next_hdr   = NTA_PROTO_TCP;
        f->frag_off_m = htons(0x0001);                   /* offset 0, M = 1 */
        nta_tcp_hdr *t = (nta_tcp_hdr *)(buf + IP6_L4 + 8);
        t->dport    = htons((uint16_t)(80 + i));
        t->data_off = 5 << 4;
        t->flags    = 0;
        analyze_packet(buf, len, T0 + i);
    }
    CHECK(detections("NULL_SCAN", frag0) == 1);

    /* Fragmento não inicial (offset 1 = 8 bytes): não tem L4. Três pacotes
     * nulos não podem gerar NULL_SCAN; se fossem lidos, gerariam. */
    const char *fragn = "2001:db8:a::302";
    for (int i = 0; i < 3; i++) {
        int len = build_ip6(buf, fragn, IP6_DST, NTA_PROTO_FRAGMENT, 8 + 20);
        nta_ipv6_frag_hdr *f = (nta_ipv6_frag_hdr *)(buf + IP6_L4);
        f->next_hdr   = NTA_PROTO_TCP;
        f->frag_off_m = htons(0x0008);                   /* offset 8 bytes */
        nta_tcp_hdr *t = (nta_tcp_hdr *)(buf + IP6_L4 + 8);
        t->dport    = htons((uint16_t)(80 + i));
        t->data_off = 5 << 4;
        t->flags    = 0;
        analyze_packet(buf, len, T0 + i);
    }
    CHECK(detections("NULL_SCAN", fragn) == 0);
}

/* Entrega só os `len` bytes em heap exato: ler além do fim vira erro do ASan. */
static int feed6_exact(const uint8_t *pkt, int len) {
    uint8_t *buf = malloc((size_t)len);
    memcpy(buf, pkt, (size_t)len);
    int r = analyze_packet(buf, len, T0);
    free(buf);
    return r;
}

static void test_ipv6_malformados(void) {
    fresh();
    const char *ip = "2001:db8:a::400";
    uint8_t pkt[128];

    /* TCP completo (IPv6 + 20 bytes) com flags 0: null scan se for lido. */
    int full = build_ip6(pkt, ip, IP6_DST, NTA_PROTO_TCP, 20);
    ((nta_tcp_hdr *)(pkt + IP6_L4))->data_off = 5 << 4;

    CHECK(feed6_exact(pkt, NTA_ETH_HLEN + 10) == 0);     /* IPv6 cortado         */
    CHECK(feed6_exact(pkt, NTA_ETH_HLEN + NTA_IPV6_HLEN - 1) == 0);
    CHECK(feed6_exact(pkt, IP6_L4 + 10) == 0);           /* TCP cortado          */
    CHECK(feed6_exact(pkt, IP6_L4) == 0);                /* sem L4 nenhum        */

    pkt[NTA_ETH_HLEN] = 0x40;                            /* versão 4 com EtherType 6 */
    CHECK(feed6_exact(pkt, full) == 0);
    pkt[NTA_ETH_HLEN] = 0x60;

    /* Hop-by-Hop com hdr_ext_len = 255: 2048 bytes, bem além do quadro. */
    uint8_t ext[128];
    int elen = build_ip6(ext, ip, IP6_DST, NTA_PROTO_HOPOPT, 8 + 20);
    ((nta_ipv6_ext_hdr *)(ext + IP6_L4))->hdr_ext_len = 255;
    ((nta_ipv6_ext_hdr *)(ext + IP6_L4))->next_hdr    = NTA_PROTO_TCP;
    CHECK(feed6_exact(ext, elen) == 0);

    /* Extensão no fim do quadro: o próprio cabeçalho de 2 bytes não cabe. */
    int hb = build_ip6(ext, ip, IP6_DST, NTA_PROTO_HOPOPT, 1);
    CHECK(feed6_exact(ext, hb) == 0);

    /* Cadeia de 9 extensões Hop-by-Hop (limite é 8): descartada. */
    uint8_t chain[NTA_ETH_HLEN + NTA_IPV6_HLEN + 9 * 8 + 20];
    memset(chain, 0, sizeof(chain));
    int clen = build_ip6(chain, ip, IP6_DST, NTA_PROTO_HOPOPT, 9 * 8 + 20);
    for (int i = 0; i < 9; i++) {
        nta_ipv6_ext_hdr *e = (nta_ipv6_ext_hdr *)(chain + IP6_L4 + i * 8);
        e->next_hdr    = (i == 8) ? NTA_PROTO_TCP : NTA_PROTO_HOPOPT;
        e->hdr_ext_len = 0;
    }
    nta_tcp_hdr *ct = (nta_tcp_hdr *)(chain + IP6_L4 + 9 * 8);
    ct->data_off = 5 << 4;
    ct->flags    = 0;                                    /* null scan se analisado */
    /* Três pacotes: NULL_SCAN dispara no 3º se a cadeia for analisada. Nada
     * pode ser registrado (checado no fim da função). */
    for (int i = 0; i < 3; i++) CHECK(feed6_exact(chain, clen) == 0);

    /* AH com tamanho que passa do quadro. */
    uint8_t ah[128];
    int alen = build_ip6(ah, ip, IP6_DST, NTA_PROTO_AH, 8 + 20);
    ((nta_ipv6_ext_hdr *)(ah + IP6_L4))->hdr_ext_len = 255;
    CHECK(feed6_exact(ah, alen) == 0);

    /* ESP e "No Next Header": sem camada superior, descartados. */
    int esp_len = build_ip6(ah, ip, IP6_DST, NTA_PROTO_ESP, 20);
    CHECK(feed6_exact(ah, esp_len) == 0);
    int nn_len = build_ip6(ah, ip, IP6_DST, NTA_PROTO_NONEXT, 0);
    CHECK(feed6_exact(ah, nn_len) == 0);

    /* Fragmento cortado no meio do cabeçalho de 8 bytes. */
    int flen = build_ip6(ah, ip, IP6_DST, NTA_PROTO_FRAGMENT, 8);
    CHECK(feed6_exact(ah, flen - 3) == 0);

    /* ICMPv6 sem os 4 bytes do cabeçalho; UDP cortado; DNS com 1 byte. */
    int il = build_ip6(ah, ip, IP6_DST, NTA_PROTO_ICMPV6, 2);
    CHECK(feed6_exact(ah, il) == 0);
    uint8_t dnsb[128];
    memset(dnsb, 0, sizeof(dnsb));
    int ul = build_ip6(dnsb, ip, IP6_DST, NTA_PROTO_UDP, 8 + 1);
    ((nta_udp_hdr *)(dnsb + IP6_L4))->dport = htons(53);
    CHECK(feed6_exact(dnsb, ul) == 0);
    CHECK(feed6_exact(dnsb, IP6_L4 + 4) == 0);

    CHECK(collector_count() == 0);                       /* nada malformado vira alerta */
}

/* Exaustão por origens IPv6 (B09): 110 origens IPv6 distintas consomem as
 * vagas de IPv6, não as de IPv4. O port scan IPv4 que vem depois tem que
 * continuar detectado. */
static void test_exaustao_origens_ipv6_nao_cega_ipv4(void) {
    fresh();
    char src[48];
    for (int i = 0; i < 110; i++) {
        snprintf(src, sizeof(src), "2001:db8:b::%x", i + 1);
        tcp6(src, 80, NTA_TH_SYN, T0 + i);
    }
    const char *scan = "192.168.1.100";
    for (int p = 0; p < 30; p++) tcp(scan, (uint16_t)(1000 + p), NTA_TH_SYN, T0 + 110 + p);
    CHECK(detections("PORT_SCAN", scan) >= 1);
}

/* Mesma regressão de B28, em IPv6: 110 clientes IPv6 distintos consultando 110
 * servidores IPv6 distintos esgotam as tabelas da família IPv6 (suspects[] e
 * srv_req são particionadas por família) e não podem cegar o port scan IPv4.
 * Os endereços são IPv6 de verdade: com um destino IPv4 o inet_pton(AF_INET6)
 * falha e as 110 consultas iriam todas para "::". */
static void test_exaustao_dns_ipv6_nao_cega_ipv4(void) {
    fresh();
    const char *scan = "192.168.1.100";
    char cli[40], srv[40];
    for (int i = 0; i < 110; i++) {
        snprintf(cli, sizeof(cli), "2001:db8:c::%x", i + 1);
        snprintf(srv, sizeof(srv), "2001:db8:5::%x", i + 1);
        udp6_dns(cli, srv, 0, 29, T0 + i);
    }
    for (int p = 0; p < 30; p++) tcp(scan, (uint16_t)(1000 + p), NTA_TH_SYN, T0 + 110 + p);
    CHECK(detections("PORT_SCAN", scan) >= 1);
}

/* ------------------------------------------------------------------------- *
 * VLAN (802.1Q / 802.1ad) e fragmentação IPv4 (B10).                        *
 * add_tags() insere tags depois dos MACs; o EtherType original fica depois  *
 * delas. Os quadros são montados em buffers de 128 bytes (cabem as 4 tags). *
 * ------------------------------------------------------------------------- */
#define IP4_MF 0x2000u               /* bit "more fragments" do frag_off */

static int add_tags(uint8_t *buf, int len, const uint16_t *tpids, int ntags) {
    if (ntags == 0) return len;
    memmove(buf + 12 + 4 * ntags, buf + 12, (size_t)(len - 12));
    for (int i = 0; i < ntags; i++) {
        buf[12 + 4 * i] = (uint8_t)(tpids[i] >> 8);
        buf[13 + 4 * i] = (uint8_t)(tpids[i] & 0xFF);
        buf[14 + 4 * i] = 0x00;                       /* PCP 0 / DEI 0 */
        buf[15 + 4 * i] = (uint8_t)(i + 1);           /* VID = i + 1 */
    }
    return len + 4 * ntags;
}

/* TCP sobre IPv4 com `ntags` tags (TPIDs em `tpids`; ntags = 0 sem tag). */
static int tcp_build(uint8_t *buf, const char *src, uint16_t dport, uint8_t flags,
                     const uint16_t *tpids, int ntags) {
    int len = build_ip(buf, src, NTA_PROTO_TCP, 20);
    nta_tcp_hdr *t = (nta_tcp_hdr *)(buf + NTA_ETH_HLEN + 20);
    t->sport    = htons(40000);
    t->dport    = htons(dport);
    t->data_off = 5 << 4;
    t->flags    = flags;
    return add_tags(buf, len, tpids, ntags);
}

static void tcp_tag(const char *src, uint16_t dport, uint8_t flags,
                    const uint16_t *tpids, int ntags, time_t ts) {
    uint8_t buf[128];
    int len = tcp_build(buf, src, dport, flags, tpids, ntags);
    analyze_packet(buf, len, ts);
}

/* ARP reply (op=2) de `mac` reivindicando `ip`, com tags opcionais. */
static int arp_build(uint8_t *buf, const uint8_t mac[6], const char *ip,
                     const uint16_t *tpids, int ntags) {
    memset(buf, 0, 64);
    memset(buf, 0xFF, 6);                             /* broadcast */
    memcpy(buf + 6, mac, 6);
    buf[12] = 0x08; buf[13] = 0x06;                   /* EtherType ARP */
    uint8_t *a = buf + NTA_ETH_HLEN;
    a[1] = 1;                                         /* htype Ethernet */
    a[2] = 0x08;                                      /* ptype IPv4 */
    a[4] = 6; a[5] = 4;                               /* hlen, plen */
    a[7] = 2;                                         /* op = reply */
    memcpy(a + 8, mac, 6);                            /* sender MAC */
    inet_pton(AF_INET, ip, a + 14);                   /* sender IP */
    return add_tags(buf, NTA_ETH_HLEN + 28, tpids, ntags);
}

/* IPv4 fragmento: `frag` é o campo frag_off em ordem de host (MF no bit 13,
 * offset em unidades de 8 bytes). tot_len = 20 + plen, como o emissor grava.
 * `total` é o tamanho do quadro: bytes além do datagrama são padding. */
static int frag_build(uint8_t *buf, const char *src, uint8_t proto, uint16_t frag,
                      const uint8_t *payload, int plen, int total) {
    memset(buf, 0, 128);
    buf[12] = 0x08; buf[13] = 0x00;
    nta_ipv4_hdr *ip = (nta_ipv4_hdr *)(buf + NTA_ETH_HLEN);
    ip->ver_ihl  = 0x45;
    ip->tot_len  = htons((uint16_t)(20 + plen));
    ip->frag_off = htons(frag);
    ip->ttl      = 64;
    ip->proto    = proto;
    inet_pton(AF_INET, src, &ip->saddr);
    inet_pton(AF_INET, "192.0.2.1", &ip->daddr);
    memcpy(buf + NTA_ETH_HLEN + 20, payload, (size_t)plen);
    return total;
}

/* Cabeçalho TCP de 20 bytes com porta de destino e flags. */
static void tcp_seg20(uint8_t seg[20], uint16_t dport, uint8_t flags) {
    memset(seg, 0, 20);
    nta_tcp_hdr *t = (nta_tcp_hdr *)seg;
    t->sport    = htons(40000);
    t->dport    = htons(dport);
    t->data_off = 5 << 4;
    t->flags    = flags;
}

/* 802.1Q, QinQ e sem tag: o mesmo scan tem que dar o mesmo alerta. */
static void test_vlan_e_qinq_mesmas_deteccoes(void) {
    static const uint16_t vlan[] = { NTA_ETH_TYPE_VLAN };
    static const uint16_t qinq[] = { NTA_ETH_TYPE_QINQ, NTA_ETH_TYPE_VLAN };
    fresh();
    for (int p = 0; p < 15; p++) {
        tcp_tag("198.51.100.70", (uint16_t)(1000 + p), NTA_TH_SYN, NULL, 0, T0 + p);
        tcp_tag("198.51.100.71", (uint16_t)(1000 + p), NTA_TH_SYN, vlan, 1, T0 + p);
        tcp_tag("198.51.100.72", (uint16_t)(1000 + p), NTA_TH_SYN, qinq, 2, T0 + p);
    }
    CHECK(detections("PORT_SCAN", "198.51.100.70") == 1);
    CHECK(detections("PORT_SCAN", "198.51.100.71") == 1);
    CHECK(detections("PORT_SCAN", "198.51.100.72") == 1);
    CHECK(collector_count() == 3);

    analyzer_stats_t st;
    analyzer_get_stats(&st);
    CHECK(st.vlan_frames == 30);                      /* 15 com 1 tag + 15 com 2 */
    CHECK(st.frag_seen == 0 && st.frag_discarded == 0);
}

/* ARP com tag: o MAC aprendido sem tag e depois reivindicando outro IP com tag
 * tem que disparar ARP_SPOOF com o IP reivindicado (offsets do ARP com VLAN). */
static void test_arp_com_vlan(void) {
    static const uint16_t vlan[] = { NTA_ETH_TYPE_VLAN };
    static const uint8_t mac[6] = { 0x02, 0x42, 0xAC, 0x11, 0x00, 0x64 };
    uint8_t buf[128];
    fresh();
    int len = arp_build(buf, mac, "192.168.1.100", NULL, 0);
    analyze_packet(buf, len, T0);                     /* MAC aprende o IP */
    len = arp_build(buf, mac, "192.168.1.1", vlan, 1);
    analyze_packet(buf, len, T0 + 1);
    CHECK(detections("ARP_SPOOF", "192.168.1.1") == 1);
}

/* Profundidade: 4 tags (o limite) são analisadas; 5 tags são descartadas. */
static void test_vlan_profundidade_limite(void) {
    static const uint16_t four[] = { NTA_ETH_TYPE_QINQ, NTA_ETH_TYPE_VLAN,
                                     NTA_ETH_TYPE_VLAN, NTA_ETH_TYPE_VLAN };
    static const uint16_t five[] = { NTA_ETH_TYPE_QINQ, NTA_ETH_TYPE_VLAN,
                                     NTA_ETH_TYPE_VLAN, NTA_ETH_TYPE_VLAN,
                                     NTA_ETH_TYPE_VLAN };
    fresh();
    /* NULL_SCAN dispara no 3º pacote nulo. */
    for (int i = 0; i < 3; i++) tcp_tag("198.51.100.80", (uint16_t)(80 + i), 0, four, 4, T0 + i);
    CHECK(detections("NULL_SCAN", "198.51.100.80") == 1);
    for (int i = 0; i < 3; i++) tcp_tag("198.51.100.81", (uint16_t)(80 + i), 0, five, 5, T0 + i);
    CHECK(detections("NULL_SCAN", "198.51.100.81") == 0);
}

/* Quadro cortado em qualquer byte, inclusive no meio de uma tag: não pode ler
 * além do que foi entregue (heap de tamanho exato, para o ASan). */
static void test_vlan_truncada_em_qualquer_byte(void) {
    static const uint16_t qinq[] = { NTA_ETH_TYPE_QINQ, NTA_ETH_TYPE_VLAN };
    static const uint16_t five[] = { NTA_ETH_TYPE_QINQ, NTA_ETH_TYPE_VLAN,
                                     NTA_ETH_TYPE_VLAN, NTA_ETH_TYPE_VLAN,
                                     NTA_ETH_TYPE_VLAN };
    fresh();
    uint8_t pkt[128];
    int full = tcp_build(pkt, "198.51.100.82", 80, 0, qinq, 2);
    for (int cut = 1; cut <= full; cut++) feed_exact(pkt, cut);

    int full5 = tcp_build(pkt, "198.51.100.83", 80, 0, five, 5);
    for (int cut = 1; cut <= full5; cut++) feed_exact(pkt, cut);

    CHECK(collector_count() == 0);                    /* nenhum corte alerta */
}

/* Fragmento não inicial (offset != 0): o começo do payload parece um TCP SYN
 * com portas distintas. Antes do B10 virava PORT_SCAN; agora é descartado e
 * contado. */
static void test_frag_nao_inicial_nao_vira_l4(void) {
    fresh();
    const char *src = "198.51.100.90";
    uint8_t seg[20], buf[128];
    for (int i = 0; i < 30; i++) {
        tcp_seg20(seg, (uint16_t)(1000 + i), NTA_TH_SYN);
        int len = frag_build(buf, src, NTA_PROTO_TCP, (uint16_t)(1 + i), seg, 20,
                             NTA_ETH_HLEN + 20 + 20);
        analyze_packet(buf, len, T0 + i);
    }
    CHECK(detections("PORT_SCAN", src) == 0);
    CHECK(detections("SYN_FLOOD", src) == 0);
    CHECK(collector_count() == 0);

    analyzer_stats_t st;
    analyzer_get_stats(&st);
    CHECK(st.frag_seen == 30);
    CHECK(st.frag_discarded == 30);
}

/* Fragmento inicial (offset 0, MF=1) com o cabeçalho TCP inteiro: é analisado. */
static void test_frag_inicial_com_l4_inteiro_analisado(void) {
    fresh();
    const char *src = "198.51.100.91";
    uint8_t seg[20], buf[128];
    for (int i = 0; i < 15; i++) {
        tcp_seg20(seg, (uint16_t)(1000 + i), NTA_TH_SYN);
        int len = frag_build(buf, src, NTA_PROTO_TCP, (uint16_t)IP4_MF, seg, 20,
                             NTA_ETH_HLEN + 20 + 20);
        analyze_packet(buf, len, T0 + i);
    }
    CHECK(detections("PORT_SCAN", src) == 1);

    analyzer_stats_t st;
    analyzer_get_stats(&st);
    CHECK(st.frag_seen == 15);
    CHECK(st.frag_discarded == 0);
}

/* Tiny fragments: o primeiro fragmento tem menos que o cabeçalho TCP. Com 8
 * bytes (portas e seq), o byte de flags (L4[13]) cai no padding de Ethernet que
 * vem depois do datagrama. Com 19 bytes, o flag está dentro do fragmento, mas o
 * cabeçalho TCP não cabe inteiro. Nos dois casos não pode haver alerta. */
static void test_frag_tiny_nao_le_padding(void) {
    fresh();
    const char *pad_src = "198.51.100.92", *short_src = "198.51.100.93";
    uint8_t seg[20], buf[128];

    for (int i = 0; i < 20; i++) {
        memset(seg, 0, 8);
        seg[0] = 0x9C; seg[1] = 0x40;                 /* sport 40000 */
        seg[2] = (uint8_t)((1000 + i) >> 8); seg[3] = (uint8_t)((1000 + i) & 0xFF);
        int len = frag_build(buf, pad_src, NTA_PROTO_TCP, (uint16_t)IP4_MF, seg, 8, 60);
        buf[NTA_ETH_HLEN + 20 + 13] = NTA_TH_SYN;     /* flag no padding (fora do IP) */
        analyze_packet(buf, len, T0 + i);
    }
    CHECK(detections("PORT_SCAN", pad_src) == 0);

    for (int i = 0; i < 20; i++) {
        tcp_seg20(seg, (uint16_t)(1000 + i), NTA_TH_SYN);   /* 20 bytes: cortado a 19 */
        int len = frag_build(buf, short_src, NTA_PROTO_TCP, (uint16_t)IP4_MF, seg, 19,
                             NTA_ETH_HLEN + 20 + 19);
        analyze_packet(buf, len, T0 + i);
    }
    CHECK(detections("PORT_SCAN", short_src) == 0);

    analyzer_stats_t st;
    analyzer_get_stats(&st);
    CHECK(st.frag_seen == 40);
    CHECK(st.frag_discarded == 40);
}

/* IPv6: fragmento não inicial conta como visto e descartado; o inicial conta só
 * como visto. Fragmento inicial com payload_len de 16 (8 de fragmento + 8 de L4)
 * tem o SYN em L4[13], que cai fora do datagrama (quadro de 84 bytes). */
static void test_ipv6_frag_contadores(void) {
    fresh();
    uint8_t buf[128];
    const char *ip = "2001:db8:a::500";
    for (int i = 0; i < 3; i++) {
        int len = build_ip6(buf, ip, IP6_DST, NTA_PROTO_FRAGMENT, 8 + 20);
        nta_ipv6_frag_hdr *f = (nta_ipv6_frag_hdr *)(buf + IP6_L4);
        f->next_hdr   = NTA_PROTO_TCP;
        f->frag_off_m = htons(0x0008);                /* offset 1 (8 bytes) */
        analyze_packet(buf, len, T0 + i);
    }
    analyzer_stats_t st;
    analyzer_get_stats(&st);
    CHECK(st.frag_seen == 3);
    CHECK(st.frag_discarded == 3);

    const char *tiny = "2001:db8:a::501";
    for (int i = 0; i < 15; i++) {
        build_ip6(buf, tiny, IP6_DST, NTA_PROTO_FRAGMENT, 8 + 8);
        nta_ipv6_frag_hdr *f = (nta_ipv6_frag_hdr *)(buf + IP6_L4);
        f->next_hdr   = NTA_PROTO_TCP;
        f->frag_off_m = htons(0x0001);                /* offset 0, M = 1 */
        uint8_t *l4 = buf + IP6_L4 + 8;
        l4[0] = 0x9C; l4[1] = 0x40;
        l4[2] = (uint8_t)((1000 + i) >> 8); l4[3] = (uint8_t)((1000 + i) & 0xFF);
        l4[13] = NTA_TH_SYN;                          /* SYN fora do datagrama */
        analyze_packet(buf, 84, T0 + i);
    }
    CHECK(detections("PORT_SCAN", tiny) == 0);
    analyzer_get_stats(&st);
    CHECK(st.frag_seen == 18);
    CHECK(st.frag_discarded == 18);
}

/* Por último: HOME_NET IPv6 não é zerado pelo reset, e não afeta os testes
 * acima (o CIDR é 2001:db8:f::/48, que nenhum outro teste usa). */
static void test_home_net_ipv6(void) {
    CHECK(analyzer_add_home_cidr("2001:db8:f::/129") == -1);
    CHECK(analyzer_add_home_cidr("2001:::1/64") == -1);
    CHECK(analyzer_add_home_cidr("2001:db8:f::/48") == 0);

    fresh();
    for (int i = 0; i < 5; i++) tcp6("2001:db8:f::5", (uint16_t)(80 + i), 0, T0);
    CHECK(detections("NULL_SCAN", "2001:db8:f::5") == 0);   /* ignorado: HOME_NET */
    for (int i = 0; i < 5; i++) tcp6("2001:db8:e::5", (uint16_t)(80 + i), 0, T0);
    CHECK(detections("NULL_SCAN", "2001:db8:e::5") == 3);   /* fora do /48 */
}

int main(void) {
    g_replay_mode = 1;             /* collector só registra em modo replay */
    RUN(test_null_scan_no_terceiro_pacote);
    RUN(test_brute_force_dentro_da_janela);
    RUN(test_brute_force_espalhado_nao_dispara);
    RUN(test_kill_chain_completa);
    RUN(test_reset_limpa_estado);
    RUN(test_pacotes_malformados);
    RUN(test_refletor_puro_dispara);
    RUN(test_dns_normal_nao_dispara);
    RUN(test_exaustao_dns_nao_cega_port_scan);
    RUN(test_ipv6_detectores_basicos);
    RUN(test_ipv6_dns_tunnel_e_icmp_flood);
    RUN(test_icmp_depende_da_familia);
    RUN(test_ipv6_refletor_dispara);
    RUN(test_ipv6_dns_normal_nao_dispara);
    RUN(test_ipv6_extensao_e_fragmento);
    RUN(test_ipv6_malformados);
    RUN(test_exaustao_origens_ipv6_nao_cega_ipv4);
    RUN(test_exaustao_dns_ipv6_nao_cega_ipv4);
    RUN(test_vlan_e_qinq_mesmas_deteccoes);
    RUN(test_arp_com_vlan);
    RUN(test_vlan_profundidade_limite);
    RUN(test_vlan_truncada_em_qualquer_byte);
    RUN(test_frag_nao_inicial_nao_vira_l4);
    RUN(test_frag_inicial_com_l4_inteiro_analisado);
    RUN(test_frag_tiny_nao_le_padding);
    RUN(test_ipv6_frag_contadores);
    RUN(test_home_net);            /* HOME_NET não é zerado pelo reset */
    RUN(test_home_net_ipv6);       /* por último */
    TEST_EXIT();
}
