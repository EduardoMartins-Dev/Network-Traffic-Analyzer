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
}

int main(void) {
    g_replay_mode = 1;             /* collector só registra em modo replay */
    RUN(test_null_scan_no_terceiro_pacote);
    RUN(test_brute_force_dentro_da_janela);
    RUN(test_brute_force_espalhado_nao_dispara);
    RUN(test_kill_chain_completa);
    RUN(test_reset_limpa_estado);
    RUN(test_pacotes_malformados);
    RUN(test_home_net);            /* por último: HOME_NET não é zerado pelo reset */
    TEST_EXIT();
}
