/* Testes do parser WHOIS do nta-server (src/server/nta_whois.c).
 * As funções de parsing são static: incluímos o .c para testá-las sem
 * abrir a API. Não faz rede — só parsing de respostas reais (resumidas). */
#include "test.h"
#include "../../src/server/nta_whois.c"

static NtaWhoisInfo parse(const char *resp) {
    NtaWhoisInfo info;
    memset(&info, 0, sizeof(info));
    parse_regional(resp, strlen(resp), &info);
    return info;
}

static void test_refer_iana(void) {
    const char *iana =
        "% IANA WHOIS server\r\n"
        "inetnum:      8.0.0.0 - 8.255.255.255\r\n"
        "refer:        whois.arin.net\r\n"
        "organisation: Administered by ARIN\r\n";
    char host[WHOIS_REFER_MAX];
    CHECK(parse_refer(iana, strlen(iana), host, sizeof(host)) == 1);
    CHECK_STR(host, "whois.arin.net");               /* sem \r nem espaços */

    const char *sem = "% nada aqui\r\nstatus: ALLOCATED\r\n";
    CHECK(parse_refer(sem, strlen(sem), host, sizeof(host)) == 0);
}

static void test_arin(void) {
    NtaWhoisInfo i = parse(
        "NetRange:       8.8.8.0 - 8.8.8.255\r\n"
        "NetName:        GOGL\r\n"
        "OrgName:        Google LLC\r\n"
        "Country:        US\r\n");
    CHECK_STR(i.org, "Google LLC");
    CHECK_STR(i.country, "US");
    CHECK_STR(i.netname, "GOGL");
    CHECK(i.has_data == 1);
}

static void test_ripe_primeiro_valor_vence(void) {
    NtaWhoisInfo i = parse(
        "inetnum:        193.0.0.0 - 193.0.7.255\n"
        "netname:        RIPE-NCC\n"
        "descr:          RIPE Network Coordination Centre\n"
        "descr:          Amsterdam, Netherlands\n"
        "country:        NL\n"
        "admin-c:        BRD-RIPE\n");
    CHECK_STR(i.org, "RIPE Network Coordination Centre");
    CHECK_STR(i.country, "NL");
    CHECK_STR(i.netname, "RIPE-NCC");
}

static void test_lacnic_owner(void) {
    NtaWhoisInfo i = parse(
        "inetnum:     200.160.0.0/20\n"
        "owner-c:     NIC-BR\n"                          /* não confundir com owner */
        "owner:       Núcleo de Inf. e Coord. do Ponto BR - NIC.BR\n"
        "country:     BR\n");
    CHECK_STR(i.org, "Núcleo de Inf. e Coord. do Ponto BR - NIC.BR");
    CHECK_STR(i.country, "BR");
}

static void test_resposta_sem_dados(void) {
    NtaWhoisInfo i = parse("% No match found\r\n\r\n");
    CHECK(i.has_data == 0);
    CHECK(i.org[0] == '\0');
}

int main(void) {
    RUN(test_refer_iana);
    RUN(test_arin);
    RUN(test_ripe_primeiro_valor_vence);
    RUN(test_lacnic_owner);
    RUN(test_resposta_sem_dados);
    TEST_EXIT();
}
