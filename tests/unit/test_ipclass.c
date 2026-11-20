/* Testes da classificação de IP privado do nta-server (include/server/nta_ipclass.h),
 * B33. Só a função de classificação: nenhum endereço sai para serviço externo.
 *   1. IPv4: regra por prefixo (inclui 172.* como privado, de propósito);
 *   2. IPv6 privados/não roteáveis (::, ::1, fe80::/10, fc00::/7, ff00::/8,
 *      2001:db8::/32) e as bordas de cada faixa;
 *   3. IPv6 públicos;
 *   4. formas não canônicas (caixa alta, zeros à esquerda, comprimidas);
 *   5. IPv4-mapeado (::ffff:a.b.c.d e forma hexadecimal);
 *   6. vazio, NULL, texto que não é IP. */
#include "test.h"
#include "nta_ipclass.h"

static void test_ipv4(void) {
    CHECK(nta_ip_is_private("127.0.0.1") == 1);
    CHECK(nta_ip_is_private("10.1.2.3") == 1);
    CHECK(nta_ip_is_private("192.168.0.1") == 1);
    CHECK(nta_ip_is_private("172.16.0.1") == 1);
    /* 172.* é privado por regra de prefixo, mesmo fora de 172.16/12 (achado
     * registrado no PR; não corrigido aqui). */
    CHECK(nta_ip_is_private("172.32.0.1") == 1);

    CHECK(nta_ip_is_private("8.8.8.8") == 0);
    CHECK(nta_ip_is_private("1.1.1.1") == 0);
    CHECK(nta_ip_is_private("192.169.0.1") == 0);
    CHECK(nta_ip_is_private("11.0.0.1") == 0);
}

static void test_ipv6_privados(void) {
    CHECK(nta_ip_is_private("::") == 1);
    CHECK(nta_ip_is_private("::1") == 1);
    CHECK(nta_ip_is_private("0:0:0:0:0:0:0:1") == 1);
    CHECK(nta_ip_is_private("0000::0001") == 1);

    /* fe80::/10: 1111 1110 10xx xxxx → fe80 a febf */
    CHECK(nta_ip_is_private("fe80::1") == 1);
    CHECK(nta_ip_is_private("febf::1") == 1);
    CHECK(nta_ip_is_private("fe7f::1") == 0);   /* logo abaixo da faixa */
    CHECK(nta_ip_is_private("fec0::1") == 0);   /* logo acima (site-local antigo, não listado) */

    /* fc00::/7: fc.. e fd.. */
    CHECK(nta_ip_is_private("fc00::1") == 1);
    CHECK(nta_ip_is_private("fd12:3456:789a::1") == 1);
    CHECK(nta_ip_is_private("fbff::1") == 0);   /* logo abaixo */
    CHECK(nta_ip_is_private("fe00::1") == 0);   /* logo acima */

    /* ff00::/8 multicast */
    CHECK(nta_ip_is_private("ff02::1") == 1);
    CHECK(nta_ip_is_private("ff00::1") == 1);

    /* 2001:db8::/32 documentação */
    CHECK(nta_ip_is_private("2001:db8::1") == 1);
    CHECK(nta_ip_is_private("2001:db8:ffff::1") == 1);
    CHECK(nta_ip_is_private("2001:db7::1") == 0);
}

static void test_ipv6_publicos(void) {
    CHECK(nta_ip_is_private("2606:4700:4700::1111") == 0);
    CHECK(nta_ip_is_private("2001:4860:4860::8888") == 0);
    CHECK(nta_ip_is_private("2a00:1450::1") == 0);
    CHECK(nta_ip_is_private("2001:dbb::1") == 0);
}

static void test_ipv6_formas_nao_canonicas(void) {
    CHECK(nta_ip_is_private("FE80::1") == 1);             /* caixa alta */
    CHECK(nta_ip_is_private("fe80:0000::0001") == 1);     /* zeros à esquerda */
    CHECK(nta_ip_is_private("FD00:0:0:0:0:0:0:1") == 1);
    CHECK(nta_ip_is_private("2001:0DB8::1") == 1);        /* doc, caixa alta */
    CHECK(nta_ip_is_private("2001:0db8:0000:0000:0000:0000:0000:0001") == 1);
    CHECK(nta_ip_is_private("2606:4700:4700:0000::1111") == 0);
    CHECK(nta_ip_is_private("2606:4700:4700::1111") == 0);
}

static void test_ipv4_mapeado(void) {
    CHECK(nta_ip_is_private("::ffff:127.0.0.1") == 1);
    CHECK(nta_ip_is_private("::ffff:10.0.0.1") == 1);
    CHECK(nta_ip_is_private("::ffff:192.168.1.1") == 1);
    CHECK(nta_ip_is_private("::ffff:172.20.0.1") == 1);
    CHECK(nta_ip_is_private("::ffff:0a00:0001") == 1);    /* 10.0.0.1 em hex */
    CHECK(nta_ip_is_private("::FFFF:10.0.0.1") == 1);     /* caixa alta */

    CHECK(nta_ip_is_private("::ffff:8.8.8.8") == 0);
    CHECK(nta_ip_is_private("::ffff:0808:0808") == 0);    /* 8.8.8.8 em hex */
    CHECK(nta_ip_is_private("::ffff:1.1.1.1") == 0);
}

static void test_vazio_null_e_lixo(void) {
    CHECK(nta_ip_is_private(NULL) == 1);
    CHECK(nta_ip_is_private("") == 1);

    /* Texto que não é IP: público, como antes. */
    CHECK(nta_ip_is_private("foo") == 0);
    CHECK(nta_ip_is_private("8.8.8") == 0);
    CHECK(nta_ip_is_private("8.8.8.8.8") == 0);
    CHECK(nta_ip_is_private("::g") == 0);
    CHECK(nta_ip_is_private("2001:db8::zz") == 0);   /* lixo com prefixo doc */
    CHECK(nta_ip_is_private("1234:::") == 0);
    /* Prefixo IPv4 por string, como nas cópias antigas: também é "privado". */
    CHECK(nta_ip_is_private("10.foo") == 1);
}

int main(void) {
    RUN(test_ipv4);
    RUN(test_ipv6_privados);
    RUN(test_ipv6_publicos);
    RUN(test_ipv6_formas_nao_canonicas);
    RUN(test_ipv4_mapeado);
    RUN(test_vazio_null_e_lixo);
    TEST_EXIT();
}
