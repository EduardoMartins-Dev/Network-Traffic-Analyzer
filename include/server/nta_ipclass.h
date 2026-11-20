/* ========================================================================= *
 *  nta_ipclass.h — classificação de IP privado/não roteável do nta-server.  *
 *                                                                           *
 *  Usado por GeoIP, AbuseIPDB e WHOIS para não consultar serviços externos  *
 *  (HTTPS/porta 43) nem gastar cota com endereços internos. Substitui as    *
 *  três cópias de is_private_ip que existiam em nta_geoip.c, nta_abuse.c e  *
 *  nta_whois.c (B33).                                                       *
 *                                                                           *
 *  IPv4: regra por prefixo de string, idêntica à das cópias antigas. Ela    *
 *  trata QUALQUER "172." como privado, embora só 172.16/12 seja privado.    *
 *  Mantido de propósito (ver PR B33); corrigir é outra mudança.             *
 *                                                                           *
 *  IPv6: classificado com inet_pton (tolera caixa alta, zeros à esquerda e  *
 *  formas comprimidas). Privado: ::, ::1, fe80::/10, fc00::/7, ff00::/8,    *
 *  2001:db8::/32 e IPv4-mapeado (::ffff:a.b.c.d, pela regra IPv4).          *
 *                                                                           *
 *  Entrada NULL/vazia é "privada" (comportamento anterior). Texto que não é *
 *  IPv4 nem IPv6 válido é "público", como antes.                            *
 * ========================================================================= */
#ifndef NTA_IPCLASS_H
#define NTA_IPCLASS_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

/* Regra IPv4 por prefixo de string (semântica das cópias antigas). */
static inline int nta_ip_v4_str_is_private(const char *ip) {
    if (strncmp(ip, "127.",     4) == 0) return 1;
    if (strncmp(ip, "192.168.", 8) == 0) return 1;
    if (strncmp(ip, "10.",      3) == 0) return 1;
    if (strncmp(ip, "172.",     4) == 0) return 1;
    return 0;
}

/* Retorna 1 se `ip` é privado/não roteável; 0 caso contrário. */
static inline int nta_ip_is_private(const char *ip) {
    if (!ip || !*ip) return 1;
    if (nta_ip_v4_str_is_private(ip)) return 1;

    /* Prefixos IPv4 acima não podem começar um literal IPv6 válido (exigem
     * '.' antes de qualquer ':'), então a ordem não muda o resultado. */
    struct in6_addr a;
    if (inet_pton(AF_INET6, ip, &a) != 1) return 0;   /* não é IP: público */

    const unsigned char *b = a.s6_addr;
    int zeros_ate_14 = 1;
    for (int i = 0; i < 15; i++) {
        if (b[i] != 0) { zeros_ate_14 = 0; break; }
    }

    /* ::ffff:a.b.c.d — aplica a regra IPv4 ao endereço embutido. */
    int zeros_10 = 1;
    for (int i = 0; i < 10; i++) {
        if (b[i] != 0) { zeros_10 = 0; break; }
    }
    if (zeros_10 && b[10] == 0xff && b[11] == 0xff) {
        char v4[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, b + 12, v4, sizeof(v4))) return 0;
        return nta_ip_v4_str_is_private(v4);
    }

    if (zeros_ate_14 && b[15] == 0) return 1;         /* :: (não especificado) */
    if (zeros_ate_14 && b[15] == 1) return 1;         /* ::1 (loopback) */
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return 1;   /* fe80::/10 */
    if ((b[0] & 0xfe) == 0xfc) return 1;              /* fc00::/7 (ULA) */
    if (b[0] == 0xff) return 1;                       /* ff00::/8 (multicast) */
    if (b[0] == 0x20 && b[1] == 0x01 &&
        b[2] == 0x0d && b[3] == 0xb8) return 1;       /* 2001:db8::/32 (doc) */
    return 0;
}

#endif /* NTA_IPCLASS_H */
