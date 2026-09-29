#ifndef NTA_NET_H
#define NTA_NET_H

/* ========================================================================= *
 * Rede portável (agente) — Linux, FreeBSD, macOS e Windows (MinGW-w64).     *
 *                                                                           *
 * - Byte order / inet_* vêm de <arpa/inet.h> (POSIX) ou Winsock2.          *
 * - Cabeçalhos IPv4/TCP/UDP são definidos aqui com o layout de wire, em     *
 *   vez de <netinet/ip.h> etc.: não existem no Windows e os nomes de campo        *
 *   variam entre BSD e glibc. Todos os campos multibyte estão em network   *
 *   byte order, como no pacote.                                             *
 * ========================================================================= */

#include <stdint.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#endif

#define NTA_ETH_HLEN      14

/* Os cabeçalhos começam em offsets não alinhados do buffer do pcap (IPv4 no
 * byte 14): `packed` faz o compilador gerar acesso desalinhado seguro —
 * sem isso o cast é comportamento indefinido (e falha em ARM estrito). */
#define NTA_PACKED __attribute__((packed))

#define NTA_PROTO_ICMP     1
#define NTA_PROTO_TCP      6
#define NTA_PROTO_UDP     17

typedef struct {
    uint8_t  ver_ihl;    /* versão (4 bits altos) + IHL em palavras de 32 bits */
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} NTA_PACKED nta_ipv4_hdr;

#define NTA_IPV4_HLEN(h)  (((h)->ver_ihl & 0x0F) * 4)

typedef struct {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off;   /* 4 bits altos = tamanho do header em palavras */
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} NTA_PACKED nta_tcp_hdr;

#define NTA_TH_FIN  0x01
#define NTA_TH_SYN  0x02
#define NTA_TH_RST  0x04
#define NTA_TH_PUSH 0x08
#define NTA_TH_ACK  0x10
#define NTA_TH_URG  0x20

typedef struct {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t check;
} NTA_PACKED nta_udp_hdr;

#endif /* NTA_NET_H */
