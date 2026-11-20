#ifndef NTA_NET_H
#define NTA_NET_H

/* ========================================================================= *
 * Rede portável (agente) — Linux, FreeBSD, macOS e Windows (MinGW-w64).     *
 *                                                                           *
 * - Byte order / inet_* vêm de <arpa/inet.h> (POSIX) ou Winsock2.          *
 * - Cabeçalhos IPv4/IPv6/TCP/UDP/ICMPv6 são definidos aqui com o layout de   *
 *   wire, em                                                                *
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

/* Tags VLAN depois dos MACs: 802.1Q (0x8100) e 802.1ad/QinQ (0x88A8). Cada tag
 * tem 4 bytes: TCI (2) + EtherType seguinte (2). Acima de NTA_VLAN_MAX_TAGS
 * tags empilhadas o quadro é descartado (B10). */
#define NTA_ETH_TYPE_VLAN  0x8100
#define NTA_ETH_TYPE_QINQ  0x88A8
#define NTA_VLAN_TAG_LEN   4
#define NTA_VLAN_MAX_TAGS  4

/* Os cabeçalhos começam em offsets não alinhados do buffer do pcap (IPv4 no
 * byte 14): `packed` faz o compilador gerar acesso desalinhado seguro —
 * sem isso o cast é comportamento indefinido (e falha em ARM estrito). */
#define NTA_PACKED __attribute__((packed))

#define NTA_PROTO_ICMP     1
#define NTA_PROTO_TCP      6
#define NTA_PROTO_UDP     17
#define NTA_PROTO_ICMPV6  58

/* Números de protocolo de cabeçalhos de extensão IPv6 (RFC 8200). */
#define NTA_PROTO_HOPOPT   0
#define NTA_PROTO_ROUTING 43
#define NTA_PROTO_FRAGMENT 44
#define NTA_PROTO_ESP     50
#define NTA_PROTO_AH      51
#define NTA_PROTO_DSTOPTS 60
#define NTA_PROTO_NONEXT 59

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

/* frag_off do IPv4: DF (0x4000), MF (0x2000) e offset em unidades de 8 bytes
 * (13 bits baixos). Fragmento = MF ou offset != 0 (B10). Aplique após ntohs. */
#define NTA_IPV4_FRAG_ANY    0x3FFFu
#define NTA_IPV4_FRAG_OFFSET 0x1FFFu

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

/* IPv6 (RFC 8200): cabeçalho fixo de 40 bytes. Os endereços ficam como bytes
 * porque não há tipo de wire portável sem Winsock. `ver_tc_flow[0]` tem a
 * versão nos 4 bits altos; lê-se como byte para não depender da ordem do host. */
typedef struct {
    uint8_t  ver_tc_flow[4];
    uint16_t payload_len;
    uint8_t  next_hdr;
    uint8_t  hop_limit;
    uint8_t  saddr[16];
    uint8_t  daddr[16];
} NTA_PACKED nta_ipv6_hdr;

#define NTA_IPV6_HLEN  40

/* Cabeçalhos de extensão Hop-by-Hop, Routing e Destination Options: tamanho em
 * unidades de 8 bytes, sem contar os primeiros 8. */
typedef struct {
    uint8_t next_hdr;
    uint8_t hdr_ext_len;
} NTA_PACKED nta_ipv6_ext_hdr;

/* Fragment: sempre 8 bytes. Offset (13 bits) nos bits altos de frag_off_m. */
typedef struct {
    uint8_t  next_hdr;
    uint8_t  reserved;
    uint16_t frag_off_m;
    uint32_t id;
} NTA_PACKED nta_ipv6_frag_hdr;

/* Aplique após ntohs(frag_off_m): offset != 0 = fragmento não inicial (sem L4). */
#define NTA_IPV6_FRAG_OFFSET_MASK 0xFFF8u

typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t check;
} NTA_PACKED nta_icmpv6_hdr;

#define NTA_ICMPV6_ECHO_REQUEST 128

#endif /* NTA_NET_H */
