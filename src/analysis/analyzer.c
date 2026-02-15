#include "../../include/analyzer.h"
#include "../../include/output.h" // Removi o include duplicado
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

static unsigned long packets_analyzed = 0;

void init_analyzer(void) {
    packets_analyzed = 0;
}

// O argumento aqui se chama 'packet_length'
void analyze_packet(const u_char *packet, int packet_length) {

    // ETHERNET MAPPING
    struct ether_header * eth_header = (struct ether_header *)packet;

    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    // MAPEAR O CABEÇALHO IP
    const u_char *ip_header_start = packet + ETHER_HDR_LEN;
    struct ip *ip_header = (struct ip *)ip_header_start;

    // CONVERSÃO DOS IP DE BIN PARA TXT
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Calcula o tam. do cabeçalho ip
    int ip_header_len = ip_header->ip_hl * 4;

    // TRANSPORTE TCP/UDP
    const u_char *transport_header_start = ip_header_start + ip_header_len;

    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)transport_header_start;
        export_to_json(src_ip, ntohs(tcp->th_sport),
            dst_ip, ntohs(tcp->th_dport),
            "TCP", packet_length);

    } else if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)transport_header_start;

        export_to_json(src_ip, ntohs(udp->uh_sport),
            dst_ip, ntohs(udp->uh_dport),
            "UDP", packet_length);
    }

    packets_analyzed++;
}