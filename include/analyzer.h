#ifndef NETWORK_TRAFFIC_ANALYZER_ANALYZER_H
#define NETWORK_TRAFFIC_ANALYZER_ANALYZER_H

#include <sys/types.h>   /* u_char (necessário antes de pcap.h no Fedora/glibc) */
#include <pcap.h>

int analyze_packet(const u_char *packet, int length);

/* HOME_NET — lista de CIDRs cujo src_ip é ignorado no IP layer (não no ARP).
 * Pacotes saindo do próprio host viram tráfego promíscuo e sem skip viram
 * falso-positivo em DNS_TUNNEL/PORT_SCAN. Adicione subnet local antes do
 * pcap_loop. Aceita "192.168.1.0/24" ou "192.168.1.5/32". Retorna 0 OK. */
int  analyzer_add_home_cidr(const char *cidr);
void analyzer_home_dump(void);   /* imprime no stderr — debug */
int  analyzer_home_count(void);

#endif