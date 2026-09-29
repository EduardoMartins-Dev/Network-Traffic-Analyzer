#ifndef NETWORK_TRAFFIC_ANALYZER_ANALYZER_H
#define NETWORK_TRAFFIC_ANALYZER_ANALYZER_H

#include <sys/types.h>   /* u_char (necessário antes de pcap.h no Fedora/glibc) */
#include <pcap.h>
#include <time.h>

/* `now` é o timestamp do pacote (pcap_pkthdr.ts), não o relógio de parede —
 * assim janelas (brute force, EWMA, kill chain) valem também no replay. */
int analyze_packet(const u_char *packet, int length, time_t now);

/* Zera suspeitos e tabela ARP (HOME_NET é mantido). Usado entre pcaps do
 * replay para que um arquivo não herde contadores do anterior. */
void analyzer_reset(void);

/* HOME_NET — lista de CIDRs cujo src_ip é ignorado no IP layer (não no ARP).
 * Pacotes saindo do próprio host viram tráfego promíscuo e sem skip viram
 * falso-positivo em DNS_TUNNEL/PORT_SCAN. Adicione subnet local antes do
 * pcap_loop. Aceita "192.168.1.0/24" ou "192.168.1.5/32". Retorna 0 OK. */
int  analyzer_add_home_cidr(const char *cidr);
void analyzer_home_dump(void);   /* imprime no stderr — debug */
int  analyzer_home_count(void);

#endif