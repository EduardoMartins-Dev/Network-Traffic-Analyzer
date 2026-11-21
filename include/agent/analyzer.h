#ifndef NETWORK_TRAFFIC_ANALYZER_ANALYZER_H
#define NETWORK_TRAFFIC_ANALYZER_ANALYZER_H

#include <sys/types.h>   /* u_char (necessário antes de pcap.h no Fedora/glibc) */
#include <pcap.h>
#include <stdint.h>
#include <time.h>
#include "rules.h"

/* Limiares dos detectores (rules.h). Troca os padrões pela estrutura `r`, já
 * validada por rules_parse()/rules_load_file(). Chamar antes de começar a
 * análise (pipeline ou replay): não é seguro trocar com a análise rodando. */
void analyzer_set_rules(const NtaRules *r);

/* Contadores de VLAN e fragmentação (B10). Zerados por analyzer_reset(). Lidos
 * pelo metrics_thread com analyzer_get_stats(): cada campo é atômico, mas os três
 * juntos não formam um instantâneo exato (são telemetria). */
typedef struct {
    uint64_t vlan_frames;     /* quadros com ao menos uma tag 802.1Q/802.1ad */
    uint64_t frag_seen;       /* fragmentos IPv4 e IPv6 vistos (inclui o inicial) */
    uint64_t frag_discarded;  /* fragmentos fora da análise L4: não inicial, ou L4 que não cabe */
} analyzer_stats_t;

void analyzer_get_stats(analyzer_stats_t *out);

/* `now` é o timestamp do pacote (pcap_pkthdr.ts), não o relógio de parede —
 * assim janelas (brute force, EWMA, kill chain) valem também no replay. */
int analyze_packet(const u_char *packet, int length, time_t now);

/* Zera suspeitos e tabela ARP (HOME_NET é mantido). Usado entre pcaps do
 * replay para que um arquivo não herde contadores do anterior. */
void analyzer_reset(void);

/* HOME_NET — lista de CIDRs cujo src_ip é ignorado no IP layer (não no ARP).
 * Pacotes saindo do próprio host viram tráfego promíscuo e sem skip viram
 * falso-positivo em DNS_TUNNEL/PORT_SCAN. Adicione subnet local antes do
 * pcap_loop. Aceita "192.168.1.0/24", "192.168.1.5/32" ou IPv6 ("2001:db8::/32").
 * IPv4 e IPv6 têm até 8 CIDRs cada. Retorna 0 OK. */
int  analyzer_add_home_cidr(const char *cidr);
void analyzer_home_dump(void);   /* imprime no stderr — debug */
int  analyzer_home_count(void);

#endif