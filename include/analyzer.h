#ifndef NETWORK_TRAFFIC_ANALYZER_ANALYZER_H
#define NETWORK_TRAFFIC_ANALYZER_ANALYZER_H

#include <sys/types.h>   /* u_char (necessário antes de pcap.h no Fedora/glibc) */
#include <pcap.h>
int analyze_packet(const u_char *packet, int length);
#endif