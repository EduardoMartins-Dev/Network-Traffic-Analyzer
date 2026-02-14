#ifndef NETWORK_TRAFFIC_ANALYZER_ANALYZER_H
#define NETWORK_TRAFFIC_ANALYZER_ANALYZER_H

#include <pcap.h>
void analyze_packet(const u_char *packet, int len);

#endif