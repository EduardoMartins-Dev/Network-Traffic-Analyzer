#ifndef NETWORK_TRAFFIC_ANALYZER_CAPTURE_H
#define NETWORK_TRAFFIC_ANALYZER_CAPTURE_H

#include <pcap.h>
#define SNAP_LEN 1518

void start_sniffer(char *device);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif