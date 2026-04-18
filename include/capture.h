#ifndef NETWORK_TRAFFIC_ANALYZER_CAPTURE_H
#define NETWORK_TRAFFIC_ANALYZER_CAPTURE_H

#include <sys/types.h>   /* u_char/u_int (necessário antes de pcap.h no Fedora/glibc) */
#include <pcap.h>
#define SNAP_LEN 1518

/* Handler do pcap_loop — bifurca modo live (push no ring buffer) e modo   *
 * replay (chamada síncrona ao analyzer, preservando determinismo dos      *
 * testes).                                                                  */
void packet_handler(u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet);

#endif
