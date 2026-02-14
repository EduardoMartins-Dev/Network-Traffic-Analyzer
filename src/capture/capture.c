#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
// Importa as headers
#include "../../include/capture.h"
#include "../../include/analyzer.h"

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Passa a bola para o módulo de análise (analyzer.c)
    analyze_packet(packet, header->len);
}

void start_sniffer(char *device)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;


    handle = pcap_open_live(device, SNAP_LEN, 1, 1000, error_buffer);

    if (handle ==NULL)
    {
        fprintf(stderr, "Erro: %s.\nMotivo: %s\n", device, error_buffer);

        //sempre rodar com SUDO

        exit(1);
    }

    printf("passou");
    pcap_loop(handle, -1, packet_handler, NULL);
}

