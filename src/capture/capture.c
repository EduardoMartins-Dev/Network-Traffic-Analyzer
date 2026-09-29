#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include "../../include/nta_net.h"
#include "../../include/capture.h"
#include "../../include/analyzer.h"
#include "../../include/collector.h"
#include "../../include/pipeline.h"

/* Em modo replay (`g_replay_mode == 1`) a análise ocorre sincronamente no *
 * mesmo thread do pcap_loop, bypassando o pipeline multi-thread para      *
 * preservar o determinismo dos gabaritos de teste.                         *
 *                                                                           *
 * Em modo live copia o pacote para um slot do ring buffer de captura e    *
 * retorna imediatamente — a thread de análise consome em paralelo.        */
void packet_handler(u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet) {
    (void)args;

    /* caplen = bytes realmente presentes em `packet`; len é o tamanho
     * original no fio e pode ser maior (pcap gravado com snaplen curto). */
    if (g_replay_mode) {
        analyze_packet(packet, (int)header->caplen, header->ts.tv_sec);
        return;
    }

    pkt_slot_t slot;
    slot.ts  = header->ts;
    int len  = (int)header->caplen;
    if (len > SNAP_LEN) len = SNAP_LEN;
    slot.len = len;
    memcpy(slot.data, packet, (size_t)len);

    pipeline_push_packet(&slot);
}

int capture_list_interfaces(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs = NULL;
    if (pcap_findalldevs(&devs, errbuf) != 0) {
        fprintf(stderr, "Erro ao listar interfaces: %s\n", errbuf);
        return 1;
    }
    if (!devs) {
        fprintf(stderr, "Nenhuma interface de captura encontrada "
                        "(sem permissão ou driver de captura ausente?).\n");
        return 1;
    }
    for (pcap_if_t *d = devs; d; d = d->next) {
        printf("%s\n", d->name);
        if (d->description) printf("    %s\n", d->description);
        for (pcap_addr_t *a = d->addresses; a; a = a->next) {
            if (!a->addr || a->addr->sa_family != AF_INET) continue;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &((struct sockaddr_in *)a->addr)->sin_addr,
                      ip, sizeof(ip));
            printf("    IPv4 %s\n", ip);
        }
    }
    pcap_freealldevs(devs);
    return 0;
}
