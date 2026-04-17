#include <string.h>
#include <pcap.h>
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

    if (g_replay_mode) {
        analyze_packet(packet, header->len);
        return;
    }

    pkt_slot_t slot;
    slot.ts  = header->ts;
    int len  = header->len;
    if (len > SNAP_LEN) len = SNAP_LEN;
    slot.len = len;
    memcpy(slot.data, packet, (size_t)len);

    pipeline_push_packet(&slot);
}
