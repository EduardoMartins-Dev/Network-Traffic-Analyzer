/* Símbolo que o publisher.c exige no link e que a ponte nunca usa.
 *
 * publisher.c define publish_packet(), que empilha em rb_evt via
 * pipeline_push_event(). Esse caminho é do pipeline de captura do agente
 * (pipeline.c, que puxa pcap e o analyzer). A ponte só chama
 * publisher_send_json() e publisher_send_batch() não é usado, então o stub
 * nunca roda. Se alguém chamar, o processo aborta com mensagem, em vez de
 * perder eventos em silêncio. */
#include <stdio.h>
#include <stdlib.h>
#include "pipeline.h"

int pipeline_push_event(const event_slot_t *evt) {
    (void)evt;
    fprintf(stderr, "[EVE] pipeline_push_event chamado na ponte (nao deveria)\n");
    abort();
}
