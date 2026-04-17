#ifndef PUBLISHER_H
#define PUBLISHER_H

#include "pipeline.h"

/* ========================================================================= *
 * PUBLISHER — AMQP em batch (v5.0)                                          *
 *                                                                           *
 * `publish_packet` não envia mais por pacote. Em modo live ele enfileira   *
 * o evento no ring buffer `rb_evt` e retorna. A thread de publicação       *
 * agrupa até AGENT_BATCH_SIZE eventos (ou espera AGENT_BATCH_TIMEOUT_MS)   *
 * e chama `publisher_send_batch`, que serializa um array JSON único com    *
 * cJSON e publica em uma única chamada AMQP.                                *
 * ========================================================================= */

void init_queue(void);
void close_queue(void);

/* Enfileira um evento parseado (ou imprime alerta, em modo replay).       */
void publish_packet(const char *src_ip, int port, const char *proto, int bytes,
                    int is_scan, const char *attack_type,
                    const char *kill_chain_stage, int kc_score,
                    const char *mitre_technique);

/* Serializa e envia um lote de eventos via AMQP em uma única mensagem.   *
 * Chamado pela thread de publicação. Thread-safe (mutex interno).         */
void publisher_send_batch(const event_slot_t *batch, int count);

/* Publica um JSON de métricas em routing key separada                     *
 * (AGENT_METRICS_QUEUE, default "traffic_metrics"). Thread-safe.          */
void publisher_send_metrics(const char *json_payload);

#endif /* PUBLISHER_H */
