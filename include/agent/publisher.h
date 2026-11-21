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
 * Chamado pela thread de publicação. Thread-safe (mutex interno).         *
 * Retorna -1 se o broker está fora (reconexão com backoff é interna) —    *
 * o chamador mantém o lote e tenta de novo.                               */
int publisher_send_batch(const event_slot_t *batch, int count);

/* Publica um array JSON já serializado (ponte EVE, nta-eve-bridge). Mesmas   *
 * propriedades do lote. Retorna -1 se o broker está fora (o chamador mantém). */
int publisher_send_json(const char *json_array);

/* Publica um JSON de métricas em routing key separada                     *
 * (AGENT_METRICS_QUEUE, default "traffic_metrics"). Thread-safe.          *
 * Retorna -1 se o broker está fora (métrica é descartável).              */
int publisher_send_metrics(const char *json_payload);

/* B16: fila dos logs de protocolo (AGENT_PROTO_QUEUE, padrão protocol_queue).
 * Chamar antes de init_queue, e só com AGENT_PROTO_LOGS ligado: só nesse caso
 * a fila é declarada no broker. */
void publisher_enable_proto_queue(void);

/* Publica um array JSON de registros de protocolo (event_type "dns") na fila
 * de logs. Mesmas propriedades do lote. Retorna -1 se o broker está fora (o
 * chamador mantém o lote). */
int publisher_send_protocol(const char *json_array);

#endif /* PUBLISHER_H */
