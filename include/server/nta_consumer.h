#ifndef NTA_CONSUMER_H
#define NTA_CONSUMER_H

#include <stddef.h>
#include <stdatomic.h>
#include <amqp.h>
#include "nta_server.h"

/* Callback chamado para cada mensagem consumida. `body` NÃO é null-terminated
 * (usar `len`); `agent_id` é extraído de `properties.user_id` (null-terminated
 * numa buffer interno), ou "unknown" se ausente. */
typedef void (*nta_on_message_fn)(const char *body, size_t len,
                                  const char *agent_id, void *user_ctx);

/* Conexão AMQP dedicada. librabbitmq não é thread-safe entre connections
 * compartilhadas — cada worker deve ter sua própria instância. */
typedef struct {
    amqp_connection_state_t conn;
    amqp_channel_t          channel;
    int                     connected;
} NtaAmqp;

/* Consumers com conexão AMQP aberta agora (todos os workers). Lido pelo
 * /health — 0 com o processo de pé significa broker inalcançável. */
extern atomic_int g_nta_amqp_connected;

/* Abre conn TCP + login + canal + declara fila durável. prefetch_count permite
 * distribuição justa entre consumers. Retorna 0 em sucesso. */
int nta_amqp_open(NtaAmqp *a, const NtaConfig *cfg,
                  const char *queue, int prefetch_count);

/* nta_amqp_open com backoff exponencial (1s → 30s) até conectar. Retorna -1
 * só quando nta_should_stop() ou `worker_stop` (NULL = ignora) pedem parada.
 * `tag` prefixa os logs (ex: "W-3"). */
int nta_amqp_open_retry(NtaAmqp *a, const NtaConfig *cfg, const char *queue,
                        int prefetch_count, atomic_int *worker_stop,
                        const char *tag);

/* Inicia basic_consume e bloqueia consumindo até nta_should_stop() ou
 * `worker_stop` virar 1 (NULL = ignora — só global). Usa auto_ack=1.
 * Timeout interno de 1s garante responsividade aos sinais.
 * Retorna 0 em parada pedida, -1 se a conexão caiu (chamador reconecta).  */
int nta_amqp_consume_loop(NtaAmqp *a, const char *queue,
                           nta_on_message_fn handler, void *user_ctx,
                           atomic_int *worker_stop);

/* Declara fila adicional como durável no canal já aberto. Usado pra criar
 * a narrator_queue antes de publicar nela. Retorna 0 em sucesso. */
int nta_amqp_declare_queue(NtaAmqp *a, const char *queue);

/* Publica payload JSON na fila informada (default exchange). Adiciona header
 * `x-agent-id` pra narrator.py recuperar a identidade do agente original.
 * delivery_mode=2 (persistente). Retorna 0 em sucesso. */
int nta_amqp_publish(NtaAmqp *a, const char *queue, const char *agent_id,
                     const char *body, size_t len);

/* Fecha canal + conexão. Safe de chamar mesmo se open falhou parcialmente. */
void nta_amqp_close(NtaAmqp *a);

#endif /* NTA_CONSUMER_H */
