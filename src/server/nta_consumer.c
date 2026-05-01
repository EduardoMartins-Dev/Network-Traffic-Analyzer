/* ========================================================================= *
 *  nta_consumer.c — consumer AMQP single-connection.                        *
 *                                                                           *
 *  1 NtaAmqp por worker. Abre conn TCP + canal + declara fila durável,     *
 *  faz basic_consume com auto_ack, e roda loop bloqueante com timeout      *
 *  curto pra não engolir SIGINT.                                           *
 * ========================================================================= */

#include "../../include/nta_consumer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <amqp_tcp_socket.h>
#include <amqp_framing.h>

#define MAX_FRAME_SIZE 131072
#define AGENT_ID_MAX   127

/* -------------------------------------------------------------------------- *
 * Helpers de erro librabbitmq                                                *
 * -------------------------------------------------------------------------- */
static int amqp_reply_ok(amqp_rpc_reply_t r, const char *ctx) {
    if (r.reply_type == AMQP_RESPONSE_NORMAL) return 1;

    switch (r.reply_type) {
    case AMQP_RESPONSE_NONE:
        fprintf(stderr, "[AMQP] %s: resposta vazia\n", ctx);
        break;
    case AMQP_RESPONSE_LIBRARY_EXCEPTION:
        fprintf(stderr, "[AMQP] %s: %s\n", ctx, amqp_error_string2(r.library_error));
        break;
    case AMQP_RESPONSE_SERVER_EXCEPTION:
        fprintf(stderr, "[AMQP] %s: server exception (class=%u method=%u)\n",
                ctx, (unsigned)r.reply.id & 0xFFFF, (unsigned)(r.reply.id >> 16));
        break;
    default:
        fprintf(stderr, "[AMQP] %s: reply_type=%d\n", ctx, r.reply_type);
    }
    return 0;
}

/* -------------------------------------------------------------------------- *
 * Open                                                                       *
 * -------------------------------------------------------------------------- */
int nta_amqp_open(NtaAmqp *a, const NtaConfig *cfg,
                  const char *queue, int prefetch_count) {
    memset(a, 0, sizeof(*a));

    a->conn = amqp_new_connection();
    if (!a->conn) {
        fprintf(stderr, "[AMQP] amqp_new_connection falhou\n");
        return -1;
    }

    amqp_socket_t *socket = amqp_tcp_socket_new(a->conn);
    if (!socket) {
        fprintf(stderr, "[AMQP] amqp_tcp_socket_new falhou\n");
        amqp_destroy_connection(a->conn);
        a->conn = NULL;
        return -1;
    }

    if (amqp_socket_open(socket, cfg->rabbit_host, cfg->rabbit_port)) {
        fprintf(stderr, "[AMQP] conexão TCP falhou em %s:%d\n",
                cfg->rabbit_host, cfg->rabbit_port);
        amqp_destroy_connection(a->conn);
        a->conn = NULL;
        return -1;
    }

    amqp_rpc_reply_t login = amqp_login(
        a->conn, cfg->rabbit_vhost, 0, MAX_FRAME_SIZE, 0,
        AMQP_SASL_METHOD_PLAIN, cfg->rabbit_user, cfg->rabbit_pass);
    if (!amqp_reply_ok(login, "login")) {
        amqp_destroy_connection(a->conn);
        a->conn = NULL;
        return -1;
    }

    a->channel = 1;
    amqp_channel_open(a->conn, a->channel);
    if (!amqp_reply_ok(amqp_get_rpc_reply(a->conn), "channel_open")) {
        amqp_destroy_connection(a->conn);
        a->conn = NULL;
        return -1;
    }

    /* durable=1: fila sobrevive a restart do broker. Mesma flag usada no
     * agente (publisher.c) e no data_ingestor.py. */
    amqp_queue_declare(a->conn, a->channel, amqp_cstring_bytes(queue),
                       0, 1, 0, 0, amqp_empty_table);
    if (!amqp_reply_ok(amqp_get_rpc_reply(a->conn), "queue_declare")) {
        amqp_channel_close(a->conn, a->channel, AMQP_REPLY_SUCCESS);
        amqp_connection_close(a->conn, AMQP_REPLY_SUCCESS);
        amqp_destroy_connection(a->conn);
        a->conn = NULL;
        return -1;
    }

    if (prefetch_count > 0) {
        amqp_basic_qos(a->conn, a->channel, 0, (uint16_t)prefetch_count, 0);
        if (!amqp_reply_ok(amqp_get_rpc_reply(a->conn), "basic_qos")) {
            /* não-fatal: segue com prefetch default do broker */
        }
    }

    a->connected = 1;
    return 0;
}

/* -------------------------------------------------------------------------- *
 * Consume loop                                                               *
 * -------------------------------------------------------------------------- */
int nta_amqp_consume_loop(NtaAmqp *a, const char *queue,
                           nta_on_message_fn handler, void *user_ctx) {
    if (!a->connected) return -1;

    /* auto_ack=1 mantém paridade com data_ingestor.py. Tradeoff: mensagens
     * podem ser perdidas se o worker crashar durante handler, mas mantém
     * throughput alto e lógica simples. */
    amqp_basic_consume(a->conn, a->channel, amqp_cstring_bytes(queue),
                       amqp_empty_bytes, 0, 1, 0, amqp_empty_table);
    if (!amqp_reply_ok(amqp_get_rpc_reply(a->conn), "basic_consume")) {
        return -1;
    }

    char agent_id[AGENT_ID_MAX + 1];

    while (!nta_should_stop()) {
        amqp_envelope_t envelope;
        amqp_maybe_release_buffers(a->conn);

        /* Timeout de 1s: ao expirar, refaz o loop e checa stop flag. */
        struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
        amqp_rpc_reply_t r = amqp_consume_message(a->conn, &envelope, &timeout, 0);

        if (r.reply_type == AMQP_RESPONSE_LIBRARY_EXCEPTION &&
            r.library_error == AMQP_STATUS_TIMEOUT) {
            continue;
        }
        if (r.reply_type != AMQP_RESPONSE_NORMAL) {
            fprintf(stderr, "[AMQP] consume falhou (reply=%d) — saindo do loop\n",
                    r.reply_type);
            return -1;
        }

        /* Extrai user_id (agent_id) das propriedades. */
        const char *aid = "unknown";
        amqp_basic_properties_t *p = &envelope.message.properties;
        if ((p->_flags & AMQP_BASIC_USER_ID_FLAG) && p->user_id.len > 0) {
            size_t n = p->user_id.len;
            if (n > AGENT_ID_MAX) n = AGENT_ID_MAX;
            memcpy(agent_id, p->user_id.bytes, n);
            agent_id[n] = '\0';
            aid = agent_id;
        }

        if (handler) {
            handler((const char *)envelope.message.body.bytes,
                    envelope.message.body.len,
                    aid, user_ctx);
        }

        amqp_destroy_envelope(&envelope);
    }

    return 0;
}

/* -------------------------------------------------------------------------- *
 * Close                                                                      *
 * -------------------------------------------------------------------------- */
void nta_amqp_close(NtaAmqp *a) {
    if (!a || !a->conn) return;
    if (a->connected) {
        amqp_channel_close(a->conn, a->channel, AMQP_REPLY_SUCCESS);
        amqp_connection_close(a->conn, AMQP_REPLY_SUCCESS);
    }
    amqp_destroy_connection(a->conn);
    a->conn = NULL;
    a->connected = 0;
}
