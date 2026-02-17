#include "../../include/publisher.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <amqp_tcp_socket.h>
#include <amqp.h>
#include <amqp_framing.h>

static amqp_connection_state_t conn;

void init_queue() {
    const char *hostname = "localhost";
    int port = 5674;

    conn = amqp_new_connection();
    amqp_socket_t *socket = amqp_tcp_socket_new(conn);

    if (!socket) {
        fprintf(stderr, "Falha ao criar socket TCP.\n");
        exit(1);
    }

    if (amqp_socket_open(socket, hostname, port)) {
        fprintf(stderr, "Falha ao conectar em %s:%d\n", hostname, port);
        exit(1);
    }

    amqp_rpc_reply_t login = amqp_login(conn, "/", 0, 131072, 0, AMQP_SASL_METHOD_PLAIN, "guest", "guest");
    if (login.reply_type != AMQP_RESPONSE_NORMAL) {
        fprintf(stderr, "Erro de Login.\n");
        exit(1);
    }

    amqp_channel_open(conn, 1);
    amqp_get_rpc_reply(conn);

    amqp_queue_declare(conn, 1, amqp_cstring_bytes("traffic_queue"), 0, 0, 0, 0, amqp_empty_table);

    // CORREÇÃO AQUI: printf em vez de print
    printf("🐰 [RABBIT] Conectado!\n");
}

void send_message(const char *message) {
    amqp_basic_properties_t props;
    props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
    props.content_type = amqp_cstring_bytes("application/json");
    props.delivery_mode = 1;

    int status = amqp_basic_publish(conn,
                                    1,
                                    amqp_empty_bytes,
                                    amqp_cstring_bytes("traffic_queue"),
                                    0,
                                    0,
                                    &props,
                                    amqp_cstring_bytes(message));

    if (status != AMQP_STATUS_OK) {
        fprintf(stderr, "⚠️ [RABBIT] Erro ao publicar pacote!\n");
    }
}

void close_queue() {
    amqp_channel_close(conn, 1, AMQP_REPLY_SUCCESS);
    amqp_connection_close(conn, AMQP_REPLY_SUCCESS);
    amqp_destroy_connection(conn);
}