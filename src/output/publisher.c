#include "../../include/publisher.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <amqp_tcp_socket.h>
#include <amqp_ssl_socket.h>
#include <amqp.h>
#include <amqp_framing.h>

/* ========================================================================= *
 * CONFIGURAÇÕES VIA VARIÁVEIS DE AMBIENTE                                   *
 *                                                                           *
 * Variável            | Padrão        | Descrição                           *
 * AGENT_SERVER_HOST   | localhost     | Endereço do RabbitMQ central        *
 * AGENT_SERVER_PORT   | 5674          | Porta (5674=TCP local, 5671=AMQPS)  *
 * AGENT_VHOST         | /             | Virtual host do RabbitMQ            *
 * AGENT_ID            | guest         | Identidade do agente (usuário AMQP) *
 * AGENT_TOKEN         | guest         | Credencial/senha do agente          *
 * AGENT_QUEUE         | traffic_queue | Nome da fila de telemetria          *
 * AGENT_USE_TLS       | 0             | 1 = ativa TLS/SSL na conexão        *
 * AGENT_CA_CERT       | (nenhum)      | Caminho para o certificado CA (.pem)*
 * ========================================================================= */

#define MAX_FRAME_SIZE  131072
#define MAX_JSON_SIZE   512

static amqp_connection_state_t conn;

/* Lê uma variável de ambiente, retornando o fallback se não estiver definida */
static const char *env_or(const char *var, const char *fallback) {
    const char *val = getenv(var);
    return (val && val[0] != '\0') ? val : fallback;
}

static void send_message(const char *message) {
    amqp_basic_properties_t props;
    props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
    props.content_type = amqp_cstring_bytes("application/json");

    // delivery_mode = 2 (Persistente): mensagens sobrevivem a reinicializações
    // do broker, garantindo que eventos forenses não sejam perdidos.
    props.delivery_mode = 2;

    const char *queue = env_or("AGENT_QUEUE", "traffic_queue");
    amqp_basic_publish(conn, 1, amqp_empty_bytes, amqp_cstring_bytes(queue),
                       0, 0, &props, amqp_cstring_bytes(message));
}

void init_queue() {
    const char *host    = env_or("AGENT_SERVER_HOST", "localhost");
    int         port    = atoi(env_or("AGENT_SERVER_PORT", "5674"));
    const char *vhost   = env_or("AGENT_VHOST", "/");
    const char *id      = env_or("AGENT_ID", "guest");
    const char *token   = env_or("AGENT_TOKEN", "guest");
    const char *queue   = env_or("AGENT_QUEUE", "traffic_queue");
    int         use_tls = atoi(env_or("AGENT_USE_TLS", "0"));
    const char *ca_cert = getenv("AGENT_CA_CERT");

    conn = amqp_new_connection();
    amqp_socket_t *socket = NULL;

    if (use_tls) {
        socket = amqp_ssl_socket_new(conn);
        if (!socket) {
            fprintf(stderr, "[RABBIT] Falha ao criar socket SSL.\n");
            exit(EXIT_FAILURE);
        }
        if (ca_cert) {
            // Modo produção: valida identidade do servidor com CA própria
            amqp_ssl_socket_set_cacert(socket, ca_cert);
            amqp_ssl_socket_set_verify_peer(socket, 1);
        } else {
            // Modo lab/dev: TLS ativo mas sem validação de certificado
            amqp_ssl_socket_set_verify_peer(socket, 0);
        }
    } else {
        socket = amqp_tcp_socket_new(conn);
        if (!socket) {
            fprintf(stderr, "[RABBIT] Falha ao criar socket TCP.\n");
            exit(EXIT_FAILURE);
        }
    }

    if (amqp_socket_open(socket, host, port)) {
        fprintf(stderr, "[RABBIT] Nao foi possivel conectar em %s:%d\n", host, port);
        exit(EXIT_FAILURE);
    }

    amqp_rpc_reply_t login = amqp_login(conn, vhost, 0, MAX_FRAME_SIZE, 0,
                                         AMQP_SASL_METHOD_PLAIN, id, token);
    if (login.reply_type != AMQP_RESPONSE_NORMAL) {
        fprintf(stderr, "[RABBIT] Erro de autenticacao. Verifique AGENT_ID e AGENT_TOKEN.\n");
        exit(EXIT_FAILURE);
    }

    amqp_channel_open(conn, 1);
    amqp_get_rpc_reply(conn);

    // durable=1: a fila sobrevive a reinicializacoes do RabbitMQ
    amqp_queue_declare(conn, 1, amqp_cstring_bytes(queue),
                       0, 1, 0, 0, amqp_empty_table);
    amqp_get_rpc_reply(conn);

    printf("[RABBIT] Conectado em %s:%d | TLS: %s | Agente: %s\n",
           host, port, use_tls ? "sim" : "nao", id);
}

void publish_packet(const char *src_ip, int port, const char *proto, int bytes, int is_scan) {
    char message[MAX_JSON_SIZE];

    const char *safe_ip    = src_ip ? src_ip : "0.0.0.0";
    const char *safe_proto = proto  ? proto  : "UNKNOWN";

    snprintf(message, sizeof(message),
             "{\"src_ip\":\"%s\", \"port\":%d, \"proto\":\"%s\", \"bytes\":%d, \"is_scan\":%d}",
             safe_ip, port, safe_proto, bytes, is_scan);

    send_message(message);

    if (is_scan) {
        printf("[IDS] Alerta: %s detectado de %s\n",
               (strcmp(safe_proto, "ICMP") == 0) ? "ICMP FLOOD" : "PORT SCAN", safe_ip);
    }
}

void close_queue() {
    amqp_channel_close(conn, 1, AMQP_REPLY_SUCCESS);
    amqp_connection_close(conn, AMQP_REPLY_SUCCESS);
    amqp_destroy_connection(conn);
    printf("[RABBIT] Conexao encerrada.\n");
}