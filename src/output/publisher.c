#include "../../include/publisher.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <amqp_tcp_socket.h>
#include <amqp.h>
#include <amqp_framing.h>

/* ========================================================================= *
 * CONFIGURAÇÕES DO BROKER (RABBITMQ)                                        *
 * ========================================================================= */
#define RMQ_HOSTNAME    "localhost"
#define RMQ_PORT        5674            // Porta mapeada do container Docker
#define RMQ_VHOST       "/"
#define RMQ_USER        "guest"
#define RMQ_PASS        "guest"
#define RMQ_QUEUE_NAME  "traffic_queue"
#define RMQ_CHANNEL     1               // Canal de comunicação padrão
#define MAX_FRAME_SIZE  131072          // Tamanho máximo do frame AMQP
#define MAX_JSON_SIZE   512             // Buffer para o payload JSON

// Estado global da conexão com o RabbitMQ mantido em memória
static amqp_connection_state_t conn;

/* ========================================================================= *
 * FUNÇÕES INTERNAS (HELPERS)                                                *
 * ========================================================================= */

/**
 * @brief Envia o payload final para a fila do RabbitMQ.
 * * Marcada como 'static' pois é uma função auxiliar interna deste arquivo,
 * isolando a lógica de baixo nível do AMQP do restante do projeto (Encapsulamento).
 * * @param message String contendo o JSON formatado.
 */
static void send_message(const char *message) {
    amqp_basic_properties_t props;

    // Configura as propriedades básicas do pacote AMQP
    props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
    props.content_type = amqp_cstring_bytes("application/json");

    // delivery_mode = 1 (Não persistente). Escolhemos isso para evitar
    // gargalos de I/O em disco, maximizando o throughput do IDS.
    props.delivery_mode = 1;

    // Publica efetivamente a mensagem na fila com a chave de roteamento padrão
    amqp_basic_publish(conn, RMQ_CHANNEL, amqp_empty_bytes, amqp_cstring_bytes(RMQ_QUEUE_NAME),
                       0, 0, &props, amqp_cstring_bytes(message));
}

/* ========================================================================= *
 * API PÚBLICA (Exposta via publisher.h)                                     *
 * ========================================================================= */

/**
 * @brief Inicializa a comunicação TCP e o canal AMQP com o broker RabbitMQ.
 * * Esta função deve ser chamada apenas uma vez durante o boot do IDS.
 */
void init_queue() {
    conn = amqp_new_connection();
    amqp_socket_t *socket = amqp_tcp_socket_new(conn);

    // Tenta abrir o socket de rede com o RabbitMQ
    if (!socket || amqp_socket_open(socket, RMQ_HOSTNAME, RMQ_PORT)) {
        fprintf(stderr, "❌ [RABBIT] Falha crítica: Não foi possível abrir o socket TCP em %s:%d\n", RMQ_HOSTNAME, RMQ_PORT);
        exit(EXIT_FAILURE);
    }

    // Tenta autenticação com as credenciais padrão
    amqp_rpc_reply_t login = amqp_login(conn, RMQ_VHOST, 0, MAX_FRAME_SIZE, 0,
                                        AMQP_SASL_METHOD_PLAIN, RMQ_USER, RMQ_PASS);

    if (login.reply_type != AMQP_RESPONSE_NORMAL) {
        fprintf(stderr, "❌ [RABBIT] Erro de Autenticação. Verifique usuário e senha.\n");
        exit(EXIT_FAILURE);
    }

    // Abre um canal de comunicação e declara a fila para garantir que ela exista
    amqp_channel_open(conn, RMQ_CHANNEL);
    amqp_get_rpc_reply(conn);
    amqp_queue_declare(conn, RMQ_CHANNEL, amqp_cstring_bytes(RMQ_QUEUE_NAME),
                       0, 0, 0, 0, amqp_empty_table);

    printf("🐰 [RABBIT] Conectado! Link de telemetria estabelecido com sucesso na porta %d.\n", RMQ_PORT);
}

/**
 * @brief Serializa os dados da rede em JSON e os despacha para a mensageria.
 * * Converte a estrutura plana do C em um formato compatível para que o
 * ingestor em Python possa consumir, tipar e enviar ao InfluxDB.
 * * @param src_ip Endereço IP do dispositivo origem.
 * @param port Porta de destino acessada.
 * @param proto Protocolo de transporte/rede (Ex: TCP, UDP, ICMP).
 * @param bytes Tamanho capturado do pacote.
 * @param is_scan Flag booleana (1 para ataque, 0 para normal).
 */
void publish_packet(const char* src_ip, int port, const char* proto, int bytes, int is_scan) {
    char message[MAX_JSON_SIZE];

    // Tratamento de segurança (fallback) para evitar NULL Pointers no snprintf
    const char* safe_ip = src_ip ? src_ip : "0.0.0.0";
    const char* safe_proto = proto ? proto : "UNKNOWN";

    // Constrói o payload estruturado
    snprintf(message, sizeof(message),
             "{\"src_ip\":\"%s\", \"port\":%d, \"proto\":\"%s\", \"bytes\":%d, \"is_scan\":%d}",
             safe_ip, port, safe_proto, bytes, is_scan);

    send_message(message);

    // Feedback visual local no terminal do sensor
    if (is_scan) {
        printf("🚨 [IDS] Alerta de Segurança: Assinatura de %s detectada originada de %s\n",
               (strcmp(safe_proto, "ICMP") == 0) ? "ICMP FLOOD" : "PORT SCAN", safe_ip);
    }
}

/**
 * @brief Encerra graciosamente os canais e o socket com o RabbitMQ.
 * * Importante para evitar "memory leaks" e conexões pendentes no lado do servidor
 * caso o programa em C seja finalizado pelo usuário (Ctrl+C).
 */
void close_queue() {
    amqp_channel_close(conn, RMQ_CHANNEL, AMQP_REPLY_SUCCESS);
    amqp_connection_close(conn, AMQP_REPLY_SUCCESS);
    amqp_destroy_connection(conn);
    printf("🐰 [RABBIT] Conexão encerrada com segurança.\n");
}