#include "../../include/publisher.h"
#include "../../include/collector.h"
#include "../../include/cJSON.h"
#include "../../include/pipeline.h"

#include <pthread.h>
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
 * Variável              | Padrão           | Descrição                      *
 * AGENT_SERVER_HOST     | localhost        | Endereço do RabbitMQ central   *
 * AGENT_SERVER_PORT     | 5674             | Porta (5674=TCP, 5671=AMQPS)   *
 * AGENT_VHOST           | /                | Virtual host do RabbitMQ       *
 * AGENT_ID              | guest            | Identidade do agente           *
 * AGENT_TOKEN           | guest            | Credencial/senha               *
 * AGENT_QUEUE           | traffic_queue    | Fila de telemetria             *
 * AGENT_METRICS_QUEUE   | traffic_metrics  | Fila de métricas do pipeline   *
 * AGENT_USE_TLS         | 0                | 1 = ativa TLS/SSL              *
 * AGENT_CA_CERT         | (nenhum)         | Certificado CA (.pem)          *
 * ========================================================================= */

#define MAX_FRAME_SIZE 131072
#define MAX_QUEUE_NAME 128

static amqp_connection_state_t conn;
static pthread_mutex_t          amqp_mutex = PTHREAD_MUTEX_INITIALIZER;

static char g_queue_name[MAX_QUEUE_NAME]  = "traffic_queue";
static char g_metrics_queue[MAX_QUEUE_NAME] = "traffic_metrics";
static char g_agent_id[128]               = "guest";

static const char *env_or(const char *var, const char *fallback) {
    const char *val = getenv(var);
    return (val && val[0] != '\0') ? val : fallback;
}

/* ========================================================================= *
 * INIT / CLOSE                                                              *
 * ========================================================================= */
void init_queue(void) {
    const char *host    = env_or("AGENT_SERVER_HOST",   "localhost");
    int         port    = atoi(env_or("AGENT_SERVER_PORT", "5674"));
    const char *vhost   = env_or("AGENT_VHOST",         "/");
    const char *id      = env_or("AGENT_ID",            "guest");
    const char *token   = env_or("AGENT_TOKEN",         "guest");
    const char *queue   = env_or("AGENT_QUEUE",         "traffic_queue");
    const char *metrics = env_or("AGENT_METRICS_QUEUE", "traffic_metrics");
    int         use_tls     = atoi(env_or("AGENT_USE_TLS",  "0"));
    const char *ca_cert     = getenv("AGENT_CA_CERT");
    const char *client_cert = getenv("AGENT_CLIENT_CERT");
    const char *client_key  = getenv("AGENT_CLIENT_KEY");
    int         use_mtls    = (use_tls && client_cert && client_key);

    strncpy(g_queue_name,    queue,   sizeof(g_queue_name)    - 1);
    strncpy(g_metrics_queue, metrics, sizeof(g_metrics_queue) - 1);
    strncpy(g_agent_id,      id,      sizeof(g_agent_id)      - 1);

    conn = amqp_new_connection();
    amqp_socket_t *socket = NULL;

    if (use_tls) {
        socket = amqp_ssl_socket_new(conn);
        if (!socket) {
            fprintf(stderr, "[RABBIT] Falha ao criar socket SSL.\n");
            exit(EXIT_FAILURE);
        }
        if (ca_cert) {
            amqp_ssl_socket_set_cacert(socket, ca_cert);
            amqp_ssl_socket_set_verify_peer(socket, 1);
        } else {
            amqp_ssl_socket_set_verify_peer(socket, 0);
        }
        if (use_mtls) {
            if (amqp_ssl_socket_set_key(socket, client_cert, client_key) != AMQP_STATUS_OK) {
                fprintf(stderr, "[RABBIT] Falha ao carregar client cert/key (%s, %s).\n",
                        client_cert, client_key);
                exit(EXIT_FAILURE);
            }
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

    amqp_rpc_reply_t login = use_mtls
        ? amqp_login(conn, vhost, 0, MAX_FRAME_SIZE, 0, AMQP_SASL_METHOD_EXTERNAL, "")
        : amqp_login(conn, vhost, 0, MAX_FRAME_SIZE, 0, AMQP_SASL_METHOD_PLAIN, id, token);
    if (login.reply_type != AMQP_RESPONSE_NORMAL) {
        fprintf(stderr, "[RABBIT] Erro de autenticacao (%s). Verifique AGENT_ID/TOKEN ou cert.\n",
                use_mtls ? "EXTERNAL" : "PLAIN");
        exit(EXIT_FAILURE);
    }

    amqp_channel_open(conn, 1);
    amqp_get_rpc_reply(conn);

    /* durable=1: filas sobrevivem a reinícios do broker. */
    amqp_queue_declare(conn, 1, amqp_cstring_bytes(g_queue_name),
                       0, 1, 0, 0, amqp_empty_table);
    amqp_get_rpc_reply(conn);

    amqp_queue_declare(conn, 1, amqp_cstring_bytes(g_metrics_queue),
                       0, 1, 0, 0, amqp_empty_table);
    amqp_get_rpc_reply(conn);

    printf("[RABBIT] Conectado em %s:%d | TLS: %s | mTLS: %s | Agente: %s\n",
           host, port, use_tls ? "sim" : "nao", use_mtls ? "sim" : "nao", id);
    printf("[RABBIT] Filas — telemetria: '%s' | metricas: '%s'\n",
           g_queue_name, g_metrics_queue);
}

void close_queue(void) {
    pthread_mutex_lock(&amqp_mutex);
    amqp_channel_close(conn, 1, AMQP_REPLY_SUCCESS);
    amqp_connection_close(conn, AMQP_REPLY_SUCCESS);
    amqp_destroy_connection(conn);
    pthread_mutex_unlock(&amqp_mutex);
    printf("[RABBIT] Conexao encerrada.\n");
}

/* ========================================================================= *
 * PUBLISH — agora enfileira em rb_evt (ou imprime alerta em replay)         *
 * ========================================================================= */
void publish_packet(const char *src_ip, int port, const char *proto, int bytes,
                    int is_scan, const char *attack_type,
                    const char *kill_chain_stage, int kc_score,
                    const char *mitre_technique) {
    const char *safe_ip     = src_ip           ? src_ip           : "0.0.0.0";
    const char *safe_proto  = proto            ? proto            : "UNKNOWN";
    const char *safe_attack = attack_type      ? attack_type      : "NONE";
    const char *safe_stage  = kill_chain_stage ? kill_chain_stage : "IDLE";
    const char *safe_mitre  = mitre_technique  ? mitre_technique  : "";

    if (is_scan) {
        printf("[IDS] Alerta: %-14s | IP: %-15s | Kill Chain: %-8s | Score: %3d | MITRE: %s\n",
               safe_attack, safe_ip, safe_stage, kc_score, safe_mitre);
    }

    if (g_replay_mode) return;

    event_slot_t evt;
    memset(&evt, 0, sizeof(evt));
    strncpy(evt.src_ip,           safe_ip,     sizeof(evt.src_ip)           - 1);
    evt.port    = port;
    strncpy(evt.proto,            safe_proto,  sizeof(evt.proto)            - 1);
    evt.bytes   = bytes;
    evt.is_scan = is_scan;
    strncpy(evt.attack_type,      safe_attack, sizeof(evt.attack_type)      - 1);
    strncpy(evt.kill_chain_stage, safe_stage,  sizeof(evt.kill_chain_stage) - 1);
    evt.kc_score = kc_score;
    strncpy(evt.mitre,            safe_mitre,  sizeof(evt.mitre)            - 1);

    pipeline_push_event(&evt);
}

/* ========================================================================= *
 * BATCH SEND — um único publish com array JSON                              *
 * ========================================================================= */
void publisher_send_batch(const event_slot_t *batch, int count) {
    if (!batch || count <= 0) return;

    cJSON *arr = cJSON_CreateArray();
    if (!arr) return;

    for (int i = 0; i < count; i++) {
        cJSON *obj = cJSON_CreateObject();
        if (!obj) continue;
        cJSON_AddStringToObject(obj, "src_ip",           batch[i].src_ip);
        cJSON_AddNumberToObject(obj, "port",             batch[i].port);
        cJSON_AddStringToObject(obj, "proto",            batch[i].proto);
        cJSON_AddNumberToObject(obj, "bytes",            batch[i].bytes);
        cJSON_AddNumberToObject(obj, "is_scan",          batch[i].is_scan);
        cJSON_AddStringToObject(obj, "attack_type",      batch[i].attack_type);
        cJSON_AddStringToObject(obj, "kill_chain_stage", batch[i].kill_chain_stage);
        cJSON_AddNumberToObject(obj, "kc_score",         batch[i].kc_score);
        cJSON_AddStringToObject(obj, "mitre",            batch[i].mitre);
        cJSON_AddItemToArray(arr, obj);
    }

    char *msg = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    if (!msg) return;

    amqp_basic_properties_t props;
    props._flags        = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG | AMQP_BASIC_USER_ID_FLAG;
    props.content_type  = amqp_cstring_bytes("application/json");
    props.delivery_mode = 2;  /* persistente */
    props.user_id       = amqp_cstring_bytes(g_agent_id);  /* broker valida contra login */

    pthread_mutex_lock(&amqp_mutex);
    amqp_basic_publish(conn, 1, amqp_empty_bytes,
                       amqp_cstring_bytes(g_queue_name),
                       0, 0, &props, amqp_cstring_bytes(msg));
    pthread_mutex_unlock(&amqp_mutex);

    free(msg);
}

/* ========================================================================= *
 * METRICS — publica num routing key separado                                *
 * ========================================================================= */
void publisher_send_metrics(const char *json_payload) {
    if (!json_payload || !*json_payload) return;

    amqp_basic_properties_t props;
    props._flags        = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG | AMQP_BASIC_USER_ID_FLAG;
    props.content_type  = amqp_cstring_bytes("application/json");
    props.delivery_mode = 1;  /* efêmero — métrica antiga não serve */
    props.user_id       = amqp_cstring_bytes(g_agent_id);

    pthread_mutex_lock(&amqp_mutex);
    amqp_basic_publish(conn, 1, amqp_empty_bytes,
                       amqp_cstring_bytes(g_metrics_queue),
                       0, 0, &props, amqp_cstring_bytes(json_payload));
    pthread_mutex_unlock(&amqp_mutex);
}
