#include "../../include/publisher.h"
#include "../../include/collector.h"
#include "../../include/cJSON.h"
#include "../../include/pipeline.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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
#define CONNECT_TIMEOUT_SEC 5      /* host remoto inalcançável não trava a thread */
#define RECONNECT_MIN_MS    1000
#define RECONNECT_MAX_MS    30000

/* Todo acesso a `conn`/`g_connected` e à política de retry é feito com
 * amqp_mutex travado (publish e metrics threads compartilham a conexão). */
static amqp_connection_state_t conn = NULL;
static int                      g_connected     = 0;
static long                     g_next_retry_ms = 0;
static long                     g_backoff_ms    = RECONNECT_MIN_MS;
static pthread_mutex_t          amqp_mutex = PTHREAD_MUTEX_INITIALIZER;

static char g_queue_name[MAX_QUEUE_NAME]  = "traffic_queue";
static char g_metrics_queue[MAX_QUEUE_NAME] = "traffic_metrics";
static char g_agent_id[128]               = "guest";

/* Parâmetros de conexão — lidos uma vez em init_queue(), reusados a cada
 * reconexão (ponteiros de getenv valem pela vida do processo). */
static const char *g_host, *g_vhost, *g_token;
static const char *g_ca_cert, *g_client_cert, *g_client_key;
static int         g_port, g_use_tls, g_use_mtls;

static const char *env_or(const char *var, const char *fallback) {
    const char *val = getenv(var);
    return (val && val[0] != '\0') ? val : fallback;
}

static long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* ========================================================================= *
 * CONEXÃO (sempre com amqp_mutex travado)                                   *
 * ========================================================================= */
static void drop_connection_locked(void) {
    if (conn) amqp_destroy_connection(conn);
    conn        = NULL;
    g_connected = 0;
}

static int rpc_ok(const char *ctx) {
    amqp_rpc_reply_t r = amqp_get_rpc_reply(conn);
    if (r.reply_type == AMQP_RESPONSE_NORMAL) return 1;
    fprintf(stderr, "[RABBIT] %s falhou (reply=%d).\n", ctx, r.reply_type);
    return 0;
}

static int connect_locked(void) {
    conn = amqp_new_connection();
    if (!conn) return -1;

    amqp_socket_t *socket = NULL;
    if (g_use_tls) {
        socket = amqp_ssl_socket_new(conn);
        if (!socket) {
            fprintf(stderr, "[RABBIT] Falha ao criar socket SSL.\n");
            drop_connection_locked();
            return -1;
        }
        if (g_ca_cert) {
            amqp_ssl_socket_set_cacert(socket, g_ca_cert);
            amqp_ssl_socket_set_verify_peer(socket, 1);
        } else {
            amqp_ssl_socket_set_verify_peer(socket, 0);
        }
        if (g_use_mtls &&
            amqp_ssl_socket_set_key(socket, g_client_cert, g_client_key) != AMQP_STATUS_OK) {
            fprintf(stderr, "[RABBIT] Falha ao carregar client cert/key (%s, %s).\n",
                    g_client_cert, g_client_key);
            drop_connection_locked();
            return -1;
        }
    } else {
        socket = amqp_tcp_socket_new(conn);
        if (!socket) {
            fprintf(stderr, "[RABBIT] Falha ao criar socket TCP.\n");
            drop_connection_locked();
            return -1;
        }
    }

    struct timeval tv = { CONNECT_TIMEOUT_SEC, 0 };
    if (amqp_socket_open_noblock(socket, g_host, g_port, &tv)) {
        fprintf(stderr, "[RABBIT] Nao foi possivel conectar em %s:%d\n", g_host, g_port);
        drop_connection_locked();
        return -1;
    }

    amqp_rpc_reply_t login = g_use_mtls
        ? amqp_login(conn, g_vhost, 0, MAX_FRAME_SIZE, 0, AMQP_SASL_METHOD_EXTERNAL, "")
        : amqp_login(conn, g_vhost, 0, MAX_FRAME_SIZE, 0, AMQP_SASL_METHOD_PLAIN,
                     g_agent_id, g_token);
    if (login.reply_type != AMQP_RESPONSE_NORMAL) {
        fprintf(stderr, "[RABBIT] Erro de autenticacao (%s). Verifique AGENT_ID/TOKEN ou cert.\n",
                g_use_mtls ? "EXTERNAL" : "PLAIN");
        drop_connection_locked();
        return -1;
    }

    amqp_channel_open(conn, 1);
    if (!rpc_ok("channel_open")) { drop_connection_locked(); return -1; }

    /* durable=1: filas sobrevivem a reinícios do broker. */
    amqp_queue_declare(conn, 1, amqp_cstring_bytes(g_queue_name),
                       0, 1, 0, 0, amqp_empty_table);
    if (!rpc_ok("queue_declare")) { drop_connection_locked(); return -1; }

    amqp_queue_declare(conn, 1, amqp_cstring_bytes(g_metrics_queue),
                       0, 1, 0, 0, amqp_empty_table);
    if (!rpc_ok("queue_declare")) { drop_connection_locked(); return -1; }

    g_connected  = 1;
    g_backoff_ms = RECONNECT_MIN_MS;
    printf("[RABBIT] Conectado em %s:%d | TLS: %s | mTLS: %s | Agente: %s\n",
           g_host, g_port, g_use_tls ? "sim" : "nao", g_use_mtls ? "sim" : "nao",
           g_agent_id);
    printf("[RABBIT] Filas — telemetria: '%s' | metricas: '%s'\n",
           g_queue_name, g_metrics_queue);
    return 0;
}

/* Conecta se preciso, respeitando o backoff (1s → 30s). Não bloqueia além
 * do CONNECT_TIMEOUT_SEC: fora da janela de retry retorna -1 na hora. */
static int ensure_connected_locked(void) {
    if (g_connected) return 0;

    long now = mono_ms();
    if (now < g_next_retry_ms) return -1;
    if (connect_locked() == 0) return 0;

    fprintf(stderr, "[RABBIT] Broker indisponivel — nova tentativa em %lds.\n",
            g_backoff_ms / 1000);
    g_next_retry_ms = now + g_backoff_ms;
    g_backoff_ms    = (g_backoff_ms * 2 > RECONNECT_MAX_MS) ? RECONNECT_MAX_MS
                                                             : g_backoff_ms * 2;
    return -1;
}

/* Publica na fila (default exchange). Erro de socket derruba a conexão pra
 * próxima chamada reconectar. Retorna 0 em sucesso. */
static int publish_to(const char *queue, const amqp_basic_properties_t *props,
                          const char *body) {
    pthread_mutex_lock(&amqp_mutex);
    int rc = -1;
    if (ensure_connected_locked() == 0) {
        int st = amqp_basic_publish(conn, 1, amqp_empty_bytes,
                                    amqp_cstring_bytes(queue),
                                    0, 0, props, amqp_cstring_bytes(body));
        if (st == AMQP_STATUS_OK) {
            rc = 0;
        } else {
            fprintf(stderr, "[RABBIT] Publish em '%s' falhou: %s — reconectando.\n",
                    queue, amqp_error_string2(st));
            drop_connection_locked();
        }
    }
    pthread_mutex_unlock(&amqp_mutex);
    return rc;
}

/* ========================================================================= *
 * INIT / CLOSE                                                              *
 * ========================================================================= */
void init_queue(void) {
    g_host        = env_or("AGENT_SERVER_HOST",   "localhost");
    g_port        = atoi(env_or("AGENT_SERVER_PORT", "5674"));
    g_vhost       = env_or("AGENT_VHOST",         "/");
    g_token       = env_or("AGENT_TOKEN",         "guest");
    g_use_tls     = atoi(env_or("AGENT_USE_TLS",  "0"));
    g_ca_cert     = getenv("AGENT_CA_CERT");
    g_client_cert = getenv("AGENT_CLIENT_CERT");
    g_client_key  = getenv("AGENT_CLIENT_KEY");
    g_use_mtls    = (g_use_tls && g_client_cert && g_client_key);

    strncpy(g_queue_name,    env_or("AGENT_QUEUE",         "traffic_queue"),
            sizeof(g_queue_name) - 1);
    strncpy(g_metrics_queue, env_or("AGENT_METRICS_QUEUE", "traffic_metrics"),
            sizeof(g_metrics_queue) - 1);
    strncpy(g_agent_id,      env_or("AGENT_ID",            "guest"),
            sizeof(g_agent_id) - 1);

    /* Broker fora não impede o agente de subir: captura segue, eventos
     * acumulam em rb_evt e a publicação reconecta em background. */
    pthread_mutex_lock(&amqp_mutex);
    if (ensure_connected_locked() != 0)
        fprintf(stderr, "[RABBIT] Iniciando sem broker — reconexao automatica ativa.\n");
    pthread_mutex_unlock(&amqp_mutex);
}

void close_queue(void) {
    pthread_mutex_lock(&amqp_mutex);
    if (g_connected) {
        amqp_channel_close(conn, 1, AMQP_REPLY_SUCCESS);
        amqp_connection_close(conn, AMQP_REPLY_SUCCESS);
    }
    drop_connection_locked();
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
int publisher_send_batch(const event_slot_t *batch, int count) {
    if (!batch || count <= 0) return 0;

    /* Sem conexão (e fora da janela de retry): falha rápido, sem montar JSON. */
    pthread_mutex_lock(&amqp_mutex);
    int up = (ensure_connected_locked() == 0);
    pthread_mutex_unlock(&amqp_mutex);
    if (!up) return -1;

    cJSON *arr = cJSON_CreateArray();
    if (!arr) return -1;

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
    if (!msg) return -1;

    amqp_basic_properties_t props;
    props._flags        = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG | AMQP_BASIC_USER_ID_FLAG;
    props.content_type  = amqp_cstring_bytes("application/json");
    props.delivery_mode = 2;  /* persistente */
    props.user_id       = amqp_cstring_bytes(g_agent_id);  /* broker valida contra login */

    int rc = publish_to(g_queue_name, &props, msg);
    free(msg);
    return rc;
}

/* ========================================================================= *
 * METRICS — publica num routing key separado                                *
 * ========================================================================= */
int publisher_send_metrics(const char *json_payload) {
    if (!json_payload || !*json_payload) return 0;

    amqp_basic_properties_t props;
    props._flags        = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG | AMQP_BASIC_USER_ID_FLAG;
    props.content_type  = amqp_cstring_bytes("application/json");
    props.delivery_mode = 1;  /* efêmero — métrica antiga não serve */
    props.user_id       = amqp_cstring_bytes(g_agent_id);

    return publish_to(g_metrics_queue, &props, json_payload);
}
