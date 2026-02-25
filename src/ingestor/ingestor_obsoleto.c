#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <amqp.h>
#include <amqp_tcp_socket.h>
#include "../../include/cJSON.h"

// --- CONFIGURAÇÕES ---
// URL deve incluir o bucket, org e precisão
#define INFLUX_URL "http://localhost:8086/api/v2/write?org=cybersecurity&bucket=network_traffic&precision=s"
// O Header deve conter o Token (não a URL)
#define INFLUX_HEADER "Authorization: Token my-super-secret-auth-token"
#define RABBIT_QUEUE "traffic_queue"

amqp_connection_state_t conn;

// --- FUNÇÃO 1: Enviar para o InfluxDB ---
void send_to_influx(const char *line_protocol) {
    CURL *curl;
    CURLcode res;

    curl = curl_easy_init();
    if(curl) {
        struct curl_slist *headers = NULL;
        // CORREÇÃO: Adiciona o Token de Autorização, não a URL
        headers = curl_slist_append(headers, INFLUX_HEADER);

        curl_easy_setopt(curl, CURLOPT_URL, INFLUX_URL);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, line_protocol);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Executa (Bloqueante)
        res = curl_easy_perform(curl);

        if(res != CURLE_OK)
            fprintf(stderr, "Erro Curl: %s\n", curl_easy_strerror(res));
        else
            printf("Gravado no Influx: %s\n", line_protocol);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
}

// --- FUNÇÃO 2: Processar Mensagem ---
void process_message(const char *json_body, int len) {
    // Garante que a string do JSON termina com \0
    char *json_str = malloc(len + 1);
    memcpy(json_str, json_body, len);
    json_str[len] = '\0';

    cJSON *json = cJSON_Parse(json_str);
    if (!json) {
        free(json_str);
        return;
    }

    // Extração segura
    cJSON *proto = cJSON_GetObjectItem(json, "protocol");
    cJSON *bytes = cJSON_GetObjectItem(json, "length_bytes");
    cJSON *src   = cJSON_GetObjectItem(json, "src_ip");

    // Formatação para Influx Line Protocol:
    // Sintaxe: measurement,tag1=val,tag2=val field=val
    // OBS: Sem espaço nas tags, Espaço antes dos fields.
    if (proto && bytes && src) {
        char line[512];
        snprintf(line, sizeof(line), "traffic,protocol=%s,src_ip=%s bytes=%d",
                 proto->valuestring,
                 src->valuestring,
                 bytes->valueint);

        send_to_influx(line);
    }

    // LIMPEZA DE MEMÓRIA (Essencial para não estourar a RAM)
    cJSON_Delete(json);
    free(json_str);
}

// --- MAIN ---
int main() {
    // 1. Conexão RabbitMQ
    conn = amqp_new_connection();
    amqp_socket_t *socket = amqp_tcp_socket_new(conn);

    if (!socket) {
        fprintf(stderr, "Erro ao criar socket TCP\n");
        return 1;
    }

    // CORREÇÃO: Porta 5674 (Padrão) e função amqp_socket_open
    if (amqp_socket_open(socket, "localhost", 5674)) {
        fprintf(stderr, "Erro: Não foi possível conectar ao RabbitMQ (Porta 5674 fechada?)\n");
        return 1;
    }

    // Login
    amqp_rpc_reply_t login = amqp_login(conn, "/", 0, 131072, 0, AMQP_SASL_METHOD_PLAIN, "guest", "guest");
    if (login.reply_type != AMQP_RESPONSE_NORMAL) {
        fprintf(stderr, "Erro de Login no RabbitMQ\n");
        return 1;
    }

    amqp_channel_open(conn, 1);
    amqp_get_rpc_reply(conn); // Checa erro

    // Inicia consumo
    amqp_basic_consume(conn, 1, amqp_cstring_bytes(RABBIT_QUEUE), amqp_empty_bytes, 0, 1, 0, amqp_empty_table);

    printf("🐰 [INGESTOR] Ouvindo a fila '%s'...\n", RABBIT_QUEUE);

    // Loop Infinito
    while (1) {
        amqp_rpc_reply_t res;
        amqp_envelope_t envelope;

        amqp_maybe_release_buffers(conn);

        // CORREÇÃO: Usar amqp_consume_message (Maneira moderna de ler)
        res = amqp_consume_message(conn, &envelope, NULL, 0);

        if (AMQP_RESPONSE_NORMAL != res.reply_type) {
            break; // Sai do loop se der erro de conexão
        }

        process_message(envelope.message.body.bytes, envelope.message.body.len);

        amqp_destroy_envelope(&envelope);
    }

    // Limpeza Final
    amqp_channel_close(conn, 1, AMQP_REPLY_SUCCESS);
    amqp_connection_close(conn, AMQP_REPLY_SUCCESS);
    amqp_destroy_connection(conn);
    printf("Conexão encerrada.\n");
    return 0;
}