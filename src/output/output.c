#include <stdio.h>
#include <stdlib.h>
#include "../../include/cJSON.h"
#include "../../include/output.h"
#include "../../include/publisher.h"

void export_to_json(const char *src_ip, int src_port, const char *dst_ip, int dst_port, const char *proto, int len) {
    // 1. CRIA O OBJETO JSON
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "src_ip", src_ip);
    cJSON_AddNumberToObject(json, "src_port", src_port);
    cJSON_AddStringToObject(json, "dst_ip", dst_ip);
    cJSON_AddNumberToObject(json, "dst_port", dst_port);
    cJSON_AddStringToObject(json, "protocol", proto);
    cJSON_AddNumberToObject(json, "length_bytes", len);

    // 2. CONVERTE PARA TEXTO
    char *json_string = cJSON_PrintUnformatted(json);

    if (json_string != NULL) {
        // 3. ENVIA PARA O RABBITMQ
        send_message(json_string);


        free(json_string); // Libera a string
    }

    // 4. LIMPA O OBJETO DA MEMÓRIA
    cJSON_Delete(json);
}