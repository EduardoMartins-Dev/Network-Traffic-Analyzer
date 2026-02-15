#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Importa a biblioteca cJSON (que deve estar na pasta include)
// Se o CMake estiver configurado certo, apenas "cJSON.h" funciona.
// Se der erro, tente "../../include/cJSON.h"
#include "../../include/cJSON.h"
#include "../../include/output.h"

void export_to_json(const char *src_ip, int src_port, const char *dst_ip, int dst_port, const char *proto, int len)
{

    //CRIAR JSON

    cJSON * root = cJSON_CreateObject();

    if (root ==NULL)
    {
        fprintf(stderr, "ERRO\n");
        return;
    }

    //PREENCHE O JSON
    cJSON_AddStringToObject(root, "sensor_id", "teste");
    cJSON_AddStringToObject(root, "timestamp", "auto-generated"); // Futuramente colocaremos hora real

    // Dados do Pacote
    cJSON_AddStringToObject(root, "protocol", proto);
    cJSON_AddNumberToObject(root, "length_bytes", len);

    // Dados de Origem
    cJSON_AddStringToObject(root, "src_ip", src_ip);
    cJSON_AddNumberToObject(root, "src_port", src_port);

    // Dados de Destino
    cJSON_AddStringToObject(root, "dst_ip", dst_ip);
    cJSON_AddNumberToObject(root, "dst_port", dst_port);

    // CONVERTE PARA STRING
    char *json_string = cJSON_Print(root);
    if (json_string == NULL)
    {
        fprintf(stderr, "ERRO\n");
        cJSON_Delete(root);
        return;
    }

    printf("%s\n", json_string);

    //LIBERA MEMEMORIA ALOCADA

    free(json_string);
    cJSON_Delete(root);

}