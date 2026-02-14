#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "../include/capture.h"

int main(int argc, char *argv[]) {
    printf("========================================\n");
    printf("    NETWORK TRAFFIC ANALYZER v0.1   \n");
    printf("      [Monitorando Camadas 2, 3 e 4]  \n");
    printf("========================================\n");

    char *interface_name = "lo";

    if (argc > 1) {
        interface_name = argv[1];
    }

    printf(" Interface Alvo: %s\n", interface_name);
    printf("Iniciando motor de captura... (Pressione Ctrl+C para parar)\n");

    // Start sniffer
    start_sniffer(interface_name);

    printf(" Encerrando.\n");
    return 0;
}