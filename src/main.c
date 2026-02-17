#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/publisher.h"
#include "../include/capture.h"

int main(int argc, char *argv[]) {

    if (argc != 2) {
        printf("Uso: %s <interface>\n", argv[0]);
        return 1;
    }

    printf("Iniciando sniffer (Pressione Ctrl+C para parar)\n");

    // Start sniffer
    init_queue();

    start_sniffer(argv[1]);

    close_queue();
    return 0;
}