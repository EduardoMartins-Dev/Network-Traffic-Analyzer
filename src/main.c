#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "../include/publisher.h"
#include "../include/capture.h"

/* ========================================================================= *
 * VERIFICAÇÃO DE PRIVILÉGIOS (Multiplataforma)                              *
 * ========================================================================= */
#ifdef _WIN32
    #include <windows.h>
    #include <shlobj.h>
    static int has_privileges() { return IsUserAnAdmin(); }
    static const char *PRIVILEGE_MSG = "Execute como Administrador.";
#else
    #include <unistd.h>
    static int has_privileges() { return getuid() == 0; }
    static const char *PRIVILEGE_MSG = "Execute com sudo ou como root.";
#endif

/* Lista todas as interfaces de rede disponíveis no sistema */
static void list_interfaces() {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Erro ao listar interfaces: %s\n", errbuf);
        return;
    }

    printf("\nInterfaces disponiveis:\n");
    int i = 1;
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        printf("  %d. %s", i++, d->name);
        if (d->description) printf("  (%s)", d->description);
        printf("\n");
    }
    printf("\n");

    pcap_freealldevs(alldevs);
}

int main(int argc, char *argv[]) {
    if (!has_privileges()) {
        fprintf(stderr, "Erro: %s\n", PRIVILEGE_MSG);
        return 1;
    }

    if (argc != 2) {
        printf("Uso: %s <interface>\n", argv[0]);
        list_interfaces();
        return 1;
    }

    printf("Iniciando sniffer na interface '%s' (Ctrl+C para parar)\n", argv[1]);

    init_queue();
    start_sniffer(argv[1]);
    close_queue();

    return 0;
}