#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "../include/publisher.h"
#include "../include/capture.h"
#include "../include/replay.h"

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
    AgentArgs args = parse_args(argc, argv);

    /* ------------------------------------------------------------------- *
     * MODO LIVE — captura de interface em tempo real                       *
     * ------------------------------------------------------------------- */
    if (args.mode == MODE_LIVE) {
        if (!has_privileges()) {
            fprintf(stderr, "Erro: %s\n", PRIVILEGE_MSG);
            return 1;
        }

        printf("Iniciando sniffer na interface '%s' (Ctrl+C para parar)\n",
               args.iface);

        init_queue();
        start_sniffer(args.iface);
        close_queue();
        return 0;
    }

    /* ------------------------------------------------------------------- *
     * MODO REPLAY FILE — processa um único .pcap                          *
     * Não requer privilégios nem RabbitMQ.                                 *
     * ------------------------------------------------------------------- */
    if (args.mode == MODE_REPLAY_FILE) {
        Gabarito *g = NULL;
        if (args.expect_file)
            g = gabarito_load(args.expect_file);

        ReplayResult r = replay_file(args.pcap_file, g);
        print_replay_result(&r);
        gabarito_free(g);

        /* Exit 1 se gabarito fornecido e score abaixo de 80% */
        return (g && r.score < 80.0) ? 1 : 0;
    }

    /* ------------------------------------------------------------------- *
     * MODO REPLAY DIR — processa todos os .pcap de um diretório           *
     * Exit code 1 definido internamente se score agregado < 80%.          *
     * ------------------------------------------------------------------- */
    if (args.mode == MODE_REPLAY_DIR) {
        replay_dir(args.replay_dir, args.report_file);
        return 0;
    }

    return 0;
}
