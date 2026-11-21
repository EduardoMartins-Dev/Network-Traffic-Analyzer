#include "cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Uso:\n"
        "  %s [--config <arq>] [<interface>]       — captura ao vivo\n"
        "        (sem <interface>: usa AGENT_IFACE do ambiente/config)\n"
        "  %s --list-interfaces                    — lista interfaces de captura\n"
#ifdef _WIN32
        "  --install-service --config <arq> [<interface>] — instala serviço NTAAgent\n"
        "  --uninstall-service                     — remove o serviço\n"
#endif
        "  %s --replay <file.pcap>                 — replay de arquivo\n"
        "        [--expect <gabarito.json>]         — valida detecções\n"
        "  %s --replay-dir <diretório>             — replay de diretório\n"
        "        [--report <relatório.json>]        — salva relatório\n",
        prog, prog, prog, prog);
}

AgentArgs parse_args(int argc, char *argv[]) {
    AgentArgs args;
    memset(&args, 0, sizeof(args));
    args.mode = MODE_LIVE;

    if (argc < 2) {
        print_usage(argv[0]);
        exit(1);
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--list-interfaces") == 0) {
            args.mode = MODE_LIST_IFACES;
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            args.config_file = argv[++i];
        } else if (strcmp(argv[i], "--service") == 0) {
            args.service = 1;
        } else if (strcmp(argv[i], "--install-service") == 0) {
            args.mode = MODE_SERVICE_INSTALL;
        } else if (strcmp(argv[i], "--uninstall-service") == 0) {
            args.mode = MODE_SERVICE_UNINSTALL;
        } else if ((args.mode == MODE_LIVE || args.mode == MODE_SERVICE_INSTALL) &&
                   argv[i][0] != '-') {
            args.iface = argv[i];
        } else if (strcmp(argv[i], "--replay") == 0 && i + 1 < argc) {
            args.mode      = MODE_REPLAY_FILE;
            args.pcap_file = argv[++i];
        } else if (strcmp(argv[i], "--replay-dir") == 0 && i + 1 < argc) {
            args.mode       = MODE_REPLAY_DIR;
            args.replay_dir = argv[++i];
        } else if (strcmp(argv[i], "--expect") == 0 && i + 1 < argc) {
            args.expect_file = argv[++i];
        } else if (strcmp(argv[i], "--report") == 0 && i + 1 < argc) {
            args.report_file = argv[++i];
        } else {
            fprintf(stderr, "Argumento desconhecido: %s\n", argv[i]);
            print_usage(argv[0]);
            exit(1);
        }
    }

    return args;
}
