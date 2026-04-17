#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pcap.h>
#include "../include/publisher.h"
#include "../include/capture.h"
#include "../include/pipeline.h"
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

/* Signal handler — seguro para SIGINT/SIGTERM (pcap_breakloop é async-safe). */
static void on_signal(int sig) {
    (void)sig;
    pipeline_request_stop();
}

int main(int argc, char *argv[]) {
    AgentArgs args = parse_args(argc, argv);

    /* ------------------------------------------------------------------- *
     * MODO LIVE — pipeline multi-thread (v5.0)                             *
     * ------------------------------------------------------------------- */
    if (args.mode == MODE_LIVE) {
        if (!has_privileges()) {
            fprintf(stderr, "Erro: %s\n", PRIVILEGE_MSG);
            return 1;
        }

        signal(SIGINT,  on_signal);
        signal(SIGTERM, on_signal);

        printf("Iniciando pipeline v5.0 em '%s' (Ctrl+C para parar)\n",
               args.iface);

        return pipeline_run(args.iface);
    }

    /* ------------------------------------------------------------------- *
     * MODO REPLAY FILE — processa um único .pcap                          *
     * ------------------------------------------------------------------- */
    if (args.mode == MODE_REPLAY_FILE) {
        Gabarito *g = NULL;
        if (args.expect_file)
            g = gabarito_load(args.expect_file);

        ReplayResult r = replay_file(args.pcap_file, g);
        print_replay_result(&r);
        gabarito_free(g);

        return (g && r.score < 80.0) ? 1 : 0;
    }

    /* ------------------------------------------------------------------- *
     * MODO REPLAY DIR — processa todos os .pcap de um diretório           *
     * ------------------------------------------------------------------- */
    if (args.mode == MODE_REPLAY_DIR) {
        replay_dir(args.replay_dir, args.report_file);
        return 0;
    }

    return 0;
}
