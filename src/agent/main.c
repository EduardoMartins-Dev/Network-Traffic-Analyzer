#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include "publisher.h"
#include "capture.h"
#include "pipeline.h"
#include "cli.h"
#include "replay.h"
#include "config.h"
#include "service.h"

/* ========================================================================= *
 * VERIFICAÇÃO DE PRIVILÉGIOS (Multiplataforma)                              *
 * ========================================================================= */
#ifdef _WIN32
    #include <windows.h>   /* SetConsoleOutputCP */
    /* Quem decide é o Npcap: com "Restrict to Administrators" (AdminOnly=1)
     * o pcap_open_live falha e o erro sai no log da captura. Sem essa opção,
     * usuário comum captura normalmente — não bloqueamos aqui. */
    static int has_privileges(void) { return 1; }
    static const char *PRIVILEGE_MSG = "";
#elif defined(__linux__)
    #include <unistd.h>
    #include <sys/syscall.h>
    #include <linux/capability.h>
    /* Aceita tanto root quanto binário com `setcap cap_net_raw,cap_net_admin+ep`. */
    static int has_cap_net_raw(void) {
        struct __user_cap_header_struct hdr = {
            .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0,
        };
        struct __user_cap_data_struct data[2] = { {0, 0, 0}, {0, 0, 0} };
        if (syscall(SYS_capget, &hdr, data) != 0) return 0;
        return (data[0].effective & (1u << CAP_NET_RAW)) != 0;
    }
    static int has_privileges(void) { return getuid() == 0 || has_cap_net_raw(); }
    static const char *PRIVILEGE_MSG =
        "Execute com sudo/root ou aplique "
        "`sudo setcap cap_net_raw,cap_net_admin+ep` no binário.";
#else
    #include <unistd.h>
    static int has_privileges() { return getuid() == 0; }
    static const char *PRIVILEGE_MSG = "Execute com sudo ou como root.";
#endif

#ifdef _WIN32
/* O Npcap sem "WinPcap API-compatible Mode" instala o wpcap.dll só em
 * System32\Npcap. Como ele é delay-load (platform/wpcap.def), apontamos a
 * busca para lá antes da 1ª chamada pcap — e já carregamos aqui, para dar
 * erro claro se o Npcap não estiver instalado. No modo compatível o mesmo
 * diretório também existe, então o caminho é único. */
static int load_npcap(void) {
    char dir[MAX_PATH];
    UINT n = GetSystemDirectoryA(dir, MAX_PATH);
    if (n > 0 && n + sizeof("\\Npcap") <= MAX_PATH) {
        strcat(dir, "\\Npcap");
        SetDllDirectoryA(dir);
    }
    if (!LoadLibraryA("wpcap.dll")) {
        fprintf(stderr, "Erro: Npcap não encontrado. Instale em "
                        "https://npcap.com/#download e tente novamente.\n");
        return 0;
    }
    return 1;
}
#endif

/* Signal handler — seguro para SIGINT/SIGTERM (pcap_breakloop é async-safe). */
static void on_signal(int sig) {
    (void)sig;
    pipeline_request_stop();
}

int main(int argc, char *argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);   /* mensagens são UTF-8 (acentos no console) */
#endif
    AgentArgs args = parse_args(argc, argv);

    /* --config: CHAVE=VALOR vira ambiente (o ambiente já definido prevalece).
     * Carregado antes de tudo — init_queue/pipeline só leem getenv(). */
    if (args.config_file) {
        int n = config_load_file(args.config_file);
        if (n < 0) {
            fprintf(stderr, "Erro: não foi possível ler a config: %s\n",
                    args.config_file);
            return 1;
        }
        fprintf(stderr, "[CONFIG] %s: %d chave(s) aplicada(s)\n",
                args.config_file, n);
    }

#ifdef _WIN32
    if (args.mode == MODE_SERVICE_INSTALL) {
        if (!args.config_file) {
            fprintf(stderr, "Erro: --install-service exige --config <arquivo>.\n");
            return 1;
        }
        return service_install(args.config_file, args.iface);
    }
    if (args.mode == MODE_SERVICE_UNINSTALL)
        return service_uninstall();

    /* Daqui em diante todos os modos usam libpcap (live, replay, listagem). */
    if (!load_npcap()) return 1;
#else
    if (args.mode == MODE_SERVICE_INSTALL || args.mode == MODE_SERVICE_UNINSTALL ||
        args.service) {
        fprintf(stderr, "Erro: modo serviço só existe no Windows "
                        "(no Linux use deploy/agent.service com systemd).\n");
        return 1;
    }
#endif

    /* ------------------------------------------------------------------- *
     * MODO LIVE — pipeline multi-thread (v5.0)                             *
     * ------------------------------------------------------------------- */
    if (args.mode == MODE_LIVE) {
        const char *iface = args.iface ? args.iface : getenv("AGENT_IFACE");
        if (!iface || !*iface) {
            fprintf(stderr, "Erro: informe a interface (argumento ou "
                            "AGENT_IFACE). Veja --list-interfaces.\n");
            return 1;
        }

        if (!has_privileges()) {
            fprintf(stderr, "Erro: %s\n", PRIVILEGE_MSG);
            return 1;
        }

#ifdef _WIN32
        if (args.service)
            return service_run(iface);
#endif

        signal(SIGINT,  on_signal);
        signal(SIGTERM, on_signal);

        printf("Iniciando pipeline v5.0 em '%s' (Ctrl+C para parar)\n", iface);

        return pipeline_run(iface) == 0 ? 0 : 1;
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

    if (args.mode == MODE_LIST_IFACES)
        return capture_list_interfaces();

    return 0;
}
