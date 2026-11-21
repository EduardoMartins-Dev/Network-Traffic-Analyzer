/* service_win32.c — integração do agente com o Service Control Manager. */
#include "service.h"
#include "pipeline.h"

#include <windows.h>
#include <direct.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STOP_WAIT_HINT_MS 30000   /* drena buffers + fecha AMQP (connect ≤ 5s) */

static SERVICE_STATUS_HANDLE g_status_handle;
static SERVICE_STATUS        g_status;
static const char           *g_iface;

static void report_status(DWORD state, DWORD exit_code, DWORD wait_hint) {
    static DWORD checkpoint = 1;
    g_status.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState            = state;
    g_status.dwWin32ExitCode           = exit_code;
    g_status.dwWaitHint                = wait_hint;
    g_status.dwControlsAccepted        = (state == SERVICE_RUNNING)
        ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
    g_status.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED)
        ? 0 : checkpoint++;
    SetServiceStatus(g_status_handle, &g_status);
}

static DWORD WINAPI control_handler(DWORD control, DWORD type, LPVOID data,
                                    LPVOID ctx) {
    (void)type; (void)data; (void)ctx;
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        report_status(SERVICE_STOP_PENDING, NO_ERROR, STOP_WAIT_HINT_MS);
        fprintf(stderr, "[SERVICE] Stop solicitado pelo SCM.\n");
        pipeline_request_stop();
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

/* Serviço não tem console: stdout/stderr vão para arquivo, sem buffer
 * (no CRT do Windows _IOLBF equivale a buffer cheio). */
static void redirect_output(void) {
    const char *log = getenv("AGENT_LOG_FILE");
    if (!log || !*log) log = NTA_DEFAULT_LOG;

    /* Cria a pasta do log (um nível — ex.: C:\ProgramData\NTA). */
    char dir[MAX_PATH];
    snprintf(dir, sizeof(dir), "%s", log);
    char *slash = strrchr(dir, '\\');
    if (slash) { *slash = '\0'; _mkdir(dir); }

    if (freopen(log, "a", stdout)) setvbuf(stdout, NULL, _IONBF, 0);
    if (freopen(log, "a", stderr)) setvbuf(stderr, NULL, _IONBF, 0);
}

static void WINAPI service_main(DWORD argc, LPSTR *argv) {
    (void)argc; (void)argv;
    g_status_handle = RegisterServiceCtrlHandlerExA(NTA_SERVICE_NAME,
                                                    control_handler, NULL);
    if (!g_status_handle) return;

    report_status(SERVICE_START_PENDING, NO_ERROR, 5000);
    redirect_output();
    fprintf(stderr, "[SERVICE] %s iniciando em '%s'.\n", NTA_SERVICE_NAME, g_iface);
    report_status(SERVICE_RUNNING, NO_ERROR, 0);

    int rc = pipeline_run(g_iface);

    fprintf(stderr, "[SERVICE] Pipeline encerrado (rc=%d).\n", rc);
    fflush(stdout);
    report_status(SERVICE_STOPPED, rc == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR, 0);
}

int service_run(const char *iface) {
    g_iface = iface;
    SERVICE_TABLE_ENTRYA table[] = {
        { (LPSTR)NTA_SERVICE_NAME, service_main },
        { NULL, NULL }
    };
    if (!StartServiceCtrlDispatcherA(table)) {
        fprintf(stderr, "Erro: --service só funciona quando iniciado pelo "
                        "Windows (sc start %s). Código %lu.\n",
                NTA_SERVICE_NAME, GetLastError());
        return 1;
    }
    return 0;
}

static void print_last_error(const char *what) {
    DWORD err = GetLastError();
    fprintf(stderr, "Erro em %s (código %lu)%s\n", what, err,
            err == ERROR_ACCESS_DENIED ? " — execute como Administrador." : ".");
}

int service_install(const char *config_path, const char *iface) {
    char exe[MAX_PATH], cfg_abs[MAX_PATH];
    if (!GetModuleFileNameA(NULL, exe, sizeof(exe))) {
        print_last_error("GetModuleFileName");
        return 1;
    }
    if (!_fullpath(cfg_abs, config_path, sizeof(cfg_abs))) {
        fprintf(stderr, "Erro: caminho de config inválido: %s\n", config_path);
        return 1;
    }
    if (GetFileAttributesA(cfg_abs) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "Erro: config não encontrada: %s\n", cfg_abs);
        return 1;
    }

    char cmd[3 * MAX_PATH];
    snprintf(cmd, sizeof(cmd), "\"%s\" --service --config \"%s\"%s%s%s",
             exe, cfg_abs, iface ? " \"" : "", iface ? iface : "", iface ? "\"" : "");

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { print_last_error("OpenSCManager"); return 1; }

    SC_HANDLE svc = CreateServiceA(scm, NTA_SERVICE_NAME, NTA_SERVICE_DISPLAY,
                                   SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                   SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                   cmd, NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
        print_last_error("CreateService");
        CloseServiceHandle(scm);
        return 1;
    }

    SERVICE_DESCRIPTIONA desc = {
        (LPSTR)"Captura trafego (Npcap), detecta ataques e envia ao servidor NTA."
    };
    ChangeServiceConfig2A(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

    /* Reinicia sozinho em falha: 10s, 30s, depois a cada 60s. */
    SC_ACTION actions[3] = {
        { SC_ACTION_RESTART, 10000 },
        { SC_ACTION_RESTART, 30000 },
        { SC_ACTION_RESTART, 60000 },
    };
    SERVICE_FAILURE_ACTIONSA fa = { 86400, NULL, NULL, 3, actions };
    ChangeServiceConfig2A(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

    printf("Serviço %s instalado.\n  Comando: %s\n  Iniciar: sc start %s\n",
           NTA_SERVICE_NAME, cmd, NTA_SERVICE_NAME);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

int service_uninstall(void) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { print_last_error("OpenSCManager"); return 1; }

    SC_HANDLE svc = OpenServiceA(scm, NTA_SERVICE_NAME,
                                 SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!svc) {
        print_last_error("OpenService");
        CloseServiceHandle(scm);
        return 1;
    }

    SERVICE_STATUS st;
    if (ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
        printf("Parando %s...\n", NTA_SERVICE_NAME);
        for (int i = 0; i < STOP_WAIT_HINT_MS / 500; i++) {
            if (!QueryServiceStatus(svc, &st) || st.dwCurrentState == SERVICE_STOPPED)
                break;
            Sleep(500);
        }
    }

    int rc = 0;
    if (DeleteService(svc)) {
        printf("Serviço %s removido.\n", NTA_SERVICE_NAME);
    } else {
        print_last_error("DeleteService");
        rc = 1;
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return rc;
}
