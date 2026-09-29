#ifndef NTA_CLI_H
#define NTA_CLI_H

/* ========================================================================= *
 * Linha de comando do agente: modos de execução e parsing de argumentos.   *
 * ========================================================================= */

typedef enum {
    MODE_LIVE        = 0,
    MODE_REPLAY_FILE = 1,
    MODE_REPLAY_DIR  = 2,
    MODE_LIST_IFACES = 3,  /* --list-interfaces: nomes aceitos pelo modo live */
    MODE_SERVICE_INSTALL   = 4,  /* --install-service (Windows)               */
    MODE_SERVICE_UNINSTALL = 5   /* --uninstall-service (Windows)             */
} RunMode;

typedef struct {
    RunMode  mode;
    char    *iface;        /* MODE_LIVE: nome da interface                  */
    char    *pcap_file;    /* MODE_REPLAY_FILE: caminho do .pcap            */
    char    *expect_file;  /* --expect: gabarito JSON (opcional)            */
    char    *replay_dir;   /* MODE_REPLAY_DIR: diretório com .pcap          */
    char    *report_file;  /* --report: caminho para relatório JSON (opt.)  */
    char    *config_file;  /* --config: arquivo CHAVE=VALOR (opt.)          */
    int      service;      /* --service: iniciado pelo SCM (Windows)        */
} AgentArgs;

/* Faz o parsing de argv. Imprime o uso e sai (exit 1) em argumento
 * inválido ou sem argumentos. Interface ausente no modo live é resolvida
 * em main() via AGENT_IFACE, depois de carregar o --config. */
AgentArgs parse_args(int argc, char *argv[]);

#endif /* NTA_CLI_H */
