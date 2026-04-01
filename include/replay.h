#ifndef NTA_REPLAY_H
#define NTA_REPLAY_H

/* ========================================================================= *
 * REPLAY FRAMEWORK (v4.1)                                                   *
 *                                                                           *
 * Modos de execução do binário:                                             *
 *   MODE_LIVE        — captura ao vivo via interface de rede (padrão)       *
 *   MODE_REPLAY_FILE — lê pacotes de um arquivo .pcap                       *
 *   MODE_REPLAY_DIR  — processa todos os .pcap de um diretório              *
 * ========================================================================= */

#define MAX_EXPECTED 256

/* ---------------------------------------------------------------------- *
 * Tipos de dados                                                           *
 * ---------------------------------------------------------------------- */

typedef enum {
    MODE_LIVE        = 0,
    MODE_REPLAY_FILE = 1,
    MODE_REPLAY_DIR  = 2
} RunMode;

typedef struct {
    RunMode  mode;
    char    *iface;        /* MODE_LIVE: nome da interface                  */
    char    *pcap_file;    /* MODE_REPLAY_FILE: caminho do .pcap            */
    char    *expect_file;  /* --expect: gabarito JSON (opcional)            */
    char    *replay_dir;   /* MODE_REPLAY_DIR: diretório com .pcap          */
    char    *report_file;  /* --report: caminho para relatório JSON (opt.)  */
} AgentArgs;

typedef struct {
    char attack_type[32];  /* ex: "SYN_FLOOD"   */
    char src_ip[16];       /* ex: "192.168.1.1" */
    int  has_time_window;
    long t_start_sec;      /* segundos relativos ao primeiro pacote         */
    long t_end_sec;
} ExpectedDetection;

typedef struct {
    ExpectedDetection entries[MAX_EXPECTED];
    int               count;
    long              pcap_start_ts;  /* timestamp do 1º pacote (epoch sec) */
} Gabarito;

typedef struct {
    const char *pcap_file;
    int         expected_count;
    int         passed;
    int         failed;
    double      score;   /* passed / expected_count * 100.0 */
} ReplayResult;

/* ---------------------------------------------------------------------- *
 * Funções públicas                                                         *
 * ---------------------------------------------------------------------- */

AgentArgs    parse_args(int argc, char *argv[]);

Gabarito    *gabarito_load(const char *json_path);
void         gabarito_free(Gabarito *g);

ReplayResult replay_file(const char *pcap_path, const Gabarito *g);
void         replay_dir(const char *dir_path, const char *report_out);
void         compare_results(const Gabarito *g, ReplayResult *r);
void         print_replay_result(const ReplayResult *r);

#endif /* NTA_REPLAY_H */
