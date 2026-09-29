#ifndef NTA_REPLAY_H
#define NTA_REPLAY_H

/* ========================================================================= *
 * REPLAY FRAMEWORK (v4.1) — replay de .pcap + validação contra gabarito.   *
 * Os modos de execução do binário ficam em cli.h.                           *
 * ========================================================================= */

#define MAX_EXPECTED 256

/* ---------------------------------------------------------------------- *
 * Tipos de dados                                                           *
 * ---------------------------------------------------------------------- */

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

Gabarito    *gabarito_load(const char *json_path);
void         gabarito_free(Gabarito *g);

ReplayResult replay_file(const char *pcap_path, const Gabarito *g);
void         replay_dir(const char *dir_path, const char *report_out);
void         compare_results(const Gabarito *g, ReplayResult *r);
void         print_replay_result(const ReplayResult *r);

#endif /* NTA_REPLAY_H */
