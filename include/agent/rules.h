#ifndef NTA_RULES_H
#define NTA_RULES_H

#include <stddef.h>

/* ========================================================================= *
 * LIMIARES DOS DETECTORES (B18, fase 1)                                     *
 *                                                                           *
 * Os valores que eram #define no analyzer.c ficam numa estrutura de tamanho *
 * fixo, com os mesmos padrões. Um arquivo JSON opcional (AGENT_RULES_FILE,  *
 * ver deploy/rules/README.md) sobrescreve campos. Sem arquivo, o agente usa *
 * exatamente os padrões abaixo.                                             *
 *                                                                           *
 * Só entram campos de limiar, janela e alfa. Tamanhos de tabela (memória) e *
 * a lista de portas de brute force ficam no código.                          *
 * ========================================================================= */

#define NTA_RULES_MAX_BYTES 16384  /* tamanho máximo do arquivo de regras */
#define NTA_RULES_MAX_DEPTH 4      /* aninhamento JSON máximo (o schema usa 1) */
#define NTA_RULES_SCAN_MAX  32     /* teto de portas por IP: dimensiona Suspect.ports[] */

typedef struct {
    int    scan_threshold;       /* PORT_SCAN: portas de destino únicas por IP  (2..32, padrão 15) */
    int    icmp_threshold;       /* ICMP_FLOOD: fallback antes da calibração    (5..100000, 20) */
    int    syn_flood_threshold;  /* SYN_FLOOD: fallback antes da calibração     (10..1000000, 100) */
    int    stealth_threshold;    /* NULL/XMAS/SYNFIN: pacotes com a combinação (2..1000, 3) */
    int    brute_threshold;      /* BRUTE_FORCE: SYNs em 22/21/3389 na janela  (5..100000, 30) */
    int    brute_window_sec;     /* BRUTE_FORCE: tamanho da janela, s          (10..3600, 60) */
    int    dns_subdomain_len;    /* DNS_TUNNEL: primeiro label maior que N     (1..63, 50) */
    double dns_entropy_thresh;   /* DNS_TUNNEL: entropia de Shannon, bits/char (1.0..8.0, 3.5) */
    int    dns_suspicious_max;   /* DNS_TUNNEL: nomes suspeitos antes do alerta (1..100000, 10) */
    int    amplification_ratio;  /* AMPLIFICATION: resposta > N x requisição   (2..10000, 10) */
    int    kc_window_sec;        /* kill chain: janela de correlação, s        (60..86400, 1800) */
    int    ewma_calibration;     /* amostras para sair da calibração EWMA      (2..100000, 100) */
    double ewma_alpha_fast;      /* EWMA durante a calibração                  (0.01..1.0, 0.3) */
    double ewma_alpha_slow;      /* EWMA depois da calibração                  (0.01..1.0, 0.1) */
    double ewma_sigma;           /* desvios-padrão do limiar adaptativo       (1.0..10.0, 3.0) */
    int    ewma_window_sec;      /* janela de agregação do baseline, s         (10..3600, 60) */
} NtaRules;

/* Padrões: exatamente os valores que eram #define no analyzer.c. */
#define NTA_RULES_DEFAULT {                 \
    .scan_threshold      = 15,              \
    .icmp_threshold      = 20,              \
    .syn_flood_threshold = 100,             \
    .stealth_threshold   = 3,               \
    .brute_threshold     = 30,              \
    .brute_window_sec    = 60,              \
    .dns_subdomain_len   = 50,              \
    .dns_entropy_thresh  = 3.5,             \
    .dns_suspicious_max  = 10,              \
    .amplification_ratio = 10,              \
    .kc_window_sec       = 1800,            \
    .ewma_calibration    = 100,             \
    .ewma_alpha_fast     = 0.3,             \
    .ewma_alpha_slow     = 0.1,             \
    .ewma_sigma          = 3.0,             \
    .ewma_window_sec     = 60               \
}

/* Carrega os padrões em `r`. */
void rules_defaults(NtaRules *r);

/* Lê `len` bytes JSON, valida e grava em `out`. Retorna 0 se válido. Retorna -1
 * com mensagem em `err` se inválido; `out` fica intacto nesse caso. Chaves
 * ausentes usam o padrão; chave desconhecida, repetida, de tipo errado ou fora da
 * faixa é erro. */
int rules_parse(const char *json, size_t len, NtaRules *out,
                char *err, size_t errlen);

/* Lê o arquivo em `path` (até NTA_RULES_MAX_BYTES) e aplica rules_parse(). */
int rules_load_file(const char *path, NtaRules *out, char *err, size_t errlen);

#endif /* NTA_RULES_H */
