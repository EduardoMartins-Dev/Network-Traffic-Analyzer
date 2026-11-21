#ifndef NTA_EVE_MAP_H
#define NTA_EVE_MAP_H

#include <stddef.h>
#include "eve_parse.h"

/* ========================================================================= *
 * nta-eve-bridge — tradução de alerta EVE para evento NTA (B17, ADR aceito). *
 *                                                                           *
 * A tabela (categoria → estágio, severidade → score, teto por categoria)     *
 * vem de arquivo JSON, não de código. Valor padrão conservador em            *
 * deploy/eve-bridge.mapping.json: categorias fracas têm teto abaixo de       *
 * NARRATOR_MIN_SCORE (80 por padrão no nta-server).                          *
 * ========================================================================= */

#define EVE_MAP_MAX_RULES   256
#define EVE_ATTACK_MAX       64   /* attack_type: cabe em tag do Influx (128)  */
#define EVE_ATTACK_BODY_MAX  48   /* parte da categoria após "SURICATA_"       */

/* Lado do atacante no evento NTA. SRC: alert.src_ip (padrão). RESPONSE: troca
 * para dest_ip quando direction == "to_client". Ver README e o PR: a doc do
 * Suricata não define a semântica de `direction`; o padrão é SRC. */
typedef enum { EVE_SIDE_SRC = 0, EVE_SIDE_RESPONSE = 1 } eve_side_t;

typedef struct {
    char category[128];
    char stage[16];       /* RECON, EXPLOIT ou EXFIL                         */
    int  max_score;       /* teto do score desta categoria (0..100)          */
    char mitre[48];       /* técnica da tabela; "" se nenhuma                */
} eve_rule_t;

typedef struct {
    int        sev_score[3];        /* score para severidade EVE 1, 2 e 3      */
    char       def_stage[16];       /* categoria fora da tabela                */
    int        def_max;             /* teto para categoria fora da tabela      */
    char       mitre_key[64];       /* chave de alert.metadata com a técnica   */
    int        n_rules;
    eve_rule_t rules[EVE_MAP_MAX_RULES];
} eve_map_t;

/* Evento NTA pronto para agregação/serialização (campos do contrato). */
typedef struct {
    char src_ip[46];          /* atacante (ver eve_side_t)                    */
    int  port;                /* porta do lado não atacante (0 se ausente)    */
    char proto[8];            /* TCP/UDP/ICMP..., "UNKNOWN" se ausente        */
    char attack_type[EVE_ATTACK_MAX];
    char stage[16];
    int  score;               /* kc_score 0..100                              */
    char mitre[48];
    long signature_id;
} eve_event_t;

/* Carrega e valida o arquivo de mapeamento. 0 ok; -1 erro (motivo em stderr). */
int eve_map_load(eve_map_t *m, const char *path);

/* Mesma validação, a partir de texto. Usado pelos testes. */
int eve_map_parse(eve_map_t *m, const char *json, size_t len);

/* "SURICATA_" + categoria normalizada (maiúsculas, [A-Z0-9] e '_', sem '_'
 * repetido nem nas pontas, até EVE_ATTACK_BODY_MAX). Categoria vazia: UNKNOWN. */
void eve_attack_type(const char *category, char *out, size_t outsz);

/* Traduz um alerta válido. Não falha. */
void eve_map_alert(const eve_map_t *m, const eve_alert_t *a, eve_side_t side,
                   eve_event_t *out);

#endif /* NTA_EVE_MAP_H */
