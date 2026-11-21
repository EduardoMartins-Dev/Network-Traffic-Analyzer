#ifndef NTA_EVE_PARSE_H
#define NTA_EVE_PARSE_H

#include <stddef.h>

/* ========================================================================= *
 * nta-eve-bridge — parser de uma linha do eve.json do Suricata (B17).        *
 *                                                                           *
 * Só lê os campos do alerta que a ponte usa. Contrato na doc oficial do      *
 * Suricata (eve-json-format): ver tests/eve/README.md e o PR.                *
 * Sem estado global: função pura sobre a linha, usada também pelo fuzz.      *
 * ========================================================================= */

/* Linha máxima aceita (bytes, sem '\n'). Linha maior é descartada pelo leitor
 * (eve_tail.c) e contada como oversized. */
#define EVE_MAX_LINE 65536

typedef struct {
    char src_ip[46];       /* alert: src_ip (IPv4/IPv6 validado)              */
    char dst_ip[46];       /* alert: dest_ip; "" se ausente ou inválido       */
    int  src_port;         /* alert: src_port; -1 se ausente                  */
    int  dst_port;         /* alert: dest_port; -1 se ausente                 */
    char proto[16];        /* alert: proto (texto original, truncado)         */
    char direction[12];    /* alert: direction ("to_server"/"to_client"/"")  */
    char category[128];    /* alert.category (texto original, truncado)       */
    long signature_id;     /* alert.signature_id; obrigatório                 */
    int  severity;         /* alert.severity (1..3 no Suricata); -1 se ausente */
    char mitre[48];        /* técnicas de alert.metadata[<chave>], "" se nenhuma */
} eve_alert_t;

typedef enum {
    EVE_ALERT,             /* alerta válido, preenchido em eve_alert_t        */
    EVE_OTHER,             /* JSON válido com outro event_type: ignorado       */
    EVE_INVALID            /* JSON inválido ou alerta sem campos obrigatórios */
} eve_kind_t;

/* Interpreta uma linha. `mitre_key` é a chave de alert.metadata com a técnica
 * ATT&CK (ex.: "mitre_technique_id"). Não aloca além do cJSON interno. */
eve_kind_t eve_parse_line(const char *line, size_t len, const char *mitre_key,
                          eve_alert_t *out);

/* Técnica ATT&CK válida: T + 4 dígitos, opcionalmente .NNN (T1190, T1190.001). */
int eve_is_mitre_token(const char *s);

#endif /* NTA_EVE_PARSE_H */
