#ifndef NTA_EXPORT_H
#define NTA_EXPORT_H

#include <stddef.h>
#include "cJSON.h"

/* -------------------------------------------------------------------------- *
 * Exportação de alertas para SIEM (B11).                                    *
 *                                                                           *
 * Opt-in: NTA_EXPORT_FORMAT vazio (padrão) = desligado, sem thread e sem     *
 * custo no caminho do consumer. Só alertas são exportados: attack_type não    *
 * vazio e diferente de "NONE" (o agente grava "NONE" em todo pacote benigno).*
 * Payload: CEF (v0) ou JSON ECS 8.11.0, dentro de uma linha                  *
 * syslog RFC 5424 enviada por UDP (RFC 5426) ou TCP (octet-counting, RFC 6587).*
 *                                                                           *
 * Desacoplamento: o consumer só copia o evento para uma fila limitada        *
 * (NTA_EXPORT_QUEUE). Uma thread própria serializa e envia. Fila cheia ou    *
 * destino fora do ar geram descarte contado; nunca bloqueiam o consumer.     *
 * -------------------------------------------------------------------------- */

typedef enum {
    NTA_EXPORT_CEF = 1,
    NTA_EXPORT_ECS = 2
} NtaExportFormat;

typedef struct {
    NtaExportFormat format;     /* 0 = desligado */
    const char     *syslog_host; /* NTA_EXPORT_SYSLOG_HOST (obrigatório se ligado) */
    int             syslog_port; /* NTA_EXPORT_SYSLOG_PORT, padrão 514 */
    int             use_tcp;     /* NTA_EXPORT_SYSLOG_PROTO=tcp; padrão udp */
    const char     *hostname;    /* NTA_EXPORT_HOSTNAME (HOSTNAME RFC 5424), padrão nta-server */
    int             queue_max;   /* NTA_EXPORT_QUEUE, padrão 1024 (16..65536) */
    int             timeout_ms;  /* NTA_EXPORT_TIMEOUT_MS, padrão 500 (50..10000) */
} NtaExportCfg;

typedef struct {
    unsigned long long sent;     /* linhas entregues ao kernel/destino */
    unsigned long long dropped;  /* descartes: fila cheia ou fim após prazo do shutdown */
    unsigned long long failed;   /* formato inválido ou falha de transporte */
} NtaExportStats;

typedef struct NtaExport NtaExport;

/* Lê as variáveis de ambiente. Com NTA_EXPORT_FORMAT vazio não emite nada. */
void nta_export_cfg_load(NtaExportCfg *cfg);

/* Abre o exportador e sobe a thread de envio. Retorna NULL se estiver
 * desligado ou mal configurado (o servidor segue normalmente). */
NtaExport *nta_export_open(const NtaExportCfg *cfg);

/* Enfileira o evento se for alerta (regra acima). NULL, benigno ou sem alerta: retorna
 * sem fazer nada. Não bloqueia em I/O. */
void nta_export_submit(NtaExport *e, const cJSON *evt, const char *agent_id);

/* Drena a fila por até 2 s, para a thread e libera tudo. `out` pode ser NULL. */
void nta_export_close(NtaExport *e, NtaExportStats *out);

/* Renderiza uma linha syslog RFC 5424 completa (sem framing de transporte)
 * em `out`, terminada em \0. Retorna o número de bytes ou 0 se o evento não
 * for alerta, se não couber em `cap` ou se o resultado contiver byte de
 * controle (< 0x20). `ts` é RFC 3339 UTC (ver nta_export_now). */
size_t nta_export_render(char *out, size_t cap, NtaExportFormat fmt,
                         const char *hostname, const cJSON *evt,
                         const char *agent_id, const char *ts);

/* Escreve o instante atual em RFC 3339 UTC com milissegundos (…Z), 24 bytes
 * + \0. `cap` precisa ser >= 25. */
void nta_export_now(char *out, size_t cap);

#endif /* NTA_EXPORT_H */
