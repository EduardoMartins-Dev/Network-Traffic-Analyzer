#ifndef NTA_EVE_TAIL_H
#define NTA_EVE_TAIL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "eve_parse.h"   /* EVE_MAX_LINE */

/* ========================================================================= *
 * nta-eve-bridge — leitura do eve.json (B17).                                *
 *                                                                           *
 * eve_linebuf_t monta linhas a partir de pedaços arbitrários. Linha maior    *
 * que EVE_MAX_LINE é descartada até o próximo '\n' e contada (oversized).   *
 * eve_file_t segue o arquivo: detecta rotação (inode trocado, o Suricata ou  *
 * o logrotate renomeia e recria) e truncamento (tamanho menor que a posição *
 * lida, copytruncate). Não há socket Unix nesta fase (ver README).           *
 * ========================================================================= */

typedef void (*eve_line_fn)(const char *line, size_t len, void *ctx);

typedef struct {
    char     buf[EVE_MAX_LINE];
    size_t   len;
    int      skipping;      /* linha atual excedeu o limite: descarta         */
    uint64_t oversized;     /* linhas descartadas por tamanho                 */
    uint64_t discarded;     /* linhas parciais descartadas (rotação/truncate) */
} eve_linebuf_t;

void eve_linebuf_feed(eve_linebuf_t *lb, const char *data, size_t n,
                      eve_line_fn fn, void *ctx);

/* Fim de arquivo no modo --once: emite a última linha sem '\n', se houver. */
void eve_linebuf_flush(eve_linebuf_t *lb, eve_line_fn fn, void *ctx);

/* Descarta a linha parcial (ao trocar de arquivo ou ao truncar). */
void eve_linebuf_reset(eve_linebuf_t *lb);

typedef struct {
    char     path[4096];
    int      fd;            /* -1 se fechado (arquivo ainda não existe)       */
    dev_t    dev;
    ino_t    ino;
    off_t    off;           /* posição lida no fd                             */
    uint64_t rotations;
    uint64_t truncations;
} eve_file_t;

/* Abre o arquivo. from_start=0 posiciona no fim (modo tail). Retorna 0 ou -1. */
int eve_file_open(eve_file_t *f, const char *path, int from_start);
void eve_file_close(eve_file_t *f);

/* Lê o que está disponível e alimenta `lb`. Se follow != 0, também verifica
 * rotação/truncamento pelo caminho e reabre quando preciso. Retorna bytes lidos
 * (>= 0), ou -1 em erro de leitura. Arquivo ausente: retorna 0 e tenta de novo. */
ssize_t eve_file_poll(eve_file_t *f, eve_linebuf_t *lb, eve_line_fn fn, void *ctx,
                      int follow);

#endif /* NTA_EVE_TAIL_H */
