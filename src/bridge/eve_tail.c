#include "eve_tail.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHUNK_SIZE 16384

/* ------------------------------------------------------------------------- *
 * Linhas                                                                    *
 * ------------------------------------------------------------------------- */

/* Entrega a linha sem o '\r' final (CRLF). Linha vazia não é entregue. */
static void emit_line(eve_linebuf_t *lb, eve_line_fn fn, void *ctx) {
    if (lb->len > 0 && lb->buf[lb->len - 1] == '\r') lb->len--;
    if (lb->len > 0) fn(lb->buf, lb->len, ctx);
    lb->len = 0;
}

void eve_linebuf_feed(eve_linebuf_t *lb, const char *data, size_t n,
                      eve_line_fn fn, void *ctx) {
    size_t i = 0;
    while (i < n) {
        const char *nl = memchr(data + i, '\n', n - i);
        size_t seg = nl ? (size_t)(nl - (data + i)) : (n - i);

        if (!lb->skipping) {
            size_t room = EVE_MAX_LINE - 1 - lb->len;
            if (seg > room) {
                /* Linha passou do limite: descarta o restante até o '\n'. */
                lb->skipping = 1;
                lb->len = 0;
                lb->oversized++;
            } else {
                memcpy(lb->buf + lb->len, data + i, seg);
                lb->len += seg;
            }
        }
        i += seg;

        if (nl) {
            i++;                         /* consome o '\n' */
            if (lb->skipping) {
                lb->skipping = 0;
                lb->len = 0;
            } else {
                emit_line(lb, fn, ctx);
            }
        }
    }
}

void eve_linebuf_flush(eve_linebuf_t *lb, eve_line_fn fn, void *ctx) {
    if (!lb->skipping) emit_line(lb, fn, ctx);
    lb->len = 0;
    lb->skipping = 0;
}

void eve_linebuf_reset(eve_linebuf_t *lb) {
    if (lb->len > 0) lb->discarded++;
    lb->len = 0;
    lb->skipping = 0;
}

/* ------------------------------------------------------------------------- *
 * Arquivo                                                                   *
 * ------------------------------------------------------------------------- */

/* Abre o caminho. from_start=0 posiciona no fim (tail). Só mexe no fd em sucesso. */
static int reopen(eve_file_t *f, int from_start) {
    int fd = open(f->path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }

    off_t pos = 0;
    if (!from_start) {
        pos = lseek(fd, 0, SEEK_END);
        if (pos < 0) { close(fd); return -1; }
    }

    f->fd  = fd;
    f->dev = st.st_dev;
    f->ino = st.st_ino;
    f->off = pos;
    return 0;
}

int eve_file_open(eve_file_t *f, const char *path, int from_start) {
    memset(f, 0, sizeof *f);
    f->fd = -1;
    if (strlen(path) >= sizeof f->path) return -1;
    strcpy(f->path, path);
    return reopen(f, from_start);
}

void eve_file_close(eve_file_t *f) {
    if (f->fd >= 0) close(f->fd);
    f->fd = -1;
}

/* Lê até o EOF fd atual. Retorna bytes lidos ou -1 em erro de leitura. */
static ssize_t drain(eve_file_t *f, eve_linebuf_t *lb, eve_line_fn fn, void *ctx) {
    ssize_t total = 0;
    char chunk[CHUNK_SIZE];
    for (;;) {
        ssize_t r = read(f->fd, chunk, sizeof chunk);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) break;
        f->off += r;
        total += r;
        eve_linebuf_feed(lb, chunk, (size_t)r, fn, ctx);
    }
    return total;
}

ssize_t eve_file_poll(eve_file_t *f, eve_linebuf_t *lb, eve_line_fn fn, void *ctx,
                      int follow) {
    ssize_t total = 0;

    /* Dois passes: se houver rotação ou truncamento, o arquivo novo é lido já
     * nesta chamada. O segundo passe nunca troca de arquivo de novo. */
    for (int pass = 0; pass < 2; pass++) {
        if (f->fd < 0 && reopen(f, 1) != 0) return total;   /* ainda não existe */

        ssize_t r = drain(f, lb, fn, ctx);
        if (r < 0) return -1;
        total += r;
        if (!follow || pass == 1) return total;

        /* Chegou ao EOF do fd: confere o caminho. Se sumiu, espera reaparecer. */
        struct stat st;
        if (stat(f->path, &st) != 0) return total;

        if (st.st_dev != f->dev || st.st_ino != f->ino) {
            /* Rotação: o arquivo antigo já foi lido até o fim. */
            eve_linebuf_reset(lb);
            eve_file_close(f);
            f->rotations++;
        } else if (st.st_size < f->off) {
            /* Truncamento (copytruncate): volta ao início. */
            eve_linebuf_reset(lb);
            if (lseek(f->fd, 0, SEEK_SET) == 0) f->off = 0;
            f->truncations++;
        } else {
            return total;
        }
    }
    return total;
}
