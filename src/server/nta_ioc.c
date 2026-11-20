/* ========================================================================= *
 *  nta_ioc.c — IoC framework (IPs) com hashtable chained.                   *
 *                                                                           *
 *  Read-only após load. Workers consultam concorrentemente sem mutex.       *
 *  List names são strings owned aqui (strdup) — todos os entries de uma     *
 *  list compartilham o mesmo ponteiro.                                      *
 * ========================================================================= */

#include "nta_ioc.h"
#include "cJSON.h"

#include <arpa/inet.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define IOC_BUCKETS  8192   /* suporta ~30k IPs c/ load factor < 4 */
#define IP_KEY_MAX   46

typedef struct IocEntry {
    char              ip[IP_KEY_MAX];
    const char       *list_name;   /* alias pra string em NtaIoc->list_names */
    struct IocEntry  *next;
} IocEntry;

struct NtaIoc {
    IocEntry  *buckets[IOC_BUCKETS];
    char     **list_names;       /* array de nomes, ownership aqui */
    int        n_lists;
    int        n_ips;
};

/* FNV-1a 32-bit. */
static unsigned hash_ip(const char *s) {
    unsigned h = 2166136261u;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 16777619u;
    }
    return h;
}

/* -------------------------------------------------------------------------- *
 * File slurp                                                                 *
 * -------------------------------------------------------------------------- */
static char *slurp_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0 || sz > 64 * 1024 * 1024) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';
    if (out_len) *out_len = n;
    return buf;
}

/* -------------------------------------------------------------------------- *
 * Insert                                                                     *
 * -------------------------------------------------------------------------- */
static int ioc_insert(NtaIoc *ioc, const char *ip, const char *list_name) {
    if (strlen(ip) >= IP_KEY_MAX) return -1;
    /* Só entra IP de verdade: lixo num feed não pode virar tabela válida. */
    unsigned char addr[16];
    if (inet_pton(AF_INET, ip, addr) != 1 && inet_pton(AF_INET6, ip, addr) != 1)
        return -1;
    unsigned h = hash_ip(ip) % IOC_BUCKETS;
    /* Dedup dentro do mesmo bucket — primeira lista a inserir vence. */
    for (IocEntry *e = ioc->buckets[h]; e; e = e->next) {
        if (strcmp(e->ip, ip) == 0) return 0;
    }
    IocEntry *e = calloc(1, sizeof(*e));
    if (!e) return -1;
    strncpy(e->ip, ip, IP_KEY_MAX - 1);
    e->list_name = list_name;
    e->next = ioc->buckets[h];
    ioc->buckets[h] = e;
    ioc->n_ips++;
    return 1;
}

/* -------------------------------------------------------------------------- *
 * Load                                                                       *
 * -------------------------------------------------------------------------- */
NtaIoc *nta_ioc_load(const char *path) {
    if (!path || !*path) return NULL;

    size_t flen = 0;
    char *buf = slurp_file(path, &flen);
    if (!buf) {
        fprintf(stderr, "[IOC] arquivo não encontrado: %s\n", path);
        return NULL;
    }

    cJSON *root = cJSON_ParseWithLength(buf, flen);
    free(buf);
    if (!cJSON_IsObject(root)) {
        if (root) cJSON_Delete(root);
        fprintf(stderr, "[IOC] JSON inválido: %s\n", path);
        return NULL;
    }

    cJSON *lists = cJSON_GetObjectItemCaseSensitive(root, "lists");
    if (!cJSON_IsArray(lists)) {
        cJSON_Delete(root);
        fprintf(stderr, "[IOC] campo 'lists' ausente ou não-array: %s\n", path);
        return NULL;
    }

    NtaIoc *ioc = calloc(1, sizeof(*ioc));
    if (!ioc) { cJSON_Delete(root); return NULL; }

    int n_lists = cJSON_GetArraySize(lists);
    if (n_lists > 0) {
        ioc->list_names = calloc((size_t)n_lists, sizeof(char *));
        if (!ioc->list_names) {
            free(ioc); cJSON_Delete(root); return NULL;
        }
    }

    const cJSON *list = NULL;
    cJSON_ArrayForEach(list, lists) {
        if (!cJSON_IsObject(list)) continue;
        const cJSON *nm = cJSON_GetObjectItemCaseSensitive(list, "name");
        const cJSON *ips = cJSON_GetObjectItemCaseSensitive(list, "ips");
        if (!cJSON_IsString(nm) || !nm->valuestring) continue;
        if (!cJSON_IsArray(ips)) continue;

        char *name_copy = strdup(nm->valuestring);
        if (!name_copy) continue;
        ioc->list_names[ioc->n_lists++] = name_copy;

        int list_ips = 0;
        const cJSON *ip_j = NULL;
        cJSON_ArrayForEach(ip_j, ips) {
            if (!cJSON_IsString(ip_j) || !ip_j->valuestring) continue;
            if (ioc_insert(ioc, ip_j->valuestring, name_copy) > 0) list_ips++;
        }
        fprintf(stderr, "[IOC] lista '%s': %d IPs carregados\n",
                name_copy, list_ips);
    }

    cJSON_Delete(root);

    if (ioc->n_ips == 0) {
        fprintf(stderr, "[IOC] zero IoCs em %s — desabilitando\n", path);
        nta_ioc_close(ioc);
        return NULL;
    }

    fprintf(stderr, "[IOC] total: %d IPs em %d listas\n",
            ioc->n_ips, ioc->n_lists);
    return ioc;
}

/* -------------------------------------------------------------------------- *
 * Match                                                                      *
 * -------------------------------------------------------------------------- */
const char *nta_ioc_match_ip(const NtaIoc *ioc, const char *ip) {
    if (!ioc || !ip || !*ip) return NULL;
    unsigned h = hash_ip(ip) % IOC_BUCKETS;
    for (const IocEntry *e = ioc->buckets[h]; e; e = e->next) {
        if (strcmp(e->ip, ip) == 0) return e->list_name;
    }
    return NULL;
}

int nta_ioc_size(const NtaIoc *ioc) {
    return ioc ? ioc->n_ips : 0;
}

/* -------------------------------------------------------------------------- *
 * Close                                                                      *
 * -------------------------------------------------------------------------- */
void nta_ioc_close(NtaIoc *ioc) {
    if (!ioc) return;
    for (int i = 0; i < IOC_BUCKETS; i++) {
        IocEntry *e = ioc->buckets[i];
        while (e) {
            IocEntry *n = e->next;
            free(e);
            e = n;
        }
    }
    if (ioc->list_names) {
        for (int i = 0; i < ioc->n_lists; i++) free(ioc->list_names[i]);
        free(ioc->list_names);
    }
    free(ioc);
}

/* ========================================================================== *
 *  Store com recarga (B03)                                                   *
 *                                                                            *
 *  Dois slots. `active` aponta o slot publicado. Leitor: incrementa refs do  *
 *  slot ativo, confirma que `active` não mudou e só então usa a tabela. Se  *
 *  mudou, desfaz e tenta de novo. Escritor (único): escreve no slot inativo  *
 *  depois de ele ficar sem leitores, publica `active`, espera os leitores do *
 *  slot antigo e libera a tabela antiga. Todos os acessos são seq_cst.       *
 * ========================================================================== */

struct NtaIocStore {
    struct {
        _Atomic(NtaIoc *) ioc;    /* mutado só pelo escritor, com refs == 0 */
        atomic_int        refs;   /* leitores que estão dentro do slot */
    } slot[2];
    atomic_int active;            /* índice do slot publicado */
    char      *path;
};

static void wait_no_readers(atomic_int *refs) {
    struct timespec pausa = { 0, 1000000 };  /* 1 ms */
    while (atomic_load(refs) != 0) nanosleep(&pausa, NULL);
}

NtaIocStore *nta_ioc_store_open(const char *path) {
    NtaIocStore *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    if (path) {
        s->path = strdup(path);
        if (!s->path) { free(s); return NULL; }
    }
    for (int i = 0; i < 2; i++) {
        atomic_init(&s->slot[i].ioc, NULL);
        atomic_init(&s->slot[i].refs, 0);
    }
    atomic_init(&s->slot[0].ioc, nta_ioc_load(s->path));
    atomic_init(&s->active, 0);
    return s;
}

NtaIoc *nta_ioc_store_acquire(NtaIocStore *s, int *slot) {
    for (;;) {
        int i = atomic_load(&s->active);
        atomic_fetch_add(&s->slot[i].refs, 1);
        if (atomic_load(&s->active) == i) {
            *slot = i;
            return atomic_load(&s->slot[i].ioc);
        }
        /* Trocou entre o load e o incremento: solta e tenta o slot novo. */
        atomic_fetch_sub(&s->slot[i].refs, 1);
    }
}

void nta_ioc_store_release(NtaIocStore *s, int slot) {
    atomic_fetch_sub(&s->slot[slot].refs, 1);
}

int nta_ioc_store_reload(NtaIocStore *s) {
    NtaIoc *fresh = s->path ? nta_ioc_load(s->path) : NULL;
    if (!fresh) {
        fprintf(stderr, "[IOC] reload rejeitado (%s) — lista anterior "
                "continua ativa\n", s->path ? s->path : "sem path");
        return -1;
    }

    int old  = atomic_load(&s->active);
    int next = 1 - old;
    /* `next` está inativo; só leitores que erraram a checagem podem estar
     * nele, e eles saem logo sem usar a tabela. */
    wait_no_readers(&s->slot[next].refs);
    atomic_store(&s->slot[next].ioc, fresh);
    atomic_store(&s->active, next);   /* publica: leitores novos veem a nova */

    /* Leitores que pegaram a tabela antiga antes da troca ainda podem usá-la. */
    wait_no_readers(&s->slot[old].refs);
    nta_ioc_close(atomic_exchange(&s->slot[old].ioc, NULL));

    fprintf(stderr, "[IOC] lista recarregada: %d IPs\n", nta_ioc_size(fresh));
    return 0;
}

int nta_ioc_store_size(NtaIocStore *s) {
    int slot;
    NtaIoc *ioc = nta_ioc_store_acquire(s, &slot);
    int n = nta_ioc_size(ioc);
    nta_ioc_store_release(s, slot);
    return n;
}

void nta_ioc_store_close(NtaIocStore *s) {
    if (!s) return;
    for (int i = 0; i < 2; i++) nta_ioc_close(atomic_load(&s->slot[i].ioc));
    free(s->path);
    free(s);
}
