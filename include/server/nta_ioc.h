#ifndef NTA_IOC_H
#define NTA_IOC_H

/* IoC (Indicators of Compromise) framework — v8.0 M3.
 *
 * Carrega JSON com listas de IoCs no startup, oferece lookup O(1) por IP.
 * Read-only após nta_ioc_load() — sem mutex (workers só consultam).
 *
 * Schema esperado em deploy/ioc/blocklist.json:
 *
 *   {
 *     "version": 1,
 *     "lists": [
 *       {
 *         "name": "feodo-c2",
 *         "url":  "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
 *         "updated": "2026-05-12T00:00:00Z",
 *         "ips": ["1.2.3.4", "5.6.7.8"]
 *       },
 *       ...
 *     ]
 *   }
 *
 * Entradas que não são IP (inet_pton) são descartadas no parse.
 *
 * Limitações conhecidas:
 *   - Apenas IPs (src_ip). Domínios/hashes ficam pra quando o analyzer
 *     emitir esses campos no evento JSON.
 *   - Recarga em runtime: ver NtaIocStore abaixo (SIGHUP, B03). */
typedef struct NtaIoc NtaIoc;

/* Abre + parseia o arquivo. Retorna NULL se path vazio, arquivo ausente,
 * JSON inválido, ou zero IoCs. Caller deve logar e seguir sem IoC. */
NtaIoc *nta_ioc_load(const char *path);

/* Match O(1). Retorna nome da lista que contém `ip` (ex "feodo-c2"), ou
 * NULL se ioc é NULL, ip é NULL, ou IP não está em nenhuma lista.
 * String retornada é owned por NtaIoc — válida até nta_ioc_close. */
const char *nta_ioc_match_ip(const NtaIoc *ioc, const char *ip);

/* Stats pra log de startup. n_ips = total de IPs únicos carregados. */
int nta_ioc_size(const NtaIoc *ioc);

void nta_ioc_close(NtaIoc *ioc);

/* -------------------------------------------------------------------------- *
 * Armazenamento com recarga (B03).                                           *
 *                                                                            *
 * Workers leem com nta_ioc_store_acquire()/nta_ioc_store_release() em volta *
 * de cada mensagem (sem mutex: dois contadores atômicos por slot). Um único  *
 * escritor (a thread de SIGHUP) chama nta_ioc_store_reload(): a tabela nova  *
 * é publicada por troca atômica, e só depois de os leitores da antiga terem  *
 * saído ela é liberada. Arquivo inválido, truncado ou sem IPs não substitui  *
 * a tabela ativa.                                                            *
 * -------------------------------------------------------------------------- */
typedef struct NtaIocStore NtaIocStore;

/* Sempre devolve um store, mesmo se a carga inicial falhar (IoC fica
 * desabilitado até um reload válido). NULL só em falta de memória. */
NtaIocStore *nta_ioc_store_open(const char *path);

/* Devolve a tabela ativa (pode ser NULL) e grava em *slot o token a passar
 * para nta_ioc_store_release(). A tabela só pode ser usada entre os dois. */
NtaIoc *nta_ioc_store_acquire(NtaIocStore *s, int *slot);
void    nta_ioc_store_release(NtaIocStore *s, int slot);

/* Recarrega do path configurado. 0 = trocada; -1 = rejeitada (a anterior
 * continua ativa). Deve ser chamada por uma única thread. */
int nta_ioc_store_reload(NtaIocStore *s);

/* IPs da tabela ativa (0 se desabilitado). */
int nta_ioc_store_size(NtaIocStore *s);

/* Libera tudo. Só depois que nenhuma thread usar o store. */
void nta_ioc_store_close(NtaIocStore *s);

#endif /* NTA_IOC_H */
