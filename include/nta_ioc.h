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
 * Limitações conhecidas:
 *   - Apenas IPs (src_ip). Domínios/hashes ficam pra quando o analyzer
 *     emitir esses campos no evento JSON.
 *   - Reload em runtime (SIGHUP) não implementado — para atualizar,
 *     reiniciar nta-server. */
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

#endif /* NTA_IOC_H */
