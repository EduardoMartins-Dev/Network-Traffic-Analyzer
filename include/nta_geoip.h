#ifndef NTA_GEOIP_H
#define NTA_GEOIP_H

/* Wrapper libmaxminddb com cache em hashtable própria. Thread-safe (mutex
 * por instância — etapa 6 vai compartilhar 1 NtaGeo entre N workers). */
typedef struct NtaGeo NtaGeo;

/* Abre o banco GeoLite2 em mmap. Retorna NULL se o arquivo não existir,
 * estiver corrompido, ou db_path for vazio. Caller deve logar warn e seguir
 * sem GeoIP — não é fatal. */
NtaGeo *nta_geo_open(const char *db_path);

/* Lookup com cache. Retorna 1 se IP foi encontrado e preencheu lat/lon;
 * 0 se IP é privado, vazio, não está no banco, ou g é NULL.
 *
 * Match com data_ingestor.py: pula 127., 192.168., 10., 172. (mesma lista,
 * mesmas limitações — incluindo o falso-positivo 172.32–172.255). */
int  nta_geo_lookup(NtaGeo *g, const char *ip, double *lat, double *lon);

void nta_geo_close(NtaGeo *g);

#endif /* NTA_GEOIP_H */
