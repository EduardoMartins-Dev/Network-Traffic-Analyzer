#ifndef NTA_GEOIP_H
#define NTA_GEOIP_H

#include <stdint.h>

/* Wrapper libmaxminddb com cache em hashtable própria. Thread-safe (mutex
 * por instância — compartilhado entre N workers).
 *
 * v8.0 (M1): suporta DOIS bancos opcionais — GeoLite2-City (lat/lon) e
 * GeoLite2-ASN (asn_number + asn_org). Cada um pode ser NULL e o cache
 * armazena ambos os resultados na mesma entrada (1 hit cobre tudo). */
typedef struct NtaGeo NtaGeo;

#define NTA_ASN_ORG_MAX 96  /* org names MaxMind ASN ficam < 80 chars */

typedef struct {
    int      has_geo;                  /* 1 = lat/lon válidos */
    int      has_asn;                  /* 1 = asn_number/asn_org válidos */
    double   lat;
    double   lon;
    uint32_t asn_number;
    char     asn_org[NTA_ASN_ORG_MAX];
} NtaGeoResult;

/* Abre os bancos disponíveis. Qualquer um (ou ambos) pode ser NULL/vazio —
 * nesse caso o lookup correspondente é skip. Retorna NULL apenas se AMBOS
 * falharem ou se calloc falhar. Caller deve logar e seguir sem GeoIP — não
 * é fatal. */
NtaGeo *nta_geo_open(const char *city_db_path, const char *asn_db_path);

/* Lookup combinado city + ASN com cache. Retorna 1 se PELO MENOS um dos dois
 * teve hit (out->has_geo || out->has_asn). 0 se IP é privado, vazio, ou
 * nenhum banco tem o IP. Sempre zera `out` antes de preencher.
 *
 * Lista de privados igual ao data_ingestor.py: 127., 192.168., 10., 172.
 * (mesmas limitações conhecidas — paridade de schema). */
int  nta_geo_lookup(NtaGeo *g, const char *ip, NtaGeoResult *out);

void nta_geo_close(NtaGeo *g);

#endif /* NTA_GEOIP_H */
