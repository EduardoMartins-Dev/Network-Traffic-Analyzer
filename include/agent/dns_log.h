#ifndef NTA_DNS_LOG_H
#define NTA_DNS_LOG_H

#include <stddef.h>
#include <stdint.h>

/* ========================================================================= *
 * LOG DE PROTOCOLO DNS (B16, PR a)                                          *
 *                                                                           *
 * Evento separado do alerta (ADR - Esquema de eventos de protocolo): cada    *
 * consulta/resposta DNS em UDP/53 ou TCP/53 vira um registro `event_type:"dns"`*
 * publicado em `AGENT_PROTO_QUEUE` (padrão `protocol_queue`). Desligado por   *
 * padrão: só liga com AGENT_PROTO_LOGS=dns.                                  *
 *                                                                           *
 * Privacidade: `qname` sai em TEXTO CLARO (é o dado). Com                     *
 * AGENT_PROTO_HASH_NAMES=1 sai só o FNV-1a 64 do nome (hex, minúsculo), que  *
 * NÃO é hash criptográfico: serve para agrupar, não para ocultar um domínio  *
 * conhecido (quem tem a lista de domínios recalcula o hash).                 *
 *                                                                           *
 * Este módulo não depende do pipeline nem do analyzer (só de ringbuf.c):     *
 * o analyzer chama dns_log_parse/dns_log_submit; a thread de publicação do   *
 * pipeline chama dns_log_pop/dns_log_render_json.                            *
 * ========================================================================= */

#define DNS_LOG_QNAME_MAX 256   /* 255 caracteres + NUL; nome maior sai truncado */
#define DNS_LOG_JSON_MAX  1024  /* teto de bytes de um registro no JSON (com escapes) */
#define DNS_PROTO_UDP      17
#define DNS_PROTO_TCP       6

/* Registro DNS. Na thread de análise ele é montado só com bytes (endereços em
 * wire order, qname em texto); o texto dos IPs, o hash (AGENT_PROTO_HASH_NAMES)
 * e o JSON são feitos depois, na thread de logs, fora do caminho quente.
 * `qname` é o texto com escape RFC 1035 §5.1 (\DDD para bytes fora de 0x21..0x7E,
 * \. e \\ para '.' e '\'). Só ASCII imprimível: o JSON não precisa de UTF-8. */
typedef struct {
    int64_t  ts_ms;              /* instante do pacote, ms desde a época */
    uint8_t  src[16];            /* IPv4 nos 4 primeiros bytes, IPv6 nos 16 */
    uint8_t  dst[16];
    char     qname[DNS_LOG_QNAME_MAX];
    uint16_t qtype;
    uint8_t  rcode;              /* 4 bits do cabeçalho DNS (0..15) */
    uint8_t  resp;               /* 1 = resposta (flag QR) */
    uint8_t  proto;              /* DNS_PROTO_UDP ou DNS_PROTO_TCP */
    uint8_t  is_v6;              /* 1 = endereços IPv6 */
    uint32_t bytes;              /* tamanho declarado da mensagem DNS */
} DnsEvent;

/* ---- Configuração (AGENT_PROTO_LOGS, AGENT_PROTO_HASH_NAMES) ----------- */

/* 1 = logs de DNS ligados. Lido pelo analyzer em cada pacote: é um inteiro
 * simples de propósito (sem chamada de função no caminho quente). */
extern int g_dns_log_on;

/* Lê AGENT_PROTO_LOGS e AGENT_PROTO_HASH_NAMES. Retorna 0 ou -1 com a mensagem
 * em `err`: tipo desconhecido ou ainda não suportado (só `dns` nesta versão) e
 * valor inválido de HASH_NAMES (aceita 1, 0 ou vazio). */
int  dns_log_config_from_env(char *err, size_t errlen);

/* Define as opções sem ler o ambiente (testes). */
void dns_log_set_options(int on, int hash_names);

/* ---- Parser (tamanhos validados; nunca lê além de `l4_len`) ----------- */

/* Interpreta o L4 (UDP ou TCP, conforme ip_proto) como DNS. Só aceita se a
 * porta de origem ou de destino for 53. Preenche qname/qtype/rcode/resp/proto/
 * bytes; não preenche IPs nem ts. Retorna 0 se há uma pergunta válida, -1 caso
 * contrário (não é DNS, truncado, sem pergunta, nome inválido ou TCP com
 * comprimento que não bate com o segmento). */
int dns_log_parse(uint8_t ip_proto, const uint8_t *l4, int l4_len, DnsEvent *out);

/* ---- Emissão ----------------------------------------------------------- */

/* Entrega um registro já completo (ts, endereços): em replay (`replay` != 0)
 * imprime uma linha `[PROTO]`; em live copia para o ring próprio (dns_log_start).
 * Descarte no ring é contado (dns_log_overflow). Não faz texto nem hash: isso é
 * da thread de logs (dns_log_render_json). */
void dns_log_submit(const DnsEvent *e, int replay);

/* ---- Ring próprio (SPSC: só a thread de análise escreve) --------------- */
int      dns_log_start(size_t capacity);   /* 0 ok, -1 sem memória */
void     dns_log_stop(void);
int      dns_log_pop(DnsEvent *out);       /* 0 ok, -1 vazio */
size_t   dns_log_depth(void);
uint64_t dns_log_overflow(void);           /* eventos descartados por ring cheio */

/* ---- Serialização -------------------------------------------------------- *
 * Array JSON de `n` registros em `out` (terminado em NUL). Formato:
 *   {"event_type":"dns","schema_version":1,"ts":..,"proto":"UDP",
 *    "src_ip":"..","dst_ip":"..","qname":"..","qtype":1,"rcode":0,
 *    "resp":0,"bytes":45,"qname_hashed":0}
 * Retorna o tamanho escrito, ou -1 se não couber (o chamador dimensiona com
 * DNS_LOG_JSON_MAX * n + 3). */
int dns_log_render_json(const DnsEvent *ev, int n, char *out, size_t cap);

/* FNV-1a 64 do texto em minúsculas ASCII, em hex (16 chars + NUL). */
void dns_log_hash_hex(const char *s, char out[17]);

#endif /* NTA_DNS_LOG_H */
