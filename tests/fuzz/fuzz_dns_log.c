/* Harness libFuzzer do parser do log de DNS (src/agent/analysis/protocols/
 * dns_log.c, B16 PR a). Cada entrada é um L4 hostil: o primeiro byte escolhe
 * UDP (par) ou TCP (ímpar) e o resto é o segmento/datagrama. Além do parse, roda
 * o render JSON e o hash do registro quando o parse aceita, porque é isso que o
 * agente faz com o que o parser devolve.
 *
 * Mesmo esquema de fuzz_parser.c e fuzz_rules.c: fuzz_dns_log_replay (driver sem
 * libFuzzer, gcc ou clang com ASan/UBSan) roda arquivos de corpus ou crash-*;
 * fuzz_dns_log (clang) é o libFuzzer. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "dns_log.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    uint8_t proto = (data[0] & 1) ? DNS_PROTO_TCP : DNS_PROTO_UDP;
    DnsEvent e;
    memset(&e, 0, sizeof(e));
    if (dns_log_parse(proto, data + 1, (int)(size - 1), &e) == 0) {
        char out[DNS_LOG_JSON_MAX];
        char h[17];
        dns_log_hash_hex(e.qname, h);
        (void)dns_log_render_json(&e, 1, out, sizeof(out));
    }
    return 0;
}
