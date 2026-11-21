/* Harness libFuzzer do parser de pacotes do analyzer (B06).
 *
 * Cada entrada é um frame Ethernet cru entregue a analyze_packet() — o mesmo
 * ponto de entrada usado pela captura (live e replay). O tráfego vem da rede,
 * então é hostil: o alvo são leituras fora do buffer e UB no caminho de
 * parsing (Ethernet, ARP, IPv4, TCP, UDP, DNS).
 *
 * - analyzer_reset() a cada entrada: um crash reproduz sozinho, sem depender
 *   das entradas anteriores.
 * - HOME_NET fica vazio de propósito: sem o skip, todo o parser é alcançável.
 * - publish_packet é stub (como em tests/unit/test_analyzer.c): o fuzz não
 *   depende de AMQP, cJSON nem do pipeline.
 */
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "analyzer.h"

/* O analyzer usa o horário do pacote. Com o estado zerado a cada entrada,
 * last_cleanup = 0: a limpeza periódica (que faz printf) roda em toda entrada
 * quando now >= 60. now = 0 a mantém fora do caminho quente. */
#define FUZZ_NOW ((time_t)0)

/* Maior frame que a captura entrega (SNAP_LEN). */
#define FUZZ_MAX_FRAME 65535

void publish_packet(const char *src_ip, int port, const char *proto, int bytes,
                    int is_scan, const char *attack_type,
                    const char *kill_chain_stage, int kc_score,
                    const char *mitre_technique) {
    (void)src_ip; (void)port; (void)proto; (void)bytes; (void)is_scan;
    (void)attack_type; (void)kill_chain_stage; (void)kc_score;
    (void)mitre_technique;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > FUZZ_MAX_FRAME) return 0;

    analyzer_reset();
    analyze_packet(data, (int)size, FUZZ_NOW);
    return 0;
}
