/* Harness libFuzzer do carregador de limiares (src/agent/analysis/rules.c, B18
 * fase 1). Cada entrada é o conteúdo de um arquivo AGENT_RULES_FILE. O arquivo
 * vem de quem administra o host, mas um JSON quebrado não pode derrubar o agente
 * nem ler fora do buffer: o alvo é a validação de forma, tipo e faixa.
 *
 * Mesmo esquema de tests/fuzz/fuzz_parser.c: o driver fuzz_rules_replay roda os
 * arquivos sem libFuzzer (gcc com ASan/UBSan); fuzz_rules (clang) é o libFuzzer.
 */
#include <stddef.h>
#include <stdint.h>
#include "rules.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    NtaRules r;
    char     err[256];
    (void)rules_parse((const char *)data, size, &r, err, sizeof(err));
    return 0;
}
