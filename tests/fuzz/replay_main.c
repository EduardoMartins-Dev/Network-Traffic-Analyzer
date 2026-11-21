/* Driver sem libFuzzer: executa LLVMFuzzerTestOneInput sobre os arquivos
 * passados na linha de comando. Serve para validar o harness com qualquer
 * compilador (ex.: gcc com ASan/UBSan) e para reproduzir um crash-* salvo pelo
 * libFuzzer:  fuzz_replay <arquivos do corpus>  ou  fuzz_replay crash-<hash>
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "uso: %s <arquivo>...\n", argv[0]);
        return 2;
    }

    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) { perror(argv[i]); return 2; }

        if (fseek(f, 0, SEEK_END) != 0) { perror(argv[i]); fclose(f); return 2; }
        long n = ftell(f);
        if (n < 0) { perror(argv[i]); fclose(f); return 2; }
        rewind(f);

        uint8_t *buf = malloc(n > 0 ? (size_t)n : 1);
        if (!buf) { fclose(f); return 2; }
        if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
            fprintf(stderr, "%s: leitura incompleta\n", argv[i]);
            free(buf); fclose(f); return 2;
        }
        fclose(f);

        LLVMFuzzerTestOneInput(buf, (size_t)n);
        free(buf);
    }

    printf("%d entrada(s) executada(s) sem crash\n", argc - 1);
    return 0;
}
