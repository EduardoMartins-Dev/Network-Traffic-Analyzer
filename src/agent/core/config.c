#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) *--end = '\0';
    return s;
}

static int set_env_if_unset(const char *key, const char *val) {
    const char *cur = getenv(key);
    if (cur && *cur) return 0;          /* ambiente tem precedência */
#ifdef _WIN32
    return _putenv_s(key, val) == 0 ? 1 : 0;
#else
    return setenv(key, val, 0) == 0 ? 1 : 0;
#endif
}

int config_load_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[1024];
    int applied = 0, lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *s = line;
        /* BOM UTF-8 (Bloco de Notas, instalador Windows) */
        if (lineno == 1 && (unsigned char)s[0] == 0xEF &&
            (unsigned char)s[1] == 0xBB && (unsigned char)s[2] == 0xBF)
            s += 3;
        s = trim(s);                    /* trim também remove \r de CRLF */
        if (*s == '\0' || *s == '#') continue;

        char *eq = strchr(s, '=');
        if (!eq) {
            fprintf(stderr, "[CONFIG] %s:%d ignorada (sem '=')\n", path, lineno);
            continue;
        }
        *eq = '\0';
        char *key = trim(s);
        char *val = trim(eq + 1);
        size_t n = strlen(val);
        if (n >= 2 && (val[0] == '"' || val[0] == '\'') && val[n - 1] == val[0]) {
            val[n - 1] = '\0';
            val++;
        }
        /* Valor vazio = chave ausente (templates trazem `AGENT_CA_CERT=` etc.). */
        if (*key && *val) applied += set_env_if_unset(key, val);
    }
    fclose(f);
    return applied;
}
