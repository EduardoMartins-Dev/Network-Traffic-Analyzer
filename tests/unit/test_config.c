/* Testes do carregador de --config (src/core/config.c). */
#include "test.h"
#include "../../include/config.h"

#include <stdlib.h>

#define TMP_CONF "test_config.tmp"

static void unset(const char *key) {
#ifdef _WIN32
    _putenv_s(key, "");         /* valor vazio remove a variável no Windows */
#else
    unsetenv(key);
#endif
}

static void set(const char *key, const char *val) {
#ifdef _WIN32
    _putenv_s(key, val);
#else
    setenv(key, val, 1);
#endif
}

static void write_file(const char *content, size_t len) {
    FILE *f = fopen(TMP_CONF, "wb");
    fwrite(content, 1, len, f);
    fclose(f);
}

static const char *K[] = { "NTA_T_HOST", "NTA_T_PORT", "NTA_T_QUOTED", "NTA_T_SINGLE",
                           "NTA_T_EMPTY", "NTA_T_SPACES", "NTA_T_PATH", "NTA_T_EQ", NULL };

static void reset_env(void) {
    for (int i = 0; K[i]; i++) unset(K[i]);
}

static void test_formato_completo(void) {
    reset_env();
    /* BOM + CRLF + comentário + linha vazia + aspas + espaços + valor vazio +
     * linha sem '=' + '=' dentro do valor + barras invertidas (Windows). */
    static const char conf[] =
        "\xEF\xBB\xBF# comentario na primeira linha (com BOM)\r\n"
        "NTA_T_HOST=10.0.0.5\r\n"
        "\r\n"
        "   # comentario indentado\r\n"
        "NTA_T_PORT = 5674 \r\n"
        "NTA_T_QUOTED=\"com espaco\"\r\n"
        "NTA_T_SINGLE='simples'\r\n"
        "NTA_T_EMPTY=\r\n"
        "linha sem igual\r\n"
        "NTA_T_SPACES=  a b  \r\n"
        "NTA_T_PATH=\\Device\\NPF_{ABC}\r\n"
        "NTA_T_EQ=chave=valor\r\n";
    write_file(conf, sizeof(conf) - 1);

    CHECK(config_load_file(TMP_CONF) == 7);    /* EMPTY e a linha inválida não contam */
    CHECK_STR(getenv("NTA_T_HOST"), "10.0.0.5");
    CHECK_STR(getenv("NTA_T_PORT"), "5674");
    CHECK_STR(getenv("NTA_T_QUOTED"), "com espaco");
    CHECK_STR(getenv("NTA_T_SINGLE"), "simples");
    CHECK(getenv("NTA_T_EMPTY") == NULL);
    CHECK_STR(getenv("NTA_T_SPACES"), "a b");
    CHECK_STR(getenv("NTA_T_PATH"), "\\Device\\NPF_{ABC}");
    CHECK_STR(getenv("NTA_T_EQ"), "chave=valor");
    remove(TMP_CONF);
}

static void test_ambiente_tem_precedencia(void) {
    reset_env();
    set("NTA_T_HOST", "do-ambiente");
    static const char conf[] = "NTA_T_HOST=do-arquivo\nNTA_T_PORT=1\n";
    write_file(conf, sizeof(conf) - 1);

    CHECK(config_load_file(TMP_CONF) == 1);    /* só PORT foi aplicada */
    CHECK_STR(getenv("NTA_T_HOST"), "do-ambiente");
    CHECK_STR(getenv("NTA_T_PORT"), "1");
    remove(TMP_CONF);
}

static void test_arquivo_inexistente(void) {
    CHECK(config_load_file("nao-existe-nta.conf") == -1);
}

int main(void) {
    RUN(test_formato_completo);
    RUN(test_ambiente_tem_precedencia);
    RUN(test_arquivo_inexistente);
    TEST_EXIT();
}
