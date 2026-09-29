#ifndef NTA_CONFIG_H
#define NTA_CONFIG_H

/* ========================================================================= *
 * Arquivo de configuração do agente (--config <arquivo>).                   *
 *                                                                           *
 * Formato: uma variável por linha, `CHAVE=VALOR` (mesmas chaves AGENT_* das *
 * variáveis de ambiente — ver deploy/agent.env.example). Linhas vazias e   *
 * `#` comentários são ignorados; aspas em volta do valor são removidas;    *
 * valor vazio (`CHAVE=`) conta como chave ausente.                          *
 *                                                                           *
 * Cada chave vira variável de ambiente do processo, a menos que já esteja  *
 * definida: o ambiente tem precedência sobre o arquivo. Assim o resto do    *
 * código continua lendo só getenv().                                        *
 *                                                                           *
 * Retorna o nº de chaves aplicadas, ou -1 se o arquivo não pôde ser lido.  *
 * ========================================================================= */
int config_load_file(const char *path);

#endif /* NTA_CONFIG_H */
