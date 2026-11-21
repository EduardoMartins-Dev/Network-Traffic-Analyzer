# Limiares dos detectores (`AGENT_RULES_FILE`)

O agente lê os limiares, janelas e alfas dos detectores de um arquivo JSON, sem
recompilar. Sem o arquivo, valem os padrões do código (os mesmos valores de
`limiares.example.json`). É a fase 1 da B18: só ajusta limiares existentes, não
cria regras novas (fase 2, ver `Decisoes/ADR - Formato de regras de deteccao`).

## Como usar

```bash
# variável de ambiente (ou AGENT_RULES_FILE= dentro do --config; o ambiente vence)
AGENT_RULES_FILE=/etc/nta-agent/limiares.json ./NetworkTrafficAnalyzer eth0
AGENT_RULES_FILE=deploy/rules/limiares.example.json ./NetworkTrafficAnalyzer --replay-dir tests/pcaps
```

- O arquivo é lido **uma vez, na subida**. Para mudar, reinicie o agente (no
  Windows é o serviço `NTAAgent`). Não há recarga por sinal nesta fase.
- Arquivo inválido ⇒ o agente sai com `rc 1` e a mensagem
  `Erro: regras de detecção inválidas em <arquivo>: <motivo>`, antes de capturar
  ou fazer replay. Nunca roda com configuração parcial.
- Chave ausente usa o padrão. Só as chaves que você quer mudar precisam estar no
  arquivo, mas `versao` é obrigatória.

## Formato

JSON (sem comentários). `versao` deve ser `1`. Todas as chaves são números.
Inteiros não podem ter parte fracionária; `15.0` é aceito, `15.5` não.

| Chave | Padrão | Faixa | Detector | O que controla |
|---|---|---|---|---|
| `scan_threshold` | 15 | 2–32 | PORT_SCAN | portas de destino únicas por IP para alertar |
| `icmp_threshold` | 20 | 5–100000 | ICMP_FLOOD | pacotes ICMP antes da calibração (depois é adaptativo) |
| `syn_flood_threshold` | 100 | 10–1000000 | SYN_FLOOD | SYNs sem ACK antes da calibração (depois é adaptativo) |
| `stealth_threshold` | 3 | 2–1000 | NULL/XMAS/SYNFIN | pacotes com a combinação de flags para alertar |
| `brute_threshold` | 30 | 5–100000 | BRUTE_FORCE | SYNs às portas 22/21/3389 na janela para alertar |
| `brute_window_sec` | 60 | 10–3600 | BRUTE_FORCE | tamanho da janela do brute force, em segundos |
| `dns_subdomain_len` | 50 | 1–63 | DNS_TUNNEL | primeiro label maior que N caracteres é suspeito |
| `dns_entropy_thresh` | 3.5 | 1.0–8.0 | DNS_TUNNEL | entropia de Shannon (bits/char) acima da qual o nome é suspeito |
| `dns_suspicious_max` | 10 | 1–100000 | DNS_TUNNEL | nomes suspeitos antes do alerta |
| `amplification_ratio` | 10 | 2–10000 | AMPLIFICATION | alerta quando resposta > N × requisição |
| `kc_window_sec` | 1800 | 60–86400 | kill chain | janela para correlacionar estágios (reset se inativo) |
| `ewma_calibration` | 100 | 2–100000 | baseline EWMA | amostras de janela para sair da calibração |
| `ewma_alpha_fast` | 0.3 | 0.01–1.0 | baseline EWMA | peso de cada amostra durante a calibração |
| `ewma_alpha_slow` | 0.1 | 0.01–1.0 | baseline EWMA | peso de cada amostra depois da calibração |
| `ewma_sigma` | 3.0 | 1.0–10.0 | baseline EWMA | desvios-padrão para o limiar adaptativo |
| `ewma_window_sec` | 60 | 10–3600 | baseline EWMA | tamanho da janela de agregação do baseline |

Os limites inclusivos são o contrato: valor fora da faixa é recusado, não
truncado. As faixas evitam limiares que alertariam no primeiro pacote; por
exemplo `scan_threshold` 1 marcaria qualquer host.

## O que não está aqui, e por quê

- **Tamanhos de tabela** (`MAX_SUSPECTS`, `MAX_ARP_ENTRIES`, `SRV_REQ_SLOTS`,
  `MAX_HOME_CIDR`): dimensionam memória fixa. Mudar exige recompilar.
- **Teto do port scan** (`NTA_RULES_SCAN_MAX` = 32): é a capacidade de
  `Suspect.ports[]`. `scan_threshold` não passa desse valor.
- **Vida do estado** (`CLEANUP_INTERVAL`, `INACTIVE_TIMEOUT`): controla quando
  IPs e contadores são descartados, não um alerta.
- **Limite de extensões IPv6** (`MAX_IPV6_EXT`): proteção do parser contra
  cadeias longas. Afrouxar piora a robustez, não a detecção.
- **Portas de brute force** (22, 21, 3389): uma lista, não um limiar. Vira
  primitiva na fase 2, se for preciso.
- **Constantes sem nome** no código: mínimo de 100 bytes de requisição para o
  AMPLIFICATION, bônus de 10 pontos se o estágio EXPLOIT vier em menos de 5 min,
  fatores 2.0 (SYN) e 1.5 (ICMP) do limiar adaptativo, pisos 10 e 5 desses
  limiares, e pontuação base por estágio. Ficam no código nesta fase.

## Validação

Chave desconhecida (inclusive typo como `scan_treshold`), chave repetida, tipo
errado (string, booleano, `null`, lista), fora da faixa, `versao` diferente de 1,
JSON quebrado, lixo depois do JSON, profundidade acima de 4 níveis, bytes nulos,
arquivo vazio e arquivo acima de 16 KiB são recusados com mensagem que aponta a
chave ou o motivo. Os testes estão em `tests/unit/test_rules.c`.
