# tests/eve — exemplos do eve.json do Suricata (nta-eve-bridge, B17)

Não há Suricata real nesta fase. Os arquivos aqui são **exemplos** montados
para testar a ponte, não capturas de um sensor.

| Arquivo | Conteúdo |
|---|---|
| `eve-sample.json` | 15 linhas: alertas de várias categorias, um `flow` (outro event_type), três linhas inválidas (JSON quebrado, sem `signature_id`, IP inválido) e uma truncada. |
| `expected-dryrun.json` | Saída esperada de `nta-eve-bridge --once --dry-run` sobre `eve-sample.json` com `deploy/eve-bridge.mapping.json` (golden do ctest `test_eve_dryrun`). |

Para regenerar o golden depois de mudar a tradução (e só depois de conferir o diff):

```bash
BRIDGE_EVE_PATH=tests/eve/eve-sample.json \
BRIDGE_MAPPING_FILE=deploy/eve-bridge.mapping.json \
BRIDGE_AGG_WINDOW_MS=60000 BRIDGE_RATE_PER_SEC=0 \
./build/nta-eve-bridge --once --dry-run 2>/dev/null > tests/eve/expected-dryrun.json
```

## Contrato lido do eve.json

Fonte: documentação oficial do Suricata, `doc/userguide/output/eve/eve-json-format.rst`
(docs.suricata.io/en/latest, título "Suricata 9.0.0-dev documentation") e a mesma
página na tag `suricata-8.0.8` (última release estável). Formato do evento `alert`
idêntico nas duas.

Campos que a ponte lê:

| Campo | Uso |
|---|---|
| `event_type` | Só `"alert"` vira alerta; outros são contados como `outros`. |
| `src_ip`, `dest_ip` | Atacante (`src_ip`, padrão) e lado oposto. IPs inválidos: linha inválida. |
| `src_port`, `dest_port` | Porta do lado não atacante (`dest_port` no padrão). Ausente: 0. |
| `proto` | Normalizado para maiúsculas, até 7 caracteres. Ausente: `UNKNOWN`. |
| `direction` | Só com `BRIDGE_ATTACKER_SIDE=response`: troca para `dest_ip` se `to_client`. |
| `alert.signature_id` | Obrigatório. Chave de agregação (com `src_ip`). Enviado como `signature_id`. |
| `alert.category` | Vira `attack_type` (`SURICATA_` + categoria normalizada) e procura a regra da tabela. |
| `alert.severity` | Índice do score (1, 2 ou 3; outro valor usa o de 3). |
| `alert.metadata[<chave>]` | Técnica ATT&CK (chave configurável, padrão `mitre_technique_id`). Aceita string ou lista. |

Não lidos: `timestamp` (o servidor usa o horário da ingestão), `alert.signature`
(texto livre que iria para o prompt do LLM), `flow`, `alert.source`/`alert.target`.

## Ressalvas do contrato

- **`direction` não tem semântica definida na doc.** A doc mostra `"direction": "to_client"`
  num alerta cujo `src_ip` é o servidor remoto que enviou o conteúdo malicioso (o atacante).
  Trocar para `dest_ip` em todo `to_client` erra nesse caso, por isso o padrão é `src`.
  O modo `response` existe para quem sabe que a assinatura casa na resposta.
- **Não há chave MITRE em `alert.metadata` na doc oficial.** `mitre_technique_id` é a
  convenção das regras Emerging Threats (não verificada aqui contra um ruleset); a chave
  é configurável em `mitre_metadata_key` da tabela.
- **A tabela de categorias é uma escolha de política**, não um fato da doc. Os nomes das
  categorias vêm do `etc/classification.config` do OISF/suricata (master, lido nesta sessão).
