<!--
Bilingual EN/PT template. Keep the language you used in the commits.
Delete the section you didn't use before submitting.
-->

## Summary / Resumo

<!--
EN: One-line "what changed and why". Body explains the why, the diff explains the what.
PT: Uma linha "o que mudou e por quê". Corpo explica o porquê; o diff explica o quê.
-->

## Type of change / Tipo de mudança

- [ ] `feat` — new feature / nova feature
- [ ] `fix` — bug fix / correção de bug
- [ ] `refactor` — no behavior change / sem mudança de comportamento
- [ ] `docs` — documentation only / só documentação
- [ ] `chore` — tooling / build / CI / ferramental
- [ ] `perf` — performance only / só performance
- [ ] Breaking change / mudança incompatível

## Related issues / Issues relacionadas

<!--
Closes #N
Refs #N
-->

## Motivation / Motivação

<!--
EN: Why does this change exist? What's the user/operator-visible impact?
PT: Por que essa mudança existe? Qual o impacto visível pro usuário/operador?
-->

## Implementation notes / Notas de implementação

<!--
EN: Design decisions, tradeoffs, alternatives rejected. Keep it short.
PT: Decisões de design, tradeoffs, alternativas rejeitadas. Seja curto.
-->

## Schema / config changes / Mudanças de schema ou config

<!--
EN: New env vars, InfluxDB tags/fields, JSON fields, RabbitMQ queues, secrets file format.
PT: Novas env vars, tags/fields InfluxDB, campos JSON, filas RabbitMQ, formato de arquivo de secrets.
Mark "None" if not applicable.
-->

None

## Test plan / Plano de teste

<!--
EN: Concrete steps you ran. Paste relevant log lines or output. PCAP filenames if applicable.
PT: Passos concretos que rodou. Cole linhas de log ou output relevante. Nome dos PCAPs se aplicável.
-->

- [ ] `cmake --build build --target nta-server` — passa sem warnings novos
- [ ] `./build/nta-server` — startup banner mostra enrichers esperados
- [ ] `tests/pcaps/` replay (se mexeu em detector): all PCAPs PASS
- [ ] Manual end-to-end (RabbitMQ + Influx + Grafana up): _describe / descreva_

## Checklist

- [ ] Commit follows Conventional Commits / Commit segue Conventional Commits
- [ ] No new compiler warnings on the touched path / Sem warnings novos no caminho tocado
- [ ] CLAUDE.md guidelines respected (no speculative scope) / Diretrizes do CLAUDE.md respeitadas
- [ ] Docs updated if user-visible behavior changed / Docs atualizadas se comportamento visível mudou
- [ ] No secrets, tokens, or PII committed / Sem secrets, tokens ou PII commitados
- [ ] `.gitignore` updated if new artifact dirs introduced / `.gitignore` atualizado se introduziu novos diretórios

## Screenshots / Screenshots

<!--
EN: For UI / dashboard / Grafana changes, paste before/after PNGs.
PT: Para mudanças de UI / dashboard / Grafana, cole PNGs before/after.
-->

N/A
