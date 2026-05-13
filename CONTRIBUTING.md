# Contributing

> 🇧🇷 [Pular para a versão em português](#contribuindo-pt-br)

Thanks for considering a contribution! This project is a personal/educational IDS built in C — keep that in mind when picking scope. Big architectural shifts are welcome via Discussions before code.

## Code of Conduct

By participating you agree to the [Code of Conduct](./CODE_OF_CONDUCT.md).

## Quick start

```bash
git clone https://github.com/EduardoMartins-Dev/Network-Traffic-Analyzer
cd Network-Traffic-Analyzer
make quickstart        # install deps + up Docker stack + smoke test
```

Detailed install steps live in [README.md § Instalação](./README.md#instalação).

## Where to start

| Want to | Look at |
|---------|---------|
| Add a new attack detector | `src/analysis/analyzer.c` + tests in `tests/pcaps/` |
| Add a new threat-intel enricher | mirror `src/server/nta_abuse.c` (cache + libcurl) |
| Improve dashboards | `grafana/dashboards/*.json` |
| Fix a bug | open an issue first if behavior is non-obvious |
| Write docs | `README.md`, `ROADMAP.MD`, `data/*.README.md` |

`ROADMAP.MD` is the source of truth for what's planned. If you want to take on a roadmap item, open an issue claiming it.

## Coding guidelines

`CLAUDE.md` at the repo root captures the behavioral rules the project follows. The short version:

1. **Think before coding.** State assumptions, surface tradeoffs.
2. **Simplicity first.** No speculative abstractions, no premature configurability.
3. **Surgical changes.** Touch only what the task requires.
4. **Goal-driven execution.** Define a verify step for every change.

Concrete style:

- C11 (`-std=c11`), `-Wall -Wextra`. No warnings on the new path.
- 4-space indent, snake_case for functions/variables, `Nta`-prefixed types for shared structs.
- No emojis in code/comments. Default to no comments — write one only when the *why* isn't obvious.
- No new dependencies without justification. Current deps: `libpcap`, `librabbitmq`, `libcurl`, `libmaxminddb`, `cJSON` (vendored).
- Match existing logging style: `[MODULE] mensagem PT-BR` to stderr.

## Commits

Conventional Commits, PT-BR allowed (matching the existing history):

```
feat(v8.0): nova feature
fix(server): corrige race em pool_join_all
docs(readme): atualiza seção XYZ
refactor(geoip): extrai cache para módulo comum
chore(ci): bump workflow runner
```

Body explains *why*, not *what*. Mention the commit hash if your change relates to a previous one.

## Pull Requests

1. Fork → branch off `main`. Branch naming: `feat/<short>`, `fix/<short>`, `docs/<short>`.
2. Keep PRs **small and focused** — one feature or fix per PR.
3. Run the CI checks locally:
   ```bash
   cmake --build build --target nta-server
   # if you changed detectors, also:
   ./build/NetworkTrafficAnalyzer --replay-dir tests/pcaps/
   ```
4. Fill the PR template completely. Empty sections will be requested.
5. Reference any related issue: `Closes #N`.
6. Be prepared to iterate on review feedback — review tone is direct, no fluff.

## Testing

- Detector changes must include a PCAP in `tests/pcaps/` plus a gabarito JSON entry.
- The `test-ids` workflow runs on every PR (`.github/workflows/test-ids.yml`); it must stay green.
- Manual integration testing (full stack up, captured traffic) is encouraged for cross-component changes.

## Security

If you find a vulnerability, **do not open a public issue**. Read [SECURITY.md](./SECURITY.md) for the private disclosure process.

---

## Contribuindo (PT-BR)

Obrigado por considerar contribuir! Este é um projeto pessoal/educacional de IDS em C — leve isso em conta ao escolher escopo. Mudanças arquiteturais grandes são bem-vindas via Discussions antes de virar código.

### Código de Conduta

Ao participar você concorda com o [Código de Conduta](./CODE_OF_CONDUCT.md).

### Início rápido

```bash
git clone https://github.com/EduardoMartins-Dev/Network-Traffic-Analyzer
cd Network-Traffic-Analyzer
make quickstart        # instala deps + sobe stack Docker + smoke test
```

Passos detalhados em [README.md § Instalação](./README.md#instalação).

### Por onde começar

| Quer | Veja |
|------|------|
| Adicionar novo detector de ataque | `src/analysis/analyzer.c` + testes em `tests/pcaps/` |
| Adicionar enricher de threat-intel | espelhe `src/server/nta_abuse.c` (cache + libcurl) |
| Melhorar dashboards | `grafana/dashboards/*.json` |
| Corrigir bug | abra issue antes se o comportamento não for óbvio |
| Escrever docs | `README.md`, `ROADMAP.MD`, `data/*.README.md` |

O `ROADMAP.MD` é a fonte da verdade do que está planejado. Se quiser pegar um item, abra issue reivindicando.

### Diretrizes de código

`CLAUDE.md` na raiz captura as regras comportamentais do projeto. Resumo:

1. **Pense antes de codar.** Explicite premissas, exponha tradeoffs.
2. **Simplicidade primeiro.** Sem abstrações especulativas, sem configurabilidade prematura.
3. **Mudanças cirúrgicas.** Toque só no que a tarefa exige.
4. **Execução orientada a objetivo.** Defina verify pra cada mudança.

Estilo concreto:

- C11 (`-std=c11`), `-Wall -Wextra`. Zero warnings no caminho novo.
- Indent 4 espaços, snake_case p/ funções/variáveis, tipos com prefixo `Nta` p/ structs compartilhadas.
- Sem emojis em código/comentários. Default = sem comentário — escreva só quando o *porquê* não for óbvio.
- Sem novas deps sem justificativa. Deps atuais: `libpcap`, `librabbitmq`, `libcurl`, `libmaxminddb`, `cJSON` (vendored).
- Use o mesmo estilo de log: `[MODULO] mensagem PT-BR` no stderr.

### Commits

Conventional Commits, PT-BR permitido (coerente com histórico):

```
feat(v8.0): nova feature
fix(server): corrige race em pool_join_all
docs(readme): atualiza seção XYZ
refactor(geoip): extrai cache para módulo comum
chore(ci): bump workflow runner
```

Corpo explica *porquê*, não *o quê*. Cite hash de commit relacionado quando fizer sentido.

### Pull Requests

1. Fork → branch a partir de `main`. Nomenclatura: `feat/<curto>`, `fix/<curto>`, `docs/<curto>`.
2. PRs **pequenos e focados** — uma feature ou correção por PR.
3. Rode o CI localmente:
   ```bash
   cmake --build build --target nta-server
   # Se mexeu nos detectores:
   ./build/NetworkTrafficAnalyzer --replay-dir tests/pcaps/
   ```
4. Preencha o template do PR completo. Seções vazias serão pedidas no review.
5. Referencie issue relacionada: `Closes #N`.
6. Esteja pronto p/ iterar no review — tom direto, sem floreio.

### Testes

- Mudanças em detector exigem um PCAP em `tests/pcaps/` + entrada no gabarito JSON.
- Workflow `test-ids` roda em todo PR (`.github/workflows/test-ids.yml`); precisa ficar verde.
- Teste de integração manual (stack completa + tráfego capturado) é encorajado p/ mudanças que cruzam componentes.

### Segurança

Achou vulnerabilidade? **Não abra issue público.** Leia [SECURITY.md](./SECURITY.md) p/ o fluxo de disclosure privado.
