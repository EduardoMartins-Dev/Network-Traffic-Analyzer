# Security Policy

> 🇧🇷 [Pular para a versão em português](#política-de-segurança-pt-br)

## Supported Versions

The `main` branch (currently **v8.0**) is the only actively maintained line. Security fixes are not backported to older tags.

| Version | Supported |
|---------|-----------|
| v8.0 (main) | ✅ |
| < v8.0 | ❌ |

## Reporting a Vulnerability

**Please do not open public GitHub issues for security reports.**

### Preferred channel — private GitHub advisory

Use [GitHub Security Advisories](https://github.com/EduardoMartins-Dev/Network-Traffic-Analyzer/security/advisories/new) to file a private report. This keeps the discussion confidential and lets us coordinate a fix + disclosure timeline before the issue becomes public.

### Alternate channel — email

If you cannot use GitHub Advisories, email **eduardo.dev.barbosa@gmail.com** with:

- A short title describing the impact
- Steps to reproduce (PoC code, pcap, request, etc.)
- Affected component (agent, `nta-server`, narrator, etc.)
- Your assessment of severity (CVSS or plain prose)
- Whether you want public credit on disclosure

### What to expect

| Step | Target |
|------|--------|
| Acknowledgement | within 72h |
| Initial triage + severity | within 7 days |
| Fix + coordinated disclosure | within 90 days (negotiable for severe issues) |

This is a personal/educational project — there is no SLA, but disclosed reports are taken seriously and treated in good faith.

### Scope

In scope:

- Memory safety bugs in C code (use-after-free, OOB, double-free, etc.)
- AMQP/TCP/HTTP parser issues in `nta-server` and the agent
- Auth/TLS handling (mTLS multi-agent, AMQP login)
- Cache poisoning, line protocol injection, log injection
- Secrets leaking into git history or logs
- Privilege misuse (`cap_net_raw` related)

Out of scope:

- Bugs in third-party dependencies (libpcap, librabbitmq, libcurl, libmaxminddb, cJSON) — report to upstream
- Issues that require physical access to the monitoring host
- Findings on default credentials in `docker-compose.yml` (these are intentional for local dev)
- Denial-of-service that requires more traffic than the host's NIC can deliver

### Safe harbor

Good-faith research conducted following this policy will not result in legal action from the project maintainers.

---

## Política de Segurança (PT-BR)

### Versões Suportadas

A branch `main` (atualmente **v8.0**) é a única linha ativamente mantida. Correções de segurança não são portadas para tags antigas.

| Versão | Suportada |
|--------|-----------|
| v8.0 (main) | ✅ |
| < v8.0 | ❌ |

### Reportando uma Vulnerabilidade

**Por favor não abra issues públicas no GitHub para reports de segurança.**

#### Canal preferido — advisory privado no GitHub

Use [GitHub Security Advisories](https://github.com/EduardoMartins-Dev/Network-Traffic-Analyzer/security/advisories/new) para abrir um report privado. Mantém a discussão confidencial e permite coordenar correção + cronograma de divulgação antes do issue se tornar público.

#### Canal alternativo — e-mail

Se não puder usar GitHub Advisories, envie e-mail para **eduardo.dev.barbosa@gmail.com** com:

- Título curto descrevendo o impacto
- Passos para reproduzir (PoC, pcap, request, etc.)
- Componente afetado (agente, `nta-server`, narrator, etc.)
- Sua avaliação de severidade (CVSS ou texto livre)
- Se deseja crédito público na divulgação

#### Cronograma esperado

| Etapa | Prazo |
|-------|-------|
| Confirmação de recebimento | até 72h |
| Triagem inicial + severidade | até 7 dias |
| Correção + divulgação coordenada | até 90 dias (negociável p/ severidade alta) |

Este é um projeto pessoal/educacional — não há SLA, mas todos os reports são tratados com seriedade e boa-fé.

#### Escopo

No escopo:

- Bugs de memory safety em código C (use-after-free, OOB, double-free, etc.)
- Issues de parser AMQP/TCP/HTTP no `nta-server` e agente
- Tratamento de auth/TLS (mTLS multi-agente, login AMQP)
- Cache poisoning, injection em line protocol, injection em logs
- Vazamento de segredos no histórico git ou nos logs
- Uso indevido de privilégios (`cap_net_raw`)

Fora do escopo:

- Bugs em dependências de terceiros (libpcap, librabbitmq, libcurl, libmaxminddb, cJSON) — reporte upstream
- Issues que exijam acesso físico ao host de monitoramento
- Credenciais default no `docker-compose.yml` (intencionais p/ dev local)
- DoS que exija mais tráfego do que a NIC do host consegue entregar

#### Safe harbor

Pesquisa de boa-fé conduzida seguindo esta política não resultará em ação legal por parte dos mantenedores.
