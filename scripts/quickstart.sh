#!/usr/bin/env bash
# quickstart.sh — caminho zero-a-rodando em uma chamada.
#
#   1. install.sh        (deps + build)
#   2. up.sh             (stack docker + ingestor)
#   3. smoke-test.sh     (build + replay opcional)
#
# Flags repassadas:
#   --no-smoke           pula etapa 3
#   --pull-llm           passa para up.sh (baixa modelo Ollama)
#   --server-only        só servidor (passado para install.sh)
#   --agent-only         só agente (passado para install.sh)

set -eu
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

DO_SMOKE=1
INSTALL_FLAGS=()
UP_FLAGS=()
for arg in "$@"; do
    case "$arg" in
        --no-smoke)            DO_SMOKE=0 ;;
        --pull-llm)            UP_FLAGS+=("--pull-llm") ;;
        --server-only)         INSTALL_FLAGS+=("--server-only") ;;
        --agent-only)          INSTALL_FLAGS+=("--agent-only"); DO_SMOKE=0 ;;
        -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "✗ flag desconhecida: $arg" >&2; exit 2 ;;
    esac
done

step() { printf '\n\033[1;35m═══ %s ═══\033[0m\n' "$*"; }

step "1/3  INSTALL"
./scripts/install.sh "${INSTALL_FLAGS[@]+${INSTALL_FLAGS[@]}}"

# Se for só agente, parou aqui — não há stack pra subir
for f in "${INSTALL_FLAGS[@]+${INSTALL_FLAGS[@]}}"; do
    [ "$f" = "--agent-only" ] && exit 0
done

step "2/3  UP (stack docker + ingestor)"
./scripts/up.sh "${UP_FLAGS[@]+${UP_FLAGS[@]}}"

if [ "$DO_SMOKE" -eq 0 ]; then
    echo
    echo "✓ quickstart concluído (smoke-test pulado)."
    exit 0
fi

step "3/3  SMOKE TEST"
./scripts/smoke-test.sh

echo
echo "✓ quickstart concluído. Acesse http://localhost:3000 (admin/admin)."
