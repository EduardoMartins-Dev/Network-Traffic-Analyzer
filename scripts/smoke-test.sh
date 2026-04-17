#!/usr/bin/env bash
# ============================================================================
# smoke-test.sh — validação mínima da v5.0 em ambiente Linux
#
# Executa, nesta ordem, as três etapas que NÃO podem ser validadas no Windows:
#
#   1. BUILD          — cmake + make (verifica libpcap, librabbitmq, pthread)
#   2. REPLAY SUITE   — --replay-dir tests/pcaps/ (bypassa pipeline; score ≥ 80%)
#   3. LIVE QUICK     — opcional: sniff de N segundos numa interface real e
#                       observa logs [PIPE] + overflow do ring buffer
#
# USO:
#   ./scripts/smoke-test.sh                    # só 1 + 2
#   ./scripts/smoke-test.sh --live eth0        # 1 + 2 + 3 (precisa sudo)
#   ./scripts/smoke-test.sh --live eth0 --seconds 15
#
# Códigos de saída:
#   0 tudo passou · 1 build · 2 replay · 3 live
# ============================================================================

set -u  # variável não-definida é erro; NÃO usamos -e pois queremos código final por etapa

# ----- args ------------------------------------------------------------------
LIVE_IFACE=""
LIVE_SECONDS=10
for arg in "$@"; do
    case "$arg" in
        --live)        shift; LIVE_IFACE="${1:-}"; shift || true ;;
        --seconds)     shift; LIVE_SECONDS="${1:-10}"; shift || true ;;
        -h|--help)
            grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
    esac
done

# ----- paths -----------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
BIN="$BUILD_DIR/NetworkTrafficAnalyzer"
PCAP_DIR="$ROOT_DIR/tests/pcaps"
REPORT="$BUILD_DIR/smoke-report.json"

cd "$ROOT_DIR"

hr()   { printf '%*s\n' 76 '' | tr ' ' '='; }
step() { hr; echo "▶ $*"; hr; }

# ============================================================================
# 1. BUILD
# ============================================================================
step "1/3  BUILD — cmake + make"
cmake -B "$BUILD_DIR" -S . || { echo "✗ cmake falhou"; exit 1; }
cmake --build "$BUILD_DIR" -j"$(nproc 2>/dev/null || echo 2)" \
    || { echo "✗ build falhou"; exit 1; }

[ -x "$BIN" ] || { echo "✗ binário não gerado: $BIN"; exit 1; }
echo "✓ binário em $BIN"

# ============================================================================
# 2. REPLAY SUITE  (determinístico, não requer RabbitMQ)
# ============================================================================
step "2/3  REPLAY — --replay-dir $PCAP_DIR"

# Replay mode não chama init_queue, então não precisa de RabbitMQ rodando.
# Exit code 1 interno se score agregado < 80%.
"$BIN" --replay-dir "$PCAP_DIR" --report "$REPORT"
REPLAY_RC=$?

if [ $REPLAY_RC -ne 0 ]; then
    echo "✗ replay falhou (exit=$REPLAY_RC). Relatório: $REPORT"
    exit 2
fi

if [ -f "$REPORT" ]; then
    SCORE=$(grep -oE '"total_score"[^,}]*' "$REPORT" | head -1)
    echo "✓ replay passou · $SCORE"
else
    echo "✓ replay passou (sem relatório gerado — possivelmente sem .pcap no diretório)"
fi

# ============================================================================
# 3. LIVE QUICK  (opcional)
# ============================================================================
if [ -z "$LIVE_IFACE" ]; then
    echo
    echo "→ smoke-test concluído (etapa 3 pulada; use --live <iface> para rodar)."
    exit 0
fi

step "3/3  LIVE — $LIVE_IFACE por ${LIVE_SECONDS}s"

if [ "$(id -u)" -ne 0 ]; then
    echo "✗ etapa live exige root (sudo)."; exit 3
fi

# RabbitMQ precisa estar acessível. Avisa mas não aborta — o binário falha rápido
# se a conexão não funcionar, o que já é feedback suficiente.
LOG="$BUILD_DIR/live.log"
: >"$LOG"

"$BIN" "$LIVE_IFACE" >"$LOG" 2>&1 &
PID=$!

# Garante kill mesmo se o script for interrompido no sleep
trap 'kill -INT "$PID" 2>/dev/null' EXIT INT TERM

sleep "$LIVE_SECONDS"
kill -INT "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
LIVE_RC=$?
trap - EXIT INT TERM

echo
echo "--- últimas 20 linhas de $LOG ---"
tail -n 20 "$LOG"
echo "----------------------------------"

# Critérios de "passou":  (a) não morreu antes do tempo  (b) ring buffers
# imprimiram a linha de descarte no shutdown  (c) nenhum segfault/backtrace
if ! grep -q "Ring buffers prontos" "$LOG"; then
    echo "✗ pipeline não inicializou (RabbitMQ offline?)"; exit 3
fi

if grep -qiE 'segfault|backtrace|core dumped' "$LOG"; then
    echo "✗ crash detectado no log"; exit 3
fi

DESCARTES=$(grep -oE 'Descartes — rb_pkt: [0-9]+ · rb_evt: [0-9]+' "$LOG" | tail -1)
echo "✓ live passou · $DESCARTES"
