#!/usr/bin/env bash
# ============================================================================
# server-up.sh — sobe o servidor central em um comando
#
# Executa, nesta ordem:
#   1. docker-compose up -d       (RabbitMQ + InfluxDB + Grafana)
#   2. python -m venv .venv       (se ainda não existe)
#   3. pip install -r requirements.txt
#   4. python3 build/data_ingestor.py (foreground; Ctrl+C para parar)
#
# Detecta automaticamente o runtime OCI disponível:
#   docker-compose → docker compose → podman-compose
#
# Uso:
#   ./scripts/server-up.sh              # sobe tudo
#   ./scripts/server-up.sh --no-ingest  # só infra, sem o ingestor Python
# ============================================================================

set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

START_INGEST=1
for arg in "$@"; do
    case "$arg" in
        --no-ingest) START_INGEST=0 ;;
        -h|--help)   sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    esac
done

# ---- 1. Detecta e sobe a infra --------------------------------------------
if command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
elif docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
elif command -v podman-compose >/dev/null 2>&1; then
    COMPOSE=(podman-compose)
else
    echo "✗ Nenhum runtime compose encontrado (docker-compose / docker compose / podman-compose)." >&2
    exit 1
fi

echo "▶ Subindo infra com: ${COMPOSE[*]}"
"${COMPOSE[@]}" up -d

# ---- 2. Espera RabbitMQ ficar pronto --------------------------------------
echo "▶ Aguardando RabbitMQ aceitar conexões na porta 5674..."
for _ in $(seq 1 60); do
    if (echo > /dev/tcp/127.0.0.1/5674) 2>/dev/null; then break; fi
    sleep 1
done

# ---- 3. Venv + deps -------------------------------------------------------
if [ ! -d .venv ]; then
    echo "▶ Criando venv em .venv/"
    python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -r requirements.txt

# ---- 4. Ingestor ----------------------------------------------------------
if [ "$START_INGEST" -eq 0 ]; then
    echo "✓ Infra de pé. Ingestor não iniciado (--no-ingest)."
    echo "  Grafana:  http://localhost:3000  (admin/admin)"
    echo "  RabbitMQ: http://localhost:15673 (guest/guest)"
    exit 0
fi

if [ ! -f build/data_ingestor.py ]; then
    echo "✗ build/data_ingestor.py não encontrado. Rode 'cmake -B build -S .' antes." >&2
    exit 1
fi

echo "▶ Iniciando data_ingestor.py (Ctrl+C para parar)"
cd build && exec python3 data_ingestor.py
