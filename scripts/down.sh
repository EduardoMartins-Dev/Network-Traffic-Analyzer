#!/usr/bin/env bash
# down.sh — derruba infra + mata ingestor (e agente, se requisitado).
# Flags:  --with-agent  → também mata ./build/NetworkTrafficAnalyzer

set -eu
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

KILL_AGENT=0
for arg in "$@"; do
    case "$arg" in
        --with-agent) KILL_AGENT=1 ;;
        -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    esac
done

if docker info >/dev/null 2>&1; then
    :
elif [ -S "/run/user/$(id -u)/podman/podman.sock" ]; then
    export DOCKER_HOST="unix:///run/user/$(id -u)/podman/podman.sock"
fi

echo "▶ Parando nta-server"
pkill -f "./build/nta-server" 2>/dev/null && echo "  morto." || echo "  não estava rodando."

if [ "$KILL_AGENT" -eq 1 ]; then
    echo "▶ Parando NetworkTrafficAnalyzer (sudo)"
    sudo pkill -f "./build/NetworkTrafficAnalyzer" 2>/dev/null && echo "  morto." || echo "  não estava rodando."
fi

echo "▶ Derrubando containers"
docker compose down

echo "✓ Tudo parado."
