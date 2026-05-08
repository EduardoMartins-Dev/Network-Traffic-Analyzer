#!/usr/bin/env bash
# up.sh — sobe infra (rabbitmq/influxdb/grafana) + nta-server (inclui narrator C).
# Detecta podman rootless e aponta DOCKER_HOST pro socket do usuário.
# Flags:
#   --no-ingest  → só infra
#   --foreground → roda o nta-server em foreground (Ctrl+C para parar). Default: background.

set -eu
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

[ -f .env ] && set -a && . ./.env && set +a

START_INGEST=1
FOREGROUND=0
for arg in "$@"; do
    case "$arg" in
        --no-ingest) START_INGEST=0 ;;
        --foreground|--fg) FOREGROUND=1 ;;
        -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    esac
done

# Runtime: docker daemon > podman user socket
if docker info >/dev/null 2>&1; then
    :
elif [ -S "/run/user/$(id -u)/podman/podman.sock" ]; then
    export DOCKER_HOST="unix:///run/user/$(id -u)/podman/podman.sock"
    echo "▶ Usando podman socket: $DOCKER_HOST"
else
    echo "✗ Nenhum socket docker/podman acessível." >&2
    exit 1
fi

echo "▶ Subindo infra"
docker compose up -d

# Espera RabbitMQ aceitar AMQP (não só TCP — o listener 5672 registra depois da porta abrir).
echo "▶ Aguardando RabbitMQ aceitar AMQP..."
RMQ_READY=0
for _ in $(seq 1 60); do
    if docker exec rabbitmq rabbitmq-diagnostics -q check_port_listener 5672 >/dev/null 2>&1; then
        RMQ_READY=1
        break
    fi
    sleep 1
done
if [ "$RMQ_READY" -eq 0 ]; then
    echo "✗ RabbitMQ não ficou pronto em 60s." >&2
    exit 1
fi

# Narrator (embutido no nta-server) usa Groq Cloud.
if [ ! -f deploy/secrets/groq.env ]; then
    echo "⚠ deploy/secrets/groq.env ausente — narrator worker desabilitado."
    echo "  cp deploy/secrets/groq.env.example deploy/secrets/groq.env e preencha GROQ_API_KEY."
fi

if [ "$START_INGEST" -eq 0 ]; then
    echo "✓ Infra no ar (ingestor não iniciado)."
    exit 0
fi

if [ ! -x build/nta-server ]; then
    echo "✗ build/nta-server não encontrado. Rode 'cmake -B build -S . && cmake --build build' antes." >&2
    exit 1
fi

if [ "$FOREGROUND" -eq 1 ]; then
    cat <<EOF
✓ Infra de pé. Iniciando nta-server em foreground (Ctrl+C para parar)
  Grafana   http://localhost:3000   admin/admin
  RabbitMQ  http://localhost:15673  guest/guest
  InfluxDB  http://localhost:8086
EOF
    exec ./build/nta-server
fi

# Background (default)
if pgrep -f "build/nta-server" >/dev/null 2>&1; then
    echo "▶ nta-server já está rodando."
else
    ( setsid nohup ./build/nta-server </dev/null \
        >/tmp/nta-server.log 2>&1 & ) 2>/dev/null
    sleep 1
    pgrep -f "build/nta-server" >/dev/null && \
        echo "▶ nta-server iniciado (log: /tmp/nta-server.log)" || \
        { echo "✗ Falha ao subir nta-server. Veja /tmp/nta-server.log"; exit 1; }
fi

cat <<EOF

✓ Tudo no ar.
  Grafana   http://localhost:3000   admin/admin
  RabbitMQ  http://localhost:15673  guest/guest
  InfluxDB  http://localhost:8086
  Agente    (rodar manualmente, precisa sudo fora de toolbox):
            sudo ./build/NetworkTrafficAnalyzer <interface>
EOF
