#!/usr/bin/env bash
# up.sh — sobe a stack do servidor em containers: rabbitmq, influxdb, grafana
# e nta-server (inclui narrator C). Funciona em Linux, macOS e Windows (Git Bash).
# Detecta podman rootless e aponta DOCKER_HOST pro socket do usuário.
# Flags:
#   --no-ingest  → só infra (sem o container nta-server)
#   --foreground → após subir, acompanha os logs do nta-server (Ctrl+C só sai dos logs)

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

# mTLS — gera CA + server cert se ainda não existem (RabbitMQ.conf espera os arquivos).
if [ ! -f deploy/secrets/tls/server.crt ] || [ ! -f deploy/secrets/tls/ca.crt ]; then
    echo "▶ Gerando CA e cert do broker (mTLS multi-agente)"
    "$ROOT_DIR/scripts/gen_agent_cert.sh" server
fi

if [ "$START_INGEST" -eq 1 ]; then
    echo "▶ Subindo stack (build do nta-server na primeira vez)"
    docker compose up -d --build
else
    echo "▶ Subindo infra (sem nta-server)"
    docker compose up -d rabbitmq influxdb grafana gf-renderer
fi

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

# Retention hot 7d + bucket warm 90d + task de downsampling (idempotente).
"$ROOT_DIR/scripts/influx_retention.sh" || \
    echo "⚠ influx_retention.sh falhou — retention/downsampling não aplicado."

# Narrator (embutido no nta-server) usa Groq Cloud.
if [ ! -f deploy/secrets/groq.env ]; then
    echo "⚠ deploy/secrets/groq.env ausente — narrator worker desabilitado."
    echo "  cp deploy/secrets/groq.env.example deploy/secrets/groq.env e preencha GROQ_API_KEY."
fi

cat <<EOF

✓ Stack no ar.
  Grafana   http://localhost:3000   admin / \$GRAFANA_ADMIN_PASSWORD (default admin)
  RabbitMQ  http://localhost:15673  \$RABBITMQ_USER / \$RABBITMQ_PASS (default nta / nta-dev-password)
  InfluxDB  http://localhost:8086
EOF
if [ "$START_INGEST" -eq 1 ]; then
    cat <<EOF
  nta-server health  http://localhost:9091/health   (logs: docker compose logs -f nta-server)
  Agente    (rodar no host monitorado, com AGENT_ID/AGENT_TOKEN = usuário RabbitMQ):
            sudo ./build/NetworkTrafficAnalyzer <interface>
EOF
fi

if [ "$FOREGROUND" -eq 1 ] && [ "$START_INGEST" -eq 1 ]; then
    exec docker compose logs -f nta-server
fi
