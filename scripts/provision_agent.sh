#!/usr/bin/env bash
# provision_agent.sh — cria credencial RabbitMQ + chave HMAC de um agente.
# Uso: scripts/provision_agent.sh <nome-do-agente> [--mtls]
#
# Cria:
#   user  agent-<nome> no vhost /          → write em traffic_queue, traffic_metrics
#   user  agent-<nome> no vhost /commands  → read em cmd.<nome>
#   fila  cmd.<nome> no vhost /commands    (durable)
#   HMAC  32 bytes hex (chave única do agente)
# Com --mtls: emite par cert/key cliente em deploy/secrets/tls/ (CN=agent-<nome>).
#
# Arquivos gerados:
#   deploy/agent/<nome>.env         → copiar pra /etc/nta/agent.env na máquina
#   deploy/secrets/ctl/<nome>.hmac  → chave HMAC, fica no control plane
#   deploy/secrets/ctl/ctl-admin.env → credencial do publisher (primeira run)
#   deploy/secrets/tls/agent-<nome>.{crt,key}  (apenas com --mtls)
set -eu
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

USE_MTLS=0
NAME=""
for arg in "$@"; do
    case "$arg" in
        --mtls) USE_MTLS=1 ;;
        -*)     echo "flag desconhecida: $arg" >&2; exit 2 ;;
        *)
            [ -z "$NAME" ] || { echo "Uso: $0 <nome-do-agente> [--mtls]"; exit 2; }
            NAME="$arg"
            ;;
    esac
done
[ -n "$NAME" ] || { echo "Uso: $0 <nome-do-agente> [--mtls]"; exit 2; }
USER="agent-$NAME"
CMD_VHOST="/commands"
MGMT_URL="http://localhost:15673"

# runtime: docker > podman rootless
if ! docker info >/dev/null 2>&1; then
    if [ -S "/run/user/$(id -u)/podman/podman.sock" ]; then
        export DOCKER_HOST="unix:///run/user/$(id -u)/podman/podman.sock"
    else
        echo "✗ docker/podman indisponível." >&2
        exit 1
    fi
fi

RMQ="docker exec rabbitmq rabbitmqctl"

# --- bootstrap ctl-admin na primeira execução ---------------------------------
if [ ! -f deploy/secrets/ctl/ctl-admin.env ]; then
    mkdir -p deploy/secrets/ctl
    CTL_TOKEN=$(openssl rand -hex 24)
    $RMQ add_vhost "$CMD_VHOST" 2>/dev/null || true
    if $RMQ list_users | awk '{print $1}' | grep -qx ctl-admin; then
        $RMQ change_password ctl-admin "$CTL_TOKEN"
    else
        $RMQ add_user ctl-admin "$CTL_TOKEN"
    fi
    $RMQ set_user_tags ctl-admin management
    $RMQ set_permissions -p "$CMD_VHOST" ctl-admin '^cmd\..+$' '^cmd\..+$' '^$'
    umask 077
    cat > deploy/secrets/ctl/ctl-admin.env <<EOF
RABBIT_HOST=localhost
RABBIT_PORT=5674
RABBIT_VHOST=$CMD_VHOST
RABBIT_USER=ctl-admin
RABBIT_TOKEN=$CTL_TOKEN
EOF
    chmod 600 deploy/secrets/ctl/ctl-admin.env
    echo "▶ ctl-admin criado → deploy/secrets/ctl/ctl-admin.env"
fi

CTL_TOKEN=$(grep '^RABBIT_TOKEN=' deploy/secrets/ctl/ctl-admin.env | cut -d= -f2-)

# --- provisão do agente (idempotente) -----------------------------------------
TOKEN=$(openssl rand -hex 24)
HMAC_KEY=$(openssl rand -hex 32)

$RMQ delete_user "$USER" 2>/dev/null || true
$RMQ add_user "$USER" "$TOKEN"

# vhost / (telemetria):
# - configure: redeclarar próprias filas (publisher.c roda queue_declare passive=0)
# - write:     amq.default (default exchange p/ publish por routing key) + as 2 filas
# - read:      nenhum
$RMQ set_permissions -p / "$USER" \
    '^(traffic_queue|traffic_metrics)$' \
    '^(amq\.default|traffic_queue|traffic_metrics)$' \
    '^$'
# vhost /commands: só pode ler da própria fila cmd.<nome>
$RMQ set_permissions -p "$CMD_VHOST" "$USER" '^$' '^$' "^cmd\\.$NAME\$"

# fila cmd.<nome> via management API (ctl-admin tem configure em cmd.*)
ENC_VHOST=$(printf '%s' "$CMD_VHOST" | sed 's|/|%2F|g')
curl -fsS -u "ctl-admin:$CTL_TOKEN" -X PUT \
    -H 'content-type: application/json' \
    -d '{"durable":true}' \
    "$MGMT_URL/api/queues/$ENC_VHOST/cmd.$NAME" > /dev/null

# --- arquivos de saída --------------------------------------------------------
mkdir -p deploy/agent deploy/secrets/ctl
umask 077
if [ "$USE_MTLS" -eq 1 ]; then
    "$ROOT_DIR/scripts/gen_agent_cert.sh" agent "$NAME"
fi

{
    cat <<EOF
# Instalar em /etc/nta/agent.env na máquina "$NAME" (chmod 600).
# Carregar antes de subir o agente C e o agent_ctl.py.
AGENT_NAME=$NAME
AGENT_SERVER_HOST=localhost
AGENT_SERVER_PORT=5674
AGENT_VHOST=/
AGENT_ID=$USER
AGENT_TOKEN=$TOKEN
AGENT_QUEUE=traffic_queue
AGENT_METRICS_QUEUE=traffic_metrics
AGENT_CMD_VHOST=$CMD_VHOST
AGENT_HMAC_KEY=$HMAC_KEY
EOF
    if [ "$USE_MTLS" -eq 1 ]; then
        cat <<EOF

# mTLS — cert cliente substitui SASL PLAIN (CN=$USER)
AGENT_SERVER_PORT=5671
AGENT_USE_TLS=1
AGENT_CA_CERT=/etc/nta-agent/ca.crt
AGENT_CLIENT_CERT=/etc/nta-agent/$USER.crt
AGENT_CLIENT_KEY=/etc/nta-agent/$USER.key
EOF
    fi
} > "deploy/agent/$NAME.env"
chmod 600 "deploy/agent/$NAME.env"

printf '%s\n' "$HMAC_KEY" > "deploy/secrets/ctl/$NAME.hmac"
chmod 600 "deploy/secrets/ctl/$NAME.hmac"

cat <<EOF

✓ Agente '$NAME' provisionado.
  user:                 $USER
  vhost /:              publish em traffic_queue, traffic_metrics
  vhost $CMD_VHOST:         read em cmd.$NAME
  env → agente:         deploy/agent/$NAME.env
  chave HMAC → ctl:     deploy/secrets/ctl/$NAME.hmac
EOF
