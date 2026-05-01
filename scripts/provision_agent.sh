#!/usr/bin/env bash
# provision_agent.sh — cria credencial RabbitMQ + chave HMAC de um agente.
# Uso: scripts/provision_agent.sh <nome-do-agente>
#
# Cria:
#   user  agent-<nome> no vhost /          → write em traffic_queue, traffic_metrics
#   user  agent-<nome> no vhost /commands  → read em cmd.<nome>
#   fila  cmd.<nome> no vhost /commands    (durable)
#   HMAC  32 bytes hex (chave única do agente)
# Arquivos gerados:
#   deploy/agent/<nome>.env         → copiar pra /etc/nta/agent.env na máquina
#   deploy/secrets/ctl/<nome>.hmac  → chave HMAC, fica no control plane
#   deploy/secrets/ctl/ctl-admin.env → credencial do publisher (primeira run)
set -eu
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

[ $# -eq 1 ] || { echo "Uso: $0 <nome-do-agente>"; exit 2; }
NAME="$1"
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

# vhost / (telemetria): pode publicar só nas 2 filas, nada de configure/read
$RMQ set_permissions -p / "$USER" '^$' '^(traffic_queue|traffic_metrics)$' '^$'
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
cat > "deploy/agent/$NAME.env" <<EOF
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
