#!/usr/bin/env bash
# up.sh — sobe infra (rabbitmq/influxdb/grafana/ollama) + ingestor.
# Detecta podman rootless e aponta DOCKER_HOST pro socket do usuário.
# Flags:
#   --no-ingest  → só infra
#   --pull-llm   → baixa OLLAMA_MODEL se ainda não existir no volume
#   --foreground → roda o ingestor em foreground (Ctrl+C para parar). Default: background.

set -eu
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

[ -f .env ] && set -a && . ./.env && set +a

START_INGEST=1
PULL_LLM=0
FOREGROUND=0
for arg in "$@"; do
    case "$arg" in
        --no-ingest) START_INGEST=0 ;;
        --pull-llm)  PULL_LLM=1 ;;
        --foreground|--fg) FOREGROUND=1 ;;
        -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    esac
done

OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.2}"
NARRATOR_BACKEND="${NARRATOR_BACKEND:-ollama}"

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

# Ollama: ready + modelo presente (só quando narrator vai usar Ollama)
if [ "$NARRATOR_BACKEND" = "ollama" ]; then
    echo "▶ Aguardando Ollama API..."
    OLLAMA_READY=0
    for _ in $(seq 1 30); do
        if curl -fs --max-time 2 http://localhost:11434/api/tags >/dev/null 2>&1; then
            OLLAMA_READY=1
            break
        fi
        sleep 1
    done
    if [ "$OLLAMA_READY" -eq 0 ]; then
        echo "⚠ Ollama não respondeu em 30s — narrator vai falhar até subir."
    elif curl -fs http://localhost:11434/api/tags | grep -q "\"name\":\"${OLLAMA_MODEL}\(:latest\)\?\""; then
        echo "▶ Ollama: modelo $OLLAMA_MODEL pronto."
    elif [ "$PULL_LLM" -eq 1 ]; then
        echo "▶ Baixando modelo $OLLAMA_MODEL (~2 GB, pode demorar)..."
        docker exec ollama ollama pull "$OLLAMA_MODEL"
    else
        echo "⚠ Ollama OK mas modelo '$OLLAMA_MODEL' não baixado."
        echo "  Rode: docker exec -it ollama ollama pull $OLLAMA_MODEL"
        echo "  Ou:   $0 --pull-llm"
    fi
else
    echo "▶ NARRATOR_BACKEND=$NARRATOR_BACKEND — pulando checagem do Ollama."
fi

if [ "$START_INGEST" -eq 0 ]; then
    echo "✓ Infra no ar (ingestor não iniciado)."
    exit 0
fi

# Venv + deps
[ -d .venv ] || python3 -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate
pip install -q -r requirements.txt

if [ ! -f build/data_ingestor.py ]; then
    echo "✗ build/data_ingestor.py não encontrado. Rode 'cmake -B build -S .' antes." >&2
    exit 1
fi

if [ "$FOREGROUND" -eq 1 ]; then
    cat <<EOF
✓ Infra de pé. Iniciando data_ingestor.py em foreground (Ctrl+C para parar)
  Grafana   http://localhost:3000   admin/admin
  RabbitMQ  http://localhost:15673  guest/guest
  InfluxDB  http://localhost:8086
  Ollama    http://localhost:11434  (model=$OLLAMA_MODEL  backend=$NARRATOR_BACKEND)
EOF
    cd build && exec python3 data_ingestor.py
fi

# Background (default)
if pgrep -f "python3 data_ingestor.py" >/dev/null 2>&1; then
    echo "▶ data_ingestor.py já está rodando."
else
    ( cd build && setsid nohup python3 data_ingestor.py </dev/null >/tmp/nta-ingestor.log 2>&1 & ) 2>/dev/null
    sleep 1
    pgrep -f "python3 data_ingestor.py" >/dev/null && \
        echo "▶ data_ingestor.py iniciado (log: /tmp/nta-ingestor.log)" || \
        { echo "✗ Falha ao subir ingestor. Veja /tmp/nta-ingestor.log"; exit 1; }
fi

cat <<EOF

✓ Tudo no ar.
  Grafana   http://localhost:3000   admin/admin
  RabbitMQ  http://localhost:15673  guest/guest
  InfluxDB  http://localhost:8086
  Ollama    http://localhost:11434  (model=$OLLAMA_MODEL  backend=$NARRATOR_BACKEND)
  Agente    (rodar manualmente, precisa sudo fora de toolbox):
            sudo ./build/NetworkTrafficAnalyzer <interface>
EOF
