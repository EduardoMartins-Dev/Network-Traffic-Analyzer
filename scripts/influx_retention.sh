#!/usr/bin/env bash
# influx_retention.sh — provisiona retention (hot 7d) + bucket warm (90d) + task de downsampling.
# Idempotente: re-rodar não destrói dados nem duplica recursos.
#
# Vars opcionais:
#   INFLUX_CONTAINER  (default: influxdb)
#   INFLUX_ORG        (default: cybersecurity)
#   INFLUX_TOKEN      (default: my-super-secret-auth-token)
#   INFLUX_HOT_BUCKET (default: network_traffic)
#   INFLUX_WARM_BUCKET(default: network_traffic_warm)
#   INFLUX_HOT_SECONDS  (default: 604800   = 7d)
#   INFLUX_WARM_SECONDS (default: 7776000  = 90d)

set -eu

CONTAINER="${INFLUX_CONTAINER:-influxdb}"
ORG="${INFLUX_ORG:-cybersecurity}"
TOKEN="${INFLUX_TOKEN:-my-super-secret-auth-token}"
HOT_BUCKET="${INFLUX_HOT_BUCKET:-network_traffic}"
WARM_BUCKET="${INFLUX_WARM_BUCKET:-network_traffic_warm}"
HOT_SECONDS="${INFLUX_HOT_SECONDS:-604800}"
WARM_SECONDS="${INFLUX_WARM_SECONDS:-7776000}"

influx_cli() {
    docker exec -e INFLUX_TOKEN="$TOKEN" -e INFLUX_ORG="$ORG" "$CONTAINER" influx "$@"
}

bucket_id() {
    influx_cli bucket list --hide-headers --name "$1" 2>/dev/null | awk 'NR==1 {print $1}'
}

# Espera o container responder ao CLI (setup já concluído).
for _ in $(seq 1 30); do
    if influx_cli bucket list >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Aplica retention no bucket hot (idempotente — update sobre valor igual é no-op).
HOT_ID=$(bucket_id "$HOT_BUCKET")
if [ -z "$HOT_ID" ]; then
    echo "✗ Bucket $HOT_BUCKET não encontrado." >&2
    exit 1
fi
echo "▶ Retention hot: $HOT_BUCKET → ${HOT_SECONDS}s"
influx_cli bucket update --id "$HOT_ID" --retention "${HOT_SECONDS}s" >/dev/null

# Cria bucket warm se não existir.
WARM_ID=$(bucket_id "$WARM_BUCKET")
if [ -z "$WARM_ID" ]; then
    echo "▶ Criando bucket warm: $WARM_BUCKET (${WARM_SECONDS}s)"
    influx_cli bucket create --name "$WARM_BUCKET" --retention "${WARM_SECONDS}s" >/dev/null
else
    echo "▶ Bucket warm já existe — ajustando retention"
    influx_cli bucket update --id "$WARM_ID" --retention "${WARM_SECONDS}s" >/dev/null
fi

# Task de downsampling: agrega traffic por 1m → traffic_1m no bucket warm.
TASK_NAME="downsample_traffic_1m"
FLUX_BODY=$(cat <<FLUX
option task = {name: "${TASK_NAME}", every: 1m, offset: 10s}

src = from(bucket: "${HOT_BUCKET}")
  |> range(start: -task.every)
  |> filter(fn: (r) => r._measurement == "traffic")

src
  |> filter(fn: (r) => r._field == "bytes")
  |> aggregateWindow(every: 1m, fn: sum, createEmpty: false)
  |> set(key: "_measurement", value: "traffic_1m")
  |> to(bucket: "${WARM_BUCKET}", org: "${ORG}")

src
  |> filter(fn: (r) => r._field == "kc_score")
  |> aggregateWindow(every: 1m, fn: max, createEmpty: false)
  |> set(key: "_measurement", value: "traffic_1m")
  |> to(bucket: "${WARM_BUCKET}", org: "${ORG}")
FLUX
)

if influx_cli task list 2>/dev/null | grep -q "$TASK_NAME"; then
    echo "▶ Task $TASK_NAME já existe — pulando criação"
else
    echo "▶ Criando task: $TASK_NAME"
    FLUX_PATH="/tmp/${TASK_NAME}.flux"
    printf '%s' "$FLUX_BODY" | docker exec -i "$CONTAINER" sh -c "cat > $FLUX_PATH"
    influx_cli task create --org "$ORG" -f "$FLUX_PATH" >/dev/null
    docker exec "$CONTAINER" rm -f "$FLUX_PATH"
fi

echo "✓ Retention/downsampling provisionados."
