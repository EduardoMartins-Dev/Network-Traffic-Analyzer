#!/usr/bin/env bash
# ioc_update.sh — baixa os feeds de IoC públicos (abuse.ch Feodo Tracker) e
# gera deploy/ioc/blocklist.json no schema do nta-server (ver deploy/ioc/README.md).
#
# Fluxo: baixa → valida cada IP → gera o JSON num diretório temporário →
# troca o arquivo por rename atômico → envia SIGHUP ao container nta-server.
# Qualquer falha antes da troca deixa o blocklist.json atual intacto.
# Os feeds baixados ficam só no diretório temporário e são apagados ao sair.
#
# Uso:  scripts/ioc_update.sh [--no-reload]
#   --no-reload  não envia SIGHUP ao container (o arquivo vale no próximo start)
#
# Variáveis (opcionais):
#   NTA_IOC_FEODO_URL  URL do feed Feodo (default: feodotracker.abuse.ch ipblocklist.json)
#   NTA_IOC_OUT        arquivo de saída (default: deploy/ioc/blocklist.json)
#   NTA_IOC_CONTAINER  container do nta-server (default: nta-server)
#
# Agendamento e limites de uso dos feeds: deploy/ioc/README.md.

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

FEODO_URL="${NTA_IOC_FEODO_URL:-https://feodotracker.abuse.ch/downloads/ipblocklist.json}"
OUT="${NTA_IOC_OUT:-$ROOT_DIR/deploy/ioc/blocklist.json}"
CONTAINER="${NTA_IOC_CONTAINER:-nta-server}"
RELOAD=1

for arg in "$@"; do
    case "$arg" in
        --no-reload) RELOAD=0 ;;
        -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "✗ argumento desconhecido: $arg" >&2; exit 2 ;;
    esac
done

die() { echo "✗ $*" >&2; exit 1; }

# A URL vai dentro de uma string JSON sem escape; recusa aspas e barras invertidas.
case "$FEODO_URL" in
    *\"*|*\\*) die "NTA_IOC_FEODO_URL contém aspas ou barra invertida" ;;
esac

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

valid_ipv4() {
    local IFS=. o
    [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    read -ra o <<< "$1"
    for x in "${o[@]}"; do (( 10#$x <= 255 )) || return 1; done
}

# -- 1. Download (falha aqui não toca no arquivo atual) ----------------------
echo "▶ Baixando feed Feodo (abuse.ch)"
curl -fsSL --max-time 120 --max-filesize 16777216 -o "$WORK/feodo.json" "$FEODO_URL" \
    || die "download do feed Feodo falhou — blocklist atual mantido"

# Feed truncado: JSON array precisa começar com '[' e terminar com ']'.
body="$(tr -d '[:space:]' < "$WORK/feodo.json")"
[ "${body:0:1}" = "[" ] && [ "${body: -1}" = "]" ] \
    || die "feed Feodo não é um JSON array completo — blocklist atual mantido"

# -- 2. Extração e validação dos IPs ----------------------------------------
grep -o '"ip_address"[[:space:]]*:[[:space:]]*"[^"]*"' "$WORK/feodo.json" \
    | sed 's/.*"\([^"]*\)"$/\1/' > "$WORK/feodo.raw" || true

: > "$WORK/feodo.ips"
while IFS= read -r ip; do
    valid_ipv4 "$ip" || die "IP inválido no feed Feodo ('$ip') — blocklist atual mantido"
    printf '%s\n' "$ip" >> "$WORK/feodo.ips"
done < "$WORK/feodo.raw"
sort -u -o "$WORK/feodo.ips" "$WORK/feodo.ips"

n_ips="$(wc -l < "$WORK/feodo.ips" | tr -d '[:space:]')"
[ "$n_ips" -ge 1 ] || die "feed Feodo sem IPs — blocklist atual mantido"
echo "  $n_ips IPs válidos (feodo-c2)"

# -- 3. Geração do JSON no schema do nta-server -----------------------------
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
    printf '{\n  "version": 1,\n  "lists": [\n    {\n'
    printf '      "name": "feodo-c2",\n      "url": "%s",\n      "updated": "%s",\n' "$FEODO_URL" "$NOW"
    printf '      "ips": [\n'
    sed -e 's/^/        "/' -e 's/$/"/' -e '$!s/$/,/' "$WORK/feodo.ips"
    printf '      ]\n    }\n  ]\n}\n'
} > "$WORK/blocklist.json"

written="$(grep -c '^        "[0-9]' "$WORK/blocklist.json" || true)"
[ "$written" -eq "$n_ips" ] || die "geração inconsistente ($written != $n_ips) — blocklist atual mantido"

# -- 4. Troca atômica --------------------------------------------------------
# Temporário no mesmo diretório do destino: o rename fica dentro do mesmo
# filesystem (e o bind mount do container é o diretório, não o arquivo).
OUT_DIR="$(dirname "$OUT")"
mkdir -p "$OUT_DIR"
TMP_OUT="$(mktemp "$OUT_DIR/.blocklist.XXXXXX")"
trap 'rm -rf "$WORK" "$TMP_OUT"' EXIT
cp "$WORK/blocklist.json" "$TMP_OUT"
chmod 644 "$TMP_OUT"   # mktemp cria 0600; o usuário nta do container precisa ler
mv -f "$TMP_OUT" "$OUT"
echo "✓ $OUT atualizado ($n_ips IPs)"

# -- 5. Reload -------------------------------------------------------------
if [ "$RELOAD" -eq 0 ]; then
    echo "  --no-reload: SIGHUP não enviado"
    exit 0
fi

if docker info >/dev/null 2>&1; then
    :
elif [ -S "/run/user/$(id -u)/podman/podman.sock" ]; then
    export DOCKER_HOST="unix:///run/user/$(id -u)/podman/podman.sock"
fi

if [ -n "$(docker ps -q --filter "name=^${CONTAINER}$" 2>/dev/null)" ]; then
    docker kill -s HUP "$CONTAINER" >/dev/null
    echo "▶ SIGHUP enviado a $CONTAINER (ver: docker logs $CONTAINER 2>&1 | grep '\[IOC\]')"
else
    echo "  container $CONTAINER não está rodando — sem reload (o arquivo vale no próximo start)"
fi
