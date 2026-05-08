#!/usr/bin/env bash
# install.sh — bootstrap idempotente do Network Traffic Analyzer.
#
# Detecta o sistema operacional e instala todas as dependências necessárias
# (servidor + agente). Builda o agente C. Cria .env de exemplo se faltar.
#
# Uso:
#   ./scripts/install.sh                # tudo (server + agente)
#   ./scripts/install.sh --server-only  # só dependências do servidor
#   ./scripts/install.sh --agent-only   # só dependências/build do agente
#   ./scripts/install.sh --no-build     # instala deps mas não compila
#   ./scripts/install.sh --no-sudo      # falha em vez de chamar sudo
#
# Suporta: Debian/Ubuntu/Kali (apt), Fedora/RHEL/CentOS (dnf), Arch (pacman),
# FreeBSD (pkg), macOS (brew). Em qualquer outra distro, lista as deps e sai.

set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

# ----- args ------------------------------------------------------------------
SERVER=1
AGENT=1
DO_BUILD=1
USE_SUDO=1
for arg in "$@"; do
    case "$arg" in
        --server-only) AGENT=0 ;;
        --agent-only)  SERVER=0 ;;
        --no-build)    DO_BUILD=0 ;;
        --no-sudo)     USE_SUDO=0 ;;
        -h|--help)     sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "✗ flag desconhecida: $arg" >&2; exit 2 ;;
    esac
done

# ----- helpers ---------------------------------------------------------------
log()  { printf '\033[1;36m▶\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m⚠\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }
ok()   { printf '\033[1;32m✓\033[0m %s\n' "$*"; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if [ "$USE_SUDO" -eq 1 ] && command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    elif [ "$USE_SUDO" -eq 0 ]; then
        fail "executando sem sudo e não-root — passe sem --no-sudo ou rode como root."
    else
        warn "sudo não encontrado; tentando sem privilégio (provavelmente vai falhar)."
    fi
fi

run_pkg() {
    # $1 = manager, resto = pacotes
    local mgr="$1"; shift
    log "instalando: $*"
    case "$mgr" in
        apt)    $SUDO apt-get update -qq && $SUDO apt-get install -y "$@" ;;
        dnf)    $SUDO dnf install -y "$@" ;;
        pacman) $SUDO pacman -Sy --noconfirm --needed "$@" ;;
        pkg)    $SUDO pkg install -y "$@" ;;
        brew)   brew install "$@" ;;
        *) fail "manager desconhecido: $mgr" ;;
    esac
}

# ----- detect OS -------------------------------------------------------------
OS=""; MGR=""
if [ -r /etc/os-release ]; then
    . /etc/os-release
    case "${ID:-}${ID_LIKE:-}" in
        *debian*|*ubuntu*|*kali*) OS="debian"; MGR="apt" ;;
        *fedora*|*rhel*|*centos*) OS="fedora"; MGR="dnf" ;;
        *arch*)                   OS="arch";   MGR="pacman" ;;
    esac
fi
if [ -z "$OS" ]; then
    case "$(uname -s)" in
        FreeBSD) OS="freebsd"; MGR="pkg" ;;
        Darwin)  OS="macos";   MGR="brew" ;;
    esac
fi
[ -n "$OS" ] || fail "SO não suportado automaticamente. Instale manualmente: docker compose, python3, libpcap-dev, librabbitmq-dev, cmake, gcc, libcurl-dev, libmaxminddb-dev."
ok "SO detectado: $OS (manager: $MGR)"

# ----- pacotes por papel -----------------------------------------------------
# server: docker compose + python (tudo o resto roda em container)
# agent : compilador, libpcap, librabbitmq, libcurl, libmaxminddb (servidor C)
case "$MGR" in
    apt)
        SERVER_PKGS="docker.io docker-compose-plugin python3 python3-venv python3-pip curl"
        AGENT_PKGS="build-essential cmake git libpcap-dev librabbitmq-dev libcurl4-openssl-dev libmaxminddb-dev pkg-config"
        ;;
    dnf)
        SERVER_PKGS="moby-engine docker-compose python3 python3-pip curl"
        AGENT_PKGS="gcc make cmake git libpcap-devel librabbitmq-devel libcurl-devel libmaxminddb-devel pkgconfig"
        ;;
    pacman)
        SERVER_PKGS="docker docker-compose python python-pip curl"
        AGENT_PKGS="base-devel cmake git libpcap rabbitmq-c curl libmaxminddb pkgconf"
        ;;
    pkg)
        SERVER_PKGS="docker docker-compose python311 py311-pip curl"
        AGENT_PKGS="cmake git rabbitmq-c curl libmaxminddb pkgconf"
        ;;
    brew)
        SERVER_PKGS="docker docker-compose python@3.11 curl"
        AGENT_PKGS="cmake git libpcap rabbitmq-c curl libmaxminddb pkg-config"
        ;;
esac

# ----- install ---------------------------------------------------------------
if [ "$SERVER" -eq 1 ]; then
    log "[1/3] dependências do SERVIDOR"
    # shellcheck disable=SC2086
    run_pkg "$MGR" $SERVER_PKGS
fi

if [ "$AGENT" -eq 1 ]; then
    log "[2/3] dependências do AGENTE"
    # shellcheck disable=SC2086
    run_pkg "$MGR" $AGENT_PKGS
fi

# ----- compose detection (ergonomia) -----------------------------------------
if [ "$SERVER" -eq 1 ]; then
    if docker compose version >/dev/null 2>&1; then
        ok "docker compose plugin OK"
    elif command -v docker-compose >/dev/null 2>&1; then
        ok "docker-compose (legacy) OK"
    elif command -v podman-compose >/dev/null 2>&1; then
        ok "podman-compose OK"
    else
        warn "compose não encontrado após install — verifique o pacote do seu SO."
    fi

    # Habilita socket podman rootless se estiver disponível (Fedora Toolbox etc.)
    if command -v systemctl >/dev/null 2>&1 && command -v podman >/dev/null 2>&1; then
        if ! [ -S "/run/user/$(id -u)/podman/podman.sock" ]; then
            systemctl --user enable --now podman.socket 2>/dev/null || true
        fi
    fi
fi

# ----- .env padrão (Telegram opcional) ---------------------------------------
if [ "$SERVER" -eq 1 ] && [ ! -f .env ]; then
    log "criando .env (Telegram desabilitado por padrão)"
    cat > .env <<'EOF'
# Telegram alerting (opcional). Deixe vazio se não usar.
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
EOF
fi

# ----- build agente ----------------------------------------------------------
if [ "$AGENT" -eq 1 ] && [ "$DO_BUILD" -eq 1 ]; then
    log "[3/3] build do agente C"
    cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
    cmake --build build -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)"
    [ -x build/NetworkTrafficAnalyzer ] || fail "binário não foi gerado."
    ok "binário: build/NetworkTrafficAnalyzer"

    # setcap p/ capturar sem root (best-effort; falha silenciosa em FS sem suporte)
    if command -v setcap >/dev/null 2>&1; then
        $SUDO setcap cap_net_raw,cap_net_admin+ep build/NetworkTrafficAnalyzer 2>/dev/null \
            && ok "capabilities aplicadas (rodar sem sudo)" \
            || warn "setcap falhou — rode com sudo ou refaça depois."
    fi
fi

cat <<EOF

$(ok "instalação concluída.")

Próximos passos:
  ./scripts/up.sh                   # sobe stack (RabbitMQ + Influx + Grafana)
  sudo ./build/NetworkTrafficAnalyzer <iface>   # roda o agente

Atalho geral:
  ./scripts/quickstart.sh           # install + up + smoke-test
EOF
