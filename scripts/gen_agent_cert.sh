#!/usr/bin/env bash
# gen_agent_cert.sh — gera CA self-signed (idempotente) + cert/key por agente.
# Uso:
#   scripts/gen_agent_cert.sh server                 # cert do broker (CN=rabbitmq)
#   scripts/gen_agent_cert.sh agent <nome>           # cert cliente (CN=agent-<nome>)
#
# Saídas em deploy/secrets/tls/:
#   ca.{crt,key}                  CA raiz (criada uma única vez)
#   server.{crt,key}              cert do broker
#   agent-<nome>.{crt,key}        cert cliente do agente
#
# RabbitMQ usa `ssl_cert_login_from = common_name` → o CN do cliente vira o user.

set -eu
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TLS_DIR="$ROOT_DIR/deploy/secrets/tls"
mkdir -p "$TLS_DIR"
# 755 — broker em container (uid mapeado) precisa atravessar p/ ler ca.crt/server.crt.
# Keys protegidos individualmente abaixo (600 cliente, 644 broker).
chmod 755 "$TLS_DIR"
umask 077

DAYS_CA=3650
DAYS_LEAF=825

ensure_ca() {
    if [ -f "$TLS_DIR/ca.crt" ] && [ -f "$TLS_DIR/ca.key" ]; then
        return
    fi
    echo "▶ Gerando CA self-signed"
    openssl genrsa -out "$TLS_DIR/ca.key" 4096 2>/dev/null
    openssl req -x509 -new -nodes -key "$TLS_DIR/ca.key" \
        -sha256 -days "$DAYS_CA" \
        -subj "/CN=nta-ca" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "$TLS_DIR/ca.crt" 2>/dev/null
    chmod 600 "$TLS_DIR/ca.key"
    chmod 644 "$TLS_DIR/ca.crt"
}

issue_cert() {
    local CN="$1"
    local PREFIX="$2"          # ex: server, agent-foo
    local EXT_FILE
    EXT_FILE=$(mktemp)
    # SAN: necessário para validação de hostname pelo cliente quando CN=server
    cat > "$EXT_FILE" <<EOF
subjectAltName = DNS:${CN},DNS:localhost,DNS:rabbitmq
extendedKeyUsage = clientAuth,serverAuth
EOF

    openssl genrsa -out "$TLS_DIR/$PREFIX.key" 4096 2>/dev/null
    openssl req -new -key "$TLS_DIR/$PREFIX.key" \
        -subj "/CN=$CN" \
        -out "$TLS_DIR/$PREFIX.csr" 2>/dev/null
    openssl x509 -req -in "$TLS_DIR/$PREFIX.csr" \
        -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
        -out "$TLS_DIR/$PREFIX.crt" -days "$DAYS_LEAF" -sha256 \
        -extfile "$EXT_FILE" 2>/dev/null
    rm -f "$EXT_FILE" "$TLS_DIR/$PREFIX.csr"
    chmod 600 "$TLS_DIR/$PREFIX.key"
    chmod 644 "$TLS_DIR/$PREFIX.crt"
    echo "▶ Cert emitido: $PREFIX (CN=$CN)"
}

[ $# -ge 1 ] || { echo "Uso: $0 server | agent <nome>"; exit 2; }
ensure_ca

case "$1" in
    server)
        issue_cert "rabbitmq" "server"
        # Broker roda dentro do container com uid remapeado — server.key fica 644
        # p/ leitura via mount. Aceitável: chave self-signed, escopo dev/lab.
        chmod 644 "$TLS_DIR/server.key"
        ;;
    agent)
        [ $# -eq 2 ] || { echo "Uso: $0 agent <nome>"; exit 2; }
        NAME="$2"
        # CN bate com o user RabbitMQ criado por provision_agent.sh
        issue_cert "agent-$NAME" "agent-$NAME"
        ;;
    *)
        echo "Modo desconhecido: $1" >&2
        exit 2
        ;;
esac
