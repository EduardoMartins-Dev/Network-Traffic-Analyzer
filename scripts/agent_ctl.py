#!/usr/bin/env python3
# agent_ctl.py — consumidor do canal de comando na máquina do agente.
# Verifica HMAC-SHA256, TTL e nonce; logga comandos aceitos.
# NÃO executa ações: ganchos (block_src, quarantine…) são stub por design.
# Uso típico (como serviço, root):
#   AGENT_ENV_FILE=/etc/nta/agent.env scripts/agent_ctl.py
import hashlib
import hmac
import json
import logging
import os
import sys
import time
from collections import OrderedDict
from pathlib import Path

import pika

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("agent_ctl")

NONCE_CACHE_SIZE = 4096
CLOCK_SKEW_TOLERANCE = 5  # seg — aceita mensagens até 5s do "futuro"


def load_env_file(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k, v)


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


class NonceCache:
    def __init__(self, limit: int = NONCE_CACHE_SIZE) -> None:
        self.limit = limit
        self.seen: "OrderedDict[str, bool]" = OrderedDict()

    def accept(self, nonce: str) -> bool:
        if nonce in self.seen:
            return False
        self.seen[nonce] = True
        if len(self.seen) > self.limit:
            self.seen.popitem(last=False)
        return True


def verify(body: bytes, key_hex: str, cache: NonceCache):
    try:
        msg = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        log.warning("drop: JSON inválido")
        return None
    if not isinstance(msg, dict):
        log.warning("drop: payload não é objeto")
        return None

    sig = msg.pop("sig", None)
    if not isinstance(sig, str):
        log.warning("drop: sem sig")
        return None

    expected = hmac.new(bytes.fromhex(key_hex), canonical(msg),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        log.warning("drop: HMAC inválido")
        return None

    issued = msg.get("issued_at")
    ttl = msg.get("ttl")
    if not isinstance(issued, int) or not isinstance(ttl, int) or ttl <= 0:
        log.warning("drop: issued_at/ttl inválido")
        return None
    now = int(time.time())
    if now - issued > ttl:
        log.warning("drop: expirado (idade=%ds ttl=%ds)", now - issued, ttl)
        return None
    if issued - now > CLOCK_SKEW_TOLERANCE:
        log.warning("drop: issued_at no futuro (delta=%ds)", issued - now)
        return None

    nonce = msg.get("nonce")
    if not isinstance(nonce, str) or not cache.accept(nonce):
        log.warning("drop: nonce ausente ou reusado")
        return None
    return msg


def main() -> int:
    load_env_file(Path(os.environ.get("AGENT_ENV_FILE", "/etc/nta/agent.env")))
    required = ("AGENT_NAME", "AGENT_ID", "AGENT_TOKEN", "AGENT_HMAC_KEY")
    missing = [v for v in required if not os.environ.get(v)]
    if missing:
        log.critical("variáveis ausentes: %s", ", ".join(missing))
        return 2

    name = os.environ["AGENT_NAME"]
    user = os.environ["AGENT_ID"]
    token = os.environ["AGENT_TOKEN"]
    key_hex = os.environ["AGENT_HMAC_KEY"]
    host = os.environ.get("AGENT_SERVER_HOST", "localhost")
    port = int(os.environ.get("AGENT_SERVER_PORT", "5674"))
    vhost = os.environ.get("AGENT_CMD_VHOST", "/commands")
    queue = f"cmd.{name}"

    conn = pika.BlockingConnection(pika.ConnectionParameters(
        host=host, port=port, virtual_host=vhost,
        credentials=pika.PlainCredentials(user, token),
    ))
    ch = conn.channel()
    cache = NonceCache()
    log.info("conectado em %s:%s vhost=%s fila=%s", host, port, vhost, queue)

    def on_msg(ch, method, properties, body):
        msg = verify(body, key_hex, cache)
        ch.basic_ack(delivery_tag=method.delivery_tag)
        if msg is None:
            return
        # Hook de execução desativado por design — conectar handlers aqui
        # (ex: nft / iptables / ip link) depois de período de baseline.
        log.info("accepted op=%s args=%s issued=%s ttl=%s",
                 msg.get("op"), msg.get("args"),
                 msg.get("issued_at"), msg.get("ttl"))

    ch.basic_consume(queue=queue, on_message_callback=on_msg, auto_ack=False)
    try:
        ch.start_consuming()
    except KeyboardInterrupt:
        log.info("encerrando")
    finally:
        if conn.is_open:
            conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
