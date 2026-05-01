#!/usr/bin/env python3
# ctl.py — control plane: envia comando assinado HMAC-SHA256 pra um agente.
# Uso:
#   scripts/ctl.py send --to maquina2 --op block_src --ip 1.2.3.4 [--ttl 60]
#   scripts/ctl.py send --to maquina2 --op quarantine [--ttl 300]
#
# Lê:
#   deploy/secrets/ctl/ctl-admin.env   → credencial AMQP do publisher
#   deploy/secrets/ctl/<to>.hmac       → chave HMAC do agente destino
import argparse
import hashlib
import hmac
import json
import sys
import time
import uuid
from pathlib import Path

import pika

ROOT = Path(__file__).resolve().parent.parent
SECRETS = ROOT / "deploy" / "secrets" / "ctl"
CTL_ENV = SECRETS / "ctl-admin.env"


def load_env(path: Path) -> dict:
    out = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k] = v
    return out


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign(payload: dict, key_hex: str) -> str:
    return hmac.new(bytes.fromhex(key_hex), canonical(payload),
                    hashlib.sha256).hexdigest()


def cmd_send(args) -> int:
    hmac_file = SECRETS / f"{args.to}.hmac"
    if not hmac_file.is_file():
        print(f"✗ chave HMAC ausente: {hmac_file}", file=sys.stderr)
        return 1
    if not CTL_ENV.is_file():
        print(f"✗ {CTL_ENV} ausente. Rode scripts/provision_agent.sh primeiro.",
              file=sys.stderr)
        return 1

    key_hex = hmac_file.read_text().strip()
    ctl = load_env(CTL_ENV)

    op_args = {}
    if args.ip is not None:
        op_args["ip"] = args.ip

    payload = {
        "op": args.op,
        "args": op_args,
        "issued_at": int(time.time()),
        "nonce": str(uuid.uuid4()),
        "ttl": args.ttl,
    }
    payload["sig"] = sign({k: v for k, v in payload.items() if k != "sig"}, key_hex)

    conn = pika.BlockingConnection(pika.ConnectionParameters(
        host=ctl["RABBIT_HOST"],
        port=int(ctl["RABBIT_PORT"]),
        virtual_host=ctl["RABBIT_VHOST"],
        credentials=pika.PlainCredentials(ctl["RABBIT_USER"], ctl["RABBIT_TOKEN"]),
    ))
    ch = conn.channel()
    ch.basic_publish(
        exchange="",
        routing_key=f"cmd.{args.to}",
        body=json.dumps(payload).encode(),
        properties=pika.BasicProperties(
            content_type="application/json",
            delivery_mode=2,
            user_id=ctl["RABBIT_USER"],
        ),
    )
    conn.close()
    print(f"✓ enviado op={args.op} to={args.to} nonce={payload['nonce']} ttl={args.ttl}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="NTA control plane CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("send", help="envia comando assinado a um agente")
    s.add_argument("--to", required=True, help="nome do agente (ex: maquina2)")
    s.add_argument("--op", required=True,
                   choices=["block_src", "unblock_src", "quarantine", "unquarantine"])
    s.add_argument("--ip", default=None, help="IP alvo (pra block_src/unblock_src)")
    s.add_argument("--ttl", type=int, default=60,
                   help="segundos até expirar (default 60)")
    args = ap.parse_args()
    if args.cmd == "send":
        return cmd_send(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
