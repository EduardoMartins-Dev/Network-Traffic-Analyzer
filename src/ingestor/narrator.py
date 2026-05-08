"""
narrator.py — gera narrativa em linguagem natural pra incidentes de score alto.

Backend único: Groq Cloud API (OpenAI-compatible).

Configuração via env vars (todas opcionais):
  NARRATOR_ENABLED      "1"|"0"            (default "1")
  NARRATOR_MIN_SCORE    int                (default 80)
  NARRATOR_TIMEOUT      seg                (default 8)

  GROQ_API_KEY          (lido também de deploy/secrets/groq.env)
  GROQ_MODEL            llama-3.3-70b-versatile
"""
import json
import logging
import os
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger("Narrator")

NARRATOR_ENABLED = os.getenv("NARRATOR_ENABLED", "1") == "1"
NARRATOR_MIN_SCORE = int(os.getenv("NARRATOR_MIN_SCORE", "80"))
NARRATOR_TIMEOUT = float(os.getenv("NARRATOR_TIMEOUT", "8"))

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# Carrega GROQ_API_KEY de deploy/secrets/groq.env se ainda não estiver no env
_GROQ_ENV = Path(__file__).resolve().parent.parent.parent / "deploy" / "secrets" / "groq.env"
if not os.getenv("GROQ_API_KEY") and _GROQ_ENV.is_file():
    for line in _GROQ_ENV.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k, v)
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

SYSTEM_PROMPT = (
    "Você é um analista de SOC sênior. Recebe um JSON de incidente do IDS "
    "e devolve uma narrativa concisa em PT-BR no formato EXATO abaixo "
    "(sem markdown, sem bullets):\n\n"
    "INCIDENT | Severidade: <Crítica|Alta|Média> (<score>/100)\n\n"
    "O QUE ACONTECEU:\n"
    "<máx 4 linhas técnicas>\n\n"
    "POR QUE É CRÍTICO:\n"
    "<máx 2 linhas, citando técnica MITRE>\n\n"
    "AÇÃO RECOMENDADA:\n"
    "<um comando concreto: iptables, nft, ip route ou similar>\n\n"
    "MITRE ATT&CK: <techniques separadas por vírgula>\n\n"
    "Não invente dados além do JSON. Seja direto."
)


def _user_prompt(event: dict, agent_id: str) -> str:
    payload = dict(event)
    payload.setdefault("agent_id", agent_id)
    return "Incidente:\n" + json.dumps(payload, ensure_ascii=False, indent=2)


def _call_groq(prompt: str) -> Optional[str]:
    if not GROQ_API_KEY:
        logger.warning("GROQ_API_KEY ausente — narrativa pulada")
        return None
    try:
        resp = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": GROQ_MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            },
            timeout=NARRATOR_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()
    except requests.exceptions.RequestException as e:
        logger.warning("Groq indisponível (%s): %s", type(e).__name__, e)
    except (KeyError, ValueError, IndexError) as e:
        logger.warning("Resposta Groq malformada: %s", e)
    return None


def should_narrate(event: dict) -> bool:
    if not NARRATOR_ENABLED:
        return False
    score = event.get("kc_score")
    return isinstance(score, (int, float)) and score >= NARRATOR_MIN_SCORE


def narrate(event: dict, agent_id: str = "unknown") -> Optional[str]:
    """Retorna texto da narrativa, ou None se desativado/falhar."""
    if not should_narrate(event):
        return None
    return _call_groq(_user_prompt(event, agent_id))


def backend_label() -> str:
    return f"groq:{GROQ_MODEL}"


# ==============================================================================
# Standalone consumer (v7.0): consome narrator_queue publicado pelo nta-server.
# Cada mensagem = 1 evento de incidente já filtrado por kc_score >= MIN_SCORE no
# servidor C. Header AMQP `x-agent-id` carrega a identidade do agente original.
# ==============================================================================
def _consumer_main() -> None:
    import logging as _logging
    import sys
    import time
    import pika
    from influxdb_client import InfluxDBClient, Point
    from influxdb_client.client.write_api import SYNCHRONOUS

    _logging.basicConfig(
        level=_logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    log = _logging.getLogger("Narrator")

    influx_url    = os.getenv("INFLUX_URL",    "http://localhost:8086")
    influx_token  = os.getenv("INFLUX_TOKEN",  "my-super-secret-auth-token")
    influx_org    = os.getenv("INFLUX_ORG",    "cybersecurity")
    influx_bucket = os.getenv("INFLUX_BUCKET", "network_traffic")

    rabbit_host  = os.getenv("RABBIT_HOST", "localhost")
    rabbit_port  = int(os.getenv("RABBIT_PORT", "5674"))
    queue        = os.getenv("NARRATOR_QUEUE", "narrator_queue")

    try:
        client = InfluxDBClient(url=influx_url, token=influx_token, org=influx_org)
        write_api = client.write_api(write_options=SYNCHRONOUS)
        log.info("Narrator consumer iniciado. backend=%s queue=%s",
                 backend_label(), queue)
    except Exception as e:
        log.critical("Falha ao conectar no InfluxDB: %s", e)
        sys.exit(1)

    def _agent_from_props(properties) -> str:
        if properties and properties.headers:
            v = properties.headers.get("x-agent-id")
            if isinstance(v, bytes):
                return v.decode("utf-8", errors="replace")
            if isinstance(v, str):
                return v
        if properties and properties.user_id:
            return properties.user_id
        return "unknown"

    def _on_message(ch, method, properties, body: bytes) -> None:
        try:
            event = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            log.error("JSON inválido em narrator_queue (%dB)", len(body))
            return
        agent_id = _agent_from_props(properties)
        text = narrate(event, agent_id)
        if not text:
            return
        try:
            point = (
                Point("incident_narrative")
                .tag("agent_id", agent_id)
                .tag("src_ip", event.get("src_ip", "0.0.0.0"))
                .tag("attack_type", event.get("attack_type", "UNKNOWN"))
                .tag("kill_chain_stage", event.get("kill_chain_stage", "UNKNOWN"))
                .tag("backend", backend_label())
                .field("narrative", text)
                .field("kc_score", float(event.get("kc_score", 0)))
            )
            write_api.write(bucket=influx_bucket, record=point)
            log.info("📝 [NARRATIVE] %s | %s | %d chars",
                     event.get("src_ip"), event.get("attack_type"), len(text))
        except Exception as e:
            log.error("Erro ao gravar narrativa: %s", e)

    retry_delay = 2
    max_delay = 30
    while True:
        connection = None
        try:
            connection = pika.BlockingConnection(
                pika.ConnectionParameters(
                    host=rabbit_host, port=rabbit_port,
                    heartbeat=30, blocked_connection_timeout=60,
                )
            )
            channel = connection.channel()
            channel.queue_declare(queue=queue, durable=True)
            channel.basic_consume(queue=queue,
                                  on_message_callback=_on_message,
                                  auto_ack=True)
            retry_delay = 2
            channel.start_consuming()
        except KeyboardInterrupt:
            log.info("Sinal de interrupção recebido. Encerrando.")
            break
        except Exception as e:
            log.warning("Conexão RabbitMQ perdida (%s: %s). Reconectando em %ds...",
                        type(e).__name__, e, retry_delay)
        finally:
            if connection is not None and connection.is_open:
                try:
                    connection.close()
                except Exception:
                    pass
        time.sleep(retry_delay)
        retry_delay = min(retry_delay * 2, max_delay)


if __name__ == "__main__":
    _consumer_main()
