import os
import sys
import json
import time
import pika
import logging
import requests
from typing import Tuple, Optional
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

import narrator

# ==============================================================================
# CONFIGURAÇÃO DE LOGS (Padrão Corporativo)
# ==============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("SOC_Ingestor")

# ==============================================================================
# CONFIGURAÇÕES DO SISTEMA (Via Variáveis de Ambiente ou Fallback local)
# ==============================================================================
INFLUX_URL = os.getenv("INFLUX_URL", "http://localhost:8086")
INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "my-super-secret-auth-token")
INFLUX_ORG = os.getenv("INFLUX_ORG", "cybersecurity")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "network_traffic")

RABBIT_HOST = os.getenv("RABBIT_HOST", "localhost")
RABBIT_PORT = int(os.getenv("RABBIT_PORT", 5674))
QUEUE_NAME = os.getenv("QUEUE_NAME", "traffic_queue")
METRICS_QUEUE = os.getenv("METRICS_QUEUE", "traffic_metrics")

class SOCIngestor:
    """
    Consome duas filas do RabbitMQ:
      - QUEUE_NAME     → telemetria de pacotes (batches v5.0 ou objetos soltos)
      - METRICS_QUEUE  → métricas do pipeline (buffers, overflows, throughput)
    Enriquece eventos com GeoIP e grava em InfluxDB.
    """

    def __init__(self):
        self.geo_cache = {}
        self._setup_influxdb()

    def _setup_influxdb(self) -> None:
        try:
            self.client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
            self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
            logger.info("Conectado ao InfluxDB com sucesso.")
        except Exception as e:
            logger.critical(f"Falha catastrófica ao conectar no InfluxDB: {e}")
            sys.exit(1)

    def _get_location(self, ip: str) -> Tuple[Optional[float], Optional[float]]:
        if not ip or ip.startswith(("127.", "192.168.", "10.", "172.")):
            return None, None
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
            if response.get("status") == "success":
                lat, lon = response.get("lat"), response.get("lon")
                self.geo_cache[ip] = (lat, lon)
                return lat, lon
        except requests.exceptions.RequestException as e:
            logger.warning(f"Erro de rede ao consultar GeoIP para {ip}: {e}")
        return None, None

    # --------------------------------------------------------------------------
    # Processa UM evento (usado pelo batch e pelo modo legado)
    # --------------------------------------------------------------------------
    def _ingest_one(self, data: dict, agent_id: str = "unknown") -> None:
        src_ip = data.get('src_ip', '0.0.0.0')
        proto = data.get('proto', 'UNKNOWN')
        is_scan = data.get('is_scan', 0)
        bytes_count = data.get('bytes', 0)
        port = data.get('port', 0)

        point = Point("traffic") \
            .tag("agent_id", agent_id) \
            .tag("src_ip", src_ip) \
            .tag("protocol", proto) \
            .field("port", int(port)) \
            .field("bytes", float(bytes_count)) \
            .field("is_scan", float(is_scan))

        # Campos adicionais da v4.0 (kill chain + MITRE) são tags para filtro
        attack = data.get('attack_type')
        stage = data.get('kill_chain_stage')
        mitre = data.get('mitre')
        if attack: point = point.tag("attack_type", attack)
        if stage:  point = point.tag("kill_chain_stage", stage)
        if mitre:  point = point.tag("mitre", mitre)
        kc_score = data.get('kc_score')
        if kc_score is not None:
            point = point.field("kc_score", float(kc_score))

        lat, lon = self._get_location(src_ip)
        if lat is not None and lon is not None:
            point.field("lat", float(lat)).field("lon", float(lon))

        self.write_api.write(bucket=INFLUX_BUCKET, record=point)

        status_icon = "🚨 [ATTACK]" if is_scan == 1 else "✅ [NORMAL]"
        logger.info(f"{status_icon} {proto} | IP: {src_ip} | Loc: {lat},{lon}")

        if narrator.should_narrate(data):
            self._narrate(data, agent_id)

    # --------------------------------------------------------------------------
    # Narrativa LLM pra incidentes de score alto (kc_score >= NARRATOR_MIN_SCORE)
    # Chamada síncrona — Groq deve responder em < NARRATOR_TIMEOUT
    # --------------------------------------------------------------------------
    def _narrate(self, data: dict, agent_id: str) -> None:
        text = narrator.narrate(data, agent_id)
        if not text:
            return
        np = (
            Point("incident_narrative")
            .tag("agent_id", agent_id)
            .tag("src_ip", data.get("src_ip", "0.0.0.0"))
            .tag("attack_type", data.get("attack_type", "UNKNOWN"))
            .tag("kill_chain_stage", data.get("kill_chain_stage", "UNKNOWN"))
            .tag("backend", narrator.backend_label())
            .field("narrative", text)
            .field("kc_score", float(data.get("kc_score", 0)))
        )
        self.write_api.write(bucket=INFLUX_BUCKET, record=np)
        logger.info("📝 [NARRATIVE] %s | %s | %d chars",
                    data.get("src_ip"), data.get("attack_type"), len(text))

    # --------------------------------------------------------------------------
    # Callback da fila de TELEMETRIA: aceita array (v5.0) ou objeto (legado)
    # --------------------------------------------------------------------------
    def _on_traffic(self, ch, method, properties, body: bytes) -> None:
        try:
            agent_id = (properties.user_id if properties and properties.user_id else "unknown")
            payload = json.loads(body.decode('utf-8'))
            events = payload if isinstance(payload, list) else [payload]
            for evt in events:
                try:
                    self._ingest_one(evt, agent_id)
                except Exception as e:
                    logger.error(f"Erro ao ingerir evento: {e}")
        except json.JSONDecodeError:
            logger.error("JSON corrompido na fila de telemetria.")

    # --------------------------------------------------------------------------
    # Callback da fila de MÉTRICAS: grava estado do pipeline em série separada
    # --------------------------------------------------------------------------
    def _on_metrics(self, ch, method, properties, body: bytes) -> None:
        try:
            agent_id = (properties.user_id if properties and properties.user_id else "unknown")
            m = json.loads(body.decode('utf-8'))
            point = Point("pipeline_metrics").tag("agent_id", agent_id)
            for k, v in m.items():
                if isinstance(v, (int, float)):
                    point = point.field(k, float(v))
            self.write_api.write(bucket=INFLUX_BUCKET, record=point)
            logger.info(
                f"📊 [METRICS] rb_pkt={m.get('rb_pkt_depth')} "
                f"rb_evt={m.get('rb_evt_depth')} "
                f"eps={m.get('events_per_sec')} "
                f"overflow(pkt={m.get('rb_pkt_overflow')},evt={m.get('rb_evt_overflow')})"
            )
        except json.JSONDecodeError:
            logger.error("JSON corrompido na fila de métricas.")
        except Exception as e:
            logger.error(f"Erro ao ingerir métricas: {e}")

    def start(self) -> None:
        retry_delay = 2
        max_delay = 30
        while True:
            connection = None
            try:
                connection = pika.BlockingConnection(
                    pika.ConnectionParameters(
                        host=RABBIT_HOST, port=RABBIT_PORT,
                        heartbeat=30, blocked_connection_timeout=60,
                    )
                )
                channel = connection.channel()
                channel.queue_declare(queue=QUEUE_NAME, durable=True)
                channel.queue_declare(queue=METRICS_QUEUE, durable=True)

                logger.info(f"SOC Ingestor conectado. Filas: '{QUEUE_NAME}', '{METRICS_QUEUE}'")

                channel.basic_consume(queue=QUEUE_NAME,
                                      on_message_callback=self._on_traffic,
                                      auto_ack=True)
                channel.basic_consume(queue=METRICS_QUEUE,
                                      on_message_callback=self._on_metrics,
                                      auto_ack=True)
                retry_delay = 2
                channel.start_consuming()
            except KeyboardInterrupt:
                logger.info("Sinal de interrupção recebido. Encerrando.")
                break
            except Exception as e:
                logger.warning("Conexão RabbitMQ perdida (%s: %s). Reconectando em %ds...",
                               type(e).__name__, e, retry_delay)
            finally:
                if connection is not None and connection.is_open:
                    try:
                        connection.close()
                    except Exception:
                        pass
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, max_delay)

# ==============================================================================
# ENTRY POINT
# ==============================================================================
if __name__ == "__main__":
    ingestor = SOCIngestor()
    ingestor.start()
