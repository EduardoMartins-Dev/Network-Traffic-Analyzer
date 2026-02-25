import os
import sys
import json
import pika
import logging
import requests
from typing import Tuple, Optional
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

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

class SOCIngestor:
    """
    Classe responsável por orquestrar a ingestão, enriquecimento (GeoIP)
    e persistência de telemetria de segurança (IDS).
    """

    def __init__(self):
        self.geo_cache = {}
        self._setup_influxdb()

    def _setup_influxdb(self) -> None:
        """Inicializa a conexão com o banco de séries temporais."""
        try:
            self.client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
            # Utiliza o modo Síncrono para garantir que a escrita não atrase em relação à fila
            self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
            logger.info("Conectado ao InfluxDB com sucesso.")
        except Exception as e:
            logger.critical(f"Falha catastrófica ao conectar no InfluxDB: {e}")
            sys.exit(1)

    def _get_location(self, ip: str) -> Tuple[Optional[float], Optional[float]]:
        """
        Consulta a localização geográfica de um IP externo usando a API ip-api.com.
        Possui cache interno e ignora ranges de IPs privados (RFC 1918) e loopback.
        """
        # Filtro de IPs internos para poupar requisições e evitar timeouts desnecessários
        if not ip or ip.startswith(("127.", "192.168.", "10.", "172.")):
            return None, None

        # Padrão de Memoization (Cache) para evitar rate-limits da API
        if ip in self.geo_cache:
            return self.geo_cache[ip]

        try:
            # Timeout explícito de 5s para evitar bloqueio da thread do RabbitMQ
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
            if response.get("status") == "success":
                lat, lon = response.get("lat"), response.get("lon")
                self.geo_cache[ip] = (lat, lon)
                return lat, lon
        except requests.exceptions.RequestException as e:
            logger.warning(f"Erro de rede ao consultar GeoIP para {ip}: {e}")

        return None, None

    def _process_event(self, ch, method, properties, body: bytes) -> None:
        """
        Callback disparado pelo RabbitMQ a cada nova mensagem na fila.
        Analisa o JSON, enriquece e persiste no InfluxDB.
        """
        try:
            # Desserialização do payload em C
            data = json.loads(body.decode('utf-8'))
            src_ip = data.get('src_ip', '0.0.0.0')
            proto = data.get('proto', 'UNKNOWN')
            is_scan = data.get('is_scan', 0)
            bytes_count = data.get('bytes', 0)
            port = data.get('port', 0)

            # Construção do "Point" (linha) para o InfluxDB
            # Nota técnica: Casting para float em 'bytes' e 'is_scan' previne o erro HTTP 422
            # de conflito de tipo caso o primeiro dado do bucket tenha sido ingerido como float.
            point = Point("traffic") \
                .tag("src_ip", src_ip) \
                .tag("protocol", proto) \
                .field("port", int(port)) \
                .field("bytes", float(bytes_count)) \
                .field("is_scan", float(is_scan))

            # Enriquecimento com coordenadas geográficas
            lat, lon = self._get_location(src_ip)
            if lat is not None and lon is not None:
                point.field("lat", float(lat)).field("lon", float(lon))

            # Persistência no Time-Series Database
            self.write_api.write(bucket=INFLUX_BUCKET, record=point)

            # Feedback de console (Logger)
            status_icon = "🚨 [ATTACK]" if is_scan == 1 else "✅ [NORMAL]"
            logger.info(f"{status_icon} {proto} | IP: {src_ip} | Loc: {lat},{lon}")

        except json.JSONDecodeError:
            logger.error("Falha ao decodificar JSON corrompido da fila.")
        except Exception as e:
            logger.error(f"Erro ao processar evento (Verifique conflito de tipo no Bucket): {e}")

    def start(self) -> None:
        """Estabelece a conexão AMQP e inicia o loop principal do consumidor."""
        try:
            connection = pika.BlockingConnection(
                pika.ConnectionParameters(host=RABBIT_HOST, port=RABBIT_PORT)
            )
            channel = connection.channel()
            channel.queue_declare(queue=QUEUE_NAME)

            logger.info("SOC Ingestor (Python) inicializado com sucesso!")
            logger.info(f"Monitorando a fila mensageria: '{QUEUE_NAME}'")

            # Inicia o consumo da fila chamando _process_event para cada pacote
            channel.basic_consume(
                queue=QUEUE_NAME,
                on_message_callback=self._process_event,
                auto_ack=True
            )
            channel.start_consuming()

        except pika.exceptions.AMQPConnectionError:
            logger.critical("Falha de conexão com RabbitMQ. O serviço está online?")
        except KeyboardInterrupt:
            logger.info("Sinal de interrupção recebido. Desligando ingestor com segurança.")
        finally:
            if 'connection' in locals() and connection.is_open:
                connection.close()

# ==============================================================================
# ENTRY POINT
# ==============================================================================
if __name__ == "__main__":
    ingestor = SOCIngestor()
    ingestor.start()