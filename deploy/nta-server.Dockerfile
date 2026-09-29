# nta-server em container — consumidor RabbitMQ → InfluxDB (+ GeoIP, IoC,
# AbuseIPDB, WHOIS, narrator Groq). Build a partir da raiz do repo:
#   docker compose build nta-server
# Dados/segredos NÃO entram na imagem: data/, deploy/ioc e deploy/secrets
# são montados read-only em /app pelo docker-compose.yml.

FROM debian:12-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake pkg-config \
        librabbitmq-dev libcurl4-openssl-dev libmaxminddb-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt ./
COPY include ./include
COPY src ./src
COPY third_party ./third_party
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DNTA_BUILD_TESTS=OFF \
    && cmake --build build --target nta-server -j"$(nproc)"

FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        librabbitmq4 libcurl4 libmaxminddb0 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /app --shell /usr/sbin/nologin nta
WORKDIR /app
COPY --from=build /src/build/nta-server /usr/local/bin/nta-server
USER nta
# Paths default do nta-server são relativos (./data, ./deploy/...) → /app.
ENV NTA_HEALTH_BIND=0.0.0.0 \
    NTA_HEALTH_PORT=9091
EXPOSE 9091
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=3 \
    CMD curl -fs http://127.0.0.1:9091/health >/dev/null || exit 1
ENTRYPOINT ["nta-server"]
