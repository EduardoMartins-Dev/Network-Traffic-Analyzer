cmake_minimum_required(VERSION 3.10)
project(NetworkTrafficAnalyzer C)

set(CMAKE_C_STANDARD 11)

# Garante que os headers sejam encontrados em todas as subpastas
include_directories(${CMAKE_SOURCE_DIR}/include)

# --- PROGRAMA 1: O SNIFFER (SENSOR) ---
# Removemos o src/output/output.c pois ele causava conflito de linkagem
# Agora o publisher.c centraliza todo o envio para o RabbitMQ
add_executable(NetworkTrafficAnalyzer
        src/main.c
        src/capture/capture.c
        src/analysis/analyzer.c
        src/output/publisher.c
)

# Linkagem das bibliotecas essenciais para o SOC
target_link_libraries(NetworkTrafficAnalyzer PRIVATE pcap rabbitmq)

# --- PROGRAMA 2: O INGESTOR (PYTHON WORKER) ---
# Copia o script para a pasta de execução, facilitando o uso do venv
add_custom_target(DataIngestor ALL
        COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_SOURCE_DIR}/src/ingestor/data_ingestor.py
        ${CMAKE_BINARY_DIR}/data_ingestor.py
)