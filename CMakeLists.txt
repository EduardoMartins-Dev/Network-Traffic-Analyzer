cmake_minimum_required(VERSION 3.10)
project(NetworkTrafficAnalyzer C)

set(CMAKE_C_STANDARD 11)
include_directories(${CMAKE_SOURCE_DIR}/include)

# --- PROGRAMA 1: O SNIFFER ---
add_executable(NetworkTrafficAnalyzer
        src/main.c
        src/capture/capture.c
        src/analysis/analyzer.c
        src/output/output.c
        src/output/cJSON.c
        src/output/publisher.c
)
target_link_libraries(NetworkTrafficAnalyzer PRIVATE pcap rabbitmq)

# --- PROGRAMA 2: O INGESTOR (ESTE ESTÁ FALTANDO!) ---
add_executable(DataIngestor
        src/ingestor/ingestor.c
        src/output/cJSON.c
)
target_link_libraries(DataIngestor PRIVATE curl rabbitmq)