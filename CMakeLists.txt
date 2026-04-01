cmake_minimum_required(VERSION 3.10)
project(NetworkTrafficAnalyzer C)

set(CMAKE_C_STANDARD 11)

include_directories(${CMAKE_SOURCE_DIR}/include)

# --- AGENTE: Sensor de captura de tráfego ---
add_executable(NetworkTrafficAnalyzer
        src/main.c
        src/capture/capture.c
        src/analysis/analyzer.c
        src/analysis/collector.c
        src/output/publisher.c
        src/output/cJSON.c
        src/replay/replay.c
)

if(WIN32)
    # -------------------------------------------------------------------------
    # Windows: requer Npcap SDK (https://npcap.com/dist/npcap-sdk-1.13.zip)
    # Defina NPCAP_SDK_DIR via cmake -DNPCAP_SDK_DIR="C:/Npcap-sdk" ou
    # crie a variável de ambiente NPCAP_SDK antes de compilar.
    # -------------------------------------------------------------------------
    set(NPCAP_SDK_DIR "C:/Npcap-sdk" CACHE PATH "Diretorio raiz do Npcap SDK")

    include_directories("${NPCAP_SDK_DIR}/Include")

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib/x64")
    else()
        set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib")
    endif()

    target_link_libraries(NetworkTrafficAnalyzer PRIVATE
        "${NPCAP_LIB_DIR}/wpcap.lib"
        "${NPCAP_LIB_DIR}/Packet.lib"
        Ws2_32      # WinSock2 — necessário para sockets no Windows
        rabbitmq
    )
else()
    # -------------------------------------------------------------------------
    # Linux/macOS: usa libpcap nativa + librabbitmq (com suporte SSL embutido)
    # -------------------------------------------------------------------------
    target_link_libraries(NetworkTrafficAnalyzer PRIVATE pcap rabbitmq m)
endif()

# --- INGESTOR: Worker Python (copia para o diretório de build) ---
add_custom_target(DataIngestor ALL
        COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_SOURCE_DIR}/src/ingestor/data_ingestor.py
        ${CMAKE_BINARY_DIR}/data_ingestor.py
)