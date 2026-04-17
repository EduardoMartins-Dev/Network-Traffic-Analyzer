cmake_minimum_required(VERSION 3.10)
project(NetworkTrafficAnalyzer C)

set(CMAKE_C_STANDARD 11)

include_directories(${CMAKE_SOURCE_DIR}/include)

# --- AGENTE: Sensor de captura de tráfego (pipeline multi-thread v5.0) ---
add_executable(NetworkTrafficAnalyzer
        src/main.c
        src/capture/capture.c
        src/analysis/analyzer.c
        src/analysis/collector.c
        src/output/publisher.c
        src/output/cJSON.c
        src/replay/replay.c
        src/core/ringbuf.c
        src/core/pipeline.c
)

if(WIN32)
    # -------------------------------------------------------------------------
    # Windows (validação planejada para v5.1): requer Npcap SDK e substituição
    # do backend de threads (pthreads-w32 ou _beginthreadex). O pipeline v5.0
    # usa pthreads + SCHED_FIFO, específicos de Linux.
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
        Ws2_32
        rabbitmq
    )
else()
    # -------------------------------------------------------------------------
    # Linux/macOS: libpcap + librabbitmq + pthreads (pipeline v5.0)
    # -------------------------------------------------------------------------
    find_package(Threads REQUIRED)
    target_link_libraries(NetworkTrafficAnalyzer PRIVATE
        pcap rabbitmq m Threads::Threads
    )
endif()

# --- INGESTOR: Worker Python (copia para o diretório de build) ---
add_custom_target(DataIngestor ALL
        COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_SOURCE_DIR}/src/ingestor/data_ingestor.py
        ${CMAKE_BINARY_DIR}/data_ingestor.py
)
