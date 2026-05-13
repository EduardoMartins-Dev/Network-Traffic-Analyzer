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
    # Linux / FreeBSD / macOS: libpcap + librabbitmq + pthreads (pipeline v5.0)
    # -------------------------------------------------------------------------
    find_package(Threads REQUIRED)

    # FreeBSD instala libs de terceiros via ports/pkg em /usr/local/{lib,include}.
    if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
        include_directories(/usr/local/include)
        link_directories(/usr/local/lib)
    endif()

    target_link_libraries(NetworkTrafficAnalyzer PRIVATE
        pcap rabbitmq m Threads::Threads
    )
endif()

# --- SERVIDOR: nta-server em C (substitui o ingestor Python legado da v6.0) ---
# Dependências: librabbitmq (já presente), libcurl, libmaxminddb.
# Fedora/Toolbx: dnf install libcurl-devel libmaxminddb-devel
if(NOT WIN32)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBCURL REQUIRED libcurl)
    pkg_check_modules(LIBMAXMINDDB REQUIRED libmaxminddb)

    add_executable(nta-server
            src/server/nta_server.c
            src/server/nta_consumer.c
            src/server/nta_influx.c
            src/server/nta_geoip.c
            src/server/nta_ioc.c
            src/server/nta_abuse.c
            src/server/nta_whois.c
            src/server/nta_narrator.c
            src/server/nta_scaler.c
            src/server/nta_health.c
            src/output/cJSON.c
    )

    target_include_directories(nta-server PRIVATE
            ${LIBCURL_INCLUDE_DIRS}
            ${LIBMAXMINDDB_INCLUDE_DIRS}
    )

    target_link_libraries(nta-server PRIVATE
            rabbitmq
            ${LIBCURL_LIBRARIES}
            ${LIBMAXMINDDB_LIBRARIES}
            Threads::Threads
    )
endif()
