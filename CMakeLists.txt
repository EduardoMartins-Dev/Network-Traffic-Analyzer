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
        src/core/config.c
)

if(WIN32)
    # -------------------------------------------------------------------------
    # Windows: toolchain MinGW-w64 (gcc/clang). MSVC não é suportado — o
    # pipeline usa atômicos C11 (<stdatomic.h>), ainda experimentais no MSVC.
    # Threads/tempo POSIX vêm do winpthreads do MinGW; requer Npcap SDK.
    # -------------------------------------------------------------------------
    target_sources(NetworkTrafficAnalyzer PRIVATE
        src/platform/netif_win32.c
        src/platform/service_win32.c
    )
    # inet_pton/inet_ntop e GetAdaptersAddresses.OnLinkPrefixLength: Windows 7+
    # AMQP_STATIC: rabbitmq-c linkado estático (sem dllimport nos headers).
    target_compile_definitions(NetworkTrafficAnalyzer PRIVATE
        _WIN32_WINNT=0x0601 AMQP_STATIC)

    # .exe autocontido: o serviço roda como LocalSystem, sem as DLLs do MSYS2
    # no PATH. Só wpcap.dll/Packet.dll (Npcap, em System32) ficam dinâmicas.
    target_link_options(NetworkTrafficAnalyzer PRIVATE -static)

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
        rabbitmq
        ssl
        crypto
        Ws2_32
        Iphlpapi
        Crypt32
        Bcrypt
        pthread
    )
else()
    # -------------------------------------------------------------------------
    # Linux / FreeBSD / macOS: libpcap + librabbitmq + pthreads (pipeline v5.0)
    # -------------------------------------------------------------------------
    find_package(Threads REQUIRED)
    target_sources(NetworkTrafficAnalyzer PRIVATE src/platform/netif_posix.c)

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
