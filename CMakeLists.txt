cmake_minimum_required(VERSION 3.10)
project(NetworkTrafficAnalyzer C)

set(CMAKE_C_STANDARD 11)

# Layout por componente:
#   include/agent  + src/agent   — agente sensor (Linux, FreeBSD, macOS, Windows)
#   include/server + src/server  — nta-server (Linux; em produção roda no Docker)
#   third_party/cjson            — cJSON (vendored), usado pelos dois
set(CJSON_DIR  ${CMAKE_SOURCE_DIR}/third_party/cjson)
set(AGENT_INC  ${CMAKE_SOURCE_DIR}/include/agent ${CJSON_DIR})
set(SERVER_INC ${CMAKE_SOURCE_DIR}/include/server ${CJSON_DIR})

# --- AGENTE: Sensor de captura de tráfego (pipeline multi-thread v5.0) ---
add_executable(NetworkTrafficAnalyzer
        src/agent/main.c
        src/agent/cli.c
        src/agent/capture/capture.c
        src/agent/analysis/analyzer.c
        src/agent/analysis/collector.c
        src/agent/output/publisher.c
        src/agent/replay/replay.c
        src/agent/core/ringbuf.c
        src/agent/core/pipeline.c
        src/agent/core/config.c
        ${CJSON_DIR}/cJSON.c
)
target_include_directories(NetworkTrafficAnalyzer PRIVATE ${AGENT_INC})

if(WIN32)
    # -------------------------------------------------------------------------
    # Windows: toolchain MinGW-w64 (gcc/clang). MSVC não é suportado — o
    # pipeline usa atômicos C11 (<stdatomic.h>), ainda experimentais no MSVC.
    # Threads/tempo POSIX vêm do winpthreads do MinGW; requer Npcap SDK.
    # -------------------------------------------------------------------------
    target_sources(NetworkTrafficAnalyzer PRIVATE
        src/agent/platform/netif_win32.c
        src/agent/platform/service_win32.c
    )
    # inet_pton/inet_ntop e GetAdaptersAddresses.OnLinkPrefixLength: Windows 7+
    # AMQP_STATIC: rabbitmq-c linkado estático (sem dllimport nos headers).
    target_compile_definitions(NetworkTrafficAnalyzer PRIVATE
        _WIN32_WINNT=0x0601 AMQP_STATIC)

    # .exe autocontido: o serviço roda como LocalSystem, sem as DLLs do MSYS2
    # no PATH. Só wpcap.dll/Packet.dll (Npcap, em System32) ficam dinâmicas.
    target_link_options(NetworkTrafficAnalyzer PRIVATE -static)

    # Do Npcap SDK só usamos os headers; o link é pelo wpcap.def abaixo.
    set(NPCAP_SDK_DIR "C:/Npcap-sdk" CACHE PATH "Diretorio raiz do Npcap SDK")

    include_directories("${NPCAP_SDK_DIR}/Include")

    # wpcap.dll em delay-load (ver src/agent/platform/wpcap.def): o Npcap sem
    # modo compatível instala o DLL só em System32\Npcap, fora da busca padrão.
    find_program(DLLTOOL NAMES dlltool REQUIRED)
    set(WPCAP_DELAYLIB ${CMAKE_BINARY_DIR}/libwpcap_delay.a)
    add_custom_command(
        OUTPUT  ${WPCAP_DELAYLIB}
        COMMAND ${DLLTOOL} --input-def ${CMAKE_SOURCE_DIR}/src/agent/platform/wpcap.def
                --dllname wpcap.dll --output-delaylib ${WPCAP_DELAYLIB}
        DEPENDS ${CMAKE_SOURCE_DIR}/src/agent/platform/wpcap.def
        COMMENT "Gerando import lib delay-load do wpcap.dll")
    add_custom_target(wpcap_delaylib DEPENDS ${WPCAP_DELAYLIB})
    add_dependencies(NetworkTrafficAnalyzer wpcap_delaylib)

    target_link_libraries(NetworkTrafficAnalyzer PRIVATE
        ${WPCAP_DELAYLIB}
        delayimp
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
    target_sources(NetworkTrafficAnalyzer PRIVATE src/agent/platform/netif_posix.c)

    # FreeBSD instala libs de terceiros via ports/pkg em /usr/local/{lib,include}.
    if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
        include_directories(/usr/local/include)
        link_directories(/usr/local/lib)
    endif()

    target_link_libraries(NetworkTrafficAnalyzer PRIVATE
        pcap rabbitmq m Threads::Threads
    )
endif()

# --- SERVIDOR: nta-server em C (em produção é compilado na imagem Docker) ---
# Dependências: librabbitmq, libcurl, libmaxminddb.
# Num host só de agente: -DNTA_BUILD_SERVER=OFF dispensa libcurl/libmaxminddb.
option(NTA_BUILD_SERVER "Compila o nta-server (Linux)" ON)
if(NTA_BUILD_SERVER AND NOT WIN32)
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
            src/server/nta_export.c
            ${CJSON_DIR}/cJSON.c
    )

    target_include_directories(nta-server PRIVATE
            ${SERVER_INC}
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

# --- TESTES UNITÁRIOS (ctest) -------------------------------------------------
# cmake --build build && ctest --test-dir build --output-on-failure
option(NTA_BUILD_TESTS "Compila os testes unitários (ctest)" ON)
if(NTA_BUILD_TESTS)
    enable_testing()
    find_package(Threads REQUIRED)

    add_executable(test_ringbuf tests/unit/test_ringbuf.c src/agent/core/ringbuf.c)
    target_link_libraries(test_ringbuf PRIVATE Threads::Threads)

    add_executable(test_config tests/unit/test_config.c src/agent/core/config.c)

    add_executable(test_analyzer tests/unit/test_analyzer.c
            src/agent/analysis/analyzer.c src/agent/analysis/collector.c)
    if(WIN32)
        target_compile_definitions(test_analyzer PRIVATE _WIN32_WINNT=0x0601)
        target_link_libraries(test_analyzer PRIVATE Ws2_32)
    else()
        target_link_libraries(test_analyzer PRIVATE m)
    endif()

    foreach(t test_ringbuf test_config test_analyzer)
        target_include_directories(${t} PRIVATE ${AGENT_INC})
        add_test(NAME ${t} COMMAND ${t})
    endforeach()

    # Parser WHOIS do nta-server (servidor é Linux/Docker)
    if(NOT WIN32)
        add_executable(test_whois tests/unit/test_whois.c)
        target_include_directories(test_whois PRIVATE ${SERVER_INC})
        target_link_libraries(test_whois PRIVATE Threads::Threads)
        add_test(NAME test_whois COMMAND test_whois)
    endif()

    # B31: NtaIocStore do nta-server (parser, recarga, concorrência). Só fora do
    # Windows, como o test_whois: nta_ioc.c usa <arpa/inet.h>. Sem libcurl.
    if(NOT WIN32)
        add_executable(test_ioc tests/unit/test_ioc.c
                src/server/nta_ioc.c ${CJSON_DIR}/cJSON.c)
        target_include_directories(test_ioc PRIVATE ${SERVER_INC})
        target_link_libraries(test_ioc PRIVATE Threads::Threads)
        add_test(NAME test_ioc COMMAND test_ioc)
    endif()

    # B33: classificação de IP privado (nta_ipclass.h) usada por GeoIP,
    # AbuseIPDB e WHOIS. Header puro (<arpa/inet.h>), só fora do Windows.
    if(NOT WIN32)
        add_executable(test_ipclass tests/unit/test_ipclass.c)
        target_include_directories(test_ipclass PRIVATE ${SERVER_INC})
        add_test(NAME test_ipclass COMMAND test_ipclass)
    endif()

    # B11: exportação SIEM (CEF/ECS/syslog) do nta-server. Só fora do Windows
    # (sockets POSIX). Sem libcurl: só render, fila e envio para loopback.
    if(NOT WIN32)
        add_executable(test_export tests/unit/test_export.c
                src/server/nta_export.c ${CJSON_DIR}/cJSON.c)
        target_include_directories(test_export PRIVATE ${SERVER_INC})
        target_link_libraries(test_export PRIVATE Threads::Threads)
        add_test(NAME test_export COMMAND test_export)
    endif()
endif()

# --- B02: BENCHMARK DE THROUGHPUT pps (opcional, desligado por padrão) -------
# Pipeline real do agente sem rede, sem privilégio e sem RabbitMQ (ver
# tests/bench/bench_pps.c). Não entra no ctest.
#   cmake -S . -B build-bench -DNTA_BUILD_BENCH=ON && cmake --build build-bench
option(NTA_BUILD_BENCH "Compila o benchmark de throughput pps (tests/bench)" OFF)
if(NTA_BUILD_BENCH)
    find_package(Threads REQUIRED)

    add_executable(bench_pps tests/bench/bench_pps.c
            src/agent/core/pipeline.c
            src/agent/core/ringbuf.c
            src/agent/capture/capture.c
            src/agent/analysis/analyzer.c
            src/agent/analysis/collector.c
            ${CJSON_DIR}/cJSON.c
    )
    target_include_directories(bench_pps PRIVATE ${AGENT_INC})

    if(WIN32)
        target_sources(bench_pps PRIVATE src/agent/platform/netif_win32.c)
        target_compile_definitions(bench_pps PRIVATE _WIN32_WINNT=0x0601)
        target_link_libraries(bench_pps PRIVATE Ws2_32 Iphlpapi pthread)
    else()
        target_sources(bench_pps PRIVATE src/agent/platform/netif_posix.c)
        target_link_libraries(bench_pps PRIVATE m Threads::Threads)
    endif()
endif()
