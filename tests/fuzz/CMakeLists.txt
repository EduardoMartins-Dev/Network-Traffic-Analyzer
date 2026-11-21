# Harness de fuzzing do parser do analyzer (B06).
#
# Projeto próprio, separado do CMakeLists da raiz (que não muda por este item):
#
#   cmake -S tests/fuzz -B build-fuzz -DCMAKE_C_COMPILER=clang
#   cmake --build build-fuzz --target fuzz_parser
#   python3 tests/fuzz/make_corpus.py tests/pcaps build-fuzz/corpus
#   ./build-fuzz/fuzz_parser build-fuzz/corpus -max_total_time=120 -max_len=4096
#
# fuzz_parser   libFuzzer + ASan + UBSan. Só com clang (-fsanitize=fuzzer).
# fuzz_replay   driver sem libFuzzer: roda arquivos (corpus ou crash-*) com
#               qualquer compilador, inclusive gcc com ASan/UBSan.
#
# Carregador de limiares (B18 fase 1), mesmo esquema:
#   cmake --build build-fuzz --target fuzz_rules          (clang)
#   mkdir corpus-rules && cp deploy/rules/*.json corpus-rules/
#   ./build-fuzz/fuzz_rules corpus-rules -max_total_time=120 -max_len=16384
#   ./build-fuzz/fuzz_rules_replay <arquivos>             (qualquer compilador)
cmake_minimum_required(VERSION 3.13)
project(NtaFuzz C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(NTA_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)

# Só o parser: analyzer.c + collector.c. publish_packet é stub no harness.
set(FUZZ_SRC
        ${NTA_ROOT}/src/agent/analysis/analyzer.c
        ${NTA_ROOT}/src/agent/analysis/collector.c)
set(FUZZ_INC ${NTA_ROOT}/include/agent)

set(FUZZ_SAN_FLAGS -fsanitize=address,undefined -fno-sanitize-recover=all
                   -fno-omit-frame-pointer -g -O1)

if(WIN32)
    # Headers do Npcap (analyzer.h inclui pcap.h); o link não usa wpcap.
    set(NPCAP_SDK_DIR "C:/Npcap-sdk" CACHE PATH "Diretorio raiz do Npcap SDK")
    include_directories("${NPCAP_SDK_DIR}/Include")
    set(FUZZ_LIBS m Ws2_32)
    set(FUZZ_DEFS _WIN32_WINNT=0x0601)
else()
    # Linux: libpcap-dev fornece pcap.h.
    set(FUZZ_LIBS m)
    set(FUZZ_DEFS "")
endif()

add_executable(fuzz_replay replay_main.c fuzz_parser.c ${FUZZ_SRC})
target_include_directories(fuzz_replay PRIVATE ${FUZZ_INC})
target_compile_definitions(fuzz_replay PRIVATE ${FUZZ_DEFS})
target_compile_options(fuzz_replay PRIVATE ${FUZZ_SAN_FLAGS})
target_link_options(fuzz_replay PRIVATE -fsanitize=address,undefined)
target_link_libraries(fuzz_replay PRIVATE ${FUZZ_LIBS})

if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_executable(fuzz_parser fuzz_parser.c ${FUZZ_SRC})
    target_include_directories(fuzz_parser PRIVATE ${FUZZ_INC})
    target_compile_definitions(fuzz_parser PRIVATE ${FUZZ_DEFS})
    target_compile_options(fuzz_parser PRIVATE -fsanitize=fuzzer ${FUZZ_SAN_FLAGS})
    target_link_options(fuzz_parser PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(fuzz_parser PRIVATE ${FUZZ_LIBS})
endif()

# B18 fase 1: carregador de limiares (rules.c + cJSON). Mesmo esquema: driver
# sem libFuzzer (fuzz_rules_replay) e o alvo libFuzzer (fuzz_rules, só clang).
set(RULES_SRC
        ${NTA_ROOT}/src/agent/analysis/rules.c
        ${NTA_ROOT}/third_party/cjson/cJSON.c)
set(RULES_INC ${FUZZ_INC} ${NTA_ROOT}/third_party/cjson)

add_executable(fuzz_rules_replay replay_main.c fuzz_rules.c ${RULES_SRC})
target_include_directories(fuzz_rules_replay PRIVATE ${RULES_INC})
target_compile_definitions(fuzz_rules_replay PRIVATE ${FUZZ_DEFS})
target_compile_options(fuzz_rules_replay PRIVATE ${FUZZ_SAN_FLAGS})
target_link_options(fuzz_rules_replay PRIVATE -fsanitize=address,undefined)
target_link_libraries(fuzz_rules_replay PRIVATE ${FUZZ_LIBS})

if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_executable(fuzz_rules fuzz_rules.c ${RULES_SRC})
    target_include_directories(fuzz_rules PRIVATE ${RULES_INC})
    target_compile_definitions(fuzz_rules PRIVATE ${FUZZ_DEFS})
    target_compile_options(fuzz_rules PRIVATE -fsanitize=fuzzer ${FUZZ_SAN_FLAGS})
    target_link_options(fuzz_rules PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(fuzz_rules PRIVATE ${FUZZ_LIBS})
endif()
