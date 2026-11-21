# Teste do AGENT_RULES_FILE no modo --replay (B18 fase 1): um limiar alterado
# muda o resultado de um pcap. Executado pelo ctest via:
#   cmake -DNTA_EXE=<bin> -DPCAP_DIR=<tests/pcaps> -DWORK_DIR=<dir>
#         -P rules_replay.cmake
# Só roda fora do Windows (mesmo critério do replay_gabarito_vazio.cmake).

if(NOT DEFINED NTA_EXE OR NOT DEFINED PCAP_DIR OR NOT DEFINED WORK_DIR)
    message(FATAL_ERROR "Defina -DNTA_EXE, -DPCAP_DIR e -DWORK_DIR")
endif()
file(MAKE_DIRECTORY "${WORK_DIR}")

# port-scan.pcap: 20 portas de destino de 192.168.1.100 (gen_pcaps.py).
file(WRITE "${WORK_DIR}/scan-alto.json" "{ \"versao\": 1, \"scan_threshold\": 32 }\n")
# Limiar 2: o null-scan.pcap (sem PORT_SCAN no padrão) passa a ter PORT_SCAN.
file(WRITE "${WORK_DIR}/scan-baixo.json" "{ \"versao\": 1, \"scan_threshold\": 2 }\n")
file(WRITE "${WORK_DIR}/invalido.json" "{ \"versao\": 1, \"scan_threshold\": 1 }\n")

# Roda --replay com (ou sem) AGENT_RULES_FILE. Deixa RC/OUT/ERR no escopo do chamador.
macro(replay pcap rules)
    if("${rules}" STREQUAL "")
        unset(ENV{AGENT_RULES_FILE})
    else()
        set(ENV{AGENT_RULES_FILE} "${rules}")
    endif()
    execute_process(
        COMMAND "${NTA_EXE}" --replay "${PCAP_DIR}/${pcap}"
        RESULT_VARIABLE RC
        OUTPUT_VARIABLE OUT
        ERROR_VARIABLE ERR
        TIMEOUT 120)
    unset(ENV{AGENT_RULES_FILE})
endmacro()

# (a) sem arquivo: o padrão (limiar 15) gera PORT_SCAN no port-scan.pcap.
replay(port-scan.pcap "")
string(FIND "${OUT}" "PORT_SCAN" POS)
if(POS EQUAL -1)
    message(FATAL_ERROR "(a) precondição: port-scan.pcap deveria gerar PORT_SCAN\n${OUT}${ERR}")
endif()

# (b) limiar 32 > 20 portas: o mesmo pcap deixa de gerar PORT_SCAN.
replay(port-scan.pcap "${WORK_DIR}/scan-alto.json")
if(NOT RC EQUAL 0)
    message(FATAL_ERROR "(b) replay com limiar válido deve sair com rc=0, obtido rc=${RC}\n${OUT}${ERR}")
endif()
string(FIND "${OUT}" "PORT_SCAN" POS)
if(NOT POS EQUAL -1)
    message(FATAL_ERROR "(b) limiar 32 não deveria gerar PORT_SCAN com 20 portas\n${OUT}")
endif()

# (c) limiar 2: alerta aparece onde no padrão não havia.
replay(null-scan.pcap "")
string(FIND "${OUT}" "PORT_SCAN" POS)
if(NOT POS EQUAL -1)
    message(FATAL_ERROR "(c) precondição: null-scan.pcap não deveria gerar PORT_SCAN no padrão\n${OUT}")
endif()
replay(null-scan.pcap "${WORK_DIR}/scan-baixo.json")
string(FIND "${OUT}" "PORT_SCAN" POS)
if(POS EQUAL -1)
    message(FATAL_ERROR "(c) limiar 2 deveria gerar PORT_SCAN em null-scan.pcap\n${OUT}${ERR}")
endif()

# (d) valor fora da faixa: o agente recusa antes do replay (rc 1, sem análise).
replay(port-scan.pcap "${WORK_DIR}/invalido.json")
if(NOT RC EQUAL 1)
    message(FATAL_ERROR "(d) regra inválida deve sair com rc=1, obtido rc=${RC}\n${OUT}${ERR}")
endif()
# Trecho sem acento: a codepage do stderr capturado pelo CMake varia por plataforma.
string(FIND "${ERR}" "fora da faixa" POS)
if(POS EQUAL -1)
    message(FATAL_ERROR "(d) mensagem de erro de regra ausente\n${ERR}")
endif()
string(FIND "${OUT}" "Resultado" POS)
if(NOT POS EQUAL -1)
    message(FATAL_ERROR "(d) com regra inválida o replay não deveria analisar nada\n${OUT}")
endif()
