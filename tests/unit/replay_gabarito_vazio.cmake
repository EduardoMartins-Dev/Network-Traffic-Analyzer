# Teste do modo --replay (arquivo único) com gabarito vazio ou não vazio.
# Executado pelo ctest via: cmake -DNTA_EXE=<bin> -DPCAP_DIR=<tests/pcaps>
#                                 -DWORK_DIR=<dir> -P replay_gabarito_vazio.cmake
# Só roda fora do Windows (o binário exige o Npcap instalado).

if(NOT DEFINED NTA_EXE OR NOT DEFINED PCAP_DIR OR NOT DEFINED WORK_DIR)
    message(FATAL_ERROR "Defina -DNTA_EXE, -DPCAP_DIR e -DWORK_DIR")
endif()
file(MAKE_DIRECTORY "${WORK_DIR}")

file(WRITE "${WORK_DIR}/empty.json" "{ \"expected\": [] }\n")
file(WRITE "${WORK_DIR}/port-scan-errado.json"
     "{ \"expected\": [ { \"attack_type\": \"PORT_SCAN\", \"src_ip\": \"192.168.1.100\" } ] }\n")

# Roda --replay e deixa RC/OUT/ERR no escopo do chamador.
macro(replay pcap gab)
    execute_process(
        COMMAND "${NTA_EXE}" --replay "${PCAP_DIR}/${pcap}" --expect "${gab}"
        RESULT_VARIABLE RC
        OUTPUT_VARIABLE OUT
        ERROR_VARIABLE ERR
        TIMEOUT 120)
endmacro()

# (a) gabarito vazio + nenhum alerta -> PASSA (rc 0)
replay(dns-normal.pcap "${WORK_DIR}/empty.json")
string(FIND "${OUT}" "Alerta:" POS_ALERTA)
if(NOT POS_ALERTA EQUAL -1)
    message(FATAL_ERROR "(a) precondição: dns-normal.pcap não deveria gerar alertas\n${OUT}")
endif()
if(NOT RC EQUAL 0)
    message(FATAL_ERROR "(a) gabarito vazio sem alertas deve sair com rc=0, obtido rc=${RC}\n${OUT}${ERR}")
endif()

# (b) gabarito vazio + alerta gerado (falso positivo) -> FALHA (rc 1)
replay(syn-flood.pcap "${WORK_DIR}/empty.json")
string(FIND "${OUT}" "Alerta:" POS_ALERTA)
if(POS_ALERTA EQUAL -1)
    message(FATAL_ERROR "(b) precondição: syn-flood.pcap deveria gerar alertas\n${OUT}")
endif()
if(NOT RC EQUAL 1)
    message(FATAL_ERROR "(b) falso positivo com gabarito vazio deve sair com rc=1, obtido rc=${RC}\n${OUT}${ERR}")
endif()

# (c1) gabarito não vazio que casa -> PASSA (rc 0), inalterado
replay(syn-flood.pcap "${PCAP_DIR}/syn-flood.json")
if(NOT RC EQUAL 0)
    message(FATAL_ERROR "(c1) gabarito não vazio atendido deve sair com rc=0, obtido rc=${RC}\n${OUT}${ERR}")
endif()

# (c2) gabarito não vazio que não casa -> FALHA (rc 1), inalterado
replay(syn-flood.pcap "${WORK_DIR}/port-scan-errado.json")
if(NOT RC EQUAL 1)
    message(FATAL_ERROR "(c2) gabarito não vazio não atendido deve sair com rc=1, obtido rc=${RC}\n${OUT}${ERR}")
endif()
