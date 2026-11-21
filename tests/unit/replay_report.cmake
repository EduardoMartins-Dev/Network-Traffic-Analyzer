# Teste do --report do --replay-dir: cada entrada do JSON deve trazer o nome do
# pcap que ela avaliou (distinto e igual aos arquivos do diretório). Antes, o
# ponteiro apontava para um buffer de pilha reutilizado e todas as entradas
# mostravam o último pcap. Executado pelo ctest via:
#   cmake -DNTA_EXE=<bin> -DPCAP_DIR=<tests/pcaps> -DWORK_DIR=<dir>
#         -P replay_report.cmake
# Só roda fora do Windows (mesmo critério do replay_gabarito_vazio.cmake).

if(NOT DEFINED NTA_EXE OR NOT DEFINED PCAP_DIR OR NOT DEFINED WORK_DIR)
    message(FATAL_ERROR "Defina -DNTA_EXE, -DPCAP_DIR e -DWORK_DIR")
endif()
file(MAKE_DIRECTORY "${WORK_DIR}")
set(REPORT "${WORK_DIR}/report.json")
file(REMOVE "${REPORT}")

execute_process(
    COMMAND "${NTA_EXE}" --replay-dir "${PCAP_DIR}" --report "${REPORT}"
    RESULT_VARIABLE RC
    OUTPUT_VARIABLE OUT
    ERROR_VARIABLE ERR
    TIMEOUT 300)
if(NOT RC EQUAL 0)
    message(FATAL_ERROR "replay-dir deve sair com rc=0, obtido rc=${RC}\n${OUT}${ERR}")
endif()
if(NOT EXISTS "${REPORT}")
    message(FATAL_ERROR "relatório não foi gravado em ${REPORT}\n${OUT}${ERR}")
endif()

# Nomes de arquivo do relatório (só o nome base, sem o diretório).
file(READ "${REPORT}" JSON)
string(REGEX MATCHALL "\"file\"[ \t]*:[ \t]*\"[^\"]*\"" ENTRIES "${JSON}")
set(NAMES "")
foreach(E IN LISTS ENTRIES)
    string(REGEX REPLACE "^\"file\"[ \t]*:[ \t]*\"([^\"]*)\"$" "\\1" P "${E}")
    get_filename_component(B "${P}" NAME)
    list(APPEND NAMES "${B}")
endforeach()
list(LENGTH NAMES N_NAMES)

# Arquivos .pcap do diretório, pelo mesmo nome base.
file(GLOB PCAPS RELATIVE "${PCAP_DIR}" "${PCAP_DIR}/*.pcap")
list(SORT PCAPS)
list(LENGTH PCAPS N_PCAPS)
if(N_PCAPS LESS 2)
    message(FATAL_ERROR "precondição: ${PCAP_DIR} deve ter pelo menos 2 .pcap (tem ${N_PCAPS})")
endif()

if(NOT N_NAMES EQUAL N_PCAPS)
    message(FATAL_ERROR "relatório tem ${N_NAMES} entradas, diretório tem ${N_PCAPS} .pcap")
endif()

# Cada entrada tem um nome próprio: sem repetição.
list(SORT NAMES)
set(UNIQUE "${NAMES}")
list(REMOVE_DUPLICATES UNIQUE)
list(LENGTH UNIQUE N_UNIQUE)
if(NOT N_UNIQUE EQUAL N_NAMES)
    message(FATAL_ERROR "nomes repetidos no relatório: ${N_UNIQUE} distintos de ${N_NAMES} entradas\n${NAMES}")
endif()

# E os nomes são exatamente os dos pcaps do diretório.
if(NOT "${NAMES}" STREQUAL "${PCAPS}")
    message(FATAL_ERROR "nomes do relatório não batem com os pcaps do diretório\nrelatório: ${NAMES}\ndiretório: ${PCAPS}")
endif()
