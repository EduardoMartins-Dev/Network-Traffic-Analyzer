# Regressão do nta-eve-bridge (B17): roda --once --dry-run sobre o EVE de
# exemplo e compara a saída (um array JSON por lote) com
# tests/eve/expected-dryrun.json. Sem AMQP, sem relógio na saída (janela longa
# e sem limite de taxa, para o resultado não depender da velocidade da máquina).
#
# Parâmetros (-D): BRIDGE_EXE, EVE_DIR, MAPPING, WORK_DIR
file(MAKE_DIRECTORY "${WORK_DIR}")

set(ENV{BRIDGE_EVE_PATH} "${EVE_DIR}/eve-sample.json")
set(ENV{BRIDGE_MAPPING_FILE} "${MAPPING}")
set(ENV{BRIDGE_AGG_WINDOW_MS} "60000")
set(ENV{BRIDGE_RATE_PER_SEC} "0")
set(ENV{BRIDGE_ATTACKER_SIDE} "src")

execute_process(
    COMMAND "${BRIDGE_EXE}" --once --dry-run
    WORKING_DIRECTORY "${WORK_DIR}"
    OUTPUT_VARIABLE out
    ERROR_VARIABLE err
    RESULT_VARIABLE rc)

if(NOT rc EQUAL 0)
    message(FATAL_ERROR "nta-eve-bridge saiu com rc=${rc}\n${err}")
endif()

file(READ "${EVE_DIR}/expected-dryrun.json" expected)
if(NOT out STREQUAL expected)
    file(WRITE "${WORK_DIR}/actual-dryrun.json" "${out}")
    message(FATAL_ERROR
        "saida do dry-run difere de tests/eve/expected-dryrun.json "
        "(ver ${WORK_DIR}/actual-dryrun.json)")
endif()
message(STATUS "dry-run do EVE de exemplo igual ao golden")
