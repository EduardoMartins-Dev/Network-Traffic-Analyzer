# Teste do log de DNS no modo --replay (B16, PR a). Executado pelo ctest via:
#   cmake -DNTA_EXE=<bin> -DPCAP_DIR=<tests/pcaps> -DWORK_DIR=<dir>
#         -P proto_dns_replay.cmake
# Só roda fora do Windows (mesmo critério dos outros testes de replay).
#
# dns-log-basico.pcap: 11 pacotes DNS (IPv4/IPv6, UDP/TCP, A/AAAA/MX/TXT,
# NOERROR/NXDOMAIN) e uma resposta sem pergunta, que não gera registro. Com
# AGENT_PROTO_LOGS=dns cada pergunta/resposta vira uma linha [PROTO]; sem a
# variável, nenhuma linha [PROTO] aparece e a saída não muda.

if(NOT DEFINED NTA_EXE OR NOT DEFINED PCAP_DIR OR NOT DEFINED WORK_DIR)
    message(FATAL_ERROR "Defina -DNTA_EXE, -DPCAP_DIR e -DWORK_DIR")
endif()
file(MAKE_DIRECTORY "${WORK_DIR}")
set(PCAP "${PCAP_DIR}/dns-log-basico.pcap")

# Roda --replay com o ambiente atual. Deixa RC/OUT/ERR no escopo do chamador.
macro(replay_dns)
    execute_process(
        COMMAND "${NTA_EXE}" --replay "${PCAP}"
        RESULT_VARIABLE RC
        OUTPUT_VARIABLE OUT
        ERROR_VARIABLE ERR
        TIMEOUT 120)
endmacro()

# (a) Flag desligada: nenhuma linha [PROTO], rc 0.
unset(ENV{AGENT_PROTO_LOGS})
unset(ENV{AGENT_PROTO_HASH_NAMES})
replay_dns()
if(NOT RC EQUAL 0)
    message(FATAL_ERROR "(a) replay sem log deve sair com rc=0, obtido rc=${RC}\n${OUT}${ERR}")
endif()
string(FIND "${OUT}" "[PROTO]" POS)
if(NOT POS EQUAL -1)
    message(FATAL_ERROR "(a) com AGENT_PROTO_LOGS ausente não deve haver linha [PROTO]\n${OUT}")
endif()

# (b) Flag ligada: as 10 linhas esperadas, na ordem do pcap. ts em ms (pacote i =
# 1700000000 + i*0.1 s). bytes = tamanho da mensagem DNS (29 em todas: sem respostas).
set(ESPERADAS
    "[PROTO] dns ts=1700000000000 proto=UDP src=192.168.1.10 dst=8.8.8.8 qname=example.com qtype=1 rcode=0 resp=0 bytes=29"
    "[PROTO] dns ts=1700000000100 proto=UDP src=8.8.8.8 dst=192.168.1.10 qname=example.com qtype=1 rcode=0 resp=1 bytes=29"
    "[PROTO] dns ts=1700000000200 proto=UDP src=192.168.1.10 dst=8.8.8.8 qname=example.org qtype=28 rcode=0 resp=0 bytes=29"
    "[PROTO] dns ts=1700000000300 proto=UDP src=8.8.8.8 dst=192.168.1.10 qname=example.org qtype=28 rcode=3 resp=1 bytes=29"
    "[PROTO] dns ts=1700000000400 proto=UDP src=198.51.100.20 dst=8.8.8.8 qname=example.net qtype=16 rcode=0 resp=0 bytes=29"
    "[PROTO] dns ts=1700000000500 proto=UDP src=8.8.8.8 dst=198.51.100.20 qname=example.net qtype=16 rcode=0 resp=1 bytes=29"
    "[PROTO] dns ts=1700000000600 proto=TCP src=198.51.100.20 dst=8.8.8.8 qname=example.com qtype=15 rcode=0 resp=0 bytes=29"
    "[PROTO] dns ts=1700000000700 proto=TCP src=8.8.8.8 dst=198.51.100.20 qname=example.com qtype=15 rcode=0 resp=1 bytes=29"
    "[PROTO] dns ts=1700000000800 proto=UDP src=2001:db8:4::20 dst=2001:db8:53::1 qname=example.com qtype=28 rcode=0 resp=0 bytes=29"
    "[PROTO] dns ts=1700000000900 proto=UDP src=2001:db8:53::1 dst=2001:db8:4::20 qname=example.com qtype=28 rcode=0 resp=1 bytes=29")

set(ENV{AGENT_PROTO_LOGS} "dns")
replay_dns()
if(NOT RC EQUAL 0)
    message(FATAL_ERROR "(b) replay com log ligado deve sair com rc=0, obtido rc=${RC}\n${OUT}${ERR}")
endif()
string(REPLACE "\n" ";" LINHAS "${OUT}")
set(OBTIDAS "")
foreach(L IN LISTS LINHAS)
    if("${L}" MATCHES "^\\[PROTO\\] ")
        list(APPEND OBTIDAS "${L}")
    endif()
endforeach()
if(NOT "${OBTIDAS}" STREQUAL "${ESPERADAS}")
    message(FATAL_ERROR "(b) linhas [PROTO] diferentes do esperado\nobtido:\n${OBTIDAS}\nesperado:\n${ESPERADAS}")
endif()

# (c) Log ligado não gera alerta: o pcap tem gabarito vazio, então com --expect
# o replay sai com rc 0 só se nenhum alerta apareceu.
execute_process(
    COMMAND "${NTA_EXE}" --replay "${PCAP}" --expect "${PCAP_DIR}/dns-log-basico.json"
    RESULT_VARIABLE RC
    OUTPUT_VARIABLE OUT
    ERROR_VARIABLE ERR
    TIMEOUT 120)
if(NOT RC EQUAL 0)
    message(FATAL_ERROR "(c) log ligado não pode gerar alerta neste pcap, rc=${RC}\n${OUT}${ERR}")
endif()

# (d) Hash: qname vira 16 hex; o texto do nome não aparece em lugar nenhum.
set(ENV{AGENT_PROTO_HASH_NAMES} "1")
replay_dns()
string(FIND "${OUT}" "example" POS)
if(NOT POS EQUAL -1)
    message(FATAL_ERROR "(d) com AGENT_PROTO_HASH_NAMES=1 o nome em texto não pode aparecer\n${OUT}")
endif()
string(REGEX MATCHALL "qname=[0-9a-f]+ " HASHES "${OUT}")
list(LENGTH HASHES N)
if(NOT N EQUAL 10)
    message(FATAL_ERROR "(d) esperados 10 qname em hash, obtidos ${N}\n${OUT}")
endif()
unset(ENV{AGENT_PROTO_HASH_NAMES})

# (e) Tipo ainda não suportado: rc 1 na subida, com a mensagem do erro.
set(ENV{AGENT_PROTO_LOGS} "dns,tls")
replay_dns()
if(NOT RC EQUAL 1)
    message(FATAL_ERROR "(e) AGENT_PROTO_LOGS=dns,tls deve sair com rc=1, obtido rc=${RC}\n${OUT}${ERR}")
endif()
string(FIND "${ERR}" "tls" POS)
if(POS EQUAL -1)
    message(FATAL_ERROR "(e) mensagem de erro sem o tipo rejeitado\n${ERR}")
endif()
string(FIND "${OUT}" "Resultado" POS)
if(NOT POS EQUAL -1)
    message(FATAL_ERROR "(e) com config inválida o replay não deveria analisar nada\n${OUT}")
endif()

unset(ENV{AGENT_PROTO_LOGS})
