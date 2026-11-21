# Benchmark de throughput pps (B02)

Mede o pipeline **real** do agente (`src/agent/core/pipeline.c`) sem rede,
sem privilégio e sem RabbitMQ. Fica atrás da opção CMake `NTA_BUILD_BENCH`,
desligada por padrão, e não entra no `ctest`.

## Build e execução

```sh
cmake -S . -B build-bench -DCMAKE_BUILD_TYPE=Release -DNTA_BUILD_BENCH=ON
cmake --build build-bench --target bench_pps

# taxa oferecida controlada (capacidade sem perda)
./build-bench/bench_pps --packets 400000 --pps 350000 --machine "descrição da máquina" --json bench.json

# rajada (sem pacing): mostra overflow sob saturação
./build-bench/bench_pps --packets 400000
```

No Windows (MSYS2 UCRT64): compilar precisa dos headers do Npcap SDK
(`-DNPCAP_SDK_DIR=C:/Npcap-sdk`), mas o `bench_pps.exe` não importa
`wpcap.dll` e roda sem Npcap instalado. Ele depende das DLLs do UCRT64 (não é
autocontido como o `.exe` do agente, que linka `-static`).

Saída: relatório em texto no stdout e, com `--json`, um arquivo JSON. Código
de saída `0` só quando a conservação fecha e o pipeline esvazia; caso
contrário `1`.

## O que é real e o que é substituído

| Parte | Situação |
|---|---|
| `pipeline.c` (threads, `rb_pkt`, `rb_evt`, batch, métricas) | real |
| `ringbuf.c`, `capture.c` (`packet_handler`), `analyzer.c`, `collector.c` | reais |
| `pcap_open_live` / `pcap_loop` | substituídos: gerador sintético chama o `packet_handler` real, dentro da thread de captura (o custo do gerador entra no número) |
| `publish_packet` | cópia do caminho live de `publisher.c`, sem AMQP |
| `publisher_send_batch` / `publisher_send_metrics` | sumidouros: contam eventos e leem as amostras reais do `metrics_thread` |
| serialização cJSON e envio AMQP | **não medidos** |

A carga são 64 hosts (`198.51.100.0/24`) com TCP ACK (80/443) e DNS query
UDP/53, sem ICMP: o `ICMP_FLOOD` do analyzer conta por IP sem zerar na
janela, e um host ICMP com volume sustentado gera um alerta por pacote.

## Métricas

- **pps processados**: eventos recebidos / (último evento − 1º pacote). Cada
  pacote IPv4 TCP/UDP/ICMP gera exatamente um evento.
- **pps oferecidos**: pacotes gerados / tempo de geração.
- **overflow**: `rb_pkt_overflow` e `rb_evt_overflow` da última amostra de
  métricas, tomada depois que o pipeline esvazia.
- **latência de fila**: fórmula de Little, W = L̄/λ, com L̄ = média das
  profundidades amostradas a 1 Hz pelo `metrics_thread`. **Não** é medida por
  item: isso exigiria instrumentar o pipeline.
- **conservação**: pacotes oferecidos − overflow(pkt) − overflow(evt) deve ser
  igual aos eventos recebidos.

## Limitações

- Uma execução por processo (o estado do analyzer é global).
- A carga é pequena e repetitiva (64 quadros em ciclo), então cabe em cache:
  é um teto otimista, não uma previsão para tráfego real.
- O pacing usa espera ativa: a thread de captura ocupa um núcleo.
- Em rajada o produtor descarta boa parte dos pacotes: o número de pps
  processados sob rajada mede a competição entre produtor e analysis, não a
  capacidade. Para capacidade, use `--pps` e procure a maior taxa com
  overflow zero.
