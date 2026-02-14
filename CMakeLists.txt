cmake_minimum_required(VERSION 3.10)
project(NetworkTrafficAnalyzer C)

set(CMAKE_C_STANDARD 11)

include_directories(include)

add_executable(NetworkTrafficAnalyzer
        src/main.c
        src/capture/capture.c
        src/analysis/analyzer.c
        src/output/output.c
        src/output/cJSON.c
)

target_link_libraries(NetworkTrafficAnalyzer pcap)