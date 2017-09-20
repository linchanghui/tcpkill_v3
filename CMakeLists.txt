cmake_minimum_required(VERSION 3.5)
project(tcpkill_v3)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11")

set(SOURCE_FILES pcaputil.c tcpkill.c)
add_executable(tcpkill ${SOURCE_FILES})

target_link_libraries(tcpkill pcap)
target_link_libraries(tcpkill net)
target_link_libraries(tcpkill pthread)

target_compile_options(tcpkill PRIVATE -Wall)
