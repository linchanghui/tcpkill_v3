cmake_minimum_required(VERSION 3.5)
project(tcpkill_v3)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11")

set(SOURCE_FILES pcaputil.c tcpkill.c)
set(SOURCE_FILES_1 nicinfo.c pcaputil.c ddp.c econet.c inet.c inet6.c ipx.c netrom.c rose.c unix.c x25.c ax25.c ash.c x25_gr.c x25_sr.c)

add_executable(tcpkill ${SOURCE_FILES})
add_executable(nicinfo ${SOURCE_FILES_1})

target_link_libraries(tcpkill pcap)
target_link_libraries(tcpkill net)
target_link_libraries(tcpkill pthread)

target_compile_options(tcpkill PRIVATE -Wall)

target_link_libraries(nicinfo pcap)
target_link_libraries(nicinfo net)
target_link_libraries(nicinfo pthread)

target_compile_options(nicinfo PRIVATE -Wall)
