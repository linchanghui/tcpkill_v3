cmake_minimum_required(VERSION 3.5)
project(tcpkill_v3)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11")

set(SOURCE_FILES pcaputil.c tcpkill.c)
set(SOURCE_FILES_1 nicinfo.c pcaputil.c)
set(SOURCE_FILES_2 newTest.c)

add_executable(tcpkill ${SOURCE_FILES})
add_executable(nicinfo ${SOURCE_FILES_1})
add_executable(newTest ${SOURCE_FILES_2})

target_link_libraries(tcpkill pcap)
target_link_libraries(tcpkill net)
target_link_libraries(tcpkill pthread)

target_compile_options(tcpkill PRIVATE -Wall)

target_link_libraries(nicinfo pcap)
target_link_libraries(nicinfo net)
target_link_libraries(nicinfo pthread)

target_compile_options(nicinfo PRIVATE -Wall)

target_link_libraries(newTest pcap)
target_link_libraries(newTest net)

target_compile_options(newTest PRIVATE -Wall)
