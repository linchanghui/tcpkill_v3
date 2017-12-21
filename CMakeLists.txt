cmake_minimum_required(VERSION 3.5)
project(tcpkill_v3)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11")

set(SOURCE_FILES pcaputil.c tcpkill.c)
set(SOURCE_FILES_1 nicinfo.c pcaputil.c)
set(SOURCE_FILES_2 newTest.c)
set(SOURCE_FILES_3 makeTcpConnection.c)
set(SOURCE_FILES_4 interface.c)

add_executable(tcpkill ${SOURCE_FILES})
add_executable(nicinfo ${SOURCE_FILES_1})
add_executable(newTest ${SOURCE_FILES_2})
add_executable(createTcp ${SOURCE_FILES_3})
add_executable(interface ${SOURCE_FILES_4})

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

target_link_libraries(createTcp pcap)
target_link_libraries(createTcp pthread)

target_compile_options(newTest PRIVATE -Wall)


add_definitions(-Dlinux)
