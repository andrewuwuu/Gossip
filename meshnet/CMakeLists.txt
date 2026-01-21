cmake_minimum_required(VERSION 3.16)
project(gossipnet VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(SOURCES
    src/connection.cpp
    src/mesh_node.cpp
    src/gossip_net.cpp
    src/logging.cpp
)

set(HEADERS
    include/packet.h
    include/connection.h
    include/mesh_node.h
    include/gossip_net.h
    include/logging.h
)

add_library(gossipnet SHARED ${SOURCES} ${HEADERS})

target_include_directories(gossipnet
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_options(gossipnet PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    $<$<CONFIG:Release>:-O3>
    $<$<CONFIG:Debug>:-g -O0>
)

find_package(Threads REQUIRED)
target_link_libraries(gossipnet PRIVATE Threads::Threads)

add_library(gossipnet_static STATIC ${SOURCES} ${HEADERS})

target_include_directories(gossipnet_static
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_options(gossipnet_static PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    $<$<CONFIG:Release>:-O3>
    $<$<CONFIG:Debug>:-g -O0>
)

target_link_libraries(gossipnet_static PRIVATE Threads::Threads)

set_target_properties(gossipnet_static PROPERTIES OUTPUT_NAME gossipnet)

install(TARGETS gossipnet gossipnet_static
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES ${HEADERS} DESTINATION include/gossip)

option(BUILD_TESTS "Build unit tests" OFF)

if(BUILD_TESTS)
    enable_testing()
    find_package(GTest REQUIRED)
    
    add_executable(test_packet tests/test_packet.cpp)
    target_link_libraries(test_packet gossipnet_static GTest::GTest GTest::Main)
    add_test(NAME PacketTests COMMAND test_packet)
endif()
