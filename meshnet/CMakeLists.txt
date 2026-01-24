cmake_minimum_required(VERSION 3.16)
project(gossipnet VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Option for static or dynamic libsodium linking
option(STATIC_LIBSODIUM "Link libsodium statically" OFF)

# Find libsodium - use simple find_library approach that works without pkg-config
find_path(SODIUM_INCLUDE_DIR sodium.h)
if(STATIC_LIBSODIUM)
    find_library(SODIUM_LIBRARY NAMES libsodium.a sodium)
else()
    find_library(SODIUM_LIBRARY NAMES sodium)
endif()

if(NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "libsodium not found. Install with: apt install libsodium-dev")
endif()

message(STATUS "Found libsodium: ${SODIUM_LIBRARY}")

set(SOURCES
    src/connection.cpp
    src/mesh_node.cpp
    src/gossip_net.cpp
    src/logging.cpp
    src/crypto.cpp
    src/session.cpp
    src/frame.cpp
    src/identity.cpp
    src/handshake.cpp
    src/trust_store.cpp
)

set(HEADERS
    include/packet.h
    include/connection.h
    include/mesh_node.h
    include/gossip_net.h
    include/logging.h
    include/crypto.h
    include/session.h
    include/frame.h
    include/identity.h
    include/protocol.h
    include/handshake.h
    include/trust_store.h
)

add_library(gossipnet SHARED ${SOURCES} ${HEADERS})

target_include_directories(gossipnet
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${SODIUM_INCLUDE_DIR}
)

target_compile_options(gossipnet PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    $<$<CONFIG:Release>:-O3>
    $<$<CONFIG:Debug>:-g -O0>
)

find_package(Threads REQUIRED)
target_link_libraries(gossipnet PRIVATE Threads::Threads ${SODIUM_LIBRARY})

if(STATIC_LIBSODIUM)
    target_link_options(gossipnet PRIVATE -static-libgcc -static-libstdc++)
endif()

add_library(gossipnet_static STATIC ${SOURCES} ${HEADERS})

target_include_directories(gossipnet_static
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${SODIUM_INCLUDE_DIR}
)

target_compile_options(gossipnet_static PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    $<$<CONFIG:Release>:-O3>
    $<$<CONFIG:Debug>:-g -O0>
)

target_link_libraries(gossipnet_static PRIVATE Threads::Threads ${SODIUM_LIBRARY})

set_target_properties(gossipnet_static PROPERTIES OUTPUT_NAME gossipnet)

install(TARGETS gossipnet gossipnet_static
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES ${HEADERS} DESTINATION include/gossip)

option(BUILD_TESTS "Build unit tests" OFF)

if(BUILD_TESTS)
    enable_testing()
    
    include(FetchContent)
    FetchContent_Declare(
      googletest
      URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    )
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
    
    add_executable(test_crypto tests/test_crypto.cpp)
    target_link_libraries(test_crypto gossipnet_static GTest::gtest_main)
    add_test(NAME CryptoTests COMMAND test_crypto)
    
    add_executable(test_session tests/test_session.cpp)
    target_link_libraries(test_session gossipnet_static GTest::gtest_main)
    add_test(NAME SessionTests COMMAND test_session)
    
    add_executable(test_handshake tests/test_handshake.cpp)
    target_link_libraries(test_handshake gossipnet_static GTest::gtest_main)
    add_test(NAME HandshakeTests COMMAND test_handshake)
endif()

