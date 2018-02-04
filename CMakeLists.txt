cmake_minimum_required(VERSION 2.8)
project(ReimuTLS)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

set(SOURCE_FILES
        ReimuTLS.cpp
        ReimuTLS.hpp CommonIncludes.hpp SSLFunctions.cpp Pipe.cpp IO.cpp)

add_library(ReimuTLS SHARED ${SOURCE_FILES} Tests/tls_over_tty_server.cpp)
add_library(ReimuTLS_Static STATIC ${SOURCE_FILES})

set_target_properties(ReimuTLS_Static PROPERTIES OUTPUT_NAME ReimuTLS)
target_link_libraries(ReimuTLS pthread mbedtls mbedx509 mbedcrypto)
target_link_libraries(ReimuTLS_Static pthread mbedtls mbedx509 mbedcrypto)

add_executable(Test_tls_over_tty_server Tests/tls_over_tty_server.cpp)
add_executable(Test_tls_over_tty_client Tests/tls_over_tty_client.cpp)
target_link_libraries(Test_tls_over_tty_server ReimuTLS)
target_link_libraries(Test_tls_over_tty_client ReimuTLS)