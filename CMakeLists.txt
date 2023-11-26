cmake_minimum_required(VERSION 3.26)
project(ja3guard C)

include_directories(/usr/local/include)
set(CMAKE_C_STANDARD 90)

find_library(TLS_LIBRARY tls)
if (NOT TLS_LIBRARY)
    message(FATAL_ERROR "libtls not found")
endif()

find_library(CRYPTO_LIBRARY crypto)
if (NOT CRYPTO_LIBRARY)
    message(FATAL_ERROR "libcrypto not found")
endif()

find_library(TOML_LIBRARY toml)
if (NOT TOML_LIBRARY)
    message(FATAL_ERROR "libtoml not found")
endif()

add_executable(ja3guard
        main.c
        j3g_config.c
        j3g_http_parse.c
        j3g_ja3_fingerprint.c
        j3g_tls_parse.c
)

target_link_libraries(ja3guard
        ${TLS_LIBRARY}
        ${CRYPTO_LIBRARY}
        ${TOML_LIBRARY}
)
