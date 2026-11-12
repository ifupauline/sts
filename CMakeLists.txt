# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.16)

# `cmake .` would overwrite the Makefile wrapper with a generated one
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
        message(FATAL_ERROR
                "In-source builds are not supported. Run `make`, or\n"
                "  cmake -S . -B build && cmake --build build\n"
                "then delete the CMakeCache.txt and CMakeFiles/ just created "
                "here (they are ignored by git).")
endif()

project(sts
        VERSION 3.0.1
        DESCRIPTION "Secure Talk System - end-to-end encrypted chat over MQTT"
        LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
        set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

option(STS_BUILD_TESTS "Build the test suite"               ON)
option(STS_SANITIZE    "Build with AddressSanitizer + UBSan" OFF)
option(STS_WERROR      "Treat warnings as errors"            OFF)
option(STS_FUZZ        "Build the libFuzzer targets (clang)"  OFF)

if(STS_SANITIZE)
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
endif()
# coverage only for the code of sts: the vendored libraries aren't the
# target, and PBKDF2 would be very slow
if(STS_FUZZ)
        add_compile_options(-fsanitize=address,undefined
                            -fno-sanitize-recover=undefined
                            -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
        set(STS_FUZZ_FLAGS -fsanitize=fuzzer-no-link)
endif()

# ---------------------------------------------------------------------------
# Third-party code in vendor/, see `make vendor`
# ---------------------------------------------------------------------------

# mbedtls: crypto, X.509 and TLS from upstream's own source lists
set(MBEDTLS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vendor/mbedtls)
file(STRINGS ${MBEDTLS_DIR}/sources.txt MBEDTLS_SOURCES)
list(REMOVE_ITEM MBEDTLS_SOURCES net_sockets.c)        # sts has its own
list(TRANSFORM MBEDTLS_SOURCES PREPEND ${MBEDTLS_DIR}/library/)
add_library(mbedtls_all STATIC ${MBEDTLS_SOURCES})
target_include_directories(mbedtls_all SYSTEM PUBLIC ${MBEDTLS_DIR}/include)
target_include_directories(mbedtls_all PRIVATE ${MBEDTLS_DIR}/library)
set_target_properties(mbedtls_all PROPERTIES C_STANDARD 99 C_EXTENSIONS ON)
target_compile_options(mbedtls_all PRIVATE -w)

# paho embedded-c: only the MQTT packet serializers
set(PAHO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vendor/paho-mqtt/MQTTPacket/src)
add_library(mqttpacket STATIC
        ${PAHO_DIR}/MQTTConnectClient.c
        ${PAHO_DIR}/MQTTDeserializePublish.c
        ${PAHO_DIR}/MQTTPacket.c
        ${PAHO_DIR}/MQTTSerializePublish.c
        ${PAHO_DIR}/MQTTSubscribeClient.c
        ${PAHO_DIR}/MQTTUnsubscribeClient.c)
target_include_directories(mqttpacket SYSTEM PUBLIC ${PAHO_DIR})
target_compile_options(mqttpacket PRIVATE -w)

# ---------------------------------------------------------------------------
# sts
# ---------------------------------------------------------------------------
set(STS_WARNINGS -Wall -Wextra -Wshadow -Wformat=2 -Wstrict-prototypes
                 -Wmissing-prototypes -Wvla)
if(STS_WERROR)
        list(APPEND STS_WARNINGS -Werror)
endif()

# hardening, fortify needs optimisation so not in Debug builds
set(STS_HARDENING -fstack-protector-strong)
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        list(APPEND STS_HARDENING -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2)
endif()

add_library(stscore STATIC
        src/platform_posix.c
        src/config.c
        src/crypto.c
        src/log.c
        src/mqtt.c
        src/room.c
        src/setup.c
        src/tls.c
        src/transfer.c
        src/trust.c
        src/tui.c
        src/util.c)
target_include_directories(stscore PUBLIC include)
target_compile_definitions(stscore PUBLIC _POSIX_C_SOURCE=200809L
                           _DEFAULT_SOURCE)
target_compile_definitions(stscore PUBLIC STS_VERSION="${PROJECT_VERSION}")
target_compile_options(stscore PRIVATE ${STS_WARNINGS} ${STS_HARDENING}
                       ${STS_FUZZ_FLAGS})
target_link_libraries(stscore PUBLIC mbedtls_all mqttpacket)

# ---------------------------------------------------------------------------
# program
# ---------------------------------------------------------------------------
add_executable(sts src/chat.c src/main.c)
target_link_libraries(sts PRIVATE stscore)
set_target_properties(sts PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                      ${PROJECT_BINARY_DIR}/bin)
target_compile_options(sts PRIVATE ${STS_WARNINGS} ${STS_HARDENING})

# make install: the program, its manual, the examples and the documentation
include(GNUInstallDirs)
install(TARGETS sts RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES doc/sts.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
# laid out as in the repository, so the links between the pages work
install(FILES README.md SECURITY.md CHANGELOG.md LICENSE NOTICE
        DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(DIRECTORY configs DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(DIRECTORY doc DESTINATION ${CMAKE_INSTALL_DOCDIR}
        FILES_MATCHING PATTERN "*.md" PATTERN "*.svg")

# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------
if(STS_BUILD_TESTS)
        enable_testing()
        add_subdirectory(tests)
elseif(STS_FUZZ)
        add_subdirectory(tests/fuzz)
endif()
