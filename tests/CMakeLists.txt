# SPDX-License-Identifier: Apache-2.0
set(STS_TESTS test_util test_crypto test_config test_room test_fuzz test_transfer)

foreach(t ${STS_TESTS})
        add_executable(${t} ${t}.c)
        target_link_libraries(${t} PRIVATE stscore)
        target_compile_options(${t} PRIVATE ${STS_WARNINGS} ${STS_HARDENING})
        add_test(NAME ${t} COMMAND ${t})
endforeach()
target_compile_definitions(test_config PRIVATE
                           STS_SOURCE_DIR="${PROJECT_SOURCE_DIR}")

# against a real broker, skipped when mosquitto or openssl is missing
find_program(MOSQUITTO mosquitto PATHS /usr/sbin /usr/local/sbin)
find_program(OPENSSL openssl)
add_executable(test_mqtt test_mqtt.c)
target_link_libraries(test_mqtt PRIVATE stscore)
target_compile_options(test_mqtt PRIVATE ${STS_WARNINGS})
add_test(NAME test_mqtt COMMAND test_mqtt "${MOSQUITTO}" "${OPENSSL}")
set_tests_properties(test_mqtt PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)

# the program itself, skipped without python3 or mosquitto
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_FOUND)
        add_test(NAME test_cli
                 COMMAND ${Python3_EXECUTABLE}
                         ${CMAKE_CURRENT_SOURCE_DIR}/test_cli.py
                         $<TARGET_FILE:sts> "${MOSQUITTO}")
        set_tests_properties(test_cli PROPERTIES SKIP_RETURN_CODE 77
                             TIMEOUT 120)
endif()

# the fuzz targets, run once on their seeds
add_subdirectory(fuzz)
