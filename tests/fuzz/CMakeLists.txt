# SPDX-License-Identifier: Apache-2.0
#
# Fuzz targets. With -DSTS_FUZZ=ON (clang): libFuzzer programs, see
# `make fuzz`. Otherwise: programs that run the seeds once, as tests.
set(STS_FUZZ_TARGETS room transfer config)

foreach(t ${STS_FUZZ_TARGETS})
        if(STS_FUZZ)
                add_executable(fuzz_${t} fuzz_${t}.c)
                target_link_options(fuzz_${t} PRIVATE -fsanitize=fuzzer)
        else()
                add_executable(fuzz_${t} fuzz_${t}.c run_seeds.c)
                add_test(NAME fuzz_${t}_seeds
                         COMMAND fuzz_${t} ${CMAKE_CURRENT_SOURCE_DIR}/seeds/${t})
        endif()
        target_link_libraries(fuzz_${t} PRIVATE stscore)
        target_compile_options(fuzz_${t} PRIVATE ${STS_WARNINGS})
        set_target_properties(fuzz_${t} PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                              ${PROJECT_BINARY_DIR}/fuzz)
endforeach()
