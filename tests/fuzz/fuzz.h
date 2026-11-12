/* SPDX-License-Identifier: Apache-2.0 */
/*
 * The fuzz targets are libFuzzer programs (make fuzz, with clang). Built
 * without -DSTS_FUZZ=ON, run_seeds.c gives them a main() that runs every
 * file given on the command line once, so the normal test suite replays
 * the seeds and the crashes found so far.
 */
#ifndef STS_FUZZ_H
#define STS_FUZZ_H

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#endif /* STS_FUZZ_H */
