/* SPDX-License-Identifier: Apache-2.0 */
#ifndef STS_TEST_H
#define STS_TEST_H

#include <stdio.h>
#include <stdlib.h>

#include "platform.h"

static int test_failures;
static int test_checks;

#define CHECK(cond)                                                            \
	do {                                                                   \
		test_checks++;                                                 \
		if (!(cond)) {                                                 \
			test_failures++;                                       \
			fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, \
				__LINE__, #cond);                              \
		}                                                              \
	} while (0)

/* stop the test program, for setup failures */
#define REQUIRE(cond)                                                  \
	do {                                                           \
		if (!(cond)) {                                         \
			fprintf(stderr, "%s:%d: REQUIRE failed: %s\n", \
				__FILE__, __LINE__, #cond);            \
			exit(1);                                       \
		}                                                      \
	} while (0)

#define RUN(fn)                                                   \
	do {                                                      \
		int before_ = test_failures;                      \
		fn();                                             \
		printf("%-52s %s\n", #fn,                         \
		       test_failures == before_ ? "ok" : "FAIL"); \
		fflush(stdout);                                   \
	} while (0)

static inline int test_summary(void)
{
	printf("%d checks, %d failures\n", test_checks, test_failures);
	return test_failures == 0 ? 0 : 1;
}

/* a new empty directory for test files */
static inline void test_tmpdir(char *out, size_t cap)
{
	const char *base = getenv("TMPDIR");
	unsigned int r;

	if (base == NULL || base[0] == '\0')
		base = "/tmp";
	r = (unsigned int)(sts_wallclock_ms() ^ (sts_monotonic_ms() << 7));
	snprintf(out, cap, "%s/sts-test-%08x", base, r);
	REQUIRE(sts_mkdirs(out) == 0);
}

#endif /* STS_TEST_H */
