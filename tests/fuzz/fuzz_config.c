// SPDX-License-Identifier: Apache-2.0
/* Configuration files: the input is the content of the file. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "fuzz.h"

static char dir[32];
static char path[64];

static void cleanup(void)
{
	unlink(path);
	rmdir(dir);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static struct sts_config cfg;
	char err[1024];
	FILE *fp;

	if (path[0] == '\0') {
		snprintf(dir, sizeof(dir), "/tmp/sts-fuzz-XXXXXX");
		if (mkdtemp(dir) == NULL)
			abort();
		snprintf(path, sizeof(path), "%s/fuzz.conf", dir);
		atexit(cleanup);
	}
	fp = fopen(path, "wb");
	if (fp == NULL || fwrite(data, 1, size, fp) != size)
		abort();
	fclose(fp);

	sts_config_init(&cfg);
	if (sts_config_load(&cfg, path, err, sizeof(err)) == 0)
		sts_config_check(&cfg, err, sizeof(err));
	return 0;
}
