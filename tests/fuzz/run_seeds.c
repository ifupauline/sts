// SPDX-License-Identifier: Apache-2.0
/*
 * main() for a fuzz target without libFuzzer: each argument is a file or a
 * directory of files, each file is one input.
 */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "fuzz.h"

#define INPUT_MAX (1024 * 1024)

static int run_file(const char *path)
{
	static uint8_t buf[INPUT_MAX];
	size_t len;
	FILE *fp;

	fp = fopen(path, "rb");
	if (fp == NULL) {
		perror(path);
		return -1;
	}
	len = fread(buf, 1, sizeof(buf), fp);
	fclose(fp);
	LLVMFuzzerTestOneInput(buf, len);
	return 0;
}

static int run_path(const char *path, int *count)
{
	char sub[4096];
	struct dirent *e;
	struct stat st;
	DIR *d;
	int ret = 0;

	if (stat(path, &st) != 0) {
		perror(path);
		return -1;
	}
	if (!S_ISDIR(st.st_mode)) {
		(*count)++;
		return run_file(path);
	}
	d = opendir(path);
	if (d == NULL) {
		perror(path);
		return -1;
	}
	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] == '.')
			continue;
		snprintf(sub, sizeof(sub), "%s/%s", path, e->d_name);
		if (run_path(sub, count) != 0)
			ret = -1;
	}
	closedir(d);
	return ret;
}

int main(int argc, char **argv)
{
	int count = 0;
	int ret = 0;
	int i;

	for (i = 1; i < argc; i++)
		if (run_path(argv[i], &count) != 0)
			ret = 1;
	printf("%s: %d inputs\n", argv[0], count);
	return ret || count == 0;
}
