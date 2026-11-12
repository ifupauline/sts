// SPDX-License-Identifier: Apache-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "platform.h"
#include "trust.h"

static struct sts_trust_entry *trust_find(const struct sts_trust *t,
					  const uint8_t fpr[STS_HASH_LEN])
{
	size_t i;

	for (i = 0; i < t->count; i++) {
		if (memcmp(t->entries[i].fpr, fpr, STS_HASH_LEN) == 0)
			return &t->entries[i];
	}
	return NULL;
}

static struct sts_trust_entry *trust_add(struct sts_trust *t)
{
	struct sts_trust_entry *e;
	size_t cap;

	if (t->count == t->cap) {
		cap = t->cap ? t->cap * 2 : 16;
		e = realloc(t->entries, cap * sizeof(*e));
		if (e == NULL)
			return NULL;
		t->entries = e;
		t->cap = cap;
	}
	e = &t->entries[t->count++];
	memset(e, 0, sizeof(*e));
	return e;
}

int sts_trust_load(struct sts_trust *t, const char *path)
{
	char line[256];
	char hex[2 * STS_HASH_LEN + 1];
	char nick[STS_NICK_MAX + 2];
	struct sts_trust_entry *e;
	unsigned long lineno = 0;
	int verified;
	FILE *fp;

	memset(t, 0, sizeof(*t));
	if (sts_strlcpy(t->path, path, sizeof(t->path)) != 0)
		return -1;

	if (!sts_file_exists(path))
		return 0;
	fp = sts_fopen(path, "r");
	if (fp == NULL)
		return -1;

	while (fgets(line, sizeof(line), fp) != NULL) {
		lineno++;
		if (line[0] == '#' || line[0] == '\n')
			continue;

		if (sscanf(line, "%64s %d %25s", hex, &verified, nick) != 3 ||
		    strlen(hex) != 2 * STS_HASH_LEN ||
		    !sts_nick_valid(nick, strlen(nick))) {
			WARN("%s:%lu: ignoring malformed line", path, lineno);
			continue;
		}

		e = trust_add(t);
		if (e == NULL)
			break;
		if (sts_unhex(hex, e->fpr, STS_HASH_LEN) != 0) {
			t->count--;
			WARN("%s:%lu: ignoring malformed line", path, lineno);
			continue;
		}
		e->verified = verified == 1;
		sts_strlcpy(e->nick, nick, sizeof(e->nick));
	}
	fclose(fp);
	return 0;
}

int sts_trust_save(const struct sts_trust *t)
{
	char hex[2 * STS_HASH_LEN + 1];
	char *buf;
	size_t cap;
	size_t len = 0;
	size_t i;
	int n;
	int ret;

	if (t->path[0] == '\0')
		return 0;

	cap = 128 + t->count * (sizeof(hex) + STS_NICK_MAX + 8);
	buf = malloc(cap);
	if (buf == NULL)
		return -1;

	n = snprintf(buf, cap,
		     "# sts known peers: <fingerprint> <verified> <nick>\n");
	len = (size_t)n;

	for (i = 0; i < t->count; i++) {
		sts_hex(t->entries[i].fpr, STS_HASH_LEN, hex);
		n = snprintf(buf + len, cap - len, "%s %d %s\n", hex,
			     t->entries[i].verified, t->entries[i].nick);
		if (n < 0 || (size_t)n >= cap - len) {
			free(buf);
			return -1;
		}
		len += (size_t)n;
	}

	ret = sts_file_write_atomic(t->path, buf, len, 1);
	free(buf);
	return ret;
}

void sts_trust_free(struct sts_trust *t)
{
	free(t->entries);
	memset(t, 0, sizeof(*t));
}

/* is @nick the last nick of a key other than @fpr? */
static int trust_nick_taken(const struct sts_trust *t, const uint8_t *fpr,
			    const char *nick)
{
	size_t i;

	for (i = 0; i < t->count; i++) {
		if (memcmp(t->entries[i].fpr, fpr, STS_HASH_LEN) != 0 &&
		    sts_strcasecmp(t->entries[i].nick, nick) == 0)
			return 1;
	}
	return 0;
}

enum sts_trust_status sts_trust_observe(struct sts_trust *t,
					const uint8_t fpr[STS_HASH_LEN],
					const char *nick)
{
	struct sts_trust_entry *e;
	enum sts_trust_status status;

	e = trust_find(t, fpr);
	if (e != NULL) {
		status = e->verified ? STS_TRUST_VERIFIED : STS_TRUST_KNOWN;
		if (strcmp(e->nick, nick) != 0) {
			/* known key taking over the nick of another key */
			if (sts_strcasecmp(e->nick, nick) != 0 &&
			    trust_nick_taken(t, fpr, nick))
				status = STS_TRUST_CONFLICT;
			sts_strlcpy(e->nick, nick, sizeof(e->nick));
			if (sts_trust_save(t) != 0)
				WARN("could not save %s", t->path);
		}
		return status;
	}

	/* an unknown key using a nick that belongs to a known key */
	status = trust_nick_taken(t, fpr, nick) ? STS_TRUST_CONFLICT :
						  STS_TRUST_NEW;

	e = trust_add(t);
	if (e != NULL) {
		memcpy(e->fpr, fpr, STS_HASH_LEN);
		sts_strlcpy(e->nick, nick, sizeof(e->nick));
		if (sts_trust_save(t) != 0)
			WARN("could not save %s", t->path);
	}
	return status;
}

int sts_trust_set_verified(struct sts_trust *t, const uint8_t fpr[STS_HASH_LEN],
			   const char *nick, int verified)
{
	struct sts_trust_entry *e;

	e = trust_find(t, fpr);
	if (e == NULL) {
		e = trust_add(t);
		if (e == NULL)
			return -1;
		memcpy(e->fpr, fpr, STS_HASH_LEN);
	}
	e->verified = verified ? 1 : 0;
	sts_strlcpy(e->nick, nick, sizeof(e->nick));
	return sts_trust_save(t);
}

int sts_trust_is_verified(const struct sts_trust *t,
			  const uint8_t fpr[STS_HASH_LEN])
{
	const struct sts_trust_entry *e = trust_find(t, fpr);

	return e != NULL && e->verified;
}
