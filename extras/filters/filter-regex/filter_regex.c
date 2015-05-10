/*      $OpenBSD$   */

/*
 * Copyright (c) 2015 Armin Wolfermann <armin@wolfermann.org>
 * Copyright (c) 2015 Joerg Jung <jung@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/queue.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>
#include <unistd.h>
#include <util.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

#define REGEX_CONF "/etc/mail/filter-regex.conf"

struct regex {
	SIMPLEQ_ENTRY(regex) entries;
	regex_t pattern;
};

static SIMPLEQ_HEAD(, regex) re_connect = SIMPLEQ_HEAD_INITIALIZER(re_connect);
static SIMPLEQ_HEAD(, regex) re_helo = SIMPLEQ_HEAD_INITIALIZER(re_helo);
static SIMPLEQ_HEAD(, regex) re_mail = SIMPLEQ_HEAD_INITIALIZER(re_mail);
static SIMPLEQ_HEAD(, regex) re_rcpt = SIMPLEQ_HEAD_INITIALIZER(re_rcpt);
static SIMPLEQ_HEAD(, regex) re_dataline = SIMPLEQ_HEAD_INITIALIZER(re_dataline);

static int
regex_parse(char *l, size_t no)
{
	struct regex *re;
	char *k, buf[BUFSIZ];
	int r;

	while (isspace((unsigned char)*l))
		l++;
	if (strlen(l) == 0)
		return 0; /* skip empty line */
	k = strsep(&l, " \t");
	while (isspace((unsigned char)*l))
		l++;
	if (strlen(l) == 0) {
		log_warnx("warn: filter-regex: parse: missing regex (line: %lu)", no);
		return -1;
	}
	re = xcalloc(1, sizeof(struct regex), "filter-regex: parse");
	if ((r = regcomp(&re->pattern, l, REG_EXTENDED|REG_NOSUB)) != 0) {
		regerror(r, &re->pattern, buf, sizeof(buf));
		log_warnx("warn: filter-regex: parse: regcomp %s (line: %lu)", buf, no);
		free(re);
		return -1;
	}
	if (strcmp(k, "connect") == 0)
		SIMPLEQ_INSERT_TAIL(&re_connect, re, entries);
	else if (strcmp(k, "helo") == 0)
		SIMPLEQ_INSERT_TAIL(&re_helo, re, entries);
	else if (strcmp(k, "mail") == 0)
		SIMPLEQ_INSERT_TAIL(&re_mail, re, entries);
	else if (strcmp(k, "rcpt") == 0)
		SIMPLEQ_INSERT_TAIL(&re_rcpt, re, entries);
	else if (strcmp(k, "dataline") == 0)
		SIMPLEQ_INSERT_TAIL(&re_dataline, re, entries);
	else {
		log_warnx("warn: filter-regex: parse: unknown regex keyword %s (line: %lu)", k, no);
		free(re);
		return -1;
	}
	return 0;
}

static int
regex_load(const char *c)
{
	FILE *f;
	char *l;
	size_t no;

	if ((f = fopen(c, "r")) == NULL) {
		log_warn("warn: filter-regex: load: fopen %s", c);
		return -1;
	}
	while ((l = fparseln(f, NULL, &no, NULL, 0)) != NULL) {
		if (regex_parse(l, no) == -1) {
			free(l);
			fclose(f);
			return -1;
		}
		free(l);
	}
	fclose(f);
	return 0;
}

static int
regex_match(regex_t *pattern, const char *s)
{
	int r = regexec(pattern, s, 0, NULL, 0);
	char buf[BUFSIZ];

	if (r != 0 && r != REG_NOMATCH) {
		regerror(r, pattern, buf, sizeof(buf));
		log_warnx("warn: filter-regex: match: regexec %s", buf);
		return 0;
	}
	return (r == 0);
}

static void
regex_clear(void)
{
	struct regex *re;

	while((re = SIMPLEQ_FIRST(&re_connect)) != NULL) {
		SIMPLEQ_REMOVE_HEAD(&re_connect, entries);
		regfree(&re->pattern), free(re);
	}
	while((re = SIMPLEQ_FIRST(&re_helo)) != NULL) {
		SIMPLEQ_REMOVE_HEAD(&re_helo, entries);
		regfree(&re->pattern), free(re);
	}
	while((re = SIMPLEQ_FIRST(&re_mail)) != NULL) {
		SIMPLEQ_REMOVE_HEAD(&re_mail, entries);
		regfree(&re->pattern), free(re);
	}
	while((re = SIMPLEQ_FIRST(&re_rcpt)) != NULL) {
		SIMPLEQ_REMOVE_HEAD(&re_rcpt, entries);
		regfree(&re->pattern), free(re);
	}
	while((re = SIMPLEQ_FIRST(&re_dataline)) != NULL) {
		SIMPLEQ_REMOVE_HEAD(&re_dataline, entries);
		regfree(&re->pattern), free(re);
	}
}

static int
regex_on_connect(uint64_t id, struct filter_connect *c)
{
	struct regex *re;

	SIMPLEQ_FOREACH(re, &re_connect, entries) {
		if (regex_match(&re->pattern, c->hostname)) {
			log_warnx("filter-regex: on_connect: REJECT connect hostname id=%016"PRIx64, id);
			return filter_api_reject_code(id, FILTER_FAIL, 554, "Hostname rejected"); /* todo: better code/message? */
		}
	}
	return filter_api_accept(id);
}

static int
regex_on_helo(uint64_t id, const char *h)
{
	struct regex *re;

	SIMPLEQ_FOREACH(re, &re_helo, entries) {
		if (regex_match(&re->pattern, h)) {
			log_warnx("filter-regex: on_helo: REJECT helo hostname id=%016"PRIx64, id);
			return filter_api_reject_code(id, FILTER_FAIL, 554, "Helo rejected"); /* todo: better code/message? */
		}
	}
	return filter_api_accept(id);
}

static int
regex_on_mail(uint64_t id, struct mailaddr *m)
{
	struct regex *re;
	const char *s = filter_api_mailaddr_to_text(m);

	SIMPLEQ_FOREACH(re, &re_mail, entries) {
		if (regex_match(&re->pattern, s)) {
			log_warnx("filter-regex: on_mail: REJECT mail from id=%016"PRIx64, id);
			return filter_api_reject_code(id, FILTER_FAIL, 554, "Sender rejected"); /* todo: better code/message? */
		}
	}
	return filter_api_accept(id);
}

static int
regex_on_rcpt(uint64_t id, struct mailaddr *r)
{
	struct regex *re;
	const char *s = filter_api_mailaddr_to_text(r);

	SIMPLEQ_FOREACH(re, &re_rcpt, entries) {
		if (regex_match(&re->pattern, s)) {
			log_warnx("filter-regex: on_rcpt: REJECT rcpt to id=%016"PRIx64, id);
			return filter_api_reject_code(id, FILTER_FAIL, 554, "Recipient rejected"); /* todo: better code/message? */
		}
	}
	return filter_api_accept(id);
}

static int
regex_on_data(uint64_t id)
{
	int *m = xcalloc(1, sizeof(int), "filter-regex: on_data");

	filter_api_set_udata(id, m);
	return filter_api_accept(id);
}

static void
regex_on_dataline(uint64_t id, const char *l)
{
	int *m;
	struct regex *re;

	filter_api_writeln(id, l);
	if ((m = filter_api_get_udata(id)) == NULL || *m)
		return;
	SIMPLEQ_FOREACH(re, &re_dataline, entries) {
		if (regex_match(&re->pattern, l)) {
			*m = 1;
			break;
		}
	}
}

static int
regex_on_eom(uint64_t id, size_t size)
{
	int *m, r;

	if ((m = filter_api_get_udata(id)) == NULL)
		return filter_api_accept(id);
	r = *m, free(m), filter_api_set_udata(id, NULL);
	if (r) {
		log_warnx("filter-regex: on_eom: REJECT dataline id=%016"PRIx64, id);
		return filter_api_reject_code(id, FILTER_CLOSE, 554, "Message content rejected"); /* todo: better code/message? */
	}
	return filter_api_accept(id);
}

static void
regex_on_reset(uint64_t id)
{
	free(filter_api_get_udata(id));
	filter_api_set_udata(id, NULL);
}

static void
regex_on_disconnect(uint64_t id)
{
	free(filter_api_get_udata(id));
	filter_api_set_udata(id, NULL);
}

static void
regex_on_rollback(uint64_t id)
{
	free(filter_api_get_udata(id));
	filter_api_set_udata(id, NULL);
}

int
main(int argc, char **argv)
{
	int	ch;

	log_init(-1);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			log_warnx("warn: filter-regex: bad option");
			return (1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;
	if (argc > 1)
		fatalx("filter-regex: bogus argument(s)");

	log_debug("debug: filter-regex: starting...");
	if (regex_load((argc == 1) ? argv[0] : REGEX_CONF) == -1)
		fatalx("filter-regex: configuration failed");

	filter_api_on_connect(regex_on_connect);
	filter_api_on_helo(regex_on_helo);
	filter_api_on_mail(regex_on_mail);
	filter_api_on_rcpt(regex_on_rcpt);
	filter_api_on_data(regex_on_data);
	filter_api_on_dataline(regex_on_dataline);
	filter_api_on_eom(regex_on_eom);
	filter_api_on_reset(regex_on_reset);
	filter_api_on_disconnect(regex_on_disconnect);
	filter_api_on_rollback(regex_on_rollback);

	filter_api_loop();
	regex_clear();
	log_debug("debug: filter-regex: exiting");

	return (1);
}
