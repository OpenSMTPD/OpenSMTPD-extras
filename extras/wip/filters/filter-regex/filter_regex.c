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
#include <limits.h>
#include <regex.h>
#include <unistd.h>
#include <util.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

#define REGEX_CONF "/etc/mail/filter-regex.conf"

struct regex {
	SIMPLEQ_ENTRY(regex) el;
	char *s, n;
	regex_t p;
};

static SIMPLEQ_HEAD(regex_q, regex)
	regex_connect = SIMPLEQ_HEAD_INITIALIZER(regex_connect),
	regex_helo = SIMPLEQ_HEAD_INITIALIZER(regex_helo),
	regex_mail = SIMPLEQ_HEAD_INITIALIZER(regex_mail),
	regex_rcpt = SIMPLEQ_HEAD_INITIALIZER(regex_rcpt),
	regex_dataline = SIMPLEQ_HEAD_INITIALIZER(regex_dataline);
static struct { const char *s; struct regex_q *rq; } regex_s[] = {
	{ "connect", &regex_connect }, { "helo", &regex_helo },
	{ "mail", &regex_mail }, { "rcpt", &regex_rcpt },
	{ "dataline", &regex_dataline }, { NULL, NULL } };
static unsigned int regex_limit;

static char *
regex_skip(char *s) {
	while (isspace((unsigned char)*s))
		s++;
	return s;
}

static int
regex_parse(char *l, size_t no)
{
	struct regex_q *rq = NULL;
	struct regex *re;
	char *k, buf[BUFSIZ];
	int i, r;

	l = regex_skip(l);
	if ((k = strsep(&l, " \t")) == NULL || strlen(k) == 0)
		return 0; /* skip empty line */
	for (i = 0; regex_s[i].s != NULL && rq == NULL; i++)
		if (strcmp(k, regex_s[i].s) == 0)
			rq = regex_s[i].rq;
	if (rq == NULL) {
		log_warnx("warn: filter-regex: parse: unknown keyword %s line %lu", k, no);
		return -1;
	}
	if (strlen((l = regex_skip(l))) == 0) {
		log_warnx("warn: filter-regex: parse: missing value line %lu", no);
		return -1;
	}
	re = xcalloc(1, sizeof(struct regex), "filter-regex: parse");
	re->s = xstrdup(l, "filter-regex: parse");
	if ((re->n = (l[0] == '!' && isspace((unsigned char)l[1]))))
		l = regex_skip(++l);
	if ((r = regcomp(&re->p, l, REG_EXTENDED|REG_NOSUB)) != 0) {
		regerror(r, &re->p, buf, sizeof(buf));
		log_warnx("warn: filter-regex: parse: regcomp %s line %lu", buf, no);
		free(re->s), free(re);
		return -1;
	}
	SIMPLEQ_INSERT_TAIL(rq, re, el);
	log_debug("debug: filter-regex: parse: %s %s line %lu", k, re->s, no);
	return 0;
}

static int
regex_load(const char *c)
{
	FILE *f;
	char *l;
	size_t no = 0;

	if ((f = fopen(c, "r")) == NULL) {
		log_warn("warn: filter-regex: load: fopen %s", c);
		return -1;
	}
	while ((l = fparseln(f, NULL, &no, NULL, 0)) != NULL) {
		if (regex_parse(l, no) == -1) {
			free(l), fclose(f);
			return -1;
		}
		free(l);
	}
	fclose(f);
	return 0;
}

static int
regex_match(struct regex_q *rq, const char *s)
{
	struct regex *re;
	char buf[BUFSIZ];
	int r;

	SIMPLEQ_FOREACH(re, rq, el) {
		if ((r = regexec(&re->p, s, 0, NULL, 0)) != 0) {
			if (r != REG_NOMATCH) {
				regerror(r, &re->p, buf, sizeof(buf));
				log_warnx("warn: filter-regex: match: regexec %s", buf);
			}
			continue;
		}
		log_info("info: filter-regex: match: %s to %s", re->s, s);
		return (re->n == 0);
	}
	return 0;
}

static void
regex_clear(void)
{
	struct regex *re;
	int i;

	for (i = 0; regex_s[i].rq != NULL; i++) {
		while((re = SIMPLEQ_FIRST(regex_s[i].rq)) != NULL) {
			SIMPLEQ_REMOVE_HEAD(regex_s[i].rq, el);
			regfree(&re->p), free(re->s), free(re);
		}
	}
}

static int
regex_on_connect(uint64_t id, struct filter_connect *c)
{
	if (regex_match(&regex_connect, c->hostname)) {
		log_warnx("filter-regex: on_connect: REJECT connect hostname id=%016"PRIx64, id);
		return filter_api_reject_code(id, FILTER_FAIL, 554, "5.7.1 Hostname rejected");
	}
	return filter_api_accept(id);
}

static int
regex_on_helo(uint64_t id, const char *h)
{
	if (regex_match(&regex_helo, h)) {
		log_warnx("filter-regex: on_helo: REJECT helo hostname id=%016"PRIx64, id);
		return filter_api_reject_code(id, FILTER_FAIL, 554, "5.7.1 Helo rejected");
	}
	return filter_api_accept(id);
}

static int
regex_on_mail(uint64_t id, struct mailaddr *m)
{
	if (regex_match(&regex_mail, filter_api_mailaddr_to_text(m))) {
		log_warnx("filter-regex: on_mail: REJECT mail from id=%016"PRIx64, id);
		return filter_api_reject_code(id, FILTER_FAIL, 554, "5.7.1 Sender rejected");
	}
	return filter_api_accept(id);
}

static int
regex_on_rcpt(uint64_t id, struct mailaddr *r)
{
	if (regex_match(&regex_rcpt, filter_api_mailaddr_to_text(r))) {
		log_warnx("filter-regex: on_rcpt: REJECT rcpt to id=%016"PRIx64, id);
		return filter_api_reject_code(id, FILTER_FAIL, 554, "5.7.1 Recipient rejected");
	}
	return filter_api_accept(id);
}

static void
regex_on_dataline(uint64_t id, const char *l)
{
	struct { int m; unsigned int l; } *u;

	filter_api_writeln(id, l);
	if ((u = filter_api_get_udata(id)) == NULL) {
		u = xcalloc(1, sizeof(*u), "filter-regex: on_dataline");
		filter_api_set_udata(id, u);
	}
	if (u->m || (regex_limit && ++u->l >= regex_limit))
		return;
	u->m = regex_match(&regex_dataline, l);
}

static int
regex_on_eom(uint64_t id, size_t size)
{
	int r, *m;

	if ((m = filter_api_get_udata(id)) == NULL)
		return filter_api_accept(id);
	r = *m, free(m), filter_api_set_udata(id, NULL);
	if (r) {
		log_warnx("filter-regex: on_eom: REJECT dataline id=%016"PRIx64, id);
		return filter_api_reject_code(id, FILTER_CLOSE, 554, "5.7.1 Message content rejected");
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
	const char *errstr, *l = NULL;

	log_init(-1);

	while ((ch = getopt(argc, argv, "l:")) != -1) {
		switch (ch) {
		case 'l':
			l = optarg;
			break;
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

	if (l) {
		regex_limit = strtonum(l, 1, UINT_MAX, &errstr);
		if (errstr)
			fatalx("filter-regex: limit option is %s: %s", errstr, l);
	}

	log_debug("debug: filter-regex: starting...");
	if (regex_load((argc == 1) ? argv[0] : REGEX_CONF) == -1)
		fatalx("filter-regex: configuration failed");

	filter_api_on_connect(regex_on_connect);
	filter_api_on_helo(regex_on_helo);
	filter_api_on_mail(regex_on_mail);
	filter_api_on_rcpt(regex_on_rcpt);
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
