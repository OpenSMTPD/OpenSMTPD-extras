/*
 * Copyright (c) 2015, Armin Wolfermann <armin@wolfermann.org>
 * Copyright (c) 2015, 2016 Joerg Jung <jung@openbsd.org>
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
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>
#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

#define REGEX_CONF SMTPD_CONFDIR "/filter-regex.conf"

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
static size_t regex_limit;

static int
regex_parse(char *l, size_t no)
{
	struct regex_q *rq = NULL;
	struct regex *re;
	char *k, buf[BUFSIZ];
	int i, r;

	l = strip(l);
	if ((k = strsep(&l, " \t")) == NULL || strlen(k) == 0 || *k == '#')
		return 0; /* skip empty or commented line */
	for (i = 0; regex_s[i].s != NULL && rq == NULL; i++)
		if (strcmp(k, regex_s[i].s) == 0)
			rq = regex_s[i].rq;
	if (rq == NULL) {
		log_warnx("warn: parse: unknown keyword %s line %lu", k, no);
		return -1;
	}
	if (strlen((l = strip(l))) == 0 || *l == '#') {
		log_warnx("warn: parse: missing value line %lu", no);
		return -1;
	}
	re = xcalloc(1, sizeof(struct regex), "parse");
	re->s = xstrdup(l, "parse");
	if ((re->n = (l[0] == '!' && isspace((unsigned char)l[1]))))
		l = strip(++l);
	if ((r = regcomp(&re->p, l, REG_EXTENDED|REG_NOSUB)) != 0) {
		regerror(r, &re->p, buf, sizeof(buf));
		log_warnx("warn: parse: regcomp %s line %lu", buf, no);
		free(re->s);
		free(re);
		return -1;
	}
	SIMPLEQ_INSERT_TAIL(rq, re, el);
	log_debug("debug: parse: %s %s line %lu", k, re->s, no);
	return 0;
}

static int
regex_load(const char *c)
{
	FILE *f;
	char *l = NULL;
	size_t sz = 0, no = 0;
	ssize_t len;

	if ((f = fopen(c, "r")) == NULL) {
		log_warn("warn: load: fopen %s", c);
		return -1;
	}
	while ((len = getline(&l, &sz, f)) != -1) {
		if (l[len - 1] == '\n')
			l[len - 1] = '\0';
		if (regex_parse(l, ++no) == -1) {
			free(l);
			fclose(f);
			return -1;
		}
	}
	if (ferror(f)) {
		log_warn("warn: load: getline");
		free(l);
		fclose(f);
		return -1;
	}
	free(l);
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
				log_warnx("warn: match: regexec %s", buf);
			}
			continue;
		}
		log_info("info: match: %s to %s", re->s, s);
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
			regfree(&re->p);
			free(re->s);
			free(re);
		}
	}
}

static int
regex_on_connect(uint64_t id, struct filter_connect *c)
{
	if (regex_match(&regex_connect, c->hostname)) {
		log_warnx("warn: session %016"PRIx64": on_connect: REJECT connect hostname", id);
		return filter_api_reject_code(id, FILTER_FAIL, 554, "5.7.1 Hostname rejected");
	}
	return filter_api_accept(id);
}

static int
regex_on_helo(uint64_t id, const char *h)
{
	if (regex_match(&regex_helo, h)) {
		log_warnx("warn: session %016"PRIx64": on_helo: REJECT helo hostname", id);
		return filter_api_reject_code(id, FILTER_FAIL, 554, "5.7.1 Helo rejected");
	}
	return filter_api_accept(id);
}

static int
regex_on_mail(uint64_t id, struct mailaddr *m)
{
	if (regex_match(&regex_mail, filter_api_mailaddr_to_text(m))) {
		log_warnx("warn: session %016"PRIx64": on_mail: REJECT mail from", id);
		return filter_api_reject_code(id, FILTER_FAIL, 554, "5.7.1 Sender rejected");
	}
	return filter_api_accept(id);
}

static int
regex_on_rcpt(uint64_t id, struct mailaddr *r)
{
	if (regex_match(&regex_rcpt, filter_api_mailaddr_to_text(r))) {
		log_warnx("warn: session %016"PRIx64": on_rcpt: REJECT rcpt to", id);
		return filter_api_reject_code(id, FILTER_FAIL, 554, "5.7.1 Recipient rejected");
	}
	return filter_api_accept(id);
}

static void
regex_on_dataline(uint64_t id, const char *l)
{
	struct { int m; size_t l; } *u;

	filter_api_writeln(id, l);
	if ((u = filter_api_get_udata(id)) == NULL) {
		u = xcalloc(1, sizeof(*u), "on_dataline");
		filter_api_set_udata(id, u);
	}
	u->l += strlen(l);
	if (u->m || (regex_limit && u->l >= regex_limit))
		return;
	u->m = regex_match(&regex_dataline, l);
}

static int
regex_on_eom(uint64_t id, size_t size)
{
	int *m;

	if ((m = filter_api_get_udata(id)) == NULL)
		return filter_api_accept(id);
	if (*m) {
		log_warnx("warn: session %016"PRIx64": on_eom: REJECT dataline", id);
		return filter_api_reject_code(id, FILTER_CLOSE, 554, "5.7.1 Message content rejected");
	}
	return filter_api_accept(id);
}

static void
regex_on_commit(uint64_t id)
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
	int ch, d = 0, v = 0;
	const char *errstr, *l = NULL;

	log_init(1);

	while ((ch = getopt(argc, argv, "dl:v")) != -1) {
		switch (ch) {
		case 'd':
			d = 1;
			break;
		case 'l':
			l = optarg;
			break;
		case 'v':
			v |= TRACE_DEBUG;
			break;
		default:
			log_warnx("warn: bad option");
			return 1;
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;
	if (argc > 1)
		fatalx("bogus argument(s)");

	if (l) {
		regex_limit = strtonum(l, 1, SIZE_MAX, &errstr);
		if (errstr)
			fatalx("limit option is %s: %s", errstr, l);
	}

	log_init(d);
	log_verbose(v);

	log_debug("debug: starting...");
	if (regex_load((argc == 1) ? argv[0] : REGEX_CONF) == -1)
		fatalx("configuration failed");

	filter_api_on_connect(regex_on_connect);
	filter_api_on_helo(regex_on_helo);
	filter_api_on_mail(regex_on_mail);
	filter_api_on_rcpt(regex_on_rcpt);
	filter_api_on_dataline(regex_on_dataline);
	filter_api_on_eom(regex_on_eom);
	filter_api_on_commit(regex_on_commit);
	filter_api_on_rollback(regex_on_rollback);

	filter_api_loop();
	regex_clear();
	log_debug("debug: exiting");

	return 1;
}
