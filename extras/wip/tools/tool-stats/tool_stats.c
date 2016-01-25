/*      $OpenBSD$   */

/*
 * Copyright (c) 2016 Joerg Jung <jung@openbsd.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <limits.h>
#include <sys/types.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"

#define STATS_YR "2016"
#define STATS_TOP 5

struct stats {
	struct { time_t first, last, time; } ts;
	struct { size_t master, mda, mta, smtp; } restart;
	struct { size_t in, relay, delivery, reject, size; } total;
	struct { struct { size_t connect, helo, mail, rcpt, dataline; } regex;
		 size_t dnsbl, spam, virus; } filter;
	struct { struct dict id, status, error, from, to, host, relay; } top;
};

static unsigned long
stats_round(double d) {
	if (d < 0 || d > ULONG_MAX - 0.5)
		errx(1, "ulong overflow");
	return (unsigned long)(d + 0.5); /* half round up */
}

static char *
stats_skip(char *l)
{
	while (isspace((unsigned char)*l))
		l++;
	return l;
}

static char *
stats_tok(char **l, size_t no, const char *e) {
	char *t;

	if (!(t = strsep(l, " ")) || !strlen(t) || (e && strcmp(t, e))) {
		e ? warnx("token %s failed line %lu", e, no) :
		    warnx("token failed line %lu", no);
		return NULL;
	}
	return t;
}

static char *
stats_kv(char **l, size_t no, const char *e)
{
	char *k, *v;

	if (!(k = strsep(l, "=")) || !strlen(k) || strcmp(k, e)) {
		warnx("key %s failed line %lu", e, no);
		return NULL;
	}
	if (!(v = strsep(l, ",")) || !strlen(v)) {
		warnx("value failed line %lu", no);
		return NULL;
	}
	return v;
}

static void
stats_init(struct stats *s)
{
	s->ts.first = s->ts.last = -1;
	dict_init(&s->top.id);
	dict_init(&s->top.status);
	dict_init(&s->top.error);
	dict_init(&s->top.from);
	dict_init(&s->top.to);
	dict_init(&s->top.host);
	dict_init(&s->top.relay);
}

static void
stats_in(struct stats *s, char *l, size_t no)
{
	const char *e;
	char *id, *v;
	size_t *p, n;

	if (strncmp(l, "New session", 11) &&
	    strncmp(l, "Accepted message", 16) &&
	    strncmp(l, "Closing session", 15))
		return;

	if (!(v = stats_tok(&l, no, NULL)))
		return;

	if (!(l = strstr(l, "session")) || !stats_tok(&l, no, "session") ||
	    !(id = stats_tok(&l, no, NULL)))
		return;
	id[strcspn(id, ":")] = '\0';

	if (!strcmp(v, "New")) {
		if (!stats_tok(&l, no, "from") || !stats_tok(&l, no, "host"))
			return;
		dict_xset(&s->top.id, id, xstrdup(l, "in"));
	} else if (!strcmp(v, "Accepted")) { /* todo: parse and count errors and failures? */
		if (!(v = stats_kv(&l, no, "from")))
			return;
		if (!(p = dict_get(&s->top.from, v)))
			dict_xset(&s->top.from, v, (p = xcalloc(1, sizeof(size_t), "in")));
		(*p)++;

		l = stats_skip(l);
		if (!(v = stats_kv(&l, no, "to")))
			return;
		if (!(p = dict_get(&s->top.to, v)))
			dict_xset(&s->top.to, v, (p = xcalloc(1, sizeof(size_t), "in")));
		(*p)++;

		l = stats_skip(l);
		if (!(v = stats_kv(&l, no, "size")))
			return;
		n = strtonum(v, 0, UINT_MAX, &e); /* todo: SIZE_MAX here? */
		if (e) {
			warnx("size value is %s: %s line %lu", e, v, no);
			return;
		}
		s->total.size += n;

		if (!(v = dict_get(&s->top.id, id))) {
			warnx("session failed line %lu", no);
			return;
		}
		if (!(p = dict_get(&s->top.host, v)))
			dict_xset(&s->top.host, v, (p = xcalloc(1, sizeof(size_t), "in")));
		(*p)++;

		s->total.in++;
	} else if (!strcmp(v, "Closing"))
		free(dict_pop(&s->top.host, id));
}

static void
stats_relay(struct stats *s, char *l, size_t no )
{
	const char *v;
	size_t *p;

	if (!(v = stats_tok(&l, no, NULL)))
		return;
	if (!(p = dict_get(&s->top.status, v)))
		dict_xset(&s->top.status, v, (p = xcalloc(1, sizeof(size_t), "relay")));
	(*p)++;
	if (!strcmp(v, "Ok")) {
		if (!(l = strstr(l, "relay="))) {
			warnx("relay failed line %lu", no);
			return;
		}
		if (!(v = stats_kv(&l, no, "relay")))
			return;
		if (!(p = dict_get(&s->top.relay, v)))
			dict_xset(&s->top.relay, v, (p = xcalloc(1, sizeof(size_t), "relay")));
		(*p)++;

		s->total.relay++;
		return;
	}
	if (!(l = strstr(l, "stat="))) {
		warnx("status failed line %lu", no);
		return;
	}
	v = l + 5; /* stat until EOL may contain commas and spaces */
	if (!(p = dict_get(&s->top.error, v)))
		dict_xset(&s->top.error, v, (p = xcalloc(1, sizeof(size_t), "relay")));
	(*p)++;
}

static void
stats_delivery(struct stats *s, char *l, size_t no)
{
	const char *v;
	size_t *p;

	if (!(v = stats_tok(&l, no, NULL)))
		return;
	if (!(p = dict_get(&s->top.status, v)))
		dict_xset(&s->top.status, v, (p = xcalloc(1, sizeof(size_t), "delivery")));
	(*p)++;
	if (!strcmp(v, "Ok")) {
		s->total.delivery++;
		return;
	}
	if (!(l = strstr(l, "stat="))) {
		warnx("status failed line %lu", no);
		return;
	}
	v = l + 5; /* stat until EOL may contain commas and spaces */
	if (!(p = dict_get(&s->top.error, v)))
		dict_xset(&s->top.error, v, (p = xcalloc(1, sizeof(size_t), "delivery")));
	(*p)++;
}

static void
stats_restart(struct stats *s, char *l, size_t no)
{
	if (!strncmp(l, "OpenSMTPD", 9) && strstr(l, "starting"))
		s->restart.master++;
	else if (!strcmp(l, "mta resumed"))
		s->restart.mta++;
	else if (!strcmp(l, "mda resumed"))
		s->restart.mda++;
	else if (!strcmp(l, "smtp resumed"))
		s->restart.smtp++;
}

static void
stats_smtpd(struct stats *s, char *l, size_t no)
{
	const char *t;

	if (!(t = stats_tok(&l, no, NULL)))
		return;
	if (!strcmp(t, "smtp-in:"))
		stats_in(s, l, no);
	else if (!strcmp(t, "relay:"))
		stats_relay(s, l, no);
	else if (!strcmp(t, "delivery:"))
		stats_delivery(s, l, no);
	else
		stats_restart(s, l, no);
}

static void
stats_filter(struct stats *s, char *l, size_t no, const char *p)
{
	if (!strncmp(p, "filter-dkim-signer", 18)) {
		/* todo */
	} else if (!strncmp(p, "filter-dnsbl", 12)) {
		if (strstr(l, "REJECT address"))
			s->filter.dnsbl++;
	} else if (!strncmp(p, "filter-regex", 12)) {
		if (strstr(l, "REJECT connect"))
			s->filter.regex.connect++;
		else if (strstr(l, "REJECT helo"))
			s->filter.regex.helo++;
		else if (strstr(l, "REJECT mail"))
			s->filter.regex.mail++;
		else if (strstr(l, "REJECT rcpt"))
			s->filter.regex.rcpt++;
		else if (strstr(l, "REJECT dataline"))
			s->filter.regex.dataline++;
	} else if (!strncmp(p, "filter-spamassassin", 19)) {
		if (strstr(l, "ACCEPT spam") || strstr(l, "REJECT spam"))
			s->filter.spam++;
	} else if (!strncmp(p, "filter-clamav", 13)) {
		if (strstr(l, "REJECT virus"))
			s->filter.virus++;
	}
}

static void
stats_line(struct stats *s, char *l, size_t no)
{
	struct tm t = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL};
	time_t ts;
	const char *p;

	if (!(l = strptime(l, "%b %d %T ", &t))) {
		warn("strptime failed line %lu", no);
		return;
	}
	if ((ts = mktime(&t)) == -1) {
		warn("mktime failed line %lu", no);
		return;
	}
	if (s->ts.first == -1 || ts < s->ts.first)
		s->ts.first = ts;
	if (s->ts.last == -1 || ts > s->ts.last)
		s->ts.last = ts;

	/* skip host, no support for multiple hosts */
	if (!stats_tok(&l, no, NULL) || !(p = stats_tok(&l, no, NULL)))
		return;
	if (!strncmp(p, "smtpd[", 6))
		stats_smtpd(s, l, no);
	else if (!strncmp(p, "filter-", 7))
		stats_filter(s, l, no, p);
}

static void
stats_read(struct stats *ls, FILE *f)
{
	char *l = NULL;
	size_t sz = 0, no = 0;
	ssize_t len;

	while ((len = getline(&l, &sz, f)) != -1) {
		if (l[len - 1] == '\n')
			l[len - 1] = '\0';
		stats_line(ls, l, ++no);
	}
	free(l);
	if (ferror(f))
		err(1, "getline");
}

static void
stats_top(struct dict *d)
{
	const char *k, *max_k;
	size_t *v, max_v, t = 0, n;
	double p;
	void *i;

	for (n = 0; n < STATS_TOP; n++) { /* this can be optimized */
		i = NULL, max_k = NULL, max_v = 0;
		while (dict_iter(d, &i, &k, (void **)&v)) {
			if (!max_k || *v > max_v )
				max_k = k, max_v = *v;
			if (!n)
				t += *v;
		}
		if (max_k) {
			p = (max_v / (double)t) * 100;
			printf("+%.*s%.*s %5.1f%% %4lu %.52s%s\n",
			    (int)stats_round(p / 10), "----------",
			    10 - (int)stats_round(p / 10), "          ",
			    p, max_v, max_k, (strlen(max_k) > 52) ? "..." : "");
			dict_xpop(d, max_k);
		}
	}
}

#define STATS_KILO (1024)
#define STATS_MEGA (1024 * 1024)
#define STATS_GIGA (1024 * 1024 * 1024)

static void
stats_byte(double b) {
	if (b > STATS_GIGA)
		printf("%.2f gbytes", b / STATS_GIGA);
	else if (b > STATS_MEGA)
		printf("%.2f mbytes", b / STATS_MEGA);
	else if (b > STATS_KILO)
		printf("%.2f kbytes", b / STATS_KILO);
	else
		printf("%.2f bytes", b);
}

static void
stats_print(struct stats *s)
{
	char first[20], last[20];

	strftime(first, 20, "%a %b %d %H:%M:%S", localtime(&s->ts.first));
	strftime(last, 20, "%a %b %d %H:%M:%S", localtime(&s->ts.last));
	s->ts.time = s->ts.last - s->ts.first;
	s->total.reject = s->filter.dnsbl + s->filter.spam + s->filter.virus +
	    s->filter.regex.connect + s->filter.regex.helo +
	    s->filter.regex.mail + s->filter.regex.rcpt +
	    s->filter.regex.dataline;
	puts("tool-stats - smtpd log statistics (c) "STATS_YR" Joerg Jung\n");
	printf("%s - %s\n\n", first, last);
	printf("%-11s master: %lu mda: %lu mta: %lu smtp: %lu\n", "Restarts:",
	    s->restart.master, s->restart.mda, s->restart.mta, s->restart.smtp);
	printf("%-11s in: %lu relay: %lu deliver: %lu reject: %lu\n", "Messages:",
	    s->total.in, s->total.relay, s->total.delivery, s->total.reject);
	printf("%-11s %.2f mails/hour ", "Throughput:",
	    s->total.in / (s->ts.time / (double)3600));
	stats_byte(s->total.size / (s->ts.time / (double)3600));
	puts("/hour\n\nFilters\n");
	printf("%-11s %lu\n", "DNSBL:", s->filter.dnsbl);
	printf("%-11s connect: %lu helo: %lu mail: %lu rcpt: %lu dataline: %lu\n",
	    "Regex:", s->filter.regex.connect, s->filter.regex.helo,
	    s->filter.regex.mail, s->filter.regex.rcpt, s->filter.regex.dataline);
	printf("%-11s %lu\n", "Spam:", s->filter.spam);
	printf("%-11s %lu\n", "Virus:", s->filter.virus);
	puts("\nStatuses\n");
	stats_top(&s->top.status);
	puts("\nErrors\n");
	stats_top(&s->top.error);
	puts("\nSender\n");
	stats_top(&s->top.from);
	puts("\nRecipients\n");
	stats_top(&s->top.to);
	puts("\nHosts\n");
	stats_top(&s->top.host);
	puts("\nRelays\n");
	stats_top(&s->top.relay);
}

static void
stats_clear(struct stats *s)
{
	size_t *v;

	while (dict_poproot(&s->top.id, (void **)&v))
		free(v);
	while (dict_poproot(&s->top.status, (void **)&v))
		free(v);
	while (dict_poproot(&s->top.error, (void **)&v))
		free(v);
	while (dict_poproot(&s->top.from, (void **)&v))
		free(v);
	while (dict_poproot(&s->top.to, (void **)&v))
		free(v);
	while (dict_poproot(&s->top.host, (void **)&v))
		free(v);
	while (dict_poproot(&s->top.relay, (void **)&v))
		free(v);
	free(s);
}

int
main(int argc, char **argv)
{
	int ch;
	FILE *f;
	struct stats *s;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			errx(1, "bad option");
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	s = xcalloc(1, sizeof(struct stats), "main");
	stats_init(s);

	if (argc) {
		for (; *argv; ++argv) {
			if (!(f = fopen(*argv, "r")))
				err(1, "fopen");
			stats_read(s, f);
			fclose(f);
		}
	} else
		stats_read(s, stdin);

	stats_print(s);
	stats_clear(s);
	return 0;
}
