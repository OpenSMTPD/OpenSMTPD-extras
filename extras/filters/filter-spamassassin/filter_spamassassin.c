/*      $OpenBSD$   */

/*
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

#include <sys/types.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"
#include "iobuf.h"

#define SPAMASSASSIN_HOST "127.0.0.1"
#define SPAMASSASSIN_PORT "783"

struct spamassassin {
	int fd, r;
	struct iobuf iobuf;
};

static enum { SPAMASSASSIN_ACCEPT, SPAMASSASSIN_REJECT } spamassassin_strategy;

static int
spamassassin_init(struct spamassassin *sa)
{
	sa->fd = sa->r = -1;
	if (iobuf_init(&sa->iobuf, LINE_MAX, LINE_MAX) == -1) {
		log_warnx("filter-spamassassin: init iobuf_init");
		return -1;
	}
	return 0;
}

static int
spamassassin_open(struct spamassassin *sa)
{
	struct addrinfo hints, *addresses, *ai;
	int r;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
	if ((r = getaddrinfo(SPAMASSASSIN_HOST, SPAMASSASSIN_PORT, &hints, &addresses))) {
		log_warnx("warn: filer-spamassassin: open: getaddrinfo %s", gai_strerror(r));
		return -1;
	}
	for (ai = addresses; ai; ai = ai->ai_next) {
		if ((sa->fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1)
			continue;
		if (connect(sa->fd, ai->ai_addr, ai->ai_addrlen) == -1) {
			close(sa->fd);
			sa->fd = -1;
			continue;
		}
		break; /* connected */
	}
	freeaddrinfo(addresses);
	if (!ai) {
		log_warnx("warn: filer-spamassassin: open: failed");
		return -1;
	}
	return 0;
}

static int
spamassassin_write(struct spamassassin *sa, const char *l) {
	size_t len = strlen(l) + 1;

	if (iobuf_fqueue(&sa->iobuf, "%s\n", l) != (int)len) {
		log_warn("warn: filer-spamassassin: write iobuf_fqueue");
		return -1;
	}
	if (iobuf_flush(&sa->iobuf, sa->fd) < 0) {
		log_warn("warn: filer-spamassassin: write iobuf_flush");
		return -1;
	}
	return 0;
}

static int
spamassassin_request(struct spamassassin *sa) {
	return spamassassin_write(sa, "PROCESS SPAMC/1.5\r\n\r"); /* spamd.raw source: content length header is optional */
}

static int
spamassassin_read(struct spamassassin *sa, char **l) {
	int r;

	while ((*l = iobuf_getline(&sa->iobuf, NULL)) == NULL) {
		if (iobuf_len(&sa->iobuf) >= LINE_MAX) {
			log_warnx("warn: filer-spamassassin: read iobuf_getline");
			return -1;
		}
		iobuf_normalize(&sa->iobuf);
		if ((r = iobuf_read(&sa->iobuf, sa->fd)) < 0) {
			if (r != IOBUF_CLOSED)
				log_warn("warn: filer-spamassassin: read iobuf_read r=%d", r);
			return r;
		}
	}
	return 0;
}

#define SPAMASSASSIN_EXPAND(tok) #tok
#define SPAMASSASSIN_QUOTE(tok) SPAMASSASSIN_EXPAND(tok)
#define SPAMASSASSIN_EX_MAX 16 /* longest spamd response e.g. strlen("EX_UNAVAILABLE") */

static int
spamassassin_status(struct spamassassin *sa, const char *l) {
	char s[SPAMASSASSIN_EX_MAX + 1];
	int r;

	if (sscanf(l, "SPAMD/%*d.%*d %d %"SPAMASSASSIN_QUOTE(SPAMASSASSIN_EX_MAX)"s", &r, s) != 2) {
		(errno ? log_warn : log_warnx)("warn: filer-spamassassin: status sscanf");
		return -1;
	}
	if (r != 0 || strcmp(s, "EX_OK") != 0) {
		log_warnx("warn: filer-spamassassin: status r=%d, s=%s", r, s);
		return -1;
	}
	return 0;
}

static int
spamassassin_result(struct spamassassin *sa, const char *l) {
	char s[SPAMASSASSIN_EX_MAX + 1];

	if (sscanf(l, "Spam: %"SPAMASSASSIN_QUOTE(SPAMASSASSIN_EX_MAX)"s ; %*f / %*f", s) != 1) {
		(errno ? log_warn : log_warnx)("warn: filer-spamassassin: result sscanf");
		return -1;
	}
	log_info("info: filter-spamassassin: result %s", l);
	sa->r = (strcmp(s, "True") == 0);
	return 0;
}

static int
spamassassin_header(struct spamassassin *sa) {
	char *l = NULL;

	if (spamassassin_read(sa, &l) != 0)
		return -1;
	if (spamassassin_status(sa, l) == -1)
		return -1;
	while (1) {
		if (spamassassin_read(sa, &l) != 0)
			return -1;
		if (strncmp(l, "Spam: ", 6) == 0 &&
		    spamassassin_result(sa, l) == -1)
			return -1;
		if (strlen(l) == 0)
			break; /* end of spamd response headers */
	}
	if (sa->r == -1) {
		log_warnx("warn: filer-spamassassin: header result failed");
		return -1;
	}
	return 0;
}

static int
spamassassin_message(struct spamassassin *sa, uint64_t id) {
	char *l = NULL;
	int r;

	while (1) {
		if ((r = spamassassin_read(sa, &l)) != 0) {
			if (r == IOBUF_CLOSED)
				break;
			return -1;
		}
		if (l)
			filter_api_writeln(id, l);
	}
	if (iobuf_len(&sa->iobuf)) {
		log_warnx("warn: filer-spamassassin: message incomplete");
		return -1;
	}
	return 0;
}

static int
spamassassin_response(struct spamassassin *sa, uint64_t id) {
	if (shutdown(sa->fd, SHUT_WR) == -1) {
		log_warn("warn: filer-spamassassin: shutdown");
		return -1;
	}
	if (spamassassin_header(sa) == -1)
		return -1;
	if (spamassassin_message(sa, id) == -1)
		return -1;
	return 0;
}

static void
spamassassin_close(struct spamassassin *sa)
{
	if (sa->fd >= 0)
		close(sa->fd);
	sa->fd = -1;
}

static void
spamassassin_clear(struct spamassassin *sa)
{
	if (sa == NULL)
		return;
	iobuf_clear(&sa->iobuf);
	spamassassin_close(sa);
	free(sa);
}

static int
spamassassin_on_data(uint64_t id)
{
	struct spamassassin *sa;

	sa = xcalloc(1, sizeof(struct spamassassin), "filter-spamassassin: on_data");
	if (spamassassin_init(sa) == -1) {
		spamassassin_clear(sa);
		return filter_api_accept(id);
	}
	if (spamassassin_open(sa) == -1) {
		spamassassin_clear(sa);
		return filter_api_accept(id);
	}
	if (spamassassin_request(sa) == -1) {
		spamassassin_clear(sa);
		return filter_api_accept(id);
	}
	filter_api_set_udata(id, sa);
	return filter_api_accept(id);
}

static void
spamassassin_on_dataline(uint64_t id, const char *l)
{
	struct spamassassin *sa;

	if ((sa = filter_api_get_udata(id)) == NULL) {
		filter_api_writeln(id, l);
		return;
	}
	if (sa->fd >= 0 && spamassassin_write(sa, l) == -1)
		spamassassin_close(sa);
}

static int
spamassassin_on_eom(uint64_t id, size_t size)
{
	struct spamassassin *sa;
	int r;

	if ((sa = filter_api_get_udata(id)) == NULL)
		return filter_api_accept(id);
	if (spamassassin_response(sa, id) == -1) {
		spamassassin_clear(sa);
		filter_api_set_udata(id, NULL);
		return filter_api_reject_code(id, FILTER_FAIL, 451, "4.7.1 Spam filter failed");
	}
	r = sa->r;
	spamassassin_clear(sa);
	filter_api_set_udata(id, NULL);
	if (r) {
		if (spamassassin_strategy == SPAMASSASSIN_ACCEPT) {
			log_warnx("warn: spamassassin_filter: on_eom: ACCEPT spam id=%016"PRIx64, id);
			return filter_api_accept(id);
		}
		if (spamassassin_strategy == SPAMASSASSIN_REJECT) {
			log_warnx("warn: spamassassin_filter: on_eom: REJECT spam id=%016"PRIx64, id);
			return filter_api_reject_code(id, FILTER_CLOSE, 554, "5.7.1 Message considered spam");
		}
	}
	return filter_api_accept(id);
}

static void
spamassassin_on_reset(uint64_t id)
{
	spamassassin_clear(filter_api_get_udata(id));
	filter_api_set_udata(id, NULL);
}

static void
spamassassin_on_disconnect(uint64_t id)
{
	spamassassin_clear(filter_api_get_udata(id));
	filter_api_set_udata(id, NULL);
}

static void
spamassassin_on_rollback(uint64_t id)
{
	spamassassin_clear(filter_api_get_udata(id));
	filter_api_set_udata(id, NULL);
}

int
main(int argc, char **argv)
{
	int	ch;
	const char *s = NULL;

	log_init(-1);

	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
			s = optarg;
			break;
		default:
			log_warnx("warn: filter-spamassassin: bad option");
			return (1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (s) {
		while (isspace((unsigned char)*s))
			s++;
		if (strncmp(s, "accept", 6) == 0)
			spamassassin_strategy = SPAMASSASSIN_ACCEPT;
		else if (strncmp(s, "reject", 6) == 0)
			spamassassin_strategy = SPAMASSASSIN_REJECT;
		else
			fatalx("filter-spamassassin: bad strategy");
	}

	log_debug("debug: filter-spamassassin: starting...");

	filter_api_on_data(spamassassin_on_data);
	filter_api_on_dataline(spamassassin_on_dataline);
	filter_api_on_eom(spamassassin_on_eom);
	filter_api_on_reset(spamassassin_on_reset);
	filter_api_on_disconnect(spamassassin_on_disconnect);
	filter_api_on_rollback(spamassassin_on_rollback);

	filter_api_loop();
	log_debug("debug: filter-spamassassin: exiting");

	return (1);
}
