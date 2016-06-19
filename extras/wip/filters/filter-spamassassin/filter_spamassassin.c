/*
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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"
#include "iobuf.h"
#include "ioev.h"

#define SPAMASSASSIN_HOST "127.0.0.1"
#define SPAMASSASSIN_PORT "783"

struct spamassassin {
	uint64_t id;
	struct iobuf iobuf;
	struct io io;
	size_t l;
	int r;
	enum { SA_DATA, SA_EOM, SA_STA, SA_HDR, SA_MSG } s;
};

static struct sockaddr_storage spamassassin_ss;
static size_t spamassassin_limit;
static enum { SPAMASSASSIN_ACCEPT, SPAMASSASSIN_REJECT } spamassassin_strategy;

static void
spamassassin_clear(struct spamassassin *sa)
{
	if (sa == NULL)
		return;
	io_clear(&sa->io);
	iobuf_clear(&sa->iobuf);
	free(sa);
}

static int
spamassassin_result(struct spamassassin *sa)
{
	if (sa->r == INT_MIN) {
		log_warnx("warn: result: failed");
		return -1;
	}
	if (sa->r) {
		if (spamassassin_strategy == SPAMASSASSIN_ACCEPT) {
			log_warnx("warn: session %016"PRIx64": result: ACCEPT spam", sa->id);
			filter_api_accept(sa->id);
		}
		if (spamassassin_strategy == SPAMASSASSIN_REJECT) {
			log_warnx("warn: session %016"PRIx64": result: REJECT spam", sa->id);
			filter_api_reject_code(sa->id, FILTER_CLOSE, 554, "5.7.1 Message considered spam");
		}
	}
	return filter_api_accept(sa->id);
}

#define SPAMASSASSIN_EXPAND(tok) #tok
#define SPAMASSASSIN_QUOTE(tok) SPAMASSASSIN_EXPAND(tok)
#define SPAMASSASSIN_EX_MAX 16 /* longest spamd response e.g. strlen("EX_UNAVAILABLE") */

static int
spamassassin_status(struct spamassassin *sa, const char *l)
{
	char s[SPAMASSASSIN_EX_MAX + 1];
	int r;

	if (sscanf(l, "SPAMD/%*d.%*d %d %"SPAMASSASSIN_QUOTE(SPAMASSASSIN_EX_MAX)"s", &r, s) != 2) {
		(errno ? log_warn : log_warnx)("warn: status: sscanf");
		return -1;
	}
	if (r != 0 || strcmp(s, "EX_OK") != 0) {
		log_warnx("warn: status: r=%d, s=%s", r, s);
		return -1;
	}
	return sa->s++;
}

static int
spamassassin_header(struct spamassassin *sa, const char *l)
{
	char s[SPAMASSASSIN_EX_MAX + 1];

	if (strlen(l) == 0)
		return sa->s++; /* end of spamd response headers */
	if (strncmp(l, "Spam: ", 6) == 0) {
		if (sscanf(l, "Spam: %"SPAMASSASSIN_QUOTE(SPAMASSASSIN_EX_MAX)"s ; %*f / %*f", s) != 1) {
			(errno ? log_warn : log_warnx)("warn: result: sscanf");
			return -1;
		}
		log_info("info: result: %s", l);
		sa->r = (strcmp(s, "True") == 0);
	}
	return 0;
}

static int
spamassassin_response(struct spamassassin *sa, const char *l)
{
	switch (sa->s) {
	case SA_STA:
		if (spamassassin_status(sa, l) == -1)
			return -1;
		break;
	case SA_HDR:
		if (spamassassin_header(sa, l) == -1)
			return -1;
		break;
	case SA_MSG:
		filter_api_writeln(sa->id, l);
		break;
	default:
		fatalx("response: bad state");
	}
	return 0;
}

static void
spamassassin_io(struct io *io, int evt)
{
	struct spamassassin *sa = io->arg;
	char *l;

	switch (evt) {
	case IO_CONNECTED:
		io_set_write(io);
		break;
	case IO_LOWAT:
		if (sa->s == SA_EOM) {
			if (shutdown(sa->io.sock, SHUT_WR) == -1) {
				log_warn("warn: io: shutdown");
				goto fail;
			}
			sa->s++;
			io_set_read(io);
		}
		break;
	case IO_DATAIN:
		while ((l = iobuf_getline(&sa->iobuf, NULL))) {
			if (iobuf_len(&sa->iobuf) >= LINE_MAX) {
				log_warnx("warn: io: iobuf_getline");
				goto fail;
			}
			if (spamassassin_response(sa, l) == -1)
				goto fail;
		}
		iobuf_normalize(&sa->iobuf);
		break;
	case IO_DISCONNECTED:
		if (sa->s == SA_MSG) {
			if (iobuf_len(&sa->iobuf)) {
				log_warnx("warn: io: incomplete");
				goto fail;
			}
			if (spamassassin_result(sa) == -1)
				goto fail;
			io_clear(io);
			break;
		} /* FALLTHROUGH */
	case IO_TIMEOUT:
	case IO_ERROR:
		log_warnx("warn: io: %s %s", io_strevent(evt), sa->io.error);
		goto fail;
	default:
		fatalx("io: bad event");
	}
	return;
fail:
	filter_api_reject_code(sa->id, FILTER_FAIL, 451, "4.7.1 Spam filter failed");
	filter_api_set_udata(sa->id, NULL);
	spamassassin_clear(sa);
}

static void
spamassassin_init(struct spamassassin *sa, uint64_t id)
{
	iobuf_xinit(&sa->iobuf, LINE_MAX, LINE_MAX, "init");
	io_init(&sa->io, -1, sa, spamassassin_io, &sa->iobuf);
	sa->id = id;
	sa->r = INT_MIN;
}

static int
spamassassin_on_data(uint64_t id)
{
	struct spamassassin *sa;

	spamassassin_init((sa = xcalloc(1, sizeof(struct spamassassin), "on_data")), id);
	if (io_connect(&sa->io, (struct sockaddr *)&spamassassin_ss, NULL) == -1) {
		log_warnx("warn: on_data: io_connect %s", sa->io.error);
		spamassassin_clear(sa);
		return filter_api_accept(id);
	}
	iobuf_xfqueue(&sa->iobuf, "io", "PROCESS SPAMC/1.5\r\n\r\n"); /* spamd.raw source: content length header is optional */
	if (spamassassin_limit)
		io_pause(&sa->io, IO_PAUSE_OUT); /* pause io until eom or limit is reached */
	filter_api_set_udata(id, sa);
	return filter_api_accept(id);
}

static void
spamassassin_on_dataline(uint64_t id, const char *l)
{
	struct spamassassin *sa;
	struct ioqbuf *q;

	if ((sa = filter_api_get_udata(id)) == NULL) {
		filter_api_writeln(id, l);
		return;
	}
	sa->l += strlen(l);
	if (spamassassin_limit && sa->l >= spamassassin_limit) {
		write(sa->io.sock, "SKIP SPAMC/1.5\r\n\r\n", 18);
		if (iobuf_queued(&sa->iobuf)) { /* get lines back, but skip first request line */
			for (q = sa->iobuf.outq->next; q; q = q->next) {
				q->buf[q->wpos - q->rpos - 1] = '\0';
				filter_api_writeln(id, q->buf + q->rpos);
			}
		}
		filter_api_writeln(id, l);
		spamassassin_clear(sa);
		filter_api_set_udata(id, NULL);
		return;
	}
	iobuf_xfqueue(&sa->iobuf, "on_dataline", "%s\n", l);
        io_reload(&sa->io);
}

static int
spamassassin_on_eom(uint64_t id, size_t size)
{
	struct spamassassin *sa;

	if ((sa = filter_api_get_udata(id)) == NULL)
		return filter_api_accept(id);
	if (spamassassin_limit)
		io_resume(&sa->io, IO_PAUSE_OUT);
	sa->s++;
	if (iobuf_queued(&sa->iobuf) == 0)
		spamassassin_io(&sa->io, IO_LOWAT);
	return 1; /* defer accept or reject */
}

static void
spamassassin_on_commit(uint64_t id)
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

static void
spamassassin_resolve(const char *h, const char *p)
{
	struct addrinfo hints, *addresses, *ai;
	int fd, r;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	if ((r = getaddrinfo(h, p, &hints, &addresses)))
		fatalx("resolve: getaddrinfo %s", gai_strerror(r));
	for (ai = addresses; ai; ai = ai->ai_next) {
		if ((fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1)
			continue;
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == -1) {
			close(fd);
			continue;
		}
		write(fd, "PING SPAMC/1.5\r\n\r\n", 18); /* avoid warning in log */
		close(fd);
		memmove(&spamassassin_ss, ai->ai_addr, ai->ai_addrlen);
		break;
	}
	freeaddrinfo(addresses);
	if (!ai)
		fatalx("resolve: failed");
}

int
main(int argc, char **argv)
{
	int ch, C = 0, d = 0, v = 0;
	const char *errstr, *l = NULL;
	char *c = NULL, *h = SPAMASSASSIN_HOST, *p = SPAMASSASSIN_PORT, *s = NULL;

	log_init(1);

	while ((ch = getopt(argc, argv, "dh:l:p:s:v")) != -1) {
		switch (ch) {
		case 'C':
			C = 1;
			break;
		case 'c':
			c = optarg;
			break;
		case 'd':
			d = 1;
			break;
		case 'h':
			h = optarg;
			break;
		case 'l':
			l = optarg;
			break;
		case 'p':
			p = optarg;
			break;
		case 's':
			s = optarg;
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

	if (c)
		c = strip(c);
	if (h)
		h = strip(h);
	if (p)
		p = strip(p);
	if (l) {
		spamassassin_limit = strtonum(l, 1, UINT_MAX, &errstr); /* todo: SIZE_MAX here? */
		if (errstr)
			fatalx("limit option is %s: %s", errstr, l);
	}
	if (s) {
		s = strip(s);
		if (strncmp(s, "accept", 6) == 0)
			spamassassin_strategy = SPAMASSASSIN_ACCEPT;
		else if (strncmp(s, "reject", 6) == 0)
			spamassassin_strategy = SPAMASSASSIN_REJECT;
		else
			fatalx("bad strategy");
	}

	log_init(d);
	log_verbose(v);

	log_debug("debug: starting...");
	spamassassin_resolve(h, p);

	filter_api_on_data(spamassassin_on_data);
	filter_api_on_dataline(spamassassin_on_dataline);
	filter_api_on_eom(spamassassin_on_eom);
	filter_api_on_commit(spamassassin_on_commit);
	filter_api_on_rollback(spamassassin_on_rollback);
	if (c)
		filter_api_set_chroot(c);
	if (C)
		filter_api_no_chroot();

	filter_api_loop();
	log_debug("debug: exiting");

	return 1;
}
