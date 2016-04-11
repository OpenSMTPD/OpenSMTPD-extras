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
#include <arpa/inet.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"
#include "iobuf.h"

#define CLAMAV_HOST "127.0.0.1"
#define CLAMAV_PORT "3310"

struct clamav {
	int fd, r;
	struct iobuf iobuf;
};

static int
clamav_init(struct clamav *cl)
{
	cl->fd = cl->r = -1;
	if (iobuf_init(&cl->iobuf, LINE_MAX, LINE_MAX) == -1) {
		log_warnx("warn: init: iobuf_init");
		return -1;
	}
	return 0;
}

static int
clamav_open(struct clamav *cl)
{
	struct addrinfo hints, *addresses, *ai;
	int r;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV; /* avoid failing name resolution in chroot() */
	if ((r = getaddrinfo(CLAMAV_HOST, CLAMAV_PORT, &hints, &addresses))) {
		log_warnx("warn: open: getaddrinfo %s", gai_strerror(r));
		return -1;
	}
	for (ai = addresses; ai; ai = ai->ai_next) {
		if ((cl->fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1)
			continue;
		if (connect(cl->fd, ai->ai_addr, ai->ai_addrlen) == -1) {
			close(cl->fd);
			cl->fd = -1;
			continue;
		}
		break; /* connected */
	}
	freeaddrinfo(addresses);
	if (!ai) {
		log_warnx("warn: open: failed");
		return -1;
	}
	return 0;
}

static int
clamav_write(struct clamav *cl, const char *l, int f) {
	size_t len = (f == EOF) ? 0 : strlen(l) + 1;
	uint32_t n = htonl(len);

	if (f && iobuf_queue(&cl->iobuf, &n, sizeof(uint32_t)) != (int)sizeof(uint32_t)) {
		log_warn("warn: write: iobuf_queue");
		return -1;
	}
	if (f != EOF && iobuf_fqueue(&cl->iobuf, "%s\n", l) != (int)len) {
		log_warn("warn: write: iobuf_fqueue");
		return -1;
	}
	if (iobuf_flush(&cl->iobuf, cl->fd) < 0) {
		log_warn("warn: write: iobuf_flush");
		return -1;
	}
	return 0;
}

static int
clamav_request(struct clamav *cl) {
	return clamav_write(cl, "nINSTREAM", 0);
}

static int
clamav_read(struct clamav *cl, char **l) {
	int r;

	while ((*l = iobuf_getline(&cl->iobuf, NULL)) == NULL) {
		if (iobuf_len(&cl->iobuf) >= LINE_MAX) {
			log_warnx("warn: read: iobuf_getline");
			return -1;
		}
		iobuf_normalize(&cl->iobuf);
		if ((r = iobuf_read(&cl->iobuf, cl->fd)) < 0) {
			if (r != IOBUF_CLOSED)
				log_warn("warn: read: iobuf_read r=%d", r);
			return r;
		}
	}
	return 0;
}

#define CLAMAV_EXPAND(tok) #tok
#define CLAMAV_QUOTE(tok) CLAMAV_EXPAND(tok)

static int
clamav_result(struct clamav *cl, const char *l) {
	char s[BUFSIZ + 1];

	if (sscanf(l, "stream: %"CLAMAV_QUOTE(BUFSIZ)"s", s) != 1) {
		(errno ? log_warn : log_warnx)("warn: result: sscanf");
		return -1;
	}
	log_info("info: result: %s", l);
	cl->r = (strcmp(s, "OK") != 0);
	return 0;
}

static int
clamav_message(struct clamav *cl) {
	char *l = NULL;

	if (clamav_read(cl, &l) != 0)
		return -1;
	if (clamav_result(cl, l) == -1)
		return -1;
	if (cl->r == -1) {
		log_warnx("warn: message: result failed");
		return -1;
	}
	if (iobuf_len(&cl->iobuf)) {
		log_warnx("warn: message: incomplete");
		return -1;
	}
	return 0;
}

static int
clamav_response(struct clamav *cl) {
	if (clamav_write(cl, "", EOF))
		return -1;
	if (clamav_message(cl) == -1)
		return -1;
	return 0;
}

static void
clamav_close(struct clamav *cl)
{
	if (cl->fd >= 0)
		close(cl->fd);
	cl->fd = -1;
}

static void
clamav_clear(struct clamav *cl)
{
	if (cl == NULL)
		return;
	iobuf_clear(&cl->iobuf);
	clamav_close(cl);
	free(cl);
}

static int
clamav_on_data(uint64_t id)
{
	struct clamav *cl;

	cl = xcalloc(1, sizeof(struct clamav), "on_data");
	if (clamav_init(cl) == -1) {
		clamav_clear(cl);
		return filter_api_accept(id);
	}
	if (clamav_open(cl) == -1) {
		clamav_clear(cl);
		return filter_api_accept(id);
	}
	if (clamav_request(cl) == -1) {
		clamav_clear(cl);
		return filter_api_accept(id);
	}
	filter_api_set_udata(id, cl);
	return filter_api_accept(id);
}

static void
clamav_on_dataline(uint64_t id, const char *l)
{
	struct clamav *cl;

	filter_api_writeln(id, l);
	if ((cl = filter_api_get_udata(id)) == NULL)
		return;
	if (cl->fd >= 0 && clamav_write(cl, l, 1) == -1)
		clamav_close(cl);
}

static int
clamav_on_eom(uint64_t id, size_t size)
{
	struct clamav *cl;
	int r;

	if ((cl = filter_api_get_udata(id)) == NULL)
		return filter_api_accept(id);
	if (clamav_response(cl) == -1) {
		clamav_clear(cl);
		filter_api_set_udata(id, NULL);
		return filter_api_reject_code(id, FILTER_FAIL, 451, "4.7.1 Virus filter failed");
	}
	r = cl->r;
	clamav_clear(cl);
	filter_api_set_udata(id, NULL);
	if (r) {
		log_warnx("warn: session %016"PRIx64": on_eom: REJECT virus", id);
		return filter_api_reject_code(id, FILTER_CLOSE, 554, "5.7.1 Virus found");
	}
	return filter_api_accept(id);
}

static void
clamav_on_reset(uint64_t id)
{
	clamav_clear(filter_api_get_udata(id));
	filter_api_set_udata(id, NULL);
}

static void
clamav_on_disconnect(uint64_t id)
{
	clamav_clear(filter_api_get_udata(id));
	filter_api_set_udata(id, NULL);
}

static void
clamav_on_rollback(uint64_t id)
{
	clamav_clear(filter_api_get_udata(id));
	filter_api_set_udata(id, NULL);
}

int
main(int argc, char **argv)
{
	int	ch, d = 0, v = 0;

	log_init(1);

	while ((ch = getopt(argc, argv, "dv")) != -1) {
		switch (ch) {
		case 'd':
			d = 1;
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

	log_init(d);
	log_verbose(v);

	log_debug("debug: starting...");

	filter_api_on_data(clamav_on_data);
	filter_api_on_dataline(clamav_on_dataline);
	filter_api_on_eom(clamav_on_eom);
	filter_api_on_reset(clamav_on_reset);
	filter_api_on_disconnect(clamav_on_disconnect);
	filter_api_on_rollback(clamav_on_rollback);

	filter_api_loop();
	log_debug("debug: exiting");

	return 1;
}
