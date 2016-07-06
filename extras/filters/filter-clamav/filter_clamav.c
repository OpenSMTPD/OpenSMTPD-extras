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

#include <sys/types.h>
#include <arpa/inet.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>

#include <smtpd-api.h>

#define CLAMAV_HOST "127.0.0.1"
#define CLAMAV_PORT "3310"

struct clamav {
	uint64_t id;
	struct iobuf iobuf;
	struct io io;
	int r;
	enum { CL_DATA, CL_EOM, CL_STA } s;
};

static struct sockaddr_storage clamav_ss;

static void
clamav_clear(struct clamav *cl)
{
	if (cl == NULL)
		return;
	io_clear(&cl->io);
	iobuf_clear(&cl->iobuf);
	free(cl);
}

static int
clamav_result(struct clamav *cl)
{
	if (cl->r == INT_MIN) {
		log_warnx("warn: result: failed");
		return -1;
	}
	if (cl->r) {
		log_warnx("warn: session %016"PRIx64": result: REJECT virus", cl->id);
		return filter_api_reject_code(cl->id, FILTER_CLOSE, 554, "5.7.1 Virus found");
	}
	return filter_api_accept(cl->id);
}

#define CLAMAV_EXPAND(tok) #tok
#define CLAMAV_QUOTE(tok) CLAMAV_EXPAND(tok)

static int
clamav_status(struct clamav *cl, const char *l) {
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
clamav_response(struct clamav *cl, const char *l)
{
	switch (cl->s) {
	case CL_STA:
		if (clamav_status(cl, l) == -1)
			return -1;
		break;
	default:
		fatalx("response: bad state");
	}
	return 0;
}

static void
clamav_io(struct io *io, int evt)
{
	struct clamav *cl = io->arg;
	char *l;

	switch (evt) {
	case IO_CONNECTED:
		io_set_write(io);
		break;
	case IO_LOWAT:
		if (cl->s == CL_EOM) {
			cl->s++;
			io_set_read(io);
		}
		break;
	case IO_DATAIN:
		while ((l = iobuf_getline(&cl->iobuf, NULL))) {
			if (iobuf_len(&cl->iobuf) >= LINE_MAX) {
				log_warnx("warn: io: iobuf_getline");
				goto fail;
			}
			if (clamav_response(cl, l) == -1)
				goto fail;
		}
		iobuf_normalize(&cl->iobuf);
		break;
	case IO_DISCONNECTED:
		if (cl->s == CL_STA) {
			if (iobuf_len(&cl->iobuf)) {
				log_warnx("warn: io: incomplete");
				goto fail;
			}
			if (clamav_result(cl) == -1)
				goto fail;
			io_clear(io);
			break;
		} /* FALLTHROUGH */
	case IO_TIMEOUT:
	case IO_ERROR:
		log_warnx("warn: io: %s %s", io_strevent(evt), cl->io.error);
		goto fail;
	default:
		fatalx("io: bad event");
	}
	return;
fail:
	if (cl->s > CL_DATA)
		filter_api_reject_code(cl->id, FILTER_FAIL, 451, "4.7.1 Virus filter failed");
	filter_api_set_udata(cl->id, NULL);
	clamav_clear(cl);
}

static void
clamav_init(struct clamav *cl, uint64_t id)
{
	iobuf_xinit(&cl->iobuf, LINE_MAX, LINE_MAX, "init");
	io_init(&cl->io, -1, cl, clamav_io, &cl->iobuf);
	cl->id = id;
	cl->r = INT_MIN;
}

static int
clamav_on_data(uint64_t id)
{
	struct clamav *cl;

	clamav_init((cl = xcalloc(1, sizeof(struct clamav), "on_data")), id);
	if (io_connect(&cl->io, (struct sockaddr *)&clamav_ss, NULL) == -1) {
		log_warnx("warn: on_data: io_connect %s", cl->io.error);
		clamav_clear(cl);
		return filter_api_accept(id);
	}
	iobuf_xfqueue(&cl->iobuf, "on_data", "nINSTREAM\n");
	filter_api_set_udata(id, cl);
	return filter_api_accept(id);
}

static void
clamav_on_dataline(uint64_t id, const char *l)
{
	struct clamav *cl;
	uint32_t n = htonl(strlen(l) + 1);

	filter_api_writeln(id, l);
	if ((cl = filter_api_get_udata(id)) == NULL)
		return;
	if (iobuf_queue(&cl->iobuf, &n, sizeof(uint32_t)) != (int)sizeof(uint32_t))
		fatalx("on_dataline: iobuf_queue");
	iobuf_xfqueue(&cl->iobuf, "on_dataline", "%s\n", l);
	io_reload(&cl->io);
}

static int
clamav_on_eom(uint64_t id, size_t size)
{
	struct clamav *cl;
	uint32_t n = htonl(0);

	if ((cl = filter_api_get_udata(id)) == NULL)
		return filter_api_accept(id);
	if (iobuf_queue(&cl->iobuf, &n, sizeof(uint32_t)) != (int)sizeof(uint32_t))
		fatalx("on_eom: iobuf_queue");
	io_reload(&cl->io);
	cl->s++;
	return 1; /* defer accept or reject */
}

static void
clamav_on_tx_commit(uint64_t id)
{
	clamav_clear(filter_api_get_udata(id));
	filter_api_set_udata(id, NULL);
}

static void
clamav_on_tx_rollback(uint64_t id)
{
	clamav_clear(filter_api_get_udata(id));
	filter_api_set_udata(id, NULL);
}


static void
clamav_resolve(const char *h, const char *p)
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
		write(fd, "nPING\n", 6);
		close(fd);
		memmove(&clamav_ss, ai->ai_addr, ai->ai_addrlen);
		break;
	}
	freeaddrinfo(addresses);
	if (!ai)
		fatalx("resolve: failed");
}

int
main(int argc, char **argv)
{
	int ch, d = 0, v = 0;
	char *h = CLAMAV_HOST, *p = CLAMAV_PORT;

	log_init(1);

	while ((ch = getopt(argc, argv, "dh:p:v")) != -1) {
		switch (ch) {
		case 'd':
			d = 1;
			break;
		case 'h':
			h = optarg;
			break;
		case 'p':
			p = optarg;
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

	if (h)
		h = strip(h);
	if (p)
		p = strip(p);

	log_init(d);
	log_verbose(v);

	log_debug("debug: starting...");
	clamav_resolve(h, p);

	filter_api_on_data(clamav_on_data);
	filter_api_on_dataline(clamav_on_dataline);
	filter_api_on_eom(clamav_on_eom);
	filter_api_on_tx_commit(clamav_on_tx_commit);
	filter_api_on_tx_rollback(clamav_on_tx_rollback);

	filter_api_loop();
	log_debug("debug: exiting");

	return 1;
}
