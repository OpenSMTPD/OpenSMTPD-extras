/*
 * Copyright (c) 2016 Gilles Chehade <gilles@poolp.org>
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
#include <stdlib.h>
#include <unistd.h>

#include <smtpd-api.h>

#include "rspamd.h"


static int
on_connect(uint64_t id, struct filter_connect *conn)
{
	struct session	*rs = filter_api_session(id);
	const char	*ip;

	//ip = filter_api_sockaddr_to_text((struct sockaddr *)&conn->local);
	ip = "127.0.0.1";
	rs->ip = xstrdup(ip, "on_connect");
	rs->hostname = xstrdup(conn->hostname, "on_connect");

	return filter_api_accept(id);
}

static int
on_helo(uint64_t id, const char *helo)
{
	struct session	*rs = filter_api_session(id);

	rs->helo = xstrdup(helo, "on_helo");

	return filter_api_accept(id);
}

static int
on_mail(uint64_t id, struct mailaddr *mail)
{
	struct session	*rs = filter_api_session(id);
	const char	*address;

	address = filter_api_mailaddr_to_text(mail);
	rs->tx.from = xstrdup(address, "on_mail");

	return filter_api_accept(id);
}

static int
on_rcpt(uint64_t id, struct mailaddr *rcpt)
{
	struct session	*rs = filter_api_session(id);
	const char	*address;

	address = filter_api_mailaddr_to_text(rcpt);
	rs->tx.rcpt = xstrdup(address, "on_rcpt");

	return filter_api_accept(id);
}

static int
on_data(uint64_t id)
{
	struct session *rs = filter_api_session(id);

	if (! rspamd_buffer(rs))
		return filter_api_reject_code(rs->id, FILTER_FAIL, 421,
		    "temporary failure");

	if (! rspamd_connect(rs))
		return filter_api_reject_code(rs->id, FILTER_FAIL, 421,
		    "temporary failure");

	return 1;
}

static void
on_dataline(uint64_t id, const char *line)
{
	struct session *rs = filter_api_session(id);
	ssize_t		sz;

	sz = fprintf(rs->tx.fp, "%s\n", line);
	if (sz == -1 || sz < (ssize_t)strlen(line) + 1)
		rs->tx.error = 1;

	rspamd_send_chunk(rs, line);
}

static int
on_eom(uint64_t id, size_t size)
{
	struct session	*rs = filter_api_session(id);

	rspamd_send_chunk(rs, NULL);

	return 1;
}
static void
on_commit(uint64_t id)
{
	struct session	*rs = filter_api_session(id);

	session_reset(rs);
}

static void
on_rollback(uint64_t id)
{
	struct session	*rs = filter_api_session(id);

	session_reset(rs);
}

static void
on_disconnect(uint64_t id)
{
}

int
main(int argc, char **argv)
{
	int ch, C = 0, d = 0, v = 0;
	const char *l = NULL;
	char *c = NULL, *h = RSPAMD_HOST, *p = RSPAMD_PORT, *s = NULL;

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

	log_init(d);
	log_verbose(v);

	log_debug("debug: starting...");

	rspamd_resolve(h, p);

	filter_api_on_connect(on_connect);
	filter_api_on_helo(on_helo);
	filter_api_on_mail(on_mail);
	filter_api_on_rcpt(on_rcpt);
	filter_api_on_data(on_data);
	filter_api_on_dataline(on_dataline);
	filter_api_on_eom(on_eom);
	filter_api_on_commit(on_commit);
	filter_api_on_rollback(on_rollback);
	filter_api_on_disconnect(on_disconnect);

	filter_api_session_allocator(session_allocator);
	filter_api_session_destructor(session_destructor);

	/*
	if (c)
		filter_api_set_chroot(c);
	if (C)
		filter_api_no_chroot();
	*/
	filter_api_no_chroot();

	filter_api_loop();
	log_debug("debug: exiting");

	return 1;
}
