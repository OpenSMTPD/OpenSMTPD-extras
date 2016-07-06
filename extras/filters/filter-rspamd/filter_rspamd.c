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

	ip = filter_api_sockaddr_to_text((struct sockaddr *)&conn->local);
	if (! session_set_ip(rs, ip ? ip : "127.0.0.1"))
		return filter_api_reject_code(id, FILTER_FAIL, 421,
		    "temporary failure");

	if (! session_set_hostname(rs, conn->hostname))
		return filter_api_reject_code(id, FILTER_FAIL, 421,
		    "temporary failure");

	return filter_api_accept(id);
}

static int
on_helo(uint64_t id, const char *helo)
{
	struct session	*rs = filter_api_session(id);

	if (! session_set_helo(rs, helo))
		return filter_api_reject_code(id, FILTER_FAIL, 421,
		    "temporary failure");

	return filter_api_accept(id);
}

static int
on_mail(uint64_t id, struct mailaddr *mail)
{
	struct transaction	*tx = filter_api_transaction(id);
	const char		*address;

	address = filter_api_mailaddr_to_text(mail);
	if (! transaction_set_from(tx, address))
		return filter_api_reject_code(id, FILTER_FAIL, 421,
		    "temporary failure");

	return filter_api_accept(id);
}

static int
on_rcpt(uint64_t id, struct mailaddr *rcpt)
{
	struct transaction	*tx = filter_api_transaction(id);
	const char		*address;

	address = filter_api_mailaddr_to_text(rcpt);
	if (! transaction_add_rcpt(tx, address))
		return filter_api_reject_code(id, FILTER_FAIL, 421,
		    "temporary failure");

	return filter_api_accept(id);
}

static int
on_data(uint64_t id)
{
	struct transaction	*tx = filter_api_transaction(id);

	if (! rspamd_connect(tx))
		return filter_api_reject_code(id, FILTER_FAIL, 421,
		    "temporary failure");

	/* accept/reject is called from rspamd.c */
	return 1;
}

static void
on_msg_start(uint64_t id)
{
}

static void
on_msg_line(uint64_t id, const char *line)
{
	struct transaction     *tx = filter_api_transaction(id);

	rspamd_send_chunk(tx, line);
}

static int
on_msg_end(uint64_t id, size_t size)
{
	struct transaction	*tx = filter_api_transaction(id);

	rspamd_send_chunk(tx, NULL);

	/* accept/reject is called from rspamd.c */
	return 1;
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
	filter_api_on_msg_start(on_msg_start);
	filter_api_on_msg_line(on_msg_line);
	filter_api_on_msg_end(on_msg_end);

	filter_api_session_allocator(session_allocator);
	filter_api_session_destructor(session_destructor);

	filter_api_transaction_allocator(transaction_allocator);
	filter_api_transaction_destructor(transaction_destructor);

	filter_api_data_buffered();

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
