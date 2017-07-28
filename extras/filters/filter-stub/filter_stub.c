/*
 * Copyright (c) 2013 Eric Faurot <eric@openbsd.org>
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
#include <unistd.h>

#include <smtpd-api.h>

static void *
session_alloc(uint64_t id)
{
	return (void *)-1;
}

static void
session_free(void *session)
{
}

static void *
transaction_alloc(uint64_t id)
{
	return (void *)-1;
}

static void
transaction_free(void *transaction)
{
}

static int
on_connect(uint64_t id, struct filter_connect *conn)
{
	log_debug("debug: on_connect");
	return filter_api_accept(id);
}

static int
on_helo(uint64_t id, const char *helo)
{
	log_debug("debug: on_helo");
	return filter_api_accept(id);
}

static int
on_mail(uint64_t id, struct mailaddr *mail)
{
	log_debug("debug: on_mail");
	return filter_api_accept(id);
}

static int
on_rcpt(uint64_t id, struct mailaddr *rcpt)
{
	log_debug("debug: on_rcpt");
	return filter_api_accept(id);
}

static int
on_data(uint64_t id)
{
	log_debug("debug: on_data");
	return filter_api_accept(id);
}

static void
on_msg_start(uint64_t id)
{
	log_debug("debug: on_msg_start");
}

static int
on_msg_end(uint64_t id, size_t size)
{
	log_debug("debug: on_msg_end");
	return filter_api_accept(id);
}

static void
on_msg_line(uint64_t id, const char *line)
{
	log_debug("debug: on_msg_line");
	filter_api_writeln(id, line);
}

static void
on_reset(uint64_t id)
{
	log_debug("debug: on_reset");
}

static void
on_tx_begin(uint64_t id)
{
	log_debug("debug: on_tx_begin");
}

static void
on_tx_commit(uint64_t id)
{
	log_debug("debug: on_tx_commit");
}

static void
on_tx_rollback(uint64_t id)
{
	log_debug("debug: on_tx_rollback");
}

static void
on_disconnect(uint64_t id)
{
	log_debug("debug: on_disconnect");
}

int
main(int argc, char **argv)
{
	int ch, d = 0, v = 0;

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
			fatalx("bad option");
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	log_init(d);
	log_verbose(v);

	log_debug("debug: starting...");

	filter_api_session_allocator(session_alloc);
	filter_api_session_destructor(session_free);
	filter_api_transaction_allocator(transaction_alloc);
	filter_api_transaction_destructor(transaction_free);

	filter_api_on_connect(on_connect);
	filter_api_on_helo(on_helo);
	filter_api_on_mail(on_mail);
	filter_api_on_rcpt(on_rcpt);
	filter_api_on_data(on_data);
	filter_api_on_reset(on_reset);
	filter_api_on_msg_start(on_msg_start);
	filter_api_on_msg_end(on_msg_end);
	filter_api_on_msg_line(on_msg_line);
	filter_api_on_tx_begin(on_tx_begin);
	filter_api_on_tx_commit(on_tx_commit);
	filter_api_on_tx_rollback(on_tx_rollback);
	filter_api_on_disconnect(on_disconnect);

	filter_api_loop();
	log_debug("debug: exiting");

	return 1;
}
