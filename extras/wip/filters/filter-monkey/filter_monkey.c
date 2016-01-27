/*	$OpenBSD$	*/

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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

static int
monkey(uint64_t id, const char *cmd)
{
	uint32_t r;

#if 0
	if (!strcmp(cmd, "eom")) {
		log_info("info: session %016"PRIx64": REJECT cmd=%s", id, cmd);
		return filter_api_reject_code(id, FILTER_FAIL, 451,
		    "I am a monkey!");
	}

	log_info("info: session %016"PRIx64": ACCEPT cmd=%s", id, cmd);
	return filter_api_accept(id);
#endif

	r = arc4random_uniform(100);
	if (r < 70) {
		log_info("info: session %016"PRIx64": ACCEPT cmd=%s", id, cmd);
		return filter_api_accept(id);
	}
	else if (r < 90) {
		log_info("info: session %016"PRIx64": REJECT cmd=%s", id, cmd);
		return filter_api_reject_code(id, FILTER_FAIL, 451,
		    "I am a monkey!");
	}
	else
	{
		log_info("info: session %016"PRIx64": CLOSE cmd=%s", id, cmd);
		return filter_api_reject_code(id, FILTER_CLOSE, 421,
		    "I am a not so funny monkey!");
	}
}

static int
on_connect(uint64_t id, struct filter_connect *conn)
{
	return monkey(id, "connect");
}

static int
on_helo(uint64_t id, const char *helo)
{
	return monkey(id, "helo");
}

static int
on_mail(uint64_t id, struct mailaddr *mail)
{
	return monkey(id, "mail");
}

static int
on_rcpt(uint64_t id, struct mailaddr *rcpt)
{
	return monkey(id, "rcpt");
}

static int
on_data(uint64_t id)
{
	return monkey(id, "data");
}

static int
on_eom(uint64_t id, size_t size)
{
	return monkey(id, "eom");
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
			return (1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	log_init(d);
	log_verbose(v);

	log_debug("debug: starting...");

	filter_api_on_connect(on_connect);
	filter_api_on_helo(on_helo);
	filter_api_on_mail(on_mail);
	filter_api_on_rcpt(on_rcpt);
	filter_api_on_data(on_data);
	filter_api_on_eom(on_eom);
	filter_api_loop();

	log_debug("debug: exiting");

	return (0);
}
