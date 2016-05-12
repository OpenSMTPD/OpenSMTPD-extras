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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

static unsigned int pause_seconds = 5;

static void
pause_timer(uint64_t id, void *p)
{
	filter_api_accept(id);
}

static int
pause_on_connect(uint64_t id, struct filter_connect *conn)
{
	struct timeval tv = { pause_seconds, 0 };

	log_debug("debug: on_connect: sleeping %u", pause_seconds);
	filter_api_timer(id, &tv, pause_timer, NULL);
	return 1;
}

int
main(int argc, char **argv)
{
	int ch, d = 0, v = 0;
	const char *errstr, *s = NULL;

	log_init(1);

	while ((ch = getopt(argc, argv, "ds:v")) != -1) {
		switch (ch) {
		case 'd':
			d = 1;
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

	if (s) { /* RFC 5321 4.5.3.2 Initial 220 Message: 5 Minutes */
		pause_seconds = strtonum(s, 1, 300, &errstr);
		if (errstr)
			fatalx("seconds option is %s: %s", errstr, s);
	}

	log_init(d);
	log_verbose(v);

	log_debug("debug: starting...");

	filter_api_on_connect(pause_on_connect);
	filter_api_loop();

	log_debug("debug: exiting");

	return 1;
}
