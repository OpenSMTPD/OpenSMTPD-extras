/*
 * Copyright (c) 2013 Eric Faurot <eric@openbsd.org>
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

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <asr.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

struct dnsbl {
	uint64_t id;
	struct asr_query *aq_bl, *aq_wl;
};

static const char *dnsbl_host = "dnsbl.sorbs.net", *dnswl_host;

static void
dnsbl_event_black(struct asr_result *ar, void *p)
{
	struct dnsbl *dl = p;

	if (ar->ar_addrinfo)
		freeaddrinfo(ar->ar_addrinfo);
	if (ar->ar_gai_errno == EAI_NODATA || ar->ar_gai_errno == EAI_NONAME) {
		log_info("info: event_black: ACCEPT address");
		filter_api_accept(dl->id);
	} else if (ar->ar_gai_errno) {
		log_warnx("warn: session %016"PRIx64": event_black: getaddrinfo '%s'", dl->id, gai_strerror(ar->ar_gai_errno));
		filter_api_reject_code(dl->id, FILTER_FAIL, 451, "4.7.1 DNSBL filter failed");
	} else {
		log_warnx("warn: session %016"PRIx64": event_black: REJECT address", dl->id);
		filter_api_reject_code(dl->id, FILTER_CLOSE, 554, "5.7.1 Address in DNSBL");
	}
	free(dl);
}

static void
dnsbl_event_white(struct asr_result *ar, void *p)
{
	struct dnsbl *dl = p;

	if (ar->ar_addrinfo)
		freeaddrinfo(ar->ar_addrinfo);
	if (ar->ar_gai_errno == EAI_NODATA || ar->ar_gai_errno == EAI_NONAME) {
		log_debug("debug: event_white: address not in DNSWL");
		event_asr_run(dl->aq_bl, dnsbl_event_black, dl);
	} else if (ar->ar_gai_errno) {
		log_warnx("warn: session %016"PRIx64": event_white: getaddrinfo '%s'", dl->id, gai_strerror(ar->ar_gai_errno));
		filter_api_reject_code(dl->id, FILTER_FAIL, 451, "4.7.1 DNSBL filter failed");
		asr_abort(dl->aq_bl);
		free(dl);
	} else {
		log_info("info: event_white: ACCEPT address");
		filter_api_accept(dl->id);
		asr_abort(dl->aq_bl);
		free(dl);
	}
}

static struct asr_query *
dnsbl_query(in_addr_t ia, const char *h)
{
	struct asr_query *aq;
	struct addrinfo hints;
	char buf[512];

	ia = ntohl(ia);
	if (snprintf(buf, sizeof(buf), "%d.%d.%d.%d.%s.",
	    ia & 0xff, (ia >> 8) & 0xff, (ia >> 16) & 0xff, (ia >> 24) & 0xff, h) >= sizeof(buf)) {
		log_warnx("warn: query: host name too long: %s", buf);
		return NULL;
	}
	log_debug("debug: query: checking %s", buf);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (!(aq = getaddrinfo_async(buf, NULL, &hints, NULL))) {
		log_warn("warn: query: getaddrinfo_async");
		return NULL;
	}
	return aq;
}

static int
dnsbl_on_connect(uint64_t id, struct filter_connect *conn)
{
	struct dnsbl *dl;
	in_addr_t ia;

	if (conn->remote.ss_family != AF_INET)
		return filter_api_accept(id);
	ia = ((const struct sockaddr_in *)&conn->remote)->sin_addr.s_addr;
	dl = xcalloc(1, sizeof(struct dnsbl), "on_connect");
	dl->id = id;
	if (!(dl->aq_bl = dnsbl_query(ia, dnsbl_host)) || (dnswl_host &&
	    !(dl->aq_wl = dnsbl_query(ia, dnswl_host)))) {
		free(dl);
		return filter_api_reject_code(id, FILTER_FAIL, 451, "4.7.1 DNSBL filter failed");
	}
	dnswl_host ? event_asr_run(dl->aq_wl, dnsbl_event_white, dl) :
	    event_asr_run(dl->aq_bl, dnsbl_event_black, dl);
	return 1;
}

int
main(int argc, char **argv)
{
	int ch, d = 0, v = 0;
	char *h = NULL, *w = NULL;

	log_init(1);

	while ((ch = getopt(argc, argv, "dh:vw:")) != -1) {
		switch (ch) {
		case 'd':
			d = 1;
			break;
		case 'h':
			h = optarg;
			break;
		case 'v':
			v |= TRACE_DEBUG;
			break;
		case 'w':
			w = optarg;
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
		dnsbl_host = strip(h);
	if (w)
		dnswl_host = strip(w);

	log_init(d);
	log_verbose(v);

	log_debug("debug: starting...");

	filter_api_on_connect(dnsbl_on_connect);
	filter_api_no_chroot(); /* getaddrinfo requires resolv.conf */
	filter_api_loop();

	log_debug("debug: exiting");

	return 1;
}
