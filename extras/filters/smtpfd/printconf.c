/*	$OpenBSD$	*/

/*
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
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
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <event.h>
#include <imsg.h>
#include <stdio.h>

#include "smtpfd.h"

void
print_config(struct smtpfd_conf *conf)
{
	struct group *g;
	char buf[INET6_ADDRSTRLEN], *bufp;

	printf("yesno %s\n", conf->yesno ? "yes" : "no");
	printf("integer %d\n", conf->integer);
	printf("\n");

	printf("global_text \"%s\"\n", conf->global_text);
	printf("\n");


	LIST_FOREACH(g, &conf->group_list, entry) {
		printf("group %s {\n", g->name);

		printf("\tyesno %s\n", g->yesno ? "yes" : "no");
		printf("\tinteger %d\n", g->integer);

		bufp = inet_net_ntop(AF_INET, &g->group_v4address,
		    g->group_v4_bits, buf, sizeof(buf));
		printf("\tgroup-v4address %s\n",
		    bufp ? bufp : "<invalid IPv4>");
		bufp = inet_net_ntop(AF_INET6, &g->group_v6address,
		    g->group_v6_bits, buf, sizeof(buf));
		printf("\tgroup-v6address %s\n",
		    bufp ? bufp : "<invalid IPv6>");

		printf("}\n");
	}
}
