/*	$OpenBSD: to.c,v 1.17 2014/04/19 14:27:29 gilles Exp $	*/

/*
 * Copyright (c) 2009 Jacek Masiulaniec <jacekm@dobremiasto.net>
 * Copyright (c) 2012 Eric Faurot <eric@openbsd.org>
 * Copyright (c) 2012 Gilles Chehade <gilles@poolp.org>
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
#include <sys/tree.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <fts.h>
#include <imsg.h>
#include <inttypes.h>
#include <libgen.h>
#include <netdb.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "smtpd-defines.h"
#include <smtpd-api.h>
#include "log.h"

static const char *in6addr_to_text(const struct in6_addr *);

const char *
sockaddr_to_text(struct sockaddr *sa)
{
	static char	buf[NI_MAXHOST];

	if (getnameinfo(sa, sa->sa_len, buf, sizeof(buf), NULL, 0,
	    NI_NUMERICHOST))
		return ("(unknown)");
	else
		return (buf);
}

static const char *
in6addr_to_text(const struct in6_addr *addr)
{
	struct sockaddr_in6	sa_in6;
	uint16_t		tmp16;

	memset(&sa_in6, 0, sizeof(sa_in6));
	sa_in6.sin6_len = sizeof(sa_in6);
	sa_in6.sin6_family = AF_INET6;
	memcpy(&sa_in6.sin6_addr, addr, sizeof(sa_in6.sin6_addr));

	/* XXX thanks, KAME, for this ugliness... adopted from route/show.c */
	if (IN6_IS_ADDR_LINKLOCAL(&sa_in6.sin6_addr) ||
	    IN6_IS_ADDR_MC_LINKLOCAL(&sa_in6.sin6_addr)) {
		memcpy(&tmp16, &sa_in6.sin6_addr.s6_addr[2], sizeof(tmp16));
		sa_in6.sin6_scope_id = ntohs(tmp16);
		sa_in6.sin6_addr.s6_addr[2] = 0;
		sa_in6.sin6_addr.s6_addr[3] = 0;
	}

	return (sockaddr_to_text((struct sockaddr *)&sa_in6));
}

int
text_to_mailaddr(struct mailaddr *maddr, const char *email)
{
	char *username;
	char *hostname;
	char  buffer[SMTPD_MAXLINESIZE];

	if (strlcpy(buffer, email, sizeof buffer) >= sizeof buffer)
		return 0;

	memset(maddr, 0, sizeof *maddr);

	username = buffer;
	hostname = strrchr(username, '@');

	if (hostname == NULL) {
		if (strlcpy(maddr->user, username, sizeof maddr->user)
		    >= sizeof maddr->user)
			return 0;
	}
	else if (username == hostname) {
		*hostname++ = '\0';
		if (strlcpy(maddr->domain, hostname, sizeof maddr->domain)
		    >= sizeof maddr->domain)
			return 0;
	}
	else {
		*hostname++ = '\0';
		if (strlcpy(maddr->user, username, sizeof maddr->user)
		    >= sizeof maddr->user)
			return 0;
		if (strlcpy(maddr->domain, hostname, sizeof maddr->domain)
		    >= sizeof maddr->domain)
			return 0;
	}	

	return 1;
}

const char *
mailaddr_to_text(const struct mailaddr *maddr)
{
	static char  buffer[SMTPD_MAXLINESIZE];

	(void)strlcpy(buffer, maddr->user, sizeof buffer);
	(void)strlcat(buffer, "@", sizeof buffer);
	if (strlcat(buffer, maddr->domain, sizeof buffer) >= sizeof buffer)
		return NULL;

	return buffer;
}


const char *
sa_to_text(const struct sockaddr *sa)
{
	static char	 buf[NI_MAXHOST + 5];
	char		*p;

	buf[0] = '\0';
	p = buf;

	if (sa->sa_family == AF_LOCAL)
		(void)strlcpy(buf, "local", sizeof buf);
	else if (sa->sa_family == AF_INET) {
		in_addr_t addr;

		addr = ((const struct sockaddr_in *)sa)->sin_addr.s_addr;
		addr = ntohl(addr);
		(void)snprintf(p, NI_MAXHOST, "%d.%d.%d.%d",
		    (addr >> 24) & 0xff, (addr >> 16) & 0xff,
		    (addr >> 8) & 0xff, addr & 0xff);
	}
	else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6;
		const struct in6_addr	*in6_addr;

		in6 = (const struct sockaddr_in6 *)sa;
		(void)strlcpy(buf, "IPv6:", sizeof(buf));
		p = buf + 5;
		in6_addr = &in6->sin6_addr;
		(void)snprintf(p, NI_MAXHOST, "%s", in6addr_to_text(in6_addr));
	}

	return (buf);
}

const char *
ss_to_text(const struct sockaddr_storage *ss)
{
	return (sa_to_text((const struct sockaddr*)ss));
}

const char *
time_to_text(time_t when)
{
	struct tm *lt;
	static char buf[40];
	char *day[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
	char *month[] = {"Jan","Feb","Mar","Apr","May","Jun",
			 "Jul","Aug","Sep","Oct","Nov","Dec"};
	int ret;

	lt = localtime(&when);
	if (lt == NULL || when == 0)
		fatalx("time_to_text: localtime");

	/* We do not use strftime because it is subject to locale substitution*/
	ret = snprintf(buf, sizeof(buf),
	    "%s, %d %s %d %02d:%02d:%02d %c%02d%02d (%s)",
	    day[lt->tm_wday], lt->tm_mday, month[lt->tm_mon],
	    lt->tm_year + 1900,
	    lt->tm_hour, lt->tm_min, lt->tm_sec,
	    lt->tm_gmtoff >= 0 ? '+' : '-',
	    abs((int)lt->tm_gmtoff / 3600),
	    abs((int)lt->tm_gmtoff % 3600) / 60,
	    lt->tm_zone);
	if (ret == -1 || ret >= sizeof (buf))
		fatalx("time_to_text: snprintf");

	return buf;
}

const char *
duration_to_text(time_t t)
{
	static char	dst[64];
	char		buf[64];
	int		h, m, s;
	long long	d;

	if (t == 0) {
		(void)strlcpy(dst, "0s", sizeof dst);
		return (dst);
	}

	dst[0] = '\0';
	if (t < 0) {
		(void)strlcpy(dst, "-", sizeof dst);
		t = -t;
	}

	s = t % 60;
	t /= 60;
	m = t % 60;
	t /= 60;
	h = t % 24;
	d = t / 24;

	if (d) {
		(void)snprintf(buf, sizeof buf, "%lldd", d);
		(void)strlcat(dst, buf, sizeof dst);
	}
	if (h) {
		(void)snprintf(buf, sizeof buf, "%dh", h);
		(void)strlcat(dst, buf, sizeof dst);
	}
	if (m) {
		(void)snprintf(buf, sizeof buf, "%dm", m);
		(void)strlcat(dst, buf, sizeof dst);
	}
	if (s) {
		(void)snprintf(buf, sizeof buf, "%ds", s);
		(void)strlcat(dst, buf, sizeof dst);
	}

	return (dst);
}

uint64_t
text_to_evpid(const char *s)
{
	uint64_t ulval;
	char	 *ep;

	errno = 0;
	ulval = strtoull(s, &ep, 16);
	if (s[0] == '\0' || *ep != '\0')
		return 0;
	if (errno == ERANGE && ulval == ULLONG_MAX)
		return 0;
	if (ulval == 0)
		return 0;
	return (ulval);
}

uint32_t
text_to_msgid(const char *s)
{
	uint64_t ulval;
	char	 *ep;

	errno = 0;
	ulval = strtoull(s, &ep, 16);
	if (s[0] == '\0' || *ep != '\0')
		return 0;
	if (errno == ERANGE && ulval == ULLONG_MAX)
		return 0;
	if (ulval == 0)
		return 0;
	if (ulval > 0xffffffff)
		return 0;
	return (ulval & 0xffffffff);
}
