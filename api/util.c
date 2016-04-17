/*
 * Copyright (c) 2000,2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2008 Gilles Chehade <gilles@poolp.org>
 * Copyright (c) 2009 Jacek Masiulaniec <jacekm@dobremiasto.net>
 * Copyright (c) 2012 Eric Faurot <eric@openbsd.org>
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

#include <netinet/in.h>

#include <base64.h>
#include <ctype.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>

#include "iobuf.h"
#include "log.h"

void *
xmalloc(size_t size, const char *where)
{
	void	*r;

	if ((r = malloc(size)) == NULL) {
		log_warnx("%s: malloc(%zu)", where, size);
		fatalx("exiting");
	}

	return (r);
}

void *
xcalloc(size_t nmemb, size_t size, const char *where)
{
	void	*r;

	if ((r = calloc(nmemb, size)) == NULL) {
		log_warnx("%s: calloc(%zu, %zu)", where, nmemb, size);
		fatalx("exiting");
	}

	return (r);
}

char *
xstrdup(const char *str, const char *where)
{
	char	*r;

	if ((r = strdup(str)) == NULL) {
		log_warnx("%s: strdup(%p)", where, str);
		fatalx("exiting");
	}

	return (r);
}

void
iobuf_xinit(struct iobuf *io, size_t size, size_t max, const char *where)
{
	if (iobuf_init(io, size, max) == -1) {
		log_warnx("%s: iobuf_init(%p, %zu, %zu)", where, io, size, max);
		fatalx("exiting");
	}
}

char *
strip(char *s)
{
	size_t	 l;

	while (isspace((unsigned char)*s))
		s++;

	for (l = strlen(s); l; l--) {
		if (!isspace((unsigned char)s[l-1]))
			break;
		s[l-1] = '\0';
	}

	return (s);
}

int
base64_encode(unsigned char const *src, size_t srclen,
	      char *dest, size_t destsize)
{
	return __b64_ntop(src, srclen, dest, destsize);
}

int
base64_decode(char const *src, unsigned char *dest, size_t destsize)
{
	return __b64_pton(src, dest, destsize);
}

