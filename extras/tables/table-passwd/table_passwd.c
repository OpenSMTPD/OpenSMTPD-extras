/*
 * Copyright (c) 2013 Gilles Chehade <gilles@poolp.org>
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

#include <err.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

static char	       *config;
static struct dict     *passwd;

static int
parse_passwd_entry(int service, struct passwd *pw, char *buf)
{
	const char     *e;
	char	       *p;

	/* username */
	if (!(pw->pw_name = strsep(&buf, ":")) || !strlen(pw->pw_name))
		return 0;

	/* password */
	if (!(pw->pw_passwd = strsep(&buf, ":")) ||
	    (service == K_CREDENTIALS && !strlen(pw->pw_passwd)))
		return 0;

	/* uid */
	if (!(p = strsep(&buf, ":")))
		return 0;
	pw->pw_uid = strtonum(p, 0, UID_MAX, &e);
	if (service == K_USERINFO && (!strlen(p) || e))
		return 0;

	/* gid */
	if (!(p = strsep(&buf, ":")))
		return 0;
	pw->pw_gid = strtonum(p, 0, GID_MAX, &e);
	if (service == K_USERINFO && (!strlen(p) || e))
		return 0;

	/* gecos */
	if (!(pw->pw_gecos = strsep(&buf, ":")))
		return 0;

	/* home */
	if (!(pw->pw_dir = strsep(&buf, ":")) ||
	    (service == K_USERINFO && !strlen(pw->pw_dir)))
		return 0;

	/* shell */
	pw->pw_shell = strsep(&buf, ":");
	/*
	 * explicitly allow further extra fields to support
	 * shared authentication with Dovecot Passwd-file format
	 */
	return 1;
}

static int
table_passwd_update(void)
{
	FILE		*fp;
	char		*buf = NULL, tmp[LINE_MAX], *skip, *p;
	size_t		 sz = 0;
	ssize_t		 len;
	struct passwd	 pw;
	struct dict	*npasswd;

	/* parse configuration */
	if ((fp = fopen(config, "r")) == NULL) {
		log_warn("warn: table-passwd: \"%s\"", config);
		return 0;
	}

	if ((npasswd = calloc(1, sizeof(*passwd))) == NULL)
		goto err;

	dict_init(npasswd);

	while ((len = getline(&buf, &sz, fp)) != -1) {
		if (buf[len - 1] == '\n')
			buf[len - 1] = '\0';

		/* skip commented entries */
		for (skip = buf; *skip; ++skip)
			if (*skip == '#') {
				*skip = '\0';
				break;
			}

		/* skip empty lines */
		if (strlen(buf) == 0)
			continue;

		if (strlcpy(tmp, buf, sizeof(tmp)) >= sizeof(tmp)) {
			log_warnx("warn: table-passwd: line too long");
			goto err;
		}

		if (!parse_passwd_entry(K_ANY, &pw, tmp)) {
			log_warnx("warn: table-passwd: invalid entry");
			goto err;
		}
		dict_set(npasswd, pw.pw_name, xstrdup(buf, "update"));
	}
	free(buf);
	fclose(fp);

	/* swap passwd table and release old one*/
	if (passwd)
		while (dict_poproot(passwd, (void**)&p))
			free(p);
	passwd = npasswd;

	return 1;

err:
	free(buf);
	fclose(fp);

	/* release passwd table */
	if (npasswd) {
		while (dict_poproot(npasswd, (void**)&p))
			free(p);
		free(npasswd);
	}
	return 0;
}

static int
table_passwd_check(int service, struct dict *params, const char *key)
{
	return -1;
}

static int
table_passwd_lookup(int service, struct dict *params, const char *key,
    char *dst, size_t sz)
{
	struct passwd	pw;
	char	       *line;
	char		tmp[LINE_MAX];

	if ((line = dict_get(passwd, key)) == NULL)
		return 0;

	(void)strlcpy(tmp, line, sizeof(tmp));
	if (!parse_passwd_entry(service, &pw, tmp)) {
		log_warnx("warn: table-passwd: invalid entry");
		return -1;
	}

	switch (service) {
	case K_CREDENTIALS:
		if (snprintf(dst, sz, "%s:%s",
			pw.pw_name, pw.pw_passwd) >= (ssize_t)sz) {
			log_warnx("warn: table-passwd: result too large");
			return -1;
		}
		break;
	case K_USERINFO:
		if (snprintf(dst, sz, "%d:%d:%s",
			pw.pw_uid, pw.pw_gid, pw.pw_dir)
		    >= (ssize_t)sz) {
			log_warnx("warn: table-passwd: result too large");
			return -1;
		}
		break;
	default:
		log_warnx("warn: table-passwd: unknown service %d",
		    service);
		return -1;
	}
	return 1;
}

static int
table_passwd_fetch(int service, struct dict *params, char *dst, size_t sz)
{
	return -1;
}

int
main(int argc, char **argv)
{
	int	ch;

	log_init(1);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			log_warnx("warn: table-passwd: bad option");
			return 1;
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		log_warnx("warn: table-passwd: bogus argument(s)");
		return 1;
	}

	config = argv[0];

	if (table_passwd_update() == 0) {
		log_warnx("warn: table-passwd: error parsing config file");
		return 1;
	}

	table_api_on_update(table_passwd_update);
	table_api_on_check(table_passwd_check);
	table_api_on_lookup(table_passwd_lookup);
	table_api_on_fetch(table_passwd_fetch);
	table_api_dispatch();

	return 0;
}
