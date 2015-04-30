/* $OpenBSD$ */

/*
 * Copyright (c) 2015 Armin Wolfermann <armin@wolfermann.org>
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
#include <sys/queue.h>
#include <sys/stat.h>

#include <inttypes.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

struct rxentry {
	SLIST_ENTRY(rxentry)	link;
	regex_t			regex;
	unsigned char		exclude;
};

struct rxlist {
	SLIST_HEAD(, rxentry)	 entries;
	char			*path;
	time_t			 mtime;
};

struct rxcontent {
	size_t			 lines;
	char			*match;
};

static struct rxlist badhostname, badhelo, badmailfrom, badrcptto, badcontent;
static int regflags = REG_EXTENDED|REG_ICASE|REG_NOSUB;
static size_t maxlines = 0;

static void
read_list(struct rxlist *rxl)
{
	FILE *fp;
	char line[1024];
	struct stat sb;
	struct rxentry *rxe, *last = NULL;

	if (stat(rxl->path, &sb) == -1) {
		log_warnx("warn: filter-regex: unable to stat %s", rxl->path);
		return;
	}
	rxl->mtime = sb.st_mtime;

	if ((fp = fopen(rxl->path, "r")) == NULL) {
		log_warnx("warn: filter-regex: unable to open %s", rxl->path);
		return;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		line[strcspn(line, "\n")] = '\0';

		if (!strlen(line))
			continue;

		rxe = xmalloc(sizeof *rxe, "filter-regex: read_list");

		rxe->exclude = (line[0] == '!');

		if (regcomp(&rxe->regex, &line[rxe->exclude], regflags)) {
			log_warnx("warn: filter-regex: no regex: '%s'", line);
			free(rxe);
			continue;
		}

		if (SLIST_EMPTY(&rxl->entries))
			SLIST_INSERT_HEAD(&rxl->entries, rxe, link);
		else
			SLIST_INSERT_AFTER(last, rxe, link);
		last = rxe;
	}

	fclose(fp);
}

static void
check_list(struct rxlist *rxl)
{
	struct stat sb;
	struct rxentry *rxe;

	if (stat(rxl->path, &sb) == -1)
		return;

	if (rxl->mtime == sb.st_mtime)
		return;

	log_debug("debug: filter-regex: reloading %s", rxl->path);

	while (!SLIST_EMPTY(&rxl->entries)) {
		rxe = SLIST_FIRST(&rxl->entries);
		SLIST_REMOVE_HEAD(&rxl->entries, link);
		free(rxe);
	}

	read_list(rxl);
}

static void
init_list(struct rxlist *rxl, char *path)
{
	SLIST_INIT(&rxl->entries);
	rxl->path = path;
	rxl->mtime = 0;
}

static int
match(const char *string, struct rxlist *rxl)
{
	struct rxentry *rxe;

	SLIST_FOREACH(rxe, &rxl->entries, link) {
		if (!regexec(&rxe->regex, string, 0, NULL, 0))
			return (!rxe->exclude);
	}

	return 0;
}

static int
on_connect(uint64_t id, struct filter_connect *conn)
{
	log_debug("debug: filter-regex: on_connect");
	check_list(&badhostname);
	if (match(conn->hostname, &badhostname)) {
		log_info("filter-regex: matching hostname '%s'",
		    conn->hostname);
		return filter_api_reject(id, FILTER_FAIL);
	}
	log_debug("debug: filter-regex: on_connect accept");
	return filter_api_accept(id);
}

static int
on_helo(uint64_t id, const char *helo)
{
	log_debug("debug: filter-regex: on_helo");
	check_list(&badhelo);
	if (match(helo, &badhelo)) {
		log_info("filter-regex: matching helo/ehlo '%s'", helo);
		return filter_api_reject(id, FILTER_FAIL);
	}
	log_debug("debug: filter-regex: on_helo accept");
	return filter_api_accept(id);
}

static int
on_mail(uint64_t id, struct mailaddr *mail)
{
	const char *email;
	log_debug("debug: filter-regex: on_mail");
	email = filter_api_mailaddr_to_text(mail);
	check_list(&badmailfrom);
	if (match(email, &badmailfrom)) {
		log_info("filter-regex: matching sender '%s'", email);
		return filter_api_reject(id, FILTER_FAIL);
	}
	log_debug("debug: filter-regex: on_mail accept");
	return filter_api_accept(id);
}

static int
on_rcpt(uint64_t id, struct mailaddr *rcpt)
{
	const char *email;
	log_debug("debug: filter-regex: on_rcpt");
	email = filter_api_mailaddr_to_text(rcpt);
	check_list(&badrcptto);
	if (match(email, &badrcptto)) {
		log_info("filter-regex: matching recipient '%s'", email);
		return filter_api_reject(id, FILTER_FAIL);
	}
	log_debug("debug: filter-regex: on_rcpt accept");
	return filter_api_accept(id);
}

static int
on_data(uint64_t id)
{
	struct rxcontent *rxc;
	log_debug("debug: filter-regex: on_data");
	check_list(&badcontent);
	rxc = xmalloc(sizeof *rxc, "filter-regex: on_data");
	rxc->lines = 0;
	rxc->match = NULL;
	filter_api_set_udata(id, rxc);
	log_debug("debug: filter-regex: on_data accept");
	return filter_api_accept(id);
}

static void
on_dataline(uint64_t id, const char *line)
{
	struct rxcontent *rxc = filter_api_get_udata(id);
	log_debug("debug: filter-regex: on_dataline");
	if (!rxc || rxc->match != NULL)
		return;
	if (maxlines && rxc->lines > maxlines) {
		filter_api_writeln(id, line);
		return;
	}
	if (match(line, &badcontent)) {
		rxc->match = xstrdup(line, "filter-regex: on_dataline");
		return;
	}
	rxc->lines += 1;
	filter_api_writeln(id, line);
}

static int
on_eom(uint64_t id, size_t size)
{
	struct rxcontent *rxc = filter_api_get_udata(id);

	log_debug("debug: filter-regex: on_eom");
	if (rxc && rxc->match != NULL) {
		log_info("filter-regex: matching content '%s' on line %ld",
		    rxc->match, rxc->lines);
		filter_api_set_udata(id, NULL);
		free(rxc);
		return filter_api_reject(id, FILTER_FAIL);
	}
	log_debug("debug: filter-regex: on_eom accept");
	return filter_api_accept(id);
}

static void
on_disconnect(uint64_t id)
{
	struct rxcontent *rxc = filter_api_get_udata(id);

	log_debug("debug: filter-regex: on_disconnect");
	if (rxc) {
		filter_api_set_udata(id, NULL);
		free(rxc);
	}
}

int
main(int argc, char **argv)
{
	int ch;
	const char *errstr;
	const char *rootpath = NULL;

	while ((ch = getopt(argc, argv, "c:n:h:m:r:d:l:")) != -1) {
		switch (ch) {
		case 'c':
			rootpath = optarg;
			break;
		case 'n':
			init_list(&badhostname, optarg);
			filter_api_on_connect(on_connect);
			break;
		case 'h':
			init_list(&badhelo, optarg);
			filter_api_on_helo(on_helo);
			break;
		case 'm':
			init_list(&badmailfrom, optarg);
			filter_api_on_mail(on_mail);
			break;
		case 'r':
			init_list(&badrcptto, optarg);
			filter_api_on_rcpt(on_rcpt);
			break;
		case 'd':
			init_list(&badcontent, optarg);
			filter_api_on_data(on_data);
			filter_api_on_dataline(on_dataline);
			filter_api_on_eom(on_eom);
			filter_api_on_disconnect(on_disconnect);
			break;
		case 'l':
			maxlines = strtonum(optarg, 1, (size_t)-1, &errstr);
			if (errstr)
				fatalx("option -l is %s", errstr);
			break;
		default:
			log_warnx("warn: filter-regex: bad option");
			return (1);
			/* NOTREACHED */
		}
	}

	log_debug("debug: filter-regex: starting");

	if (rootpath)
		filter_api_set_chroot(rootpath);
	else
		filter_api_no_chroot();

	filter_api_loop();

	log_debug("debug: filter-regex: exiting");

	return (1);
}

