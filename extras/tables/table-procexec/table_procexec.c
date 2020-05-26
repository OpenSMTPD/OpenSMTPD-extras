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

#include <sys/types.h>

#include <err.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>

#include <smtpd-api.h>

#define	PROTOCOL_VERSION	"0.1"
#define	PATH_LIBEXEC		"/usr/local/libexec/smtpd"

FILE *backend_w = NULL;
FILE *backend_r = NULL;

const char *
service_to_name(int service) {
	switch (service) {
	case K_ALIAS:
		return "alias";
	case K_DOMAIN:
		return "domain";
	case K_CREDENTIALS:
		return "credentials";
	case K_NETADDR:
		return "netaddr";
	case K_USERINFO:
		return "userinfo";
	case K_SOURCE:
		return "source";
	case K_MAILADDR:
		return "mailaddr";
	case K_ADDRNAME:
		return "addrname";
	case K_MAILADDRMAP:
		return "mailaddrmap";
	case K_RELAYHOST:
		return "relayhost";
	case K_STRING:
		return "string";
	case K_REGEX:
		return "regex";
	default:
		break;
	}
	fatalx("unsupported service: %d", service);
}

uint64_t
generate_uid(void)
{
	static uint32_t	id;
	static uint8_t	inited;
	uint64_t	uid;

	if (!inited) {
		id = arc4random();
		inited = 1;
	}
	while ((uid = ((uint64_t)(id++) << 32 | arc4random())) == 0)
		;

	return (uid);
}


static int
table_procexec_update(void)
{
	struct timeval tv;
	uint64_t reqid;

	reqid = generate_uid();
	gettimeofday(&tv, NULL);

	fprintf(backend_w, "table|%s|%lld.%06ld|update|%016"PRIx64"\n",
		PROTOCOL_VERSION,
		tv.tv_sec, tv.tv_usec, reqid);
	fflush(backend_w);
	return 1;
}

static int
table_procexec_check(int service, struct dict *params, const char *key)
{
	struct timeval tv;
	uint64_t reqid;

	reqid = generate_uid();
	gettimeofday(&tv, NULL);

	fprintf(backend_w, "table|%s|%lld.%06ld|check|%016"PRIx64"|%s|%s\n",
		PROTOCOL_VERSION,
		tv.tv_sec, tv.tv_usec, reqid, service_to_name(service), key);
	fflush(backend_w);
	return -1;
}

static int
table_procexec_lookup(int service, struct dict *params, const char *key, char *dst,
    size_t sz)
{
	struct timeval tv;
	uint64_t reqid;

	reqid = generate_uid();
	gettimeofday(&tv, NULL);

	fprintf(backend_w, "table|%s|%lld.%06ld|lookup|%016"PRIx64"|%s|%s\n",
		PROTOCOL_VERSION,
		tv.tv_sec, tv.tv_usec, reqid, service_to_name(service), key);
	fflush(backend_w);
	return -1;
}

static int
table_procexec_fetch(int service, struct dict *params, char *dst, size_t sz)
{
	struct timeval tv;
	uint64_t reqid;

	reqid = generate_uid();
	gettimeofday(&tv, NULL);

	fprintf(backend_w, "table|%s|%lld.%06ld|fetch|%016"PRIx64"|%s\n",
		PROTOCOL_VERSION,
		tv.tv_sec, tv.tv_usec, reqid, service_to_name(service));
	fflush(backend_w);
	return -1;
}

static void
fork_table(const char *table)
{
	pid_t pid;
	int sp[2];
	int execr;
	char exec[_POSIX_ARG_MAX];

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, sp) == -1)
		err(1, "socketpair");

	if ((pid = fork()) == -1)
		err(1, "fork");

	if (pid > 0) {
		close(sp[0]);

		if ((backend_w = fdopen(sp[1], "w")) == NULL)
			err(1, "fdopen");

		if ((backend_r = fdopen(sp[1], "r")) == NULL)
			err(1, "fdopen");

		return;
	}

	close(sp[1]);
	dup2(sp[0], STDIN_FILENO);
	dup2(sp[0], STDOUT_FILENO);

	if (table[0] == '/')
		execr = snprintf(exec, sizeof(exec), "exec %s" , table);
	else
		execr = snprintf(exec, sizeof(exec), "exec %s/%s" , PATH_LIBEXEC, table);
	if (execr >= (int) sizeof(exec))
		errx(1, "exec path too long");

	execl("/bin/sh", "/bin/sh", "-c", exec, (char *)NULL);
	err(1, NULL);
}

int
main(int argc, char **argv)
{
	int ch;

	log_init(1);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			fatalx("bad option");
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
		fatalx("bogus argument(s)");

	fork_table(argv[0]);

	table_api_on_update(table_procexec_update);
	table_api_on_check(table_procexec_check);
	table_api_on_lookup(table_procexec_lookup);
	table_api_on_fetch(table_procexec_fetch);
	table_api_dispatch();

	return 0;
}

