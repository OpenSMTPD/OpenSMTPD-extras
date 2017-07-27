/*	$OpenBSD$	*/

/*
 * Copyright (c) 2017 Eric Faurot <eric@openbsd.org>
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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpfd.h"

#include "io.h"
#include "log.h"

#define	SMTPF_LINEMAX		4096
#define	SMTPF_MAXSESSIONNAME	32

struct smtpf_session {
	SPLAY_ENTRY(smtpf_session)	entry;
	char				name[SMTPF_MAXSESSIONNAME];
};

SPLAY_HEAD(sessiontree, smtpf_session);

struct smtpf_client {
	uint32_t		 id;
	struct io		*io;
	struct sessiontree	 sessions;
	struct smtpf_session	*last;
};

static void smtpf_close(struct smtpf_client *);
static void smtpf_dispatch_io(struct io *, int, void *);
static void smtpf_process_line(struct smtpf_client *, char *);
static void smtpf_session_open(struct smtpf_client *, const char *);
static void smtpf_session_close(struct smtpf_client *, const char *);
static void smtpf_session_line(struct smtpf_client *, int, const char *, const char *);
static struct smtpf_session *smtpf_session_find(struct smtpf_client *, const char *);
static int smtpf_session_cmp(struct smtpf_session *, struct smtpf_session *);
SPLAY_PROTOTYPE(sessiontree, smtpf_session, entry, smtpf_session_cmp);

void
frontend_smtpf_init(void)
{
}

void
frontend_smtpf_conn(uint32_t connid, struct listener *l, int sock,
    const struct sockaddr *sa)
{
	struct smtpf_client *clt;

	if ((clt = calloc(1, sizeof(*clt))) == NULL) {
		log_warn("%s: calloc", __func__);
		close(sock);
		frontend_conn_closed(connid);
		return;
	}
	clt->id = connid;
	clt->io = io_new();
	if (clt->io == NULL) {
		close(sock);
		free(clt);
		frontend_conn_closed(connid);
		return;
	}
	io_set_callback(clt->io, smtpf_dispatch_io, clt);
	io_attach(clt->io, sock);
}

static void
smtpf_close(struct smtpf_client *clt)
{
	struct smtpf_session *s;
	uint32_t connid;

	while ((s = SPLAY_ROOT(&clt->sessions))) {
		SPLAY_REMOVE(sessiontree, &clt->sessions, s);
		free(s);
	}

	connid = clt->id;
	io_free(clt->io);
	free(clt);

	frontend_conn_closed(connid);
}

static void
smtpf_dispatch_io(struct io *io, int evt, void *arg)
{
	struct smtpf_client *clt = arg;
	char *line;

	switch (evt) {
	case IO_CONNECTED:
	case IO_TLSREADY:
	case IO_TLSERROR:
		break;

	case IO_DATAIN:
		while ((line = io_getline(clt->io, NULL)))
			smtpf_process_line(clt, line);

		if (io_datalen(clt->io) > SMTPF_LINEMAX) {
			log_warnx("%s: line too long", __func__);
			break;
		}
		return;

	case IO_LOWAT:
		return;

	case IO_DISCONNECTED:
		log_debug("%08x disconnected", clt->id);
		break;

	case IO_TIMEOUT:
		log_debug("%08x timeout", clt->id);
		break;

	case IO_ERROR:
		log_warnx("%08x io error: %s", clt->id, io_error(io));
		break;

	default:
		fatalx("%s: unexpected event %d", __func__, evt);
	}

	smtpf_close(clt);
}

static void
smtpf_process_line(struct smtpf_client *clt, char *line)
{
	#define MAXARGS	8
	char *cmd, *name, *data, *last, *args[MAXARGS], *p;
	int i = 0;

	if ((name = strchr(line, ':')) == NULL) {
		log_warnx("%s: invalid line \"%s\"", __func__, line);
		return;
	}
	if ((data = strchr(name + 1, ':')) == NULL) {
		log_warnx("%s: invalid session name \"%s\"", __func__, name+1);
		return;
	}
	cmd = line;
	*name++ = '\0';
	*data++ = '\0';

	if (!strcmp(cmd, "A")) {
		smtpf_session_line(clt, 0, name, data);
	}
	if (!strcmp(cmd, "B")) {
		smtpf_session_line(clt, 1, name, data);
	}
	else if (!strcmp(cmd, "SMTPF")) {
		for (p = strtok_r(data, " ", &last); p; p = strtok_r(NULL, " ", &last)) {
			if (i >= MAXARGS) {
				log_warnx("%s: too many args", __func__);
				return;
			}
			args[i++] = p;
		}
		args[i] = NULL;

		if (i != 1) {
			log_warnx("%s: no command (%d)", __func__, i);
			return;
		}

		if (!strcmp(args[0], "OPEN"))
			smtpf_session_open(clt, name);
		else if (!strcmp(args[0], "CLOSE"))
			smtpf_session_close(clt, name);
	}
	else
		log_warn("%s: invalid command \"%s\"", __func__, line);
}

static struct smtpf_session *
smtpf_session_find(struct smtpf_client *clt, const char *name)
{
	struct smtpf_session key, *s;

	if (clt->last && !(strcmp(name, clt->last->name)))
		return clt->last;

	if (strlcpy(key.name, name, sizeof(key.name)) >= sizeof(key.name)) {
		log_warnx("%s: name too long", __func__);
		return NULL;
	}

	s = SPLAY_FIND(sessiontree, &clt->sessions, &key);
	if (s == NULL)
		return NULL;

	clt->last = s;
	return clt->last;

}

static void
smtpf_session_open(struct smtpf_client *clt, const char *name)
{
	struct smtpf_session *s;

	s = calloc(1, sizeof(*s));
	if (s == NULL) {
		log_warn("%s: calloc", __func__);
		goto fail;
	}

	if (strlcpy(s->name, name, sizeof(s->name)) >= sizeof(s->name)) {
		log_warnx("%s: name too long", __func__);
		free(s);
		goto fail;
	}

	if (smtpf_session_find(clt, name)) {
		log_warnx("%s: duplicate token", __func__);
		free(s);
		goto fail;
	}

	SPLAY_INSERT(sessiontree, &clt->sessions, s);
	clt->last = s;
	io_printf(clt->io, "SMTPF:%s:OPEN OK\n", name);
	return;
    fail:
	io_printf(clt->io, "SMTPF:%s:OPEN FAILED\n", name);
}

static void
smtpf_session_close(struct smtpf_client *clt, const char *name)
{
	struct smtpf_session *s;

	s = smtpf_session_find(clt, name);
	if (s == NULL) {
		log_warnx("%s: session not found", __func__);
		return;
	}

	SPLAY_REMOVE(sessiontree, &clt->sessions, s);
	clt->last = NULL;
	free(s);
}

static void
smtpf_session_line(struct smtpf_client *clt, int srv, const char *name,
    const char *line)
{
	struct smtpf_session *s;

	s = smtpf_session_find(clt, name);
	if (s == NULL) {
		log_warnx("%s: session not found", __func__);
		return;
	}

	/* relay between the two ends of the session */
	io_printf(clt->io, "%c:%s:%s\n", srv ? 'A' : 'B', name, line);
}

static int
smtpf_session_cmp(struct smtpf_session *a, struct smtpf_session *b)
{
	return strcmp(a->name, b->name);
}

SPLAY_GENERATE(sessiontree, smtpf_session, entry, smtpf_session_cmp);
