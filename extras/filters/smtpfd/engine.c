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

#include <sys/stat.h>

#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "smtpfd.h"

#include "log.h"
#include "proc.h"

struct filter_proc {
	TAILQ_ENTRY(filter_proc) entry;
	struct imsgproc *proc;
};

struct filter_node {
	TAILQ_ENTRY(filter_node) entry;
	struct filter_proc *proc;
};

struct filter {
	char *name;
	TAILQ_ENTRY(filter)        entry;
	TAILQ_HEAD(, filter_node)  nodes;
};

struct engine_config {
	TAILQ_HEAD(, filter_proc) procs;
	TAILQ_HEAD(, filter) filters;
};

static void engine_shutdown(void);
static void engine_dispatch_priv(struct imsgproc *, struct imsg *, void *);
static void engine_dispatch_filter(struct imsgproc *, struct imsg *, void *);
static void engine_dispatch_frontend(struct imsgproc *, struct imsg *, void *);

static struct engine_config *tmpconf, *conf;

void
engine(int debug, int verbose)
{
	struct passwd *pw;

	/* Early initialisation. */
	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);
	log_procinit("engine");
	setproctitle("engine");

	/* Drop priviledges. */
	if ((pw = getpwnam(SMTPFD_USER)) == NULL)
		fatal("%s: getpwnam: %s", __func__, SMTPFD_USER);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("%s: cannot drop privileges", __func__);

	if (pledge("stdio rpath wpath cpath dns sendfd recvfd", NULL) == -1)
		fatal("%s: pledge", __func__);

	event_init();

	signal(SIGPIPE, SIG_IGN);

	/* Setup imsg socket with parent. */
	p_priv = proc_attach(PROC_PRIV, 3);
	if (p_priv == NULL)
		fatal("%s: proc_attach", __func__);
	proc_setcallback(p_priv, engine_dispatch_priv, NULL);
	proc_enable(p_priv);

	event_dispatch();

	engine_shutdown();
}

static void
engine_shutdown()
{
	log_debug("exiting");

	exit(0);
}

static void
engine_dispatch_priv(struct imsgproc *proc, struct imsg *imsg, void *arg)
{
	struct filter_proc *fproc;

	if (imsg == NULL) {
		log_debug("%s: imsg connection lost", __func__);
		event_loopexit(NULL);
		return;
	}

	if (log_getverbose() > LOGLEVEL_IMSG)
		log_imsg(proc, imsg);

	switch (imsg->hdr.type) {
	case IMSG_SOCK_FRONTEND:
		m_end(proc);

		if (imsg->fd == -1)
			fatalx("failed to receive frontend socket");
		p_frontend = proc_attach(PROC_FRONTEND, imsg->fd);
		proc_setcallback(p_frontend, engine_dispatch_frontend, NULL);
		proc_enable(p_frontend);
		break;

	case IMSG_CONF_START:
		m_end(proc);
		tmpconf = calloc(1, sizeof(*tmpconf));
		if (tmpconf == NULL)
			fatal("%s: calloc", __func__);
		TAILQ_INIT(&tmpconf->procs);
		TAILQ_INIT(&tmpconf->filters);
		break;

	case IMSG_CONF_FILTER_PROC:
		if (imsg->fd == -1)
			fatalx("%s: filter process fd not received", __func__);
		fproc = calloc(1, sizeof(*fproc));
		if (fproc == NULL)
			fatal("%s: calloc", __func__);
		fproc->proc = proc_attach(PROC_FILTER, imsg->fd);
		if (fproc->proc == NULL)
			fatal("%s: proc_attach", __func__);
		proc_settitle(fproc->proc, imsg->data);
		proc_setcallback(fproc->proc, engine_dispatch_filter, fproc);
		proc_enable(fproc->proc);
		TAILQ_INSERT_TAIL(&tmpconf->procs, fproc, entry);
		log_info("new filter process: %s", (char *)imsg->data);
		break;

	case IMSG_CONF_END:
		m_end(proc);
		conf = tmpconf;
		break;

	default:
		fatalx("%s: unexpected imsg %s", __func__,
		    log_fmt_imsgtype(imsg->hdr.type));
	}
}

static void
engine_dispatch_frontend(struct imsgproc *proc, struct imsg *imsg, void *arg)
{
	if (imsg == NULL) {
		log_debug("%s: imsg connection lost", __func__);
		event_loopexit(NULL);
		return;
	}

	if (log_getverbose() > LOGLEVEL_IMSG)
		log_imsg(proc, imsg);

	switch (imsg->hdr.type) {
	case IMSG_RES_GETADDRINFO:
	case IMSG_RES_GETNAMEINFO:
		resolver_dispatch_request(proc, imsg);
		break;

	default:
		fatalx("%s: unexpected imsg %s", __func__,
		    log_fmt_imsgtype(imsg->hdr.type));
	}
}

static void
engine_dispatch_filter(struct imsgproc *proc, struct imsg *imsg, void *arg)
{
	if (imsg == NULL) {
		log_debug("%s: imsg connection lost", __func__);
		event_loopexit(NULL);
		return;
	}

	if (log_getverbose() > LOGLEVEL_IMSG)
		log_imsg(proc, imsg);

	return;

	switch (imsg->hdr.type) {
	default:
		fatalx("%s: unexpected imsg %s", __func__,
		    log_fmt_imsgtype(imsg->hdr.type));
	}
}
