/*	$OpenBSD$	*/

/*
 * Copyright (c) 2004, 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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
#include <sys/socket.h>
#include <sys/syslog.h>

#include <event.h>
#include <imsg.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "proc.h"
#include "smtpfd.h"

struct filter_process {
	TAILQ_ENTRY(filter_process) entry;
	struct imsgproc *proc;
};

struct filter_node {
	TAILQ_ENTRY(filter_node) entry;
	struct filter_process *fproc;
};

struct filter {
	char *name;
	TAILQ_ENTRY(filter)        entry;
	TAILQ_HEAD(, filter_node)  nodes;
};

struct engine_config {
	TAILQ_HEAD(, filter_process) procs;
	TAILQ_HEAD(, filter) filters;
};

static void engine_dispatch_frontend(struct imsgproc *, struct imsg *, void *);
static void engine_dispatch_priv(struct imsgproc *, struct imsg *, void *);
static void engine_dispatch_filter(struct imsgproc *, struct imsg *, void *);

static struct engine_config *conf;
static struct engine_config *tmpconf;

void
engine(int debug, int verbose)
{
	struct passwd *pw;

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);
	log_procinit("engine");
	setproctitle("engine");

	if ((pw = getpwnam(SMTPFD_USER)) == NULL)
		fatal("getpwnam");

	if (chroot(pw->pw_dir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	if (pledge("stdio recvfd", NULL) == -1)
		fatal("pledge");

	event_init();

	/* Setup imsg socket with parent. */
	p_priv = proc_attach(PROC_PRIV, 3);
	proc_setcallback(p_priv, engine_dispatch_priv, NULL);
	proc_enable(p_priv);

	event_dispatch();

	exit(0);
}

static void
engine_dispatch_priv(struct imsgproc *p, struct imsg *imsg, void *bula)
{
	struct filter_process *fproc;
	struct filter_node *fnode;
	struct filter *f;

	if (imsg == NULL) {
		log_debug("%s: imsg connection lost", __func__);
		event_loopexit(NULL);
		return;
	}

	switch (imsg->hdr.type) {
	case IMSG_SOCKET_IPC:
		/*
		 * Setup pipe and event handler to the frontend
		 * process.
		 */
		if (p_frontend)
			fatalx("frontend process already set");

		if (imsg->fd == -1)
			fatalx("failed to receive frontend process fd");

		p_frontend = proc_attach(PROC_FRONTEND, imsg->fd);
		if (p_frontend == NULL)
			fatal("proc_attach");
		proc_setcallback(p_frontend, engine_dispatch_frontend, NULL);
		proc_enable(p_frontend);
		break;

	case IMSG_RECONF_CONF:
		if (tmpconf)
			fatalx("already configuring");
		tmpconf = calloc(1, sizeof(*tmpconf));
		if (tmpconf == NULL)
			fatal("calloc");
		TAILQ_INIT(&tmpconf->procs);
		TAILQ_INIT(&tmpconf->filters);
		break;

	case IMSG_RECONF_FILTER_PROC:
		if (imsg->fd == -1)
			fatalx("failed to receive filter process fd");

		fproc = calloc(1, sizeof(*fproc));
		if (fproc == NULL)
			fatal("calloc");
		fproc->proc = proc_attach(PROC_FILTER, imsg->fd);
		if (fproc->proc == NULL)
			fatal("proc_attach");
		proc_settitle(fproc->proc, imsg->data);
		proc_setcallback(fproc->proc, engine_dispatch_filter, fproc);
		proc_enable(fproc->proc);
		TAILQ_INSERT_TAIL(&tmpconf->procs, fproc, entry);
		log_info("new filter process: %s", (char *)imsg->data);
		break;

	case IMSG_RECONF_FILTER:
		f = calloc(1, sizeof(*f));
		if (f == NULL)
			fatal("calloc");
		f->name = strdup(imsg->data);
		if (f->name == NULL)
			fatal("strdup");
		TAILQ_INIT(&f->nodes);
		TAILQ_INSERT_HEAD(&tmpconf->filters, f, entry);
		log_info("new filter: %s", (char *)imsg->data);
		break;

	case IMSG_RECONF_FILTER_NODE:
		fnode = calloc(1, sizeof(*fnode));
		if (fnode == NULL)
			fatal("calloc");
		TAILQ_FOREACH(fproc, &tmpconf->procs, entry) {
			if (!strcmp(proc_gettitle(fproc->proc), imsg->data)) {
				fnode->fproc = fproc;
				break;
			}
		}
		if (fnode->fproc == NULL)
			fatalx("unknown filter process %s", (char *)imsg->data);
		f = TAILQ_FIRST(&tmpconf->filters);
		TAILQ_INSERT_TAIL(&f->nodes, fnode, entry);
		log_info("new node filter on filter %s: %s", f->name, (char *)imsg->data);
		break;

	case IMSG_RECONF_END:
		/* XXX purge old config */
		conf = tmpconf;
		tmpconf = NULL;
		break;

	default:
		log_debug("%s: unexpected imsg %d", __func__, imsg->hdr.type);
		break;
	}
}

static void
engine_dispatch_frontend(struct imsgproc *p, struct imsg *imsg, void *bula)
{
	int verbose;

	if (imsg == NULL) {
		log_debug("%s: imsg connection lost", __func__);
		event_loopexit(NULL);
		return;
	}

	switch (imsg->hdr.type) {
	case IMSG_CTL_LOG_VERBOSE:
		/* Already checked by frontend. */
		memcpy(&verbose, imsg->data, sizeof(verbose));
		log_setverbose(verbose);
		break;
	case IMSG_CTL_SHOW_ENGINE_INFO:
		proc_compose(p_frontend, IMSG_CTL_END, 0, imsg->hdr.pid, -1,
		    NULL, 0);
		break;
	default:
		log_debug("%s: unexpected imsg %d", __func__, imsg->hdr.type);
		break;
	}
}

static void
engine_dispatch_filter(struct imsgproc *p, struct imsg *imsg, void *bula)
{
	if (imsg == NULL) {
		log_debug("%s: imsg connection lost to filter %s", __func__,
		    proc_gettitle(p));
		event_loopexit(NULL);
		return;
	}

	switch (imsg->hdr.type) {
	default:
		log_debug("%s: unexpected imsg %d from filter %s", __func__,
		    imsg->hdr.type, proc_gettitle(p));
		proc_compose(p, 1, 0, 0, -1, NULL, 0);
		break;
	}
}
