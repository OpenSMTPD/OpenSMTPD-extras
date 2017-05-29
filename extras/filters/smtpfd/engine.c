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
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/uio.h>

#include <netinet/in.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>

#include "log.h"
#include "proc.h"
#include "smtpfd.h"
#include "engine.h"

static void engine_dispatch_frontend(struct imsgproc *, struct imsg *, void *);
static void engine_dispatch_main(struct imsgproc *, struct imsg *, void *);
static void engine_showinfo_ctl(struct imsg *);

struct imsgproc	*p_frontend;
struct imsgproc	*p_main;

void
engine(int debug, int verbose)
{
	struct passwd		*pw;

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

	/* Setup pipe and event handler to the main process. */
	p_main = proc_attach(PROC_MAIN, 3);
	proc_setcallback(p_main, engine_dispatch_main, NULL);
	proc_enable(p_main);

	event_dispatch();

	exit(0);
}

int
engine_imsg_compose_frontend(int type, pid_t pid, void *data,
    uint16_t datalen)
{
	return proc_compose(p_frontend, type, 0, pid, -1, data, datalen);
}

void
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
		engine_showinfo_ctl(imsg);
		break;
	default:
		log_debug("%s: unexpected imsg %d", __func__, imsg->hdr.type);
		break;
	}
}

void
engine_dispatch_main(struct imsgproc *p, struct imsg *imsg, void *bula)
{
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
	default:
		log_debug("%s: unexpected imsg %d", __func__, imsg->hdr.type);
		break;
	}
}

void
engine_showinfo_ctl(struct imsg *imsg)
{
	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_ENGINE_INFO:
		engine_imsg_compose_frontend(IMSG_CTL_END, imsg->hdr.pid, NULL,
		    0);
		break;
	default:
		log_debug("%s: unexpected imsg %d", __func__, imsg->hdr.type);
		break;
	}
}
