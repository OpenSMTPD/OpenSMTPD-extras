/*	$OpenBSD$	*/

/*
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
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
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "proc.h"
#include "smtpfd.h"
#include "frontend.h"
#include "control.h"


static void frontend_dispatch_main(struct imsgproc *, struct imsg *, void *);
static void frontend_dispatch_engine(struct imsgproc *, struct imsg *, void *);


void
frontend(int debug, int verbose, char *sockname)
{
	struct passwd	*pw;

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);
	log_procinit("frontend");
	setproctitle("frontend");

	/* Create smtpfd control socket outside chroot. */
	if (control_init(sockname) == -1)
		fatalx("control socket setup failed");

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

	if (pledge("stdio inet recvfd", NULL) == -1)
		fatal("pledge");

	event_init();

	/* Setup pipe and event handler to the parent process. */
	p_main = proc_attach(PROC_MAIN, 3);
	proc_setcallback(p_main, frontend_dispatch_main, NULL);
	proc_enable(p_main);

	/* Listen on control socket. */
	control_listen();

	event_dispatch();

	exit(0);
}

static void
frontend_dispatch_main(struct imsgproc *p, struct imsg *imsg, void *arg)
{
	if (imsg == NULL) {
		log_debug("%s: imsg connection lost", __func__);
		event_loopexit(NULL);
		return;
	}

	switch (imsg->hdr.type) {
	case IMSG_SOCKET_IPC:
		/*
		 * Setup pipe and event handler to the engine
		 * process.
		 */
		if (p_engine)
			fatalx("engine process already set");

		if (imsg->fd == -1)
			fatalx("failed to receive engine process fd");

		p_engine = proc_attach(PROC_ENGINE, imsg->fd);
		if (p_engine == NULL)
			fatal("proc_attach");
		proc_setcallback(p_engine, frontend_dispatch_engine, NULL);
		proc_enable(p_engine);
		break;
	default:
		log_debug("%s: unexpected imsg %d", __func__, imsg->hdr.type);
		break;
	}
}

static void
frontend_dispatch_engine(struct imsgproc *p, struct imsg *imsg, void *arg)
{
	if (imsg == NULL) {
		log_debug("%s: imsg connection lost", __func__);
		event_loopexit(NULL);
		return;
	}

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_ENGINE_INFO:
		control_imsg_relay(imsg);
		break;
	default:
		log_debug("%s: unexpected imsg %d", __func__, imsg->hdr.type);
	}
}

void
frontend_showinfo_ctl(struct imsgproc *proc)
{
	struct ctl_frontend_info cfi;

	proc_compose(proc, IMSG_CTL_SHOW_FRONTEND_INFO, 0, 0, -1,
	    &cfi, sizeof(struct ctl_frontend_info));
}
