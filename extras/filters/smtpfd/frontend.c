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

__dead void	 frontend_shutdown(void);
void		 frontend_sig_handler(int, short, void *);

struct imsgproc	*p_main;
struct imsgproc	*p_engine;

void
frontend_sig_handler(int sig, short event, void *bula)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGINT:
	case SIGTERM:
		frontend_shutdown();
	default:
		fatalx("unexpected signal");
	}
}

void
frontend(int debug, int verbose, char *sockname)
{
	struct event	 ev_sigint, ev_sigterm;
	struct passwd	*pw;

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	/* Create smtpfd control socket outside chroot. */
	if (control_init(sockname) == -1)
		fatalx("control socket setup failed");

	if ((pw = getpwnam(SMTPFD_USER)) == NULL)
		fatal("getpwnam");

	if (chroot(pw->pw_dir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	smtpfd_process = PROC_FRONTEND;
	setproctitle(log_procnames[smtpfd_process]);
	log_procinit(log_procnames[smtpfd_process]);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	if (pledge("stdio inet recvfd", NULL) == -1)
		fatal("pledge");

	event_init();

	/* Setup signal handler. */
	signal_set(&ev_sigint, SIGINT, frontend_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, frontend_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/* Setup pipe and event handler to the parent process. */
	p_main = proc_attach(PROC_MAIN, 3);
	proc_setcallback(p_main, frontend_dispatch_main, NULL);
	proc_enable(p_main);

	/* Listen on control socket. */
	TAILQ_INIT(&ctl_conns);
	control_listen();

	event_dispatch();

	frontend_shutdown();
}

__dead void
frontend_shutdown(void)
{
	/* Close pipes. */
	proc_free(p_engine);
	proc_free(p_main);

	log_info("frontend exiting");
	exit(0);
}

int
frontend_imsg_compose_main(int type, pid_t pid, void *data,
    uint16_t datalen)
{
	return proc_compose(p_main, type, 0, pid, -1, data, datalen);
}

int
frontend_imsg_compose_engine(int type, uint32_t peerid, pid_t pid,
    void *data, uint16_t datalen)
{
	return proc_compose(p_engine, type, peerid, pid, -1, data, datalen);
}

void
frontend_dispatch_main(struct imsgproc *p, struct imsg *imsg, void *arg)
{
	if (imsg == NULL) {
		event_loopexit(NULL);
		return;
	}

	switch (imsg->hdr.type) {
	case IMSG_SOCKET_IPC:
		/*
		 * Setup pipe and event handler to the engine
		 * process.
		 */
		if (p_engine) {
			log_warnx("%s: received unexpected imsg fd "
			    "to frontend", __func__);
			break;
		}
		if (imsg->fd == -1) {
			log_warnx("%s: expected to receive imsg fd to "
			   "frontend but didn't receive any",
			   __func__);
			break;
		}

		p_engine = proc_attach(PROC_ENGINE, imsg->fd);
		proc_setcallback(p_engine, frontend_dispatch_engine, NULL);
		proc_enable(p_engine);
		break;
	case IMSG_CTL_END:
	case IMSG_CTL_SHOW_MAIN_INFO:
		control_imsg_relay(imsg);
		break;
	default:
		log_debug("%s: error handling imsg %d", __func__,
		    imsg->hdr.type);
		break;
	}
}

void
frontend_dispatch_engine(struct imsgproc *p, struct imsg *imsg, void *arg)
{
	if (imsg == NULL) {
		event_loopexit(NULL);
		return;
	}

	switch (imsg->hdr.type) {
	case IMSG_CTL_END:
	case IMSG_CTL_SHOW_ENGINE_INFO:
		control_imsg_relay(imsg);
		break;
	default:
		log_debug("%s: error handling imsg %d", __func__,
		    imsg->hdr.type);
		break;
	}
}

void
frontend_showinfo_ctl(struct ctl_conn *c)
{
	struct ctl_frontend_info cfi;

	proc_compose(c->proc, IMSG_CTL_SHOW_FRONTEND_INFO, 0, 0, -1,
	    &cfi, sizeof(struct ctl_frontend_info));
}
