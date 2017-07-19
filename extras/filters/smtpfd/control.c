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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpfd.h"

#include "log.h"
#include "proc.h"

#define	CONTROL_BACKLOG	5

static int  control_init(const char *);
static int  control_listen(void);
static void control_accept(int, short, void *);
static void control_close(struct imsgproc *);
static void control_dispatch_priv(struct imsgproc *, struct imsg *, void *);
static void control_dispatch_client(struct imsgproc *, struct imsg *, void *);

static struct {
	struct event	ev;
	struct event	evt;
	int		fd;
} control_state;

void
control(int debug, int verbose)
{
	struct passwd *pw;

	/* Early initialisation */
	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);
	log_procinit("control");
	setproctitle("control");

	control_init(SMTPFD_SOCKET);

	/* Drop priviledges */
	if ((pw = getpwnam(SMTPFD_USER)) == NULL)
		fatalx("unknown user " SMTPFD_USER);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("cannot drop privileges");

	if (chroot(pw->pw_dir) == 1)
		fatal("chroot");

	if (pledge("stdio unix recvfd sendfd", NULL) == -1)
		fatal("pledge");

	event_init();

	signal(SIGPIPE, SIG_IGN);

	/* Setup imsg socket with parent */
	p_priv = proc_attach(PROC_PRIV, 3);
	proc_setcallback(p_priv, control_dispatch_priv, NULL);
	proc_enable(p_priv);

	event_dispatch();

	exit(0);
}

static int
control_init(const char *path)
{
	struct sockaddr_un	 sun;
	int			 fd;
	mode_t			 old_umask;

	if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    0)) == -1) {
		log_warn("%s: socket", __func__);
		return (-1);
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, SMTPFD_SOCKET, sizeof(sun.sun_path));

	if (unlink(path) == -1)
		if (errno != ENOENT) {
			log_warn("%s: unlink %s", __func__, path);
			close(fd);
			return (-1);
		}

	old_umask = umask(S_IXUSR|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH);
	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		log_warn("%s: bind: %s", __func__, path);
		close(fd);
		umask(old_umask);
		return (-1);
	}
	umask(old_umask);

	if (chmod(path, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) == -1) {
		log_warn("%s: chmod", __func__);
		close(fd);
		(void)unlink(path);
		return (-1);
	}

	control_state.fd = fd;

	return (0);
}

static int
control_listen(void)
{

	if (listen(control_state.fd, CONTROL_BACKLOG) == -1) {
		log_warn("%s: listen", __func__);
		return (-1);
	}

	event_set(&control_state.ev, control_state.fd, EV_READ,
	    control_accept, NULL);
	event_add(&control_state.ev, NULL);
	evtimer_set(&control_state.evt, control_accept, NULL);

	return (0);
}

static void
control_accept(int listenfd, short event, void *bula)
{
	int			 connfd;
	socklen_t		 len;
	struct sockaddr_un	 sun;
	struct imsgproc		*proc;

	event_add(&control_state.ev, NULL);
	if ((event & EV_TIMEOUT))
		return;

	len = sizeof(sun);
	if ((connfd = accept4(listenfd, (struct sockaddr *)&sun, &len,
	    SOCK_CLOEXEC | SOCK_NONBLOCK)) == -1) {
		/*
		 * Pause accept if we are out of file descriptors, or
		 * libevent will haunt us here too.
		 */
		if (errno == ENFILE || errno == EMFILE) {
			struct timeval evtpause = { 1, 0 };

			event_del(&control_state.ev);
			evtimer_add(&control_state.evt, &evtpause);
		} else if (errno != EWOULDBLOCK && errno != EINTR &&
		    errno != ECONNABORTED)
			log_warn("%s: accept4", __func__);
		return;
	}

	proc = proc_attach(PROC_CLIENT, connfd);
	proc_setcallback(proc, control_dispatch_client, NULL);
	proc_enable(proc);
}

static void
control_close(struct imsgproc *proc)
{
	proc_free(proc);

	/* Some file descriptors are available again. */
	if (evtimer_pending(&control_state.evt, NULL)) {
		evtimer_del(&control_state.evt);
		event_add(&control_state.ev, NULL);
	}
}

static void
control_dispatch_priv(struct imsgproc *proc, struct imsg *imsg, void *arg)
{
	if (imsg == NULL) {
		log_debug("%s: imsg connection lost", __func__);
		event_loopexit(NULL);
		return;
	}

	if (log_getverbose() > LOGLEVEL_IMSG)
		log_imsg(proc, imsg);

	switch (imsg->hdr.type) {
	case IMSG_CONF_START:
		m_end(proc);
		break;

	case IMSG_CONF_END:
		m_end(proc);
		control_listen();
		break;

	default:
		fatalx("%s: unexpected imsg %s", __func__,
		    log_fmt_imsgtype(imsg->hdr.type));
	}
}

static void
control_dispatch_client(struct imsgproc *proc, struct imsg *imsg, void *arg)
{
	if (imsg == NULL) {
		control_close(proc);
		return;
	}

	if (log_getverbose() > LOGLEVEL_IMSG)
		log_imsg(proc, imsg);

	switch (imsg->hdr.type) {
	default:
		log_debug("%s: error handling imsg %d", __func__,
		    imsg->hdr.type);
		break;
	}
}
