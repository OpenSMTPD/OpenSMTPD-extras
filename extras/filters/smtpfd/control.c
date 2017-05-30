/*	$OpenBSD$	*/

/*
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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "proc.h"
#include "smtpfd.h"
#include "control.h"

#define	CONTROL_BACKLOG	5

static void control_accept(int, short, void *);
static void control_close(struct imsgproc *);
static void control_dispatch_imsg(struct imsgproc *, struct imsg *, void *);

static struct {
	struct event	ev;
	struct event	evt;
	int		fd;
} control_state;


int
control_init(char *path)
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
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));

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

int
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

void
control_cleanup(char *path)
{
	if (path == NULL)
		return;
	event_del(&control_state.ev);
	event_del(&control_state.evt);
	unlink(path);
}

static void
control_accept(int listenfd, short event, void *bula)
{
	int			 connfd;
	socklen_t		 len;
	struct sockaddr_un	 sun;
	struct imsgproc		*p;

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

	p = proc_attach(PROC_CLIENT, connfd);
	proc_setcallback(p, control_dispatch_imsg, NULL);
	proc_enable(p);
}

static void
control_close(struct imsgproc *p)
{
	proc_free(p);

	/* Some file descriptors are available again. */
	if (evtimer_pending(&control_state.evt, NULL)) {
		evtimer_del(&control_state.evt);
		event_add(&control_state.ev, NULL);
	}
}

static void
control_dispatch_imsg(struct imsgproc *p, struct imsg *imsg, void *arg)
{
	int verbose;

	if (imsg == NULL) {
		control_close(p);
		return;
	}

	switch (imsg->hdr.type) {
	case IMSG_CTL_RELOAD:
		proc_compose(p_main, imsg->hdr.type, 0, 0, -1, NULL, 0);
		break;
	case IMSG_CTL_LOG_VERBOSE:
		if (imsg->hdr.len != IMSG_HEADER_SIZE +
		    sizeof(verbose))
			break;

		/* Forward to all other processes. */
		proc_compose(p_main, imsg->hdr.type, 0, imsg->hdr.pid, -1,
		    imsg->data, imsg->hdr.len - IMSG_HEADER_SIZE);
		proc_compose(p_engine, imsg->hdr.type, 0, imsg->hdr.pid, -1,
		    imsg->data, imsg->hdr.len - IMSG_HEADER_SIZE);

		memcpy(&verbose, imsg->data, sizeof(verbose));
		log_setverbose(verbose);
		break;
	case IMSG_CTL_SHOW_MAIN_INFO:
		proc_setpid(p, imsg->hdr.pid);
		proc_compose(p_main, imsg->hdr.type, 0, imsg->hdr.pid, -1,
		    imsg->data, imsg->hdr.len - IMSG_HEADER_SIZE);
		break;
	case IMSG_CTL_SHOW_FRONTEND_INFO:
		frontend_showinfo_ctl(p);
		proc_compose(p, IMSG_CTL_END, 0, 0, -1, NULL, 0);
		break;
	case IMSG_CTL_SHOW_ENGINE_INFO:
		proc_setpid(p, imsg->hdr.pid);
		proc_compose(p_engine, imsg->hdr.type, 0, imsg->hdr.pid, -1,
		    imsg->data, imsg->hdr.len - IMSG_HEADER_SIZE);
		break;
	default:
		log_debug("%s: error handling imsg %d", __func__,
		    imsg->hdr.type);
		break;
	}
}

int
control_imsg_relay(struct imsg *imsg)
{
	struct imsgproc *p;

	if ((p = proc_bypid(imsg->hdr.pid)) == NULL ||
	    proc_gettype(p) != PROC_CLIENT)
		return (0);

	return (proc_compose(p, imsg->hdr.type, 0, imsg->hdr.pid, -1,
	    imsg->data, imsg->hdr.len - IMSG_HEADER_SIZE));
}
