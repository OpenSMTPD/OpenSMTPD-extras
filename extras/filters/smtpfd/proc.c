/*	$OpenBSD$	*/

/*
 * Copyright (c) 2016-2017 Eric Faurot <eric@openbsd.org>
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

#include <sys/queue.h>
#include <sys/socket.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "proc.h"

struct imsgproc {
	TAILQ_ENTRY(imsgproc) tqe;
	int		 type;
	int		 instance;
	char		*title;
	pid_t		 pid;
	void		*arg;
	void		(*cb)(struct imsgproc *, struct imsg *, void *);
	struct imsgbuf	 imsgbuf;
	short		 events;
	struct event	 ev;
};

static struct imsgproc *proc_new(int);
static void proc_setsock(struct imsgproc *, int);
static void proc_callback(struct imsgproc *, struct imsg *);
static void proc_dispatch(int, short, void *);
static void proc_event_add(struct imsgproc *);

static TAILQ_HEAD(, imsgproc) procs = TAILQ_HEAD_INITIALIZER(procs);

pid_t
proc_getpid(struct imsgproc *p)
{
	return p->pid;
}

int
proc_gettype(struct imsgproc *p)
{
	return p->type;
}

int
proc_getinstance(struct imsgproc *p)
{
	return p->instance;
}

const char *
proc_gettitle(struct imsgproc *p)
{
	return p->title;
}

struct imsgproc *
proc_bypid(pid_t pid)
{
	struct imsgproc *p;

	TAILQ_FOREACH(p, &procs, tqe)
		if (pid == p->pid)
			return p;

	return NULL;
}

struct imsgproc *
proc_exec(int type, char **argv)
{
	struct imsgproc *p;
	int sp[2];
	pid_t pid;

	p = proc_new(type);
	if (p == NULL)
		fatal("proc_exec: calloc");

	if (socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, PF_UNSPEC, sp) == -1)
		fatal("proc_exec: socketpair");

	switch (pid = fork()) {
	case -1:
		fatal("proc_exec: fork");
	case 0:
		break;
	default:
		close(sp[0]);
		p->pid = pid;
		proc_setsock(p, sp[1]);
		return p;
	}

	if (dup2(sp[0], 3) == -1)
		fatal("proc_exec: dup2");

	if (closefrom(4) == -1)
		fatal("proc_exec: closefrom");

	execvp(argv[0], argv);
	fatal("proc_exec: execvp: %s", argv[0]);
}

struct imsgproc *
proc_attach(int type, int fd)
{
	struct imsgproc *p;

	p = proc_new(type);
	if (p == NULL)
		fatal("proc_exec: calloc");

	proc_setsock(p, fd);
	return p;
}

void
proc_settitle(struct imsgproc *p, const char *title)
{
	free(p->title);
	if (title) {
		p->title = strdup(title);
		if (p->title == NULL)
			fatal("proc_title: strdup");
	}
	else
		p->title = NULL;
}

void
proc_setcallback(struct imsgproc *p,
    void(*cb)(struct imsgproc *, struct imsg *, void *), void *arg)
{
	p->cb = cb;
	p->arg = arg;
}

void
proc_enable(struct imsgproc *p)
{
	proc_event_add(p);
}

void
proc_free(struct imsgproc *p)
{

	if (p == NULL)
		return;

	TAILQ_REMOVE(&procs, p, tqe);

	event_del(&p->ev);
	close(p->imsgbuf.fd);
	imsg_clear(&p->imsgbuf);
	free(p->title);
	free(p);
}

static struct imsgproc *
proc_new(int type)
{
	struct imsgproc *p;

	p = calloc(1, sizeof(*p));
	if (p == NULL)
		return NULL;

	p->type = type;
	p->instance = -1;
	p->pid = -1;
	imsg_init(&p->imsgbuf, -1);

	TAILQ_INSERT_TAIL(&procs, p, tqe);

	return p;
}

static void
proc_setsock(struct imsgproc *p, int sock)
{
	p->imsgbuf.fd = sock;
	p->imsgbuf.w.fd = sock;
}

static void
proc_event_add(struct imsgproc *p)
{
	short	events;

	events = EV_READ;
	if (p->imsgbuf.w.queued)
		events |= EV_WRITE;

	if (p->events)
		event_del(&p->ev);

	p->events = events;
	if (events) {
		event_set(&p->ev, p->imsgbuf.fd, events, proc_dispatch, p);
		event_add(&p->ev, NULL);
	}
}

static void
proc_callback(struct imsgproc *p, struct imsg *imsg)
{
	p->cb(p, imsg, p->arg);
}

static void
proc_dispatch(int fd, short event, void *arg)
{
	struct imsgproc	*p = arg;
	struct imsg	 imsg;
	ssize_t		 n;

	p->events = 0;

	if (event & EV_READ) {

		n = imsg_read(&p->imsgbuf);

		switch (n) {
		case -1:
			if (errno == EAGAIN)
				return;
			fatal("proc_dispatch: imsg_read");
			/* NOTREACHED */
		case 0:
			/* this pipe is dead, so remove the event handler */
			proc_callback(p, NULL);
			return;
		default:
			break;
		}
	}

	if (event & EV_WRITE) {
		n = msgbuf_write(&p->imsgbuf.w);
		if (n == 0 || (n == -1 && errno != EAGAIN)) {
			/* this pipe is dead, so remove the event handler */
			proc_callback(p, NULL);
			return;
		}
	}

	for (;;) {
		if ((n = imsg_get(&p->imsgbuf, &imsg)) == -1) {
			log_warn("proc_dispatch: imsg_get");
			proc_callback(p, NULL);
			return;
		}
		if (n == 0)
			break;

		proc_callback(p, &imsg);
		imsg_free(&imsg);
	}

	proc_event_add(p);
}

int
proc_compose(struct imsgproc *p, int type, uint32_t peerid, pid_t pid, int fd,
    void *data, uint16_t datalen)
{
	int r;

	r = imsg_compose(&p->imsgbuf, type, peerid, pid, fd, data, datalen);
	if (r != -1)
		proc_event_add(p);

	return r;
}
