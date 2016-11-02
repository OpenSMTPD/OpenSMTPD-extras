/*	$OpenBSD: mproc.c,v 1.8 2014/04/19 17:45:05 gilles Exp $	*/

/*
 * Copyright (c) 2012 Eric Faurot <eric@faurot.net>
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

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/tree.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <limits.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <smtpd-api.h>


/* from filter_api.c */
const char *proc_name(enum smtp_proc_type);
const char *imsg_to_str(int);

enum smtp_proc_type	smtpd_process = PROC_PONY;

static void mproc_dispatch(int, short, void *);

static ssize_t msgbuf_write2(struct msgbuf *);

void
session_socket_blockmode(int fd, enum blockmodes bm)
{
	int	flags;

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("fcntl F_GETFL");

	if (bm == BM_NONBLOCK)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;

	if ((flags = fcntl(fd, F_SETFL, flags)) == -1)
		fatal("fcntl F_SETFL");
}

int
mproc_fork(struct mproc *p, const char *path, char *argv[])
{
	int sp[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, sp) < 0)
		return (-1);

	session_socket_blockmode(sp[0], BM_NONBLOCK);
	session_socket_blockmode(sp[1], BM_NONBLOCK);

	if ((p->pid = fork()) == -1)
		goto err;

	if (p->pid == 0) {
		/* child process */
		dup2(sp[0], STDIN_FILENO);
		closefrom(STDERR_FILENO + 1);

		execv(path, argv);
		err(1, "execv: %s", path);
	}

	/* parent process */
	close(sp[0]);
	mproc_init(p, sp[1]);
	return (0);

err:
	log_warn("warn: Failed to start process %s, instance of %s", argv[0], path);
	close(sp[0]);
	close(sp[1]);
	return (-1);
}

void
mproc_init(struct mproc *p, int fd)
{
	imsg_init(&p->imsgbuf, fd);
}

void
mproc_clear(struct mproc *p)
{
	event_del(&p->ev);
	close(p->imsgbuf.fd);
	imsg_clear(&p->imsgbuf);
}

void
mproc_enable(struct mproc *p)
{
	if (p->enable == 0) {
		log_trace(TRACE_MPROC, "mproc: %s -> %s: enabled",
		    proc_name(smtpd_process),
		    proc_name(p->proc));
		p->enable = 1;
	}
	mproc_event_add(p);
}

void
mproc_disable(struct mproc *p)
{
	if (p->enable == 1) {
		log_trace(TRACE_MPROC, "mproc: %s -> %s: disabled",
		    proc_name(smtpd_process),
		    proc_name(p->proc));
		p->enable = 0;
	}
	mproc_event_add(p);
}

void
mproc_event_add(struct mproc *p)
{
	short	events;

	if (p->enable)
		events = EV_READ;
	else
		events = 0;

	if (p->imsgbuf.w.queued)
		events |= EV_WRITE;

	if (p->events)
		event_del(&p->ev);

	p->events = events;
	if (events) {
		event_set(&p->ev, p->imsgbuf.fd, events, mproc_dispatch, p);
		event_add(&p->ev, NULL);
	}
}

static void
mproc_dispatch(int fd, short event, void *arg)
{
	struct mproc	*p = arg;
	struct imsg	 imsg;
	ssize_t		 n;

	p->events = 0;

	if (event & EV_READ) {

		if ((n = imsg_read(&p->imsgbuf)) == -1) {
			log_warn("warn: %s -> %s: imsg_read",
			    proc_name(smtpd_process),  p->name);
			if (errno != EAGAIN)
				fatal("exiting");
		}
		else if (n == 0) {
			/* this pipe is dead, so remove the event handler */
			if (smtpd_process != PROC_CONTROL ||
			    p->proc != PROC_CLIENT)
				log_warnx("warn: %s -> %s: pipe closed",
				    proc_name(smtpd_process),  p->name);
			p->handler(p, NULL);
			return;
		}
		else
			p->bytes_in += n;
	}

	if (event & EV_WRITE) {
		n = msgbuf_write2(&p->imsgbuf.w);
		if (n == 0 || (n == -1 && errno != EAGAIN)) {
			/* this pipe is dead, so remove the event handler */
			if (smtpd_process != PROC_CONTROL ||
			    p->proc != PROC_CLIENT)
				log_warnx("warn: %s -> %s: pipe closed",
				    proc_name(smtpd_process),  p->name);
			p->handler(p, NULL);
			return;
		} else if (n != -1) {
			p->bytes_out += n;
			p->bytes_queued -= n;
		}
	}

	for (;;) {
		if ((n = imsg_get(&p->imsgbuf, &imsg)) == -1) {
			log_warn("fatal: %s: error in imsg_get for %s",
			    proc_name(smtpd_process),  p->name);
			fatalx(NULL);
		}
		if (n == 0)
			break;

		p->msg_in += 1;
		p->handler(p, &imsg);

		imsg_free(&imsg);
	}

#if 0
	if (smtpd_process == PROC_QUEUE)
		queue_flow_control();
#endif

	mproc_event_add(p);
}

/* XXX msgbuf_write() should return n ... */
static ssize_t
msgbuf_write2(struct msgbuf *msgbuf)
{
	struct iovec	 iov[IOV_MAX];
	struct ibuf	*buf;
	unsigned int	 i = 0;
	ssize_t		 n;
	struct msghdr	 msg;
	struct cmsghdr	*cmsg;
	union {
		struct cmsghdr	hdr;
		char		buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;

	memset(&iov, 0, sizeof(iov));
	memset(&msg, 0, sizeof(msg));
	TAILQ_FOREACH(buf, &msgbuf->bufs, entry) {
		if (i >= IOV_MAX)
			break;
		iov[i].iov_base = buf->buf + buf->rpos;
		iov[i].iov_len = buf->wpos - buf->rpos;
		i++;
		if (buf->fd != -1)
			break;
	}

	msg.msg_iov = iov;
	msg.msg_iovlen = i;

	if (buf != NULL && buf->fd != -1) {
		msg.msg_control = (caddr_t)&cmsgbuf.buf;
		msg.msg_controllen = sizeof(cmsgbuf.buf);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		*(int *)CMSG_DATA(cmsg) = buf->fd;
	}

again:
	if ((n = sendmsg(msgbuf->fd, &msg, 0)) == -1) {
		if (errno == EINTR)
			goto again;
		if (errno == ENOBUFS)
			errno = EAGAIN;
		return (-1);
	}

	if (n == 0) {			/* connection closed */
		errno = 0;
		return (0);
	}

	/*
	 * assumption: fd got sent if sendmsg sent anything
	 * this works because fds are passed one at a time
	 */
	if (buf != NULL && buf->fd != -1) {
		close(buf->fd);
		buf->fd = -1;
	}

	msgbuf_drain(msgbuf, n);

	return (n);
}

void
m_forward(struct mproc *p, struct imsg *imsg)
{
	imsg_compose(&p->imsgbuf, imsg->hdr.type, imsg->hdr.peerid,
	    imsg->hdr.pid, imsg->fd, imsg->data,
	    imsg->hdr.len - sizeof(imsg->hdr));

	log_trace(TRACE_MPROC, "mproc: %s -> %s : %zu %s (forward)",
		    proc_name(smtpd_process),
		    proc_name(p->proc),
		    imsg->hdr.len - sizeof(imsg->hdr),
		    imsg_to_str(imsg->hdr.type));

	p->msg_out += 1;
	p->bytes_queued += imsg->hdr.len;
	if (p->bytes_queued > p->bytes_queued_max)
		p->bytes_queued_max = p->bytes_queued;

	mproc_event_add(p);
}

void
m_compose(struct mproc *p, uint32_t type, uint32_t peerid, pid_t pid, int fd,
    void *data, size_t len)
{
	imsg_compose(&p->imsgbuf, type, peerid, pid, fd, data, len);

	log_trace(TRACE_MPROC, "mproc: %s -> %s : %zu %s",
		    proc_name(smtpd_process),
		    proc_name(p->proc),
		    len,
		    imsg_to_str(type));

	p->msg_out += 1;
	p->bytes_queued += len + IMSG_HEADER_SIZE;
	if (p->bytes_queued > p->bytes_queued_max)
		p->bytes_queued_max = p->bytes_queued;

	mproc_event_add(p);
}

void
m_composev(struct mproc *p, uint32_t type, uint32_t peerid, pid_t pid,
    int fd, const struct iovec *iov, int n)
{
	size_t	len;
	int	i;

	imsg_composev(&p->imsgbuf, type, peerid, pid, fd, iov, n);

	len = 0;
	for (i = 0; i < n; i++)
		len += iov[i].iov_len;

	p->msg_out += 1;
	p->bytes_queued += IMSG_HEADER_SIZE + len;
	if (p->bytes_queued > p->bytes_queued_max)
		p->bytes_queued_max = p->bytes_queued;

	log_trace(TRACE_MPROC, "mproc: %s -> %s : %zu %s",
		    proc_name(smtpd_process),
		    proc_name(p->proc),
		    len,
		    imsg_to_str(type));

	mproc_event_add(p);
}

void
m_create(struct mproc *p, uint32_t type, uint32_t peerid, pid_t pid, int fd)
{
	if (p->m_buf == NULL) {
		p->m_alloc = 128;
		log_trace(TRACE_MPROC, "mproc: %s -> %s: allocating %zu", 
		    proc_name(smtpd_process),
		    proc_name(p->proc),
		    p->m_alloc);
		p->m_buf = malloc(p->m_alloc);
		if (p->m_buf == NULL)
			fatal("warn: m_create: malloc");
	}

	p->m_pos = 0;
	p->m_type = type;
	p->m_peerid = peerid;
	p->m_pid = pid;
	p->m_fd = fd;
}

void
m_add(struct mproc *p, const void *data, size_t len)
{
	size_t	 alloc;
	void	*tmp;

	if (p->m_pos + len + IMSG_HEADER_SIZE > MAX_IMSGSIZE) {
		log_warnx("warn: message to large");
		fatal(NULL);
	}

	alloc = p->m_alloc;
	while (p->m_pos + len > alloc)
		alloc *= 2;
	if (alloc != p->m_alloc) {
		log_trace(TRACE_MPROC, "mproc: %s -> %s: realloc %zu -> %zu",
		    proc_name(smtpd_process),
		    proc_name(p->proc),
		    p->m_alloc,
		    alloc);

		tmp = realloc(p->m_buf, alloc);
		if (tmp == NULL)
			fatal("realloc");
		p->m_alloc = alloc;
		p->m_buf = tmp;
	}

	memmove(p->m_buf + p->m_pos, data, len);
	p->m_pos += len;
}

void
m_close(struct mproc *p)
{
	if (imsg_compose(&p->imsgbuf, p->m_type, p->m_peerid, p->m_pid, p->m_fd,
	    p->m_buf, p->m_pos) == -1)
		fatal("imsg_compose");

	log_trace(TRACE_MPROC, "mproc: %s -> %s : %zu %s",
		    proc_name(smtpd_process),
		    proc_name(p->proc),
		    p->m_pos,
		    imsg_to_str(p->m_type));

	p->msg_out += 1;
	p->bytes_queued += p->m_pos + IMSG_HEADER_SIZE;
	if (p->bytes_queued > p->bytes_queued_max)
		p->bytes_queued_max = p->bytes_queued;

	mproc_event_add(p);
}

void
m_flush(struct mproc *p)
{
	if (imsg_compose(&p->imsgbuf, p->m_type, p->m_peerid, p->m_pid, p->m_fd,
	    p->m_buf, p->m_pos) == -1)
		fatal("imsg_compose");

	log_trace(TRACE_MPROC, "mproc: %s -> %s : %zu %s (flush)",
	    proc_name(smtpd_process),
	    proc_name(p->proc),
	    p->m_pos,
	    imsg_to_str(p->m_type));

	p->msg_out += 1;
	p->m_pos = 0;

	imsg_flush(&p->imsgbuf);
}

static struct imsg * current;

static void
m_error(const char *error)
{
	char	buf[512];

	(void)snprintf(buf, sizeof buf, "%s: %s: %s",
	    proc_name(smtpd_process),
	    imsg_to_str(current->hdr.type),
	    error);
	fatalx("%s", buf);
}

void
m_msg(struct msg *m, struct imsg *imsg)
{
	current = imsg;
	m->pos = imsg->data;
	m->end = m->pos + (imsg->hdr.len - sizeof(imsg->hdr));
}

void
m_end(struct msg *m)
{
	if (m->pos != m->end)
		m_error("not at msg end");
}

int
m_is_eom(struct msg *m)
{
	return (m->pos == m->end);
}

static inline void
m_get(struct msg *m, void *dst, size_t sz)
{
	if (sz > MAX_IMSGSIZE ||
	    m->end - m->pos < (ssize_t)sz)
		m_error("msg too short");

	memmove(dst, m->pos, sz);
	m->pos += sz;
}

void
m_add_int(struct mproc *m, int v)
{
	m_add(m, &v, sizeof(v));
};

void
m_add_u32(struct mproc *m, uint32_t u32)
{
	m_add(m, &u32, sizeof(u32));
};

void
m_add_size(struct mproc *m, size_t sz)
{
	m_add(m, &sz, sizeof(sz));
};

void
m_add_time(struct mproc *m, time_t v)
{
	m_add(m, &v, sizeof(v));
};

void
m_add_string(struct mproc *m, const char *v)
{
	m_add(m, v, strlen(v) + 1);
};

void
m_add_data(struct mproc *m, const void *v, size_t len)
{
	m_add_size(m, len);
	m_add(m, v, len);
};

void
m_add_id(struct mproc *m, uint64_t v)
{
	m_add(m, &v, sizeof(v));
}

void
m_add_evpid(struct mproc *m, uint64_t v)
{
	m_add(m, &v, sizeof(v));
}

void
m_add_msgid(struct mproc *m, uint32_t v)
{
	m_add(m, &v, sizeof(v));
}

void
m_add_sockaddr(struct mproc *m, const struct sockaddr *sa)
{
	m_add_size(m, SA_LEN(sa));
	m_add(m, sa, SA_LEN(sa));
}

void
m_add_mailaddr(struct mproc *m, const struct mailaddr *maddr)
{
	m_add(m, maddr, sizeof(*maddr));
}

void
m_get_int(struct msg *m, int *i)
{
	m_get(m, i, sizeof(*i));
}

void
m_get_u32(struct msg *m, uint32_t *u32)
{
	m_get(m, u32, sizeof(*u32));
}

void
m_get_size(struct msg *m, size_t *sz)
{
	m_get(m, sz, sizeof(*sz));
}

void
m_get_time(struct msg *m, time_t *t)
{
	m_get(m, t, sizeof(*t));
}

void
m_get_string(struct msg *m, const char **s)
{
	uint8_t	*end;

	if (m->pos >= m->end)
		m_error("msg too short");

	end = memchr(m->pos, 0, m->end - m->pos);
	if (end == NULL)
		m_error("unterminated string");

	*s = m->pos;
	m->pos = end + 1;
}

void
m_get_data(struct msg *m, const void **data, size_t *sz)
{
	m_get_size(m, sz);

	if (m->pos + *sz > m->end)
		m_error("msg too short");

	*data = m->pos;
	m->pos += *sz;
}

void
m_get_evpid(struct msg *m, uint64_t *evpid)
{
	m_get(m, evpid, sizeof(*evpid));
}

void
m_get_msgid(struct msg *m, uint32_t *msgid)
{
	m_get(m, msgid, sizeof(*msgid));
}

void
m_get_id(struct msg *m, uint64_t *id)
{
	m_get(m, id, sizeof(*id));
}

void
m_get_sockaddr(struct msg *m, struct sockaddr *sa)
{
	size_t len;

	m_get_size(m, &len);
	m_get(m, sa, len);
}

void
m_get_mailaddr(struct msg *m, struct mailaddr *maddr)
{
	m_get(m, maddr, sizeof(*maddr));
}
