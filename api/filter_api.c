/*	$OpenBSD$	*/

/*
 * Copyright (c) 2013 Eric Faurot <eric@openbsd.org>
 * Copyright (c) 2011 Gilles Chehade <gilles@poolp.org>
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
#include <sys/queue.h>
#include <sys/uio.h>

#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <inttypes.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>

#include <smtpd-api.h>

#define FILTER_HIWAT 65536

static struct tree	queries;
static struct tree	sessions;

struct filter_session {
	uint64_t	id;
	uint64_t	qid;
	int		qtype;
	size_t		datalen;

	int		tx;
	struct {
		int		 eom_called;

		int		 error;
		struct io	 iev;
		struct iobuf	 ibuf;
		size_t		 idatalen;
		struct io	 oev;
		struct iobuf	 obuf;
		size_t		 odatalen;
	} pipe;

	struct {
		int		 ready;
		int		 status;
		int		 code;
		char		*line;
	} response;

	void			*usession;
	void			*utx;

	void			*data_buffer;
	void		       (*data_buffer_cb)(uint64_t, FILE *, void *);

	struct rfc2822_parser	rfc2822_parser;
	struct dict		headers_replace;
	struct dict		headers_add;

};

struct filter_timer {
	struct event		 ev;
	uint64_t		 id;
	void			(*cb)(uint64_t, void *);
	void			*arg;
};

static int		 register_done;
static const char	*filter_name;

static struct filter_internals {
	struct mproc	p;

	uint32_t	flags;

	uid_t		uid;
	gid_t		gid;
	const char     *rootpath;

	struct {
		int  (*connect)(uint64_t, struct filter_connect *);
		int  (*helo)(uint64_t, const char *);
		int  (*mail)(uint64_t, struct mailaddr *);
		int  (*rcpt)(uint64_t, struct mailaddr *);
		int  (*data)(uint64_t);

		void (*msg_line)(uint64_t, const char *);
		void (*msg_start)(uint64_t);
		int  (*msg_end)(uint64_t, size_t);

		void (*disconnect)(uint64_t);
		void (*reset)(uint64_t);

		void *(*session_alloc)(uint64_t);
		void (*session_free)(void *);

		void *(*tx_alloc)(uint64_t);
		void (*tx_free)(void *);
		void (*tx_begin)(uint64_t);
		void (*tx_commit)(uint64_t);
		void (*tx_rollback)(uint64_t);
	} cb;

	int		data_buffered;
} fi;

static void filter_api_init(void);
static void filter_response(struct filter_session *, int, int, const char *);
static void filter_send_response(struct filter_session *);
static void filter_register_query(uint64_t, uint64_t, int);
static void filter_dispatch(struct mproc *, struct imsg *);
static void filter_dispatch_data(uint64_t);
static void filter_dispatch_msg_line(uint64_t, const char *);
static void filter_dispatch_msg_start(uint64_t);
static void filter_dispatch_msg_end(uint64_t, size_t);
static void filter_dispatch_connect(uint64_t, struct filter_connect *);
static void filter_dispatch_helo(uint64_t, const char *);
static void filter_dispatch_mail(uint64_t, struct mailaddr *);
static void filter_dispatch_rcpt(uint64_t, struct mailaddr *);
static void filter_dispatch_reset(uint64_t);
static void filter_dispatch_tx_begin(uint64_t);
static void filter_dispatch_tx_commit(uint64_t);
static void filter_dispatch_tx_rollback(uint64_t);
static void filter_dispatch_disconnect(uint64_t);

static void filter_trigger_eom(struct filter_session *);
static void filter_io_in(struct io *, int);
static void filter_io_out(struct io *, int);
static const char *filterimsg_to_str(int);
static const char *query_to_str(int);
static const char *event_to_str(int);

static void	data_buffered_setup(struct filter_session *);
static void	data_buffered_release(struct filter_session *);
static void	data_buffered_stream_process(uint64_t, FILE *, void *);


static void
filter_response(struct filter_session *s, int status, int code, const char *line)
{
	log_trace(TRACE_FILTERS, "filter-api:%s %016"PRIx64" %s filter_response(%d, %d, %s)",
	    filter_name, s->id, query_to_str(s->qtype), status, code, line);

	s->response.ready = 1;
	s->response.status = status;
	s->response.code = code;
	if (line)
		s->response.line = strdup(line);
	else
		s->response.line = NULL;

	/* eom is special, as the reponse has to be deferred until the pipe is all flushed */
	if (s->qtype == QUERY_EOM) {
		/* wait for the obuf to drain */
		if (iobuf_queued(&s->pipe.obuf))
			return;

		if (s->pipe.oev.sock != -1) {
			io_clear(&s->pipe.oev);
			iobuf_clear(&s->pipe.obuf);
		}
		filter_trigger_eom(s);
	}
	else
		filter_send_response(s);
}

static void
filter_send_response(struct filter_session *s)
{
	log_trace(TRACE_FILTERS, "filter-api:%s %016"PRIx64" %s filter_send_response() -> %d, %d, %s",
	    filter_name, s->id, query_to_str(s->qtype),
	    s->response.status,
	    s->response.code,
	    s->response.line);

	tree_xpop(&queries, s->qid);

	m_create(&fi.p, IMSG_FILTER_RESPONSE, 0, 0, -1);
	m_add_id(&fi.p, s->qid);
	m_add_int(&fi.p, s->qtype);
	if (s->qtype == QUERY_EOM)
		m_add_u32(&fi.p, s->datalen);
	m_add_int(&fi.p, s->response.status);
	m_add_int(&fi.p, s->response.code);
	if (s->response.line) {
		m_add_string(&fi.p, s->response.line);
		free(s->response.line);
		s->response.line = NULL;
	}
	m_close(&fi.p);

	s->qid = 0;
	s->response.ready = 0;
}

static void
filter_dispatch(struct mproc *p, struct imsg *imsg)
{
	struct filter_session	*s;
	struct filter_connect	 q_connect;
	struct mailaddr		 maddr;
	struct msg		 m;
	const char		*line, *name;
	uint32_t		 v, datalen;
	uint64_t		 id, qid;
	int			 type;
	int			 fds[2], fdin, fdout;

#ifdef EXPERIMENTAL
	log_warnx("filter is EXPERIMENTAL and NOT meant to be used in production.");
#endif

	if (imsg == NULL) {
		log_trace(TRACE_FILTERS, "filter-api:%s server closed", filter_name);
		exit(0);
	}

	log_trace(TRACE_FILTERS, "filter-api:%s imsg %s", filter_name,
	    filterimsg_to_str(imsg->hdr.type));

	switch (imsg->hdr.type) {
	case IMSG_FILTER_REGISTER:
		m_msg(&m, imsg);
		m_get_u32(&m, &v);
		m_get_string(&m, &name);
		filter_name = strdup(name);
		m_end(&m);
		if (v != FILTER_API_VERSION) {
			log_warnx("warn: filter-api:%s API mismatch", filter_name);
			fatalx("filter-api: exiting");
		}
		m_create(p, IMSG_FILTER_REGISTER, 0, 0, -1);
		/* all hooks for now */
		m_add_int(p, ~0);
		m_add_int(p, fi.flags);
		m_close(p);
		break;

	case IMSG_FILTER_EVENT:
		m_msg(&m, imsg);
		m_get_id(&m, &id);
		m_get_int(&m, &type);
		m_end(&m);
		switch (type) {
		case EVENT_CONNECT:
			s = calloc(1, sizeof(*s));
			if (s == NULL)
				fatal("filter_dispatch");
			s->id = id;
			s->pipe.iev.sock = -1;
			s->pipe.oev.sock = -1;
			tree_xset(&sessions, id, s);
			if (fi.cb.session_alloc)
				s->usession = fi.cb.session_alloc(id);
			break;
		case EVENT_DISCONNECT:
			filter_dispatch_disconnect(id);
			s = tree_xpop(&sessions, id);
			if (fi.cb.session_free && s->usession)
				fi.cb.session_free(s->usession);
			free(s);
			break;
		case EVENT_RESET:
			filter_dispatch_reset(id);
			break;
		case EVENT_TX_BEGIN:
			filter_dispatch_tx_begin(id);
			break;
		case EVENT_TX_COMMIT:
			filter_dispatch_tx_commit(id);
			break;
		case EVENT_TX_ROLLBACK:
			filter_dispatch_tx_rollback(id);
			break;
		default:
			log_warnx("warn: filter-api:%s bad event %d", filter_name, type);
			fatalx("filter-api: exiting");
		}
		break;

	case IMSG_FILTER_QUERY:
		m_msg(&m, imsg);
		m_get_id(&m, &id);
		m_get_id(&m, &qid);
		m_get_int(&m, &type);
		switch(type) {
		case QUERY_CONNECT:
			m_get_sockaddr(&m, (struct sockaddr*)&q_connect.local);
			m_get_sockaddr(&m, (struct sockaddr*)&q_connect.remote);
			m_get_string(&m, &q_connect.hostname);
			m_end(&m);
			filter_register_query(id, qid, type);
			filter_dispatch_connect(id, &q_connect);
			break;
		case QUERY_HELO:
			m_get_string(&m, &line);
			m_end(&m);
			filter_register_query(id, qid, type);
			filter_dispatch_helo(id, line);
			break;
		case QUERY_MAIL:
			m_get_mailaddr(&m, &maddr);
			m_end(&m);
			filter_register_query(id, qid, type);
			filter_dispatch_mail(id, &maddr);
			break;
		case QUERY_RCPT:
			m_get_mailaddr(&m, &maddr);
			m_end(&m);
			filter_register_query(id, qid, type);
			filter_dispatch_rcpt(id, &maddr);
			break;
		case QUERY_DATA:
			m_end(&m);
			filter_register_query(id, qid, type);
			filter_dispatch_data(id);
			break;
		case QUERY_EOM:
			m_get_u32(&m, &datalen);
			m_end(&m);
			filter_register_query(id, qid, type);
			filter_dispatch_msg_end(id, datalen);
			break;
		default:
			log_warnx("warn: filter-api:%s bad query %d", filter_name, type);
			fatalx("filter-api: exiting");
		}
		break;

	case IMSG_FILTER_PIPE:
		m_msg(&m, imsg);
		m_get_id(&m, &id);
		m_end(&m);

		fdout = imsg->fd;
		fdin = -1;

		if (fdout == -1) {
			log_warnx("warn: %016"PRIx64" failed to receive pipe",
			    id);
		}
		else if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, fds) == -1) {
			log_warn("warn: filter-api:%s socketpair", filter_name);
			close(fdout);
		}
		else {
			s = tree_xget(&sessions, id);

			s->pipe.eom_called = 0;
			s->pipe.error = 0;
			s->pipe.idatalen = 0;
			s->pipe.odatalen = 0;

			iobuf_init(&s->pipe.obuf, 0, 0);
			io_init(&s->pipe.oev, fdout, s, filter_io_out, &s->pipe.obuf);
			io_set_write(&s->pipe.oev);

			iobuf_init(&s->pipe.ibuf, 0, 0);
			io_init(&s->pipe.iev, fds[0], s, filter_io_in, &s->pipe.ibuf);
			io_set_read(&s->pipe.iev);

			fdin = fds[1];
		}

		log_trace(TRACE_FILTERS, "filter-api:%s %016"PRIx64" tx pipe %d -> %d",
		    filter_name, id, fdin, fdout);

		m_create(&fi.p, IMSG_FILTER_PIPE, 0, 0, fdin);
		m_add_id(&fi.p, id);
		m_close(&fi.p);

		if (fdin != -1)
			filter_dispatch_msg_start(id);

		break;
	}
}

static void
filter_register_query(uint64_t id, uint64_t qid, int type)
{
	struct filter_session	*s;

	log_trace(TRACE_FILTERS, "filter-api:%s %016"PRIx64" %s", filter_name, id, query_to_str(type));

	s = tree_xget(&sessions, id);
	if (s->qid) {
		log_warnx("warn: filter-api:%s query already in progress",
		    filter_name);
		fatalx("filter-api: exiting");
	}
	s->qid = qid;
	s->qtype = type;
	s->response.ready = 0;

	tree_xset(&queries, qid, s);
}

static void
filter_dispatch_connect(uint64_t id, struct filter_connect *conn)
{
	if (fi.cb.connect)
		fi.cb.connect(id, conn);
	else
		filter_api_accept(id);
}

static void
filter_dispatch_helo(uint64_t id, const char *helo)
{
	if (fi.cb.helo)
		fi.cb.helo(id, helo);
	else
		filter_api_accept(id);
}

static void
filter_dispatch_mail(uint64_t id, struct mailaddr *mail)
{
	if (fi.cb.mail)
		fi.cb.mail(id, mail);
	else
		filter_api_accept(id);
}

static void
filter_dispatch_rcpt(uint64_t id, struct mailaddr *rcpt)
{
	if (fi.cb.rcpt)
		fi.cb.rcpt(id, rcpt);
	else
		filter_api_accept(id);
}

static void
filter_dispatch_data(uint64_t id)
{
	if (fi.cb.data)
		fi.cb.data(id);
	else
		filter_api_accept(id);
}

static void
filter_dispatch_reset(uint64_t id)
{
	if (fi.cb.reset)
		fi.cb.reset(id);
}

static void
filter_dispatch_tx_begin(uint64_t id)
{
	struct filter_session *s;

	s = tree_xget(&sessions, id);
	if (s->tx)
		fatalx("tx-begin: session %016"PRIx64" in transaction", id);

	s->tx = 1;

	if (fi.cb.tx_alloc)
		s->utx = fi.cb.tx_alloc(id);

	if (fi.cb.tx_begin)
		fi.cb.tx_begin(id);
}

static void
filter_dispatch_tx_commit(uint64_t id)
{
	struct filter_session	*s;

	s = tree_xget(&sessions, id);
	if (s->tx == 0)
		fatalx("tx-commit: session %016"PRIx64" not in transaction", id);

	s->tx = 0;
	io_clear(&s->pipe.oev);
	iobuf_clear(&s->pipe.obuf);
	io_clear(&s->pipe.iev);
	iobuf_clear(&s->pipe.ibuf);

	if (fi.cb.tx_commit)
		fi.cb.tx_commit(id);

	if (fi.cb.tx_free && s->utx) {
		fi.cb.tx_free(s->utx);
		s->utx = NULL;
	}

	if (s->data_buffer)
		data_buffered_release(s);
}

static void
filter_dispatch_tx_rollback(uint64_t id)
{
	struct filter_session	*s;

	s = tree_xget(&sessions, id);
	if (s->tx == 0)
		fatalx("tx-rollback: session %016"PRIx64" not in transaction", id);

	s->tx = 0;
	io_clear(&s->pipe.oev);
	iobuf_clear(&s->pipe.obuf);
	io_clear(&s->pipe.iev);
	iobuf_clear(&s->pipe.ibuf);

	if (fi.cb.tx_rollback)
		fi.cb.tx_rollback(id);

	if (fi.cb.tx_free && s->utx) {
		fi.cb.tx_free(s->utx);
		s->utx = NULL;
	}

	if (s->data_buffer)
		data_buffered_release(s);
}

static void
filter_dispatch_disconnect(uint64_t id)
{
	if (fi.cb.disconnect)
		fi.cb.disconnect(id);
}

static void
filter_dispatch_msg_line(uint64_t id, const char *data)
{
	if (fi.cb.msg_line)
		fi.cb.msg_line(id, data);
	else
		filter_api_writeln(id, data);
}

static void
filter_dispatch_msg_start(uint64_t id)
{

	struct filter_session *s;

	if (fi.data_buffered) {
		s = tree_xget(&sessions, id);
		data_buffered_setup(s);
	}

	if (fi.cb.msg_start)
		fi.cb.msg_start(id);
}

static void
filter_dispatch_msg_end(uint64_t id, size_t datalen)
{
	struct filter_session	*s;

	s = tree_xget(&sessions, id);
	s->datalen = datalen;

	filter_trigger_eom(s);
}

static void
filter_trigger_eom(struct filter_session *s)
{
	log_trace(TRACE_FILTERS, "filter-api:%s %016"PRIx64" filter_trigger_eom(%d, %d, %zu, %zu, %zu)",
	    filter_name, s->id, s->pipe.iev.sock, s->pipe.oev.sock,
	    s->datalen, s->pipe.idatalen, s->pipe.odatalen);

	/* This is called when
	 * - EOM query is first received
	 * - input data is closed
	 * - output has been written
	 */

	/* input not done yet, or EOM query not received */
	if (s->pipe.iev.sock != -1 || s->qid == 0)
		return;

	if (s->pipe.error)
		goto fail;

	/* if size don't match, error out */
	if (s->pipe.idatalen != s->datalen) {
		log_trace(TRACE_FILTERS, "filter-api:%s tx datalen mismatch: %zu/%zu",
		    filter_name, s->pipe.idatalen, s->datalen);
		s->pipe.error = 1;
		goto fail;
	}

	/* if we didn't send the eom to the user do it now */
	if (!s->pipe.eom_called) {
		s->pipe.eom_called = 1;
		if (fi.cb.msg_end)
			fi.cb.msg_end(s->id, s->datalen);
		else
			filter_api_accept(s->id);
		return;
	}

	if (s->pipe.error)
		goto fail;

	/* wait for the output socket to be closed */
	if (s->pipe.oev.sock != -1)
		return;

	s->datalen = s->pipe.odatalen;
	filter_send_response(s);

    fail:
	/* XXX */
	return;
}

static void
filter_io_in(struct io *io, int evt)
{
	struct filter_session	*s = io->arg;
	char			*line;
	size_t			 len;

	log_trace(TRACE_FILTERS, "filter-api:%s filter_io_in(%p, %s)",
	    filter_name, s, io_strevent(evt));

	switch (evt) {
	case IO_DATAIN:
	    nextline:
		line = iobuf_getline(&s->pipe.ibuf, &len);
		if ((line == NULL && iobuf_len(&s->pipe.ibuf) >= SMTPD_MAXLINESIZE) ||
		    (line && len >= SMTPD_MAXLINESIZE)) {
			s->pipe.error = 1;
			break;
		}
		/* No complete line received */
		if (line == NULL) {
			iobuf_normalize(&s->pipe.ibuf);
			/* flow control */
			if (iobuf_queued(&s->pipe.obuf) >= FILTER_HIWAT)
				io_pause(&s->pipe.iev, IO_PAUSE_IN);
			return;
		}

		s->pipe.idatalen += len + 1;
		/* XXX warning: do not clear io from this call! */
		if (s->data_buffer) {
			/* XXX handle errors somehow */
			fprintf(s->data_buffer, "%s\n", line);
		}
		filter_dispatch_msg_line(s->id, line);
		goto nextline;

	case IO_DISCONNECTED:
		if (iobuf_len(&s->pipe.ibuf)) {
			log_warn("warn: filter-api:%s %016"PRIx64" incomplete input",
			    filter_name, s->id);
		}
		log_trace(TRACE_FILTERS, "filter-api:%s %016"PRIx64" input done (%zu bytes)",
		    filter_name, s->id, s->pipe.idatalen);
		break;

	default:
		log_warn("warn: filter-api:%s %016"PRIx64": unexpected io event %d on data pipe",
		    filter_name, s->id, evt);
		s->pipe.error = 1;

	}
	if (s->pipe.error) {
		io_clear(&s->pipe.oev);
		iobuf_clear(&s->pipe.obuf);
	}
	io_clear(&s->pipe.iev);
	iobuf_clear(&s->pipe.ibuf);
	filter_trigger_eom(s);
}

static void
filter_io_out(struct io *io, int evt)
{
	struct filter_session    *s = io->arg;

	log_trace(TRACE_FILTERS, "filter-api:%s %016"PRIx64" filter_io_out(%s)",
	    filter_name, s->id, io_strevent(evt));

	switch (evt) {
	case IO_TIMEOUT:
	case IO_DISCONNECTED:
	case IO_ERROR:
		log_trace(TRACE_FILTERS, "filter-api:%s %016"PRIx64" io error on output pipe",
		    filter_name, s->id);
		s->pipe.error = 1;
		break;

	case IO_LOWAT:
		/* flow control */
		if (s->pipe.iev.sock != -1 && s->pipe.iev.flags & IO_PAUSE_IN) {
			io_resume(&s->pipe.iev, IO_PAUSE_IN);
			return;
		}

		/* if the input is done and there is a response we are done */
		if (s->pipe.iev.sock == -1 && s->response.ready)
			break;

		/* just wait for more data to send or feed through callback */
		if (s->data_buffer_cb)
			s->data_buffer_cb(s->id, s->data_buffer, s);
		return;

	default:
		fatalx("filter_io_out()");
	}

	io_clear(&s->pipe.oev);
	iobuf_clear(&s->pipe.obuf);
	if (s->pipe.error) {
		io_clear(&s->pipe.iev);
		iobuf_clear(&s->pipe.ibuf);
	}
	filter_trigger_eom(s);
}

#define CASE(x) case x : return #x

static const char *
filterimsg_to_str(int imsg)
{
	switch (imsg) {
	CASE(IMSG_FILTER_REGISTER);
	CASE(IMSG_FILTER_EVENT);
	CASE(IMSG_FILTER_QUERY);
	CASE(IMSG_FILTER_PIPE);
	CASE(IMSG_FILTER_RESPONSE);
	default:
		return ("IMSG_FILTER_???");
	}
}

static const char *
query_to_str(int query)
{
	switch (query) {
	CASE(QUERY_CONNECT);
	CASE(QUERY_HELO);
	CASE(QUERY_MAIL);
	CASE(QUERY_RCPT);
	CASE(QUERY_DATA);
	CASE(QUERY_EOM);
	CASE(QUERY_DATALINE);
	default:
		return ("QUERY_???");
	}
}

static const char *
event_to_str(int event)
{
	switch (event) {
	CASE(EVENT_CONNECT);
	CASE(EVENT_RESET);
	CASE(EVENT_DISCONNECT);
	CASE(EVENT_TX_BEGIN);
	CASE(EVENT_TX_COMMIT);
	CASE(EVENT_TX_ROLLBACK);
	default:
		return ("EVENT_???");
	}
}

/*
 * These functions are called from mproc.c
 */

enum smtp_proc_type smtpd_process;

const char *
proc_name(enum smtp_proc_type proc)
{
	if (proc == PROC_FILTER)
		return (filter_name);
	return ("filter");
}

const char *
imsg_to_str(int imsg)
{
	static char buf[32];

	snprintf(buf, sizeof(buf), "%d", imsg);

	return (buf);
}


/*
 * These functions are callable by filters
 */

void
filter_api_session_allocator(void *(*f)(uint64_t))
{
	fi.cb.session_alloc = f;
}

void
filter_api_session_destructor(void (*f)(void *))
{
	fi.cb.session_free = f;
}

void *
filter_api_session(uint64_t id)
{
	struct filter_session	*s;

	s = tree_xget(&sessions, id);
	return s->usession;
}

void
filter_api_transaction_allocator(void *(*f)(uint64_t))
{
	fi.cb.tx_alloc = f;
}

void
filter_api_transaction_destructor(void (*f)(void *))
{
	fi.cb.tx_free = f;
}

void *
filter_api_transaction(uint64_t id)
{
	struct filter_session	*s;

	s = tree_xget(&sessions, id);
	return s->utx;
}

void
filter_api_setugid(uid_t uid, gid_t gid)
{
	filter_api_init();

	if (!uid) {
		log_warn("warn: filter-api:%s can't set uid 0", filter_name);
		fatalx("filter-api: exiting");
	}
	if (!gid) {
		log_warn("warn: filter-api:%s can't set gid 0", filter_name);
		fatalx("filter-api: exiting");
	}
	fi.uid = uid;
	fi.gid = gid;
}

void
filter_api_no_chroot(void)
{
	filter_api_init();

	fi.rootpath = NULL;
}

void
filter_api_set_chroot(const char *rootpath)
{
	filter_api_init();

	fi.rootpath = rootpath;
}

static void
filter_api_init(void)
{
	extern const char *__progname;
	struct passwd  *pw;
	static int	init = 0;

	if (init)
		return;

	init = 1;

	smtpd_process = PROC_FILTER;
	filter_name = __progname;

	pw = getpwnam(SMTPD_USER);
	if (pw == NULL) {
		log_warn("warn: filter-api:%s getpwnam", filter_name);
		fatalx("filter-api: exiting");
	}

	tree_init(&queries);
	tree_init(&sessions);
	event_init();

	memset(&fi, 0, sizeof(fi));
	fi.p.proc = PROC_PONY;
	fi.p.name = "filter";
	fi.p.handler = filter_dispatch;
	fi.uid = pw->pw_uid;
	fi.gid = pw->pw_gid;
	fi.rootpath = PATH_CHROOT;

	mproc_init(&fi.p, 0);
}

void
filter_api_on_connect(int(*cb)(uint64_t, struct filter_connect *))
{
	filter_api_init();

	fi.cb.connect = cb;
}

void
filter_api_on_helo(int(*cb)(uint64_t, const char *))
{
	filter_api_init();

	fi.cb.helo = cb;
}

void
filter_api_on_mail(int(*cb)(uint64_t, struct mailaddr *))
{
	filter_api_init();

	fi.cb.mail = cb;
}

void
filter_api_on_rcpt(int(*cb)(uint64_t, struct mailaddr *))
{
	filter_api_init();

	fi.cb.rcpt = cb;
}

void
filter_api_on_data(int(*cb)(uint64_t))
{
	filter_api_init();

	fi.cb.data = cb;
}

void
filter_api_on_msg_line(void(*cb)(uint64_t, const char *))
{
	filter_api_init();

	fi.cb.msg_line = cb;
}

void
filter_api_on_msg_start(void(*cb)(uint64_t))
{
	filter_api_init();

	fi.cb.msg_start = cb;
}

void
filter_api_on_msg_end(int(*cb)(uint64_t, size_t))
{
	filter_api_init();

	fi.cb.msg_end = cb;
}

void
filter_api_on_reset(void(*cb)(uint64_t))
{
	filter_api_init();

	fi.cb.reset = cb;
}

void
filter_api_on_disconnect(void(*cb)(uint64_t))
{
	filter_api_init();

	fi.cb.disconnect = cb;
}

void
filter_api_on_tx_begin(void(*cb)(uint64_t))
{
	filter_api_init();

	fi.cb.tx_begin = cb;
}

void
filter_api_on_tx_commit(void(*cb)(uint64_t))
{
	filter_api_init();

	fi.cb.tx_commit = cb;
}

void
filter_api_on_tx_rollback(void(*cb)(uint64_t))
{
	filter_api_init();

	fi.cb.tx_rollback = cb;
}

void
filter_api_loop(void)
{
	if (register_done) {
		log_warnx("warn: filter-api:%s filter_api_loop() already called", filter_name);
		fatalx("filter-api: exiting");
	}

	filter_api_init();

	register_done = 1;

	mproc_enable(&fi.p);

	if (fi.rootpath) {
		if (chroot(fi.rootpath) == -1) {
			log_warn("warn: filter-api:%s chroot", filter_name);
			fatalx("filter-api: exiting");
		}
		if (chdir("/") == -1) {
			log_warn("warn: filter-api:%s chdir", filter_name);
			fatalx("filter-api: exiting");
		}
	}

	if (setgroups(1, &fi.gid) ||
	    setresgid(fi.gid, fi.gid, fi.gid) ||
	    setresuid(fi.uid, fi.uid, fi.uid)) {
		log_warn("warn: filter-api:%s cannot drop privileges", filter_name);
		fatalx("filter-api: exiting");
	}

	/* we must ignore SIGPIPE otherwise we might die when a data pipe goes away */
	signal(SIGPIPE, SIG_IGN);

	if (event_dispatch() < 0) {
		log_warn("warn: filter-api:%s event_dispatch", filter_name);
		fatalx("filter-api: exiting");
	}
}

int
filter_api_accept(uint64_t id)
{
	struct filter_session	*s;

	log_trace(TRACE_FILTERS, "filter-api:%s %016"PRIx64" filter_api_accept()", filter_name, id);

	s = tree_xget(&sessions, id);
	filter_response(s, FILTER_OK, 0, NULL);

	return (1);
}

int
filter_api_reject(uint64_t id, enum filter_status status)
{
	struct filter_session	*s;

	log_trace(TRACE_FILTERS, "filter-api:%s %016"PRIx64" filter_api_reject(%d)",
	    filter_name, id, status);

	s = tree_xget(&sessions, id);

	/* This is NOT an acceptable status for a failure */
	if (status == FILTER_OK)
		status = FILTER_FAIL;

	filter_response(s, status, 0, NULL);

	return (1);
}

int
filter_api_reject_code(uint64_t id, enum filter_status status, uint32_t code,
    const char *line)
{
	struct filter_session	*s;

	log_trace(TRACE_FILTERS, "filter-api:%s %016"PRIx64" filter_api_reject_code(%d, %u, %s)",
	    filter_name, id, status, code, line);

	s = tree_xget(&sessions, id);

	/* This is NOT an acceptable status for a failure */
	if (status == FILTER_OK)
		status = FILTER_FAIL;

	filter_response(s, status, code, line);

	return (1);
}

void
filter_api_writeln(uint64_t id, const char *line)
{
	struct filter_session	*s;

	log_trace(TRACE_FILTERS, "filter-api:%s %016"PRIx64" filter_api_writeln(%s)", filter_name, id, line);

	s = tree_xget(&sessions, id);

	if (s->pipe.oev.sock == -1) {
		log_warnx("warn: session %016"PRIx64": write out of sequence", id);
		return;
	}

	s->pipe.odatalen += strlen(line) + 1;
	iobuf_fqueue(&s->pipe.obuf, "%s\n", line);
	io_reload(&s->pipe.oev);
}

void
filter_api_printf(uint64_t id, const char *fmt, ...)
{
	struct filter_session  *s;
	va_list			ap;
	int			len;

	log_trace(TRACE_FILTERS, "filter-api:%s %016"PRIx64" filter_api_printf(%s)",
	    filter_name, id, fmt);

	s = tree_xget(&sessions, id);

	if (s->pipe.oev.sock == -1) {
		log_warnx("warn: session %016"PRIx64": write out of sequence", id);
		return;
	}

	va_start(ap, fmt);
	len = iobuf_vfqueue(&s->pipe.obuf, fmt, ap);
	iobuf_fqueue(&s->pipe.obuf, "\n");
	va_end(ap);
	s->pipe.odatalen += len + 1;
	io_reload(&s->pipe.oev);
}

static void
filter_api_timer_cb(int fd, short evt, void *arg)
{
	struct filter_timer *ft = arg;

	ft->cb(ft->id, ft->arg);
	free(ft);
}

void
filter_api_timer(uint64_t id, uint32_t tmo, void (*cb)(uint64_t, void *), void *arg)
{
	struct filter_timer *ft = xcalloc(1, sizeof(struct filter_timer), "filter_api_timer");
	struct timeval tv = { tmo / 1000, (tmo % 1000) * 1000 };

	ft->id = id;
	ft->cb = cb;
	ft->arg = arg;
	evtimer_set(&ft->ev, filter_api_timer_cb, ft);
	evtimer_add(&ft->ev, &tv);
}

const char *
filter_api_sockaddr_to_text(const struct sockaddr *sa)
{
	static char	buf[NI_MAXHOST];

	if (getnameinfo(sa, SA_LEN(sa), buf, sizeof(buf), NULL, 0,
		NI_NUMERICHOST))
		return ("(unknown)");
	else
		return (buf);
}

const char *
filter_api_mailaddr_to_text(const struct mailaddr *maddr)
{
	static char  buffer[SMTPD_MAXLINESIZE];

	strlcpy(buffer, maddr->user, sizeof buffer);
	if (maddr->domain[0] == '\0')
		return (buffer);
	strlcat(buffer, "@", sizeof buffer);
	if (strlcat(buffer, maddr->domain, sizeof buffer) >= sizeof buffer)
		return (NULL);

	return (buffer);
}


/* X X X */
static void
data_buffered_stream_process(uint64_t id, FILE *fp, void *arg)
{
	struct filter_session	*s;
	size_t	 sz;
	ssize_t	 len;
	char	*line = NULL;

	s = tree_xget(&sessions, id);
	errno = 0;
	if ((len = getline(&line, &sz, fp)) == -1) {
		if (errno) {
			filter_api_reject_code(id, FILTER_FAIL, 421,
			    "Internal Server Error");
			return;
		}
		filter_api_accept(id);
		return;
	}
	line[strcspn(line, "\n")] = '\0';
	rfc2822_parser_feed(&s->rfc2822_parser, line);
	free(line);

	/* XXX - should be driven by parser_feed */
	if (1)
		io_callback(&s->pipe.oev, IO_LOWAT);
}

static void
default_header_callback(const struct rfc2822_header *hdr, void *arg)
{
	struct filter_session	*s = arg;
	struct rfc2822_line     *l;
	int                      i = 0;

	TAILQ_FOREACH(l, &hdr->lines, next) {
		if (i++ == 0) {
			filter_api_printf(s->id, "%s: %s", hdr->name, l->buffer + 1);
			continue;
		}
		filter_api_printf(s->id, "%s", l->buffer);
	}
}

static void
default_body_callback(const char *line, void *arg)
{
	struct filter_session	*s = arg;

	filter_api_writeln(s->id, line);
}

static void
header_remove_callback(const struct rfc2822_header *hdr, void *arg)
{
}

static void
header_replace_callback(const struct rfc2822_header *hdr, void *arg)
{
	struct filter_session	*s = arg;
	char			*value;
	char			*key;

	key = xstrdup(hdr->name, "header_replace_callback");
	lowercase(key, key, strlen(key)+1);

	value = dict_xget(&s->headers_replace, key);
	filter_api_printf(s->id, "%s: %s", hdr->name, value);
	free(key);
}

static void
header_eoh_callback(void *arg)
{
	struct filter_session	*s = arg;
	void			*iter;
	const char		*key;
	void			*data;

	iter = NULL;
	while (dict_iter(&s->headers_add, &iter, &key, &data))
		filter_api_printf(s->id, "%s: %s", key, (char *)data);
}

void
data_buffered_setup(struct filter_session *s)
{
	FILE   *fp;
	int	fd;
	char	pathname[] = "/tmp/XXXXXXXXXX";

	fd = mkstemp(pathname);
	if (fd == -1)
		return;

	fp = fdopen(fd, "w+b");
	if (fp == NULL) {
		close(fd);
		return;
	}
	unlink(pathname);

	s->data_buffer = fp;
	s->data_buffer_cb = data_buffered_stream_process;

	rfc2822_parser_init(&s->rfc2822_parser);
	rfc2822_parser_reset(&s->rfc2822_parser);
	rfc2822_header_default_callback(&s->rfc2822_parser,
	    default_header_callback, s);
	rfc2822_body_callback(&s->rfc2822_parser,
	    default_body_callback, s);
	rfc2822_eoh_callback(&s->rfc2822_parser,
	    header_eoh_callback, s);

	dict_init(&s->headers_replace);
	dict_init(&s->headers_add);
}

static void
data_buffered_release(struct filter_session *s)
{
	void	*data;

	rfc2822_parser_release(&s->rfc2822_parser);
	if (s->data_buffer) {
		fclose(s->data_buffer);
		s->data_buffer = NULL;
	}

	while (dict_poproot(&s->headers_replace, &data))
		free(data);

	while (dict_poproot(&s->headers_add, &data))
		free(data);
}

void
filter_api_data_buffered(void)
{
	fi.data_buffered = 1;
}

void
filter_api_data_buffered_stream(uint64_t id)
{
	struct filter_session	*s;

	s = tree_xget(&sessions, id);
	if (s->data_buffer)
		fseek(s->data_buffer, 0, 0);
	io_callback(&s->pipe.oev, IO_LOWAT);
}

void
filter_api_header_remove(uint64_t id, const char *header)
{
	struct filter_session	*s;

	s = tree_xget(&sessions, id);
	rfc2822_header_callback(&s->rfc2822_parser, header,
	    header_remove_callback, s);
}

void
filter_api_header_replace(uint64_t id, const char *header, const char *fmt, ...)
{
	struct filter_session	*s;
	char			*key;
	char			*buffer = NULL;
	va_list			ap;

	s = tree_xget(&sessions, id);
	va_start(ap, fmt);
	vasprintf(&buffer, fmt, ap);
	va_end(ap);

	key = xstrdup(header, "filter_api_header_replace");
	lowercase(key, key, strlen(key)+1);
	dict_set(&s->headers_replace, header, buffer);
	free(key);

	rfc2822_header_callback(&s->rfc2822_parser, header,
	    header_replace_callback, s);
}

void
filter_api_header_add(uint64_t id, const char *header, const char *fmt, ...)
{
	struct filter_session	*s;
	char			*key;
	char			*buffer = NULL;
	va_list			ap;

	s = tree_xget(&sessions, id);
	va_start(ap, fmt);
	vasprintf(&buffer, fmt, ap);
	va_end(ap);

	key = xstrdup(header, "filter_api_header_replace");
	lowercase(key, key, strlen(key)+1);
	dict_set(&s->headers_add, header, buffer);
	free(key);
}
