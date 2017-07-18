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
#include <sys/tree.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <netdb.h>

#define PORT_SMTPF		2626

#define	SMTPFD_CONFIG		"/etc/mail/smtpfd.conf"
#define	SMTPFD_SOCKET		"/var/run/smtpfd.sock"
#define	SMTPFD_CHROOT		"/var/empty"
#define	SMTPFD_USER		"_smtpfd"

#define	SMTPFD_MAXFILTERARG	32

enum {
	IMSG_NONE,

	IMSG_SOCK_ENGINE,
	IMSG_SOCK_FRONTEND,

	IMSG_CONF_START,
	IMSG_CONF_FILTER_PROC,
	IMSG_CONF_LISTENER,
	IMSG_CONF_END,

	IMSG_RES_GETADDRINFO,
	IMSG_RES_GETADDRINFO_END,
	IMSG_RES_GETNAMEINFO
};

enum {
	PROC_CLIENT,
	PROC_CONTROL,
	PROC_ENGINE,
	PROC_FILTER,
	PROC_FRONTEND,
	PROC_PRIV
};

enum {
	PROTO_NONE = 0,
	PROTO_SMTPF
};

struct listener {
	int			 sock;
	int			 proto;
	struct sockaddr_storage	 ss;
	struct timeval		 timeout;
	struct event		 ev;
	TAILQ_ENTRY(listener)	 entry;
};

struct filter_conf {
	TAILQ_ENTRY(filter_conf)	 entry;
	char				*name;
	int				 chain;
	int				 argc;
	char				*argv[SMTPFD_MAXFILTERARG + 1];
	pid_t				 pid;
	int				 sock;
};

struct smtpfd_conf {
	TAILQ_HEAD(, listener)		 listeners;
	TAILQ_HEAD(, filter_conf)	 filters;
};

struct io;
struct imsgproc;

extern struct smtpfd_conf *env;
extern struct imsgproc *p_control;
extern struct imsgproc *p_engine;
extern struct imsgproc *p_frontend;
extern struct imsgproc *p_priv;

/* control.c */
void control(int, int);

/* engine.c */
void engine(int, int);

/* frontend.c */
void frontend(int, int);
void frontend_conn_closed(uint32_t);

/* frontend_smtpf.c */
void frontend_smtpf_init(void);
void frontend_smtpf_conn(uint32_t, struct listener *, int,
    const struct sockaddr *);

/* logmsg.c */
const char *log_fmt_proto(int);
const char *log_fmt_imsgtype(int);
const char *log_fmt_proctype(int);
const char *log_fmt_sockaddr(const struct sockaddr *);
void log_imsg(struct imsgproc *, struct imsg *);
void log_io(const char *, struct io *, int);

/* parse.y */
struct smtpfd_conf *parse_config(const char *, int);
int cmdline_symset(char *);

/* resolver.c */
void resolver_getaddrinfo(const char *, const char *, const struct addrinfo *,
    void(*)(void *, int, struct addrinfo*), void *);
void resolver_getnameinfo(const struct sockaddr *, int,
    void(*)(void *, int, const char *, const char *), void *);
void resolver_dispatch_request(struct imsgproc *, struct imsg *);
void resolver_dispatch_result(struct imsgproc *, struct imsg *);

/* smtpfd.c */
struct smtpfd_conf *config_new_empty(void);
void config_clear(struct smtpfd_conf *);
