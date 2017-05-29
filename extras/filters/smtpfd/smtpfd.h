/*	$OpenBSD$	*/

/*
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

#define CONF_FILE		"/etc/mail/smtpfd.conf"
#define	SMTPFD_SOCKET		"/var/run/smtpfd.sock"
#define SMTPFD_USER		"_smtpfd"

#define SMTPFD_MAXFILTERARG	32

#define OPT_VERBOSE	0x00000001
#define OPT_VERBOSE2	0x00000002
#define OPT_NOACTION	0x00000004

enum imsg_type {
	IMSG_NONE,
	IMSG_CTL_LOG_VERBOSE,
	IMSG_CTL_RELOAD,
	IMSG_CTL_SHOW_ENGINE_INFO,
	IMSG_CTL_SHOW_FRONTEND_INFO,
	IMSG_CTL_SHOW_MAIN_INFO,
	IMSG_CTL_END,
	IMSG_RECONF_CONF,
	IMSG_RECONF_GROUP,
	IMSG_RECONF_END,
	IMSG_SOCKET_IPC
};

enum smtpfd_process {
	PROC_MAIN,
	PROC_ENGINE,
	PROC_FRONTEND,
	PROC_CLIENT,
};


struct filter_conf {
	TAILQ_ENTRY(filter_conf)	 entry;
	char				*name;
	int				 chain;
	int				 argc;
	char				*argv[SMTPFD_MAXFILTERARG + 1];
};

struct smtpfd_conf {
	TAILQ_HEAD(, filter_conf) filters;
};

struct ctl_frontend_info {
};

struct ctl_engine_info {
};

struct ctl_main_info {
};

extern uint32_t	 cmd_opts;
extern struct imsgproc *p_frontend;
extern struct imsgproc *p_engine;
extern struct imsgproc *p_main;

/* smtpfd.c */
void	main_imsg_compose_frontend(int, pid_t, void *, uint16_t);
void	main_imsg_compose_engine(int, pid_t, void *, uint16_t);
struct smtpfd_conf *config_new_empty(void);
void config_clear(struct smtpfd_conf *);

/* parse.y */
struct smtpfd_conf	*parse_config(char *);
int			 cmdline_symset(char *);
