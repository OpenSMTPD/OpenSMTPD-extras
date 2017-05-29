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
#include <sys/wait.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "log.h"
#include "proc.h"
#include "smtpfd.h"
#include "frontend.h"
#include "engine.h"
#include "control.h"

__dead void	usage(void);
__dead void	main_shutdown(void);

void	main_sig_handler(int, short, void *);

void	main_dispatch_frontend(struct imsgproc *, struct imsg*, void *);
void	main_dispatch_engine(struct imsgproc *, struct imsg*, void *);
static int	main_imsg_send_config(struct smtpfd_conf *);

static int	main_reload(void);
static int	main_sendboth(enum imsg_type, void *, uint16_t);
static void	main_showinfo_ctl(struct imsg *);
static void	config_print(struct smtpfd_conf *);

struct smtpfd_conf	*main_conf;
struct imsgproc		*p_frontend;
struct imsgproc		*p_engine;
struct imsgproc		*p_main;

char			*conffile;
char			*csock;

uint32_t cmd_opts;

void
main_sig_handler(int sig, short event, void *arg)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGTERM:
	case SIGINT:
		main_shutdown();
	case SIGHUP:
		if (main_reload() == -1)
			log_warnx("configuration reload failed");
		else
			log_debug("configuration reloaded");
		break;
	default:
		fatalx("unexpected signal");
	}
}

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-dnv] [-f file] [-s socket]\n",
	    __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct event	 ev_sigint, ev_sigterm, ev_sighup;
	int		 ch, sp[2], rargc = 0;
	int		 debug = 0, engine_flag = 0, frontend_flag = 0;
	char		*saved_argv0;
	char		*rargv[7];

	conffile = CONF_FILE;
	csock = SMTPFD_SOCKET;

	log_init(1, LOG_DAEMON);	/* Log to stderr until daemonized. */
	log_setverbose(1);

	saved_argv0 = argv[0];
	if (saved_argv0 == NULL)
		saved_argv0 = "smtpfd";

	while ((ch = getopt(argc, argv, "dEFf:ns:v")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'E':
			engine_flag = 1;
			break;
		case 'F':
			frontend_flag = 1;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'n':
			cmd_opts |= OPT_NOACTION;
			break;
		case 's':
			csock = optarg;
			break;
		case 'v':
			if (cmd_opts & OPT_VERBOSE)
				cmd_opts |= OPT_VERBOSE2;
			cmd_opts |= OPT_VERBOSE;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc > 0 || (engine_flag && frontend_flag))
		usage();

	if (engine_flag)
		engine(debug, cmd_opts & OPT_VERBOSE);
	else if (frontend_flag)
		frontend(debug, cmd_opts & OPT_VERBOSE, csock);

	/* parse config file */
	if ((main_conf = parse_config(conffile)) == NULL) {
		exit(1);
	}

	if (cmd_opts & OPT_NOACTION) {
		if (cmd_opts & OPT_VERBOSE)
			config_print(main_conf);
		else
			fprintf(stderr, "configuration OK\n");
		exit(0);
	}

	/* Check for root privileges. */
	if (geteuid())
		errx(1, "need root privileges");

	/* Check for assigned daemon user */
	if (getpwnam(SMTPFD_USER) == NULL)
		errx(1, "unknown user %s", SMTPFD_USER);

	log_init(debug, LOG_DAEMON);
	log_setverbose(cmd_opts & OPT_VERBOSE);
	log_procinit("main");
	setproctitle("main");

	if (!debug)
		daemon(1, 0);

	log_info("startup");

	rargc = 0;
	rargv[rargc++] = saved_argv0;
	rargv[rargc++] = "-F";
	if (debug)
		rargv[rargc++] = "-d";
	if (cmd_opts & OPT_VERBOSE)
		rargv[rargc++] = "-v";
	rargv[rargc++] = "-s";
	rargv[rargc++] = csock;
	rargv[rargc++] = NULL;

	p_frontend = proc_exec(PROC_FRONTEND, rargv);
	rargv[1] = "-E";
	rargv[argc - 3] = NULL;
	p_engine = proc_exec(PROC_ENGINE, rargv);

	event_init();

	/* Setup signal handler. */
	signal_set(&ev_sigint, SIGINT, main_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, main_sig_handler, NULL);
	signal_set(&ev_sighup, SIGHUP, main_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sighup, NULL);
	signal(SIGPIPE, SIG_IGN);

	/* Start children */
	proc_enable(p_frontend);
	proc_enable(p_engine);

	/* Connect the two children */
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, sp) == -1)
		fatal("socketpair");
	if (proc_compose(p_frontend, IMSG_SOCKET_IPC, 0, 0, sp[0], NULL, 0)
	    == -1)
		fatal("proc_compose");
	if (proc_compose(p_engine, IMSG_SOCKET_IPC, 0, 0, sp[1], NULL, 0)
	    == -1)
		fatal("proc_compose");

	main_imsg_send_config(main_conf);

	if (pledge("rpath stdio sendfd cpath", NULL) == -1)
		fatal("pledge");

	event_dispatch();

	main_shutdown();
	return (0);
}

__dead void
main_shutdown(void)
{
	pid_t	 pid;
	pid_t	 frontend_pid;
	pid_t	 engine_pid;
	int	 status;

	frontend_pid = proc_getpid(p_frontend);
	engine_pid = proc_getpid(p_frontend);

	/* Close pipes. */
	proc_free(p_frontend);
	proc_free(p_engine);

	config_clear(main_conf);

	log_debug("waiting for children to terminate");
	do {
		pid = wait(&status);
		if (pid == -1) {
			if (errno != EINTR && errno != ECHILD)
				fatal("wait");
		} else if (WIFSIGNALED(status))
			log_warnx("%s terminated; signal %d",
			    (pid == engine_pid) ? "engine" :
			    "frontend", WTERMSIG(status));
	} while (pid != -1 || (pid == -1 && errno == EINTR));

	control_cleanup(csock);

	log_info("terminating");
	exit(0);
}

void
main_dispatch_frontend(struct imsgproc *p, struct imsg *imsg, void *arg)
{
	int verbose;

	if (imsg == NULL) {
		event_loopexit(NULL);
		return;
	}

	switch (imsg->hdr.type) {
	case IMSG_CTL_RELOAD:
		if (main_reload() == -1)
			log_warnx("configuration reload failed");
		else
			log_warnx("configuration reloaded");
		break;
	case IMSG_CTL_LOG_VERBOSE:
		/* Already checked by frontend. */
		memcpy(&verbose, imsg->data, sizeof(verbose));
		log_setverbose(verbose);
		break;
	case IMSG_CTL_SHOW_MAIN_INFO:
		main_showinfo_ctl(imsg);
		break;
	default:
		log_debug("%s: error handling imsg %d", __func__,
		    imsg->hdr.type);
		break;
	}
}

void
main_dispatch_engine(struct imsgproc *p, struct imsg *imsg, void *arg)
{
	if (imsg == NULL) {
		event_loopexit(NULL);
		return;
	}

	switch (imsg->hdr.type) {
	default:
		log_debug("%s: error handling imsg %d", __func__,
		    imsg->hdr.type);
		break;
	}
}

void
main_imsg_compose_frontend(int type, pid_t pid, void *data, uint16_t datalen)
{
	if (p_frontend)
		proc_compose(p_frontend, type, 0, pid, -1, data, datalen);
}

void
main_imsg_compose_engine(int type, pid_t pid, void *data, uint16_t datalen)
{
	if (p_engine)
		proc_compose(p_engine, type, 0, pid, -1, data, datalen);
}

int
main_reload(void)
{
	struct smtpfd_conf *xconf;

	if ((xconf = parse_config(conffile)) == NULL)
		return (-1);

	if (main_imsg_send_config(xconf) == -1)
		return (-1);

	config_clear(main_conf);
	main_conf = xconf;

	return (0);
}

int
main_imsg_send_config(struct smtpfd_conf *xconf)
{
	/* Send fixed part of config to children. */
	if (main_sendboth(IMSG_RECONF_CONF, xconf, sizeof(*xconf)) == -1)
		return (-1);

	/* Tell children the revised config is now complete. */
	if (main_sendboth(IMSG_RECONF_END, NULL, 0) == -1)
		return (-1);

	return (0);
}

int
main_sendboth(enum imsg_type type, void *buf, uint16_t len)
{
	if (proc_compose(p_frontend, type, 0, 0, -1, buf, len) == -1)
		return (-1);
	if (proc_compose(p_engine, type, 0, 0, -1, buf, len) == -1)
		return (-1);
	return (0);
}

void
main_showinfo_ctl(struct imsg *imsg)
{
	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_MAIN_INFO:
		main_imsg_compose_frontend(IMSG_CTL_END, imsg->hdr.pid, NULL,
		    0);
		break;
	default:
		log_debug("%s: error handling imsg", __func__);
		break;
	}
}

struct smtpfd_conf *
config_new_empty(void)
{
	struct smtpfd_conf	*conf;

	conf = calloc(1, sizeof(*conf));
	if (conf == NULL)
		fatal(NULL);

	TAILQ_INIT(&conf->filters);

	return (conf);
}

void
config_clear(struct smtpfd_conf *conf)
{
	struct filter_conf *f;
	int i;

	while ((f = TAILQ_FIRST(&conf->filters))) {
		TAILQ_REMOVE(&conf->filters, f, entry);
		free(f->name);
		for (i = 0; i < f->argc; i++)
			free(f->argv[i]);
		free(f);
	}

	free(conf);
}

void
config_print(struct smtpfd_conf *conf)
{
	struct filter_conf *f;
	int i;

	TAILQ_FOREACH(f, &conf->filters, entry) {
		printf("%s %s", f->chain ? "chain":"filter", f->name);
		for (i = 0; i < f->argc; i++)
			printf(" %s", f->argv[i]);
		printf("\n");
	}
}
