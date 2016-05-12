/*
 * Copyright (c) 2013, 2016 Eric Faurot <eric@openbsd.org>
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

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

#define MONKEY_CONF "/etc/mail/filter-monkey.conf"

struct rule {
	uint32_t            limit;
	enum filter_status  status;
	int                 code;
	char		   *response;
	TAILQ_ENTRY(rule)   entry;
};

TAILQ_HEAD(tq_rules, rule);

struct ruleset {
	uint32_t	delay_min;
	uint32_t	delay_max;
	struct tq_rules	rules;
};

struct dict rulesets;

static int
monkey(uint64_t id, const char *cmd)
{
	uint32_t p;
	struct rule *rule;
	struct ruleset *ruleset;

	ruleset = dict_xget(&rulesets, cmd);

	p = arc4random_uniform(100);

	TAILQ_FOREACH(rule, &ruleset->rules, entry)
		if (p >= rule->limit)
			break;

	switch (rule->status) {
	case FILTER_OK:
		log_info("info: session %016"PRIx64": ACCEPT cmd=%s", id, cmd);
		return filter_api_accept(id);
	case FILTER_FAIL:
	case FILTER_CLOSE:
		if (rule->code == 0) {
			log_info("info: session %016"PRIx64": REJECT cmd=%s", id, cmd);
			return filter_api_reject(id, rule->status);
		}
		log_info("info: session %016"PRIx64": REJECT cmd=%s, code=%i, response=%s",
		    id, cmd, rule->code, rule->response);
		return filter_api_reject_code(id, rule->status, rule->code, rule->response);

	default:
		fatalx("invalid status");
	}

	return 0;
}

static void
monkey_timer(uint64_t id, void *p)
{
	(void)monkey(id, (const char *)p);
}

static int
monkey_defer(uint64_t id, const char *cmd)
{
	struct ruleset	*ruleset;
	struct timeval tv;
	uint32_t delay;

	ruleset = dict_xget(&rulesets, cmd);
	if (ruleset->delay_max == 0)
		return monkey(id, cmd);

	delay = arc4random_uniform(ruleset->delay_max - ruleset->delay_min);
	delay += ruleset->delay_min;

	tv.tv_sec = delay  / 1000;
	tv.tv_usec = (delay % 1000) * 1000;

	filter_api_timer(id, &tv, monkey_timer, (void *)cmd);
	return 0;
}

static int
on_connect(uint64_t id, struct filter_connect *conn)
{
	return monkey_defer(id, "connect");
}

static int
on_helo(uint64_t id, const char *helo)
{
	return monkey_defer(id, "helo");
}

static int
on_mail(uint64_t id, struct mailaddr *mail)
{
	return monkey_defer(id, "mail");
}

static int
on_rcpt(uint64_t id, struct mailaddr *rcpt)
{
	return monkey_defer(id, "rcpt");
}

static int
on_data(uint64_t id)
{
	return monkey_defer(id, "data");
}

static int
on_eom(uint64_t id, size_t size)
{
	return monkey_defer(id, "eom");
}

static void
add_rule(const char *cmd, uint32_t proba, int status, int code, const char *msg)
{
	struct rule *rule;
	struct ruleset *ruleset;
	uint32_t limit;

	log_debug("info: adding rule cmd=%s, proba=%i, status=%i, code=%i, msg=\"%s\"",
	    cmd, proba, status, code, msg);

	ruleset = dict_xget(&rulesets, cmd);

	rule = TAILQ_LAST(&ruleset->rules, tq_rules);
	limit = rule ? rule->limit : 100;

	if (proba > limit)
		fatalx("invalid limit");

	rule = xcalloc(1, sizeof(*rule), "read_config: rule");
	rule->limit = limit - proba;
	rule->status = status;
	rule->code = code;
	if (msg)
		rule->response = xstrdup(msg, "add_rule");
	TAILQ_INSERT_TAIL(&ruleset->rules, rule, entry);
}

static void
read_config(const char *path)
{
	static char *entries[] = { "connect", "helo", "mail", "rcpt", "data", "eom", NULL };
	struct rule *rule;
	struct ruleset *ruleset;
	FILE *fp;
	char **s, *line = NULL, *start, action[17], cmd[17];
	ssize_t len;
	size_t linelen = 0;
	int n, lineno = 0, proba, status = 0, code, offset;
	uint32_t delay_min, delay_max;

	log_debug("info: config file is %s", path);

	dict_init(&rulesets);

	for (s = entries; *s; s++) {
		ruleset = xcalloc(1, sizeof(*ruleset), "read_config: ruleset");
		TAILQ_INIT(&ruleset->rules);
		dict_xset(&rulesets, *s, ruleset);
	}

	if ((fp = fopen(path, "r")) == NULL)
		fatal("fopen");

	while ((len = getline(&line, &linelen, fp)) != -1) {
		lineno += 1;
		if (len)
			len--;
		for (start = line + len; start >= line && isspace((int)(*start)); start--)
			*start = '\0';

		for (start = line; *start && isspace((int)(*start)); start++)
			;

		if (*start == '\0')
			continue;
		if (*start == '#')
			continue;

		if (!strncmp(start, "delay", strlen("delay"))) {
			n = sscanf(start, "delay %u:%u on %16s", &delay_min, &delay_max, cmd);
			if (n < 3)
				fatalx("line %i: parse error: %i", lineno, n);

			if (delay_min > delay_max)
				fatalx("line %i: invalid delays", lineno);

			for (s = entries; *s; s++)
				if (!strcmp(*s, cmd))
					break;
			if (*s == NULL)
				fatalx("line %i: invalid command", lineno);

			ruleset = dict_xget(&rulesets, cmd);
			ruleset->delay_min = delay_min;
			ruleset->delay_max = delay_max;
			continue;
		}

		n = sscanf(start, "%16s %i%% on %16s %i %n", action, &proba, cmd, &code, &offset);
		if (n < 3)
			fatalx("line %i: parse error: %i", lineno, n);

		if (!strcmp(action, "reject"))
			status = FILTER_FAIL;
		else if (!strcmp(action, "close"))
			status = FILTER_CLOSE;
		else
			fatalx("line %i: invalid action", lineno);

		if (proba < 0 || proba > 100)
			fatalx("line %i: invalid probability", lineno);

		for (s = entries; *s; s++)
			if (!strcmp(*s, cmd))
				break;
		if (*s == NULL)
			fatalx("line %i: invalid command", lineno);

		if (n == 3)
			add_rule(cmd, proba, status, 0, NULL);
		else {
			if (code < 400 || code >= 600)
				fatalx("line %i: invalid code", lineno);
			add_rule(cmd, proba, status, code, start + offset);
		}
	}

	if (ferror(fp))
		fatal("ferror");
	free(line);
	fclose(fp);

	for (s = entries; *s; s++) {
		ruleset = dict_xget(&rulesets, *s);
		rule = xcalloc(1, sizeof(*rule), "read_config: rule");
		rule->limit = 0;
		rule->status = FILTER_OK;
		TAILQ_INSERT_TAIL(&ruleset->rules, rule, entry);
	}
}

int
main(int argc, char **argv)
{
	int ch, d = 0, v = 0;

	log_init(1);

	while ((ch = getopt(argc, argv, "dv")) != -1) {
		switch (ch) {
		case 'd':
			d = 1;
			break;
		case 'v':
			v |= TRACE_DEBUG;
			break;
		default:
			log_warnx("warn: bad option");
			return 1;
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;
	if (argc > 1)
		fatalx("bogus argument(s)");

	log_init(d);
	log_verbose(v);

	log_debug("debug: starting...");
	read_config((argc == 1) ? argv[0] : MONKEY_CONF);

	filter_api_on_connect(on_connect);
	filter_api_on_helo(on_helo);
	filter_api_on_mail(on_mail);
	filter_api_on_rcpt(on_rcpt);
	filter_api_on_data(on_data);
	filter_api_on_eom(on_eom);
	filter_api_loop();

	log_debug("debug: exiting");

	return 0;
}
