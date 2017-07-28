/*
 * Copyright (c) 2013 Eric Faurot <eric@openbsd.org>
 * Copyright (c) 2014 Michael Neumann <mneumann@ntecs.de>
 * Copyright (c) 2015 Emmanuel Vadot <manu@bidouilliste.com>
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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <hiredis.h>

#include <smtpd-api.h>

enum {
	REDIS_ALIAS = 0,
	REDIS_DOMAIN,
	REDIS_CREDENTIALS,
	REDIS_NETADDR,
	REDIS_USERINFO,
	REDIS_SOURCE,
	REDIS_MAILADDR,
	REDIS_ADDRNAME,

	REDIS_MAX
};

struct config {
	struct dict	 conf;
	redisContext    *master;
	redisContext	*slave;
	char		*queries[REDIS_MAX];
};

static void		 config_free(struct config *);

static char		*conffile;
static struct config	*config;

static struct config *
config_load(const char *path)
{
	struct config	*config;
	FILE		*fp;
	size_t		 sz = 0;
	ssize_t		 flen;
	char		*key, *value, *buf = NULL;

	if ((config = calloc(1, sizeof(*config))) == NULL) {
		log_warn("warn: calloc");
		return NULL;
	}

	dict_init(&config->conf);

	if ((fp = fopen(path, "r")) == NULL) {
		log_warn("warn: \"%s\"", path);
		goto end;
	}

	while ((flen = getline(&buf, &sz, fp)) == -1) {
		if (buf[flen - 1] == '\n')
			buf[flen - 1] = '\0';

		key = strip(buf);
		if (*key == '\0' || *key == '#')
			continue;
		value = key;
		strsep(&value, " \t:");
		if (value) {
			while (*value) {
				if (!isspace((unsigned char)*value) &&
				    !(*value == ':' && isspace((unsigned char)*(value + 1))))
					break;
				++value;
			}
			if (*value == '\0')
				value = NULL;
		}

		if (value == NULL) {
			log_warnx("warn: missing value for key %s", key);
			goto end;
		}

		if (dict_check(&config->conf, key)) {
			log_warnx("warn: duplicate key %s", key);
			goto end;
		}

		if ((value = strdup(value)) == NULL) {
			log_warn("warn: strdup");
			goto end;
		}

		dict_set(&config->conf, key, value);
	}

	free(buf);
	fclose(fp);
	return config;

end:
	free(buf);
	fclose(fp);
	config_free(config);
	return NULL;
}

static void
config_reset(struct config *config)
{
	size_t	i;

	for (i = 0; i < REDIS_MAX; i++)
		if (config->queries[i]) {
			free(config->queries[i]);
			config->queries[i] = NULL;
		}

	if (config->master) {
		redisFree(config->master);
		config->master = NULL;
	}
}

static int
config_connect(struct config *config)
{
	static const struct {
		const char	*name;
		const char	*default_query;
	} qspec[REDIS_MAX] = {
		{ "query_alias",	"GET alias:%s" },
		{ "query_domain",	"GET domain:%s" },
		{ "query_credentials",	"GET credentials:%s" },
		{ "query_netaddr",	"GET netaddr:%s" },
		{ "query_userinfo",	"GET userinfo:%s" },
		{ "query_source",	"GET source:%s" },
		{ "query_mailaddr",	"GET mailaddr:%s" },
		{ "query_addrname",	"GET addrname:%s" },
	};
	size_t	 i;

	char	*master = "127.0.0.1";
	int	master_port = 6379;
	char	*slave = "NULL";
	int	slave_port = 6380;
	char	*password = NULL;
	int	database = 0;

	char	*q;

	char		*value;
	const char	*e;
	long long	 ll;

	redisReply	*res = NULL;

	log_debug("debug: (re)connecting");

	/* disconnect first, if needed */
	config_reset(config);

	if ((value = dict_get(&config->conf, "master")))
		master = value;
	if ((value = dict_get(&config->conf, "slave")))
		slave = value;

	if ((value = dict_get(&config->conf, "master_port"))) {
		e = NULL;
		ll = strtonum(value, 0, 65535, &e);
		if (e) {
			log_warnx("warn: bad value for master_port: %s", e);
			goto end;
		}
		master_port = ll;
	}
	if ((value = dict_get(&config->conf, "slave_port"))) {
		e = NULL;
		ll = strtonum(value, 0, 65535, &e);
		if (e) {
			log_warnx("warn: bad value for slave_port: %s", e);
			goto end;
		}
		slave_port = ll;
	}

	if ((value = dict_get(&config->conf, "password")))
	        password = value;

	if ((value = dict_get(&config->conf, "database"))) {
		e = NULL;
		ll = strtonum(value, 0, 256, &e);
		if (e) {
			log_warnx("warn: bad value for database: %s", e);
			goto end;
		}
		database = ll;
	}

	if (!strncmp("unix:", master, 5)) {
		log_debug("debug: connect via unix socket %s", master + 5);
		config->master = redisConnectUnix(master + 5);
	} else {
		log_debug("debug: connect to master via tcp at %s:%d", master, master_port);
		config->master = redisConnect(master, master_port);
	}
	if (config->master == NULL) {
		log_warnx("warn: can't create redis context for master");
		goto end;
	}

	if (!config->master->err) {
		log_debug("debug: connected to master");
		if (password) {
			res = redisCommand(config->master, "AUTH %s", password);
			if (res->type == REDIS_REPLY_ERROR) {
				log_warnx("warn: authentication on master failed");
				goto end;
			}
			freeReplyObject(res);
		}

		if (database != 0) {
			res = redisCommand(config->master, "SELECT %d", database);
			if (res->type != REDIS_REPLY_STATUS) {
				log_warnx("warn: database selection on master failed");
				goto end;
			}
			freeReplyObject(res);
		}
	}

	if (slave) {
		if (!strncmp("unix:", slave, 5)) {
			log_debug("debug: connect to slave via unix socket %s", slave + 5);
			config->slave = redisConnectUnix(slave + 5);
		}
		else {
			log_debug("debug: connect to slave via tcp at %s:%d", slave, slave_port);
			config->slave = redisConnect(slave, slave_port);
		}

		if (config->slave == NULL) {
			log_warnx("warn: can't create redis context for slave");
			goto end;
		}
		if (!config->slave->err) {
			if (password) {
				res = redisCommand(config->slave, "AUTH %s", password);
				if (res->type == REDIS_REPLY_ERROR) {
					log_warnx("warn: authentication on slave failed");
					goto end;
				}
				freeReplyObject(res);
			}

			if (database != 0) {
				res = redisCommand(config->slave, "SELECT %d", database);
				if (res->type != REDIS_REPLY_STATUS) {
					log_warnx("warn: database selection on slave failed");
					goto end;
				}
				freeReplyObject(res);
			}
		}
	}

	for (i = 0; i < REDIS_MAX; i++) {
		q = dict_get(&config->conf, qspec[i].name);
		if (q)
			config->queries[i] = strdup(q);
		else
			config->queries[i] = strdup(qspec[i].default_query);
		if (config->queries[i] == NULL) {
			log_warn("warn: strdup");
			goto end;
		}
	}

	if (config->master->err && config->slave->err) {
		log_warnx("warn: redisConnect for master and slave failed");
		goto end;
	}

	log_debug("debug: connected");
	return 1;

end:
	if (res)
		freeReplyObject(res);
	config_reset(config);
	return 0;
}

static void
config_free(struct config *config)
{
	void	*value;

	config_reset(config);

	while (dict_poproot(&config->conf, &value))
		free(value);

	free(config);
}

static int
table_redis_update(void)
{
	struct config	*c;

	if ((c = config_load(conffile)) == NULL)
		return 0;
	if (config_connect(c) == 0) {
		config_free(c);
		return 0;
	}

	config_free(config);
	config = c;
	return 1;
}

static redisReply *
table_redis_query(const char *key, int service)
{
	redisReply	*res;
	char		*query = NULL;
	int		i;
	int		retry_times;

	retry_times = 3;

retry:
	--retry_times;
	if (retry_times < 0) {
		log_warnx("warn: giving up: too many retries");
		return NULL;
	}

	for(i = 0; i < REDIS_MAX; i++)
		if (service == 1 << i) {
			query = config->queries[i];
			break;
		}

	if (query == NULL)
		return NULL;

	if (!config->master->err) {
		log_debug("debug: running query \"%s\" on master", query);
		res = redisCommand(config->master, query, key);
	} else if (!config->slave->err) {
		log_debug("debug: running query \"%s\" on slave", query);
		res = redisCommand(config->slave, query, key);
	} else
		return NULL;
	if (res == NULL) {
		log_warnx("warn: redisCommand: %s",
		    config->master->errstr);

		if (config_connect(config))
			goto retry;

		return NULL;
	}

	return res;
}

static int
table_redis_check(int service, struct dict *params, const char *key)
{
	int		 r;
	redisReply	*reply;

	if (config->master == NULL && config_connect(config) == 0)
		return -1;

	reply = table_redis_query(key, service);
	if (reply == NULL)
		return -1;

	r = 0;
	switch (reply->type) {
		case REDIS_REPLY_INTEGER:
			r = reply->integer;
			break;
		case REDIS_REPLY_STRING:
		case REDIS_REPLY_ARRAY:
			r = 1;
			break;

		case REDIS_REPLY_NIL:
			r = 0;
			break;

		case REDIS_REPLY_STATUS:
		case REDIS_REPLY_ERROR:
		default:
			r = -1;
			break;
	}

	freeReplyObject(reply);

	return r;
}

static int
table_redis_lookup(int service, struct dict *params, const char *key, char *dst, size_t sz)
{
	redisReply	*reply, *elmt;
	unsigned int	i;
	int		r;

	if (config->master == NULL && config_connect(config) == 0)
		return -1;

	reply = table_redis_query(key, service);
	if (reply == NULL)
		return -1;

	r = 1;
	switch(service) {
	case K_ALIAS:
	case K_CREDENTIALS:
	case K_USERINFO:
		memset(dst, 0, sz);
		if (reply->type == REDIS_REPLY_STRING) {
			if (strlcat(dst, reply->str, sz) >= sz) {
				log_warnx("warn: result too large");
				r = -1;
			}
		}
		else if (reply->type == REDIS_REPLY_ARRAY) {
			if (reply->elements == 0)
				r = 0;

			for (i = 0; i < reply->elements; i++) {
				elmt = reply->element[i];
				if (elmt == NULL ||
				    elmt->type != REDIS_REPLY_STRING) {
					r = -1;
					break;
				}
				if (dst[0] && strlcat(dst, service == K_ALIAS ? ", " : ":", sz) >= sz) {
					log_warnx("warn: result too large");
					r = -1;
				}
				if (strlcat(dst, elmt->str, sz) >= sz) {
					log_warnx("warn: result too large");
					r = -1;
				}
			}
		}
		else
			r = -1;
		break;
	case K_DOMAIN:
	case K_NETADDR:
	case K_SOURCE:
	case K_MAILADDR:
	case K_ADDRNAME:
		if (reply->type == REDIS_REPLY_STRING) {
			if (strlcpy(dst, reply->str, sz) >= sz) {
				log_warnx("warn: result too large");
				r = -1;
			}
		}
		else
			r = -1;
		break;
	default:
		log_warnx("warn: unknown service %d",
		    service);
		r = -1;
	}

	log_debug("debug: table_redis_lookup return %d (result = \"%s\")", r, dst);
	freeReplyObject(reply);
	return r;
}

static int
table_redis_fetch(int service, struct dict *params, char *dst, size_t sz)
{
	return -1;
}

int
main(int argc, char **argv)
{
	int ch;

	log_init(1);
	log_verbose(~0);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			fatalx("bad option");
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
		fatalx("bogus argument(s)");

	conffile = argv[0];

	if ((config = config_load(conffile)) == NULL)
		fatalx("error parsing config file");
	if (config_connect(config) == 0)
		fatalx("could not connect");

	table_api_on_update(table_redis_update);
	table_api_on_check(table_redis_check);
	table_api_on_lookup(table_redis_lookup);
	table_api_on_fetch(table_redis_fetch);
	table_api_dispatch();

	return 0;
}
