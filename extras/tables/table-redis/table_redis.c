/*	$OpenBSD$	*/

/*
 * Copyright (c) 2013 Eric Faurot <eric@openbsd.org>
 * Copyright (c) 2014 Michael Neumann <mneumann@ntecs.de>
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

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

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
	redisContext    *db;
	char		*queries[REDIS_MAX];
};

static int table_redis_update(void);
static int table_redis_lookup(int, struct dict *, const char *, char *, size_t);
static int table_redis_check(int, struct dict *, const char *);
static int table_redis_fetch(int, struct dict *, char *, size_t);

static redisReply *table_redis_query(const char *key, int service);

static struct config 	*config_load(const char *);
static void		 config_reset(struct config *);
static int		 config_connect(struct config *);
static void		 config_free(struct config *);

static char		*conffile;
static struct config	*config;

int
main(int argc, char **argv)
{
	int	ch;

	log_init(1);
	log_verbose(~0);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			log_warnx("warn: table-redis: bad option");
			return (1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		log_warnx("warn: table-redis: bogus argument(s)");
		return (1);
	}

	conffile = argv[0];

	config = config_load(conffile);
	if (config == NULL) {
		log_warnx("warn: table-redis: error parsing config file");
		return (1);
	}
	if (config_connect(config) == 0) {
		log_warnx("warn: table-redis: could not connect");
	}

	table_api_on_update(table_redis_update);
	table_api_on_check(table_redis_check);
	table_api_on_lookup(table_redis_lookup);
	table_api_on_fetch(table_redis_fetch);
	table_api_dispatch();

	return (0);
}

static struct config *
config_load(const char *path)
{
	struct config	*conf;
	FILE		*fp;
	size_t		 flen;
	char		*key, *value, *buf, *lbuf;

	lbuf = NULL;

	conf = calloc(1, sizeof(*conf));
	if (conf == NULL) {
		log_warn("warn: table-redis: calloc");
		return (NULL);
	}

	dict_init(&conf->conf);

	fp = fopen(path, "r");
	if (fp == NULL) {
		log_warn("warn: table-redis: fopen");
		goto end;
	}

	while ((buf = fgetln(fp, &flen))) {
		if (buf[flen - 1] == '\n')
			buf[flen - 1] = '\0';
		else {
			lbuf = malloc(flen + 1);
			if (lbuf == NULL) {
				log_warn("warn: table-redis: malloc");
				goto end;
			}
			memcpy(lbuf, buf, flen);
			lbuf[flen] = '\0';
			buf = lbuf;
		}

		key = buf;
		while (isspace((unsigned char)*key))
			++key;
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
			log_warnx("warn: table-redis: missing value for key %s", key);
			goto end;
		}

		if (dict_check(&conf->conf, key)) {
			log_warnx("warn: table-redis: duplicate key %s", key);
			goto end;
		}

		value = strdup(value);
		if (value == NULL) {
			log_warn("warn: table-redis: malloc");
			goto end;
		}

		dict_set(&conf->conf, key, value);
	}

	free(lbuf);
	fclose(fp);
	return (conf);

end:
	free(lbuf);
	if (fp)
		fclose(fp);
	config_free(conf);
	return (NULL);
}

static void
config_reset(struct config *conf)
{
	size_t	i;

	for (i = 0; i < REDIS_MAX; i++)
		if (conf->queries[i]) {
			free(conf->queries[i]);
			conf->queries[i] = NULL;
		}

	if (conf->db) {
		redisFree(conf->db);
		conf->db = NULL;
	}
}

static int
config_connect(struct config *conf)
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

	char	*host = "127.0.0.1";
	int	port = 6379;
	char	*password = NULL;
	int	database;

	char	*q;

	char		*value;
	const char	*e;
	long long	 ll;

	redisReply	*res = NULL;

	log_debug("debug: table-redis: (re)connecting");

	/* Disconnect first, if needed */
	config_reset(conf);

	if ((value = dict_get(&conf->conf, "host")))
		host = value;

	if ((value = dict_get(&conf->conf, "port"))) {
		e = NULL;
		ll = strtonum(value, 0, 65535, &e);
		if (e) {
			log_warnx("warn: table-redis: bad value for port: %s", e);
			goto end;
		}
		port = ll;
	}

	if ((value = dict_get(&conf->conf, "password")))
	        password = value;

	if ((value = dict_get(&conf->conf, "database"))) {
		e = NULL;
		ll = strtonum(value, 0, 256, &e);
		if (e) {
			log_warnx("warn: table-redis: bad value for database: %s", e);
			goto end;
		}
		database = ll;
	}

	conf->db = redisConnect(host, port);
	if (conf->db == NULL) {
		log_warnx("warn: table-redis: redisConnect return NULL");
		goto end;
	}

	if (password) {
		res = redisCommand(conf->db, "AUTH %s", password);
		if (res->type == REDIS_REPLY_ERROR) {
			log_warnx("warn: table-redis: authentication failed");
			goto end;
		}
		freeReplyObject(res);
	}

	if (database != 0) {
		res = redisCommand(conf->db, "SELECT %d", database);
		if (res->type != REDIS_REPLY_STATUS) {
			log_warnx("warn: table-redis: authentication failed");
			goto end;
		}
		freeReplyObject(res);
	}

	for (i = 0; i < REDIS_MAX; i++) {
		q = dict_get(&conf->conf, qspec[i].name);
		if (q)
			conf->queries[i] = strdup(q);
		else
			conf->queries[i] = strdup(qspec[i].default_query);
		if (conf->queries[i] == NULL) {
			log_warn("warn: table-redis: malloc");
			goto end;
		}
	}

	log_debug("debug: table-redis: connected");

	return (1);

end:
	if (res)
		freeReplyObject(res);
	config_reset(conf);
	return (0);
}

static void
config_free(struct config *conf)
{
	void	*value;

	config_reset(conf);

	while (dict_poproot(&conf->conf, &value))
		free(value);

	free(conf);
}

static int
table_redis_update(void)
{
	struct config	*c;

	if ((c = config_load(conffile)) == NULL)
		return (0);
	if (config_connect(c) == 0) {
		config_free(c);
		return (0);
	}

	config_free(config);
	config = c;
	return (1);
}

static redisReply *
table_redis_query(const char *key, int service)
{
	redisReply	*res;
	char		*stmt;
	int		i;
	int		retry_times;

	retry_times = 3;

retry:
	--retry_times;
	if (retry_times < 0) {
		log_warnx("warn: table-redis: giving up: too many retries");
		return (NULL);
	}

	stmt = NULL;
	for(i = 0; i < REDIS_MAX; i++)
		if (service == 1 << i) {
			stmt = config->queries[i];
			break;
		}

	if (stmt == NULL)
		return (NULL);

	res = redisCommand(config->db, stmt, key);
	if (res == NULL) {
		log_warnx("warn: table-redis: redisCommand: %s",
		    config->db->errstr);

		if (config_connect(config))
			goto retry;

		return (NULL);
	}

	return (res);
}

static int
table_redis_check(int service, struct dict *params, const char *key)
{
	int		 r;
	redisReply	*reply;

	if (config->db == NULL && config_connect(config) == 0)
		return (-1);

	reply = table_redis_query(key, service);
	if (reply == NULL)
		return (-1);

	switch (reply->type) {
		case REDIS_REPLY_INTEGER:
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

	return (r);
}

static int
table_redis_lookup(int service, struct dict *params, const char *key, char *dst, size_t sz)
{
	redisReply	*reply, *elmt;
	unsigned int	i;
	int		r;

	if (config->db == NULL && config_connect(config) == 0)
		return (-1);

	reply = table_redis_query(key, service);
	if (reply == NULL)
		return (-1);

	r = 1;
	switch(service) {
	case K_ALIAS:
		memset(dst, 0, sz);
		if (reply->type == REDIS_REPLY_STRING) {
			if (strlcat(dst, reply->str, sz) >= sz) {
				log_warnx("warn: table-redis: result too large");
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
				if (dst[0] && strlcat(dst, ", ", sz) >= sz) {
					log_warnx("warn: table-redis: result too large");
					r = -1;
				}
				if (strlcat(dst, elmt->str, sz) >= sz) {
					log_warnx("warn: table-redis: result too large");
					r = -1;
				}
			}
		}
		else
			r = -1;
		break;
	case K_CREDENTIALS:
	case K_USERINFO:
		memset(dst, 0, sz);
		if (reply->type == REDIS_REPLY_STRING) {
			if (strlcpy(dst, reply->str, sz) >= sz) {
				log_warnx("warn: table-redis: result too large");
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
				if (dst[0] && strlcat(dst, ":", sz) >= sz) {
					log_warnx("warn: table-redis: result too large");
					r = -1;
				}
				if (strlcat(dst, elmt->str, sz) >= sz) {
					log_warnx("warn: table-redis: result too large");
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
				log_warnx("warn: table-redis: result too large");
				r = -1;
			}
		}
		else
			r = -1;
		break;
	default:
		log_warnx("warn: table-redis: unknown service %d",
		    service);
		r = -1;
	}

	freeReplyObject(reply);
	return (r);
}

static int
table_redis_fetch(int service, struct dict *params, char *dst, size_t sz)
{
	return (-1);
}
