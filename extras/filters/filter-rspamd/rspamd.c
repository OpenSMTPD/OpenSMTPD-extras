/*
 * Copyright (c) 2016 Gilles Chehade <gilles@poolp.org>
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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#include <smtpd-api.h>

#include "rspamd.h"
#include "json.h"

extern struct sockaddr_storage	ss;

void *
session_allocator(uint64_t id)
{
	return xcalloc(1, sizeof (struct session), "on_connect");
}

void
session_destructor(void *ctx)
{
	struct session	*rs = ctx;

	free(rs->ip);
	free(rs->hostname);
	free(rs->helo);
	free(rs);
}

void *
transaction_allocator(uint64_t id)
{
	struct transaction	*tx;

	tx = xcalloc(1, sizeof *tx, "transaction_allocator");
	tx->id = id;

	iobuf_xinit(&tx->iobuf, 0, 0, "on_eom");
	io_init(&tx->io, -1, tx, rspamd_io, &tx->iobuf);

	dict_init(&tx->rcpts);

	return tx;
}

void
transaction_destructor(void *ctx)
{
	struct transaction *tx = ctx;
	void		   *data;

	iobuf_clear(&tx->iobuf);
	io_clear(&tx->io);

	if (tx->from)
		free(tx->from);
	if (tx->rspamd.body)
		free(tx->rspamd.body);
	if (tx->rspamd.subject)
		free(tx->rspamd.subject);

	tx->eom = 0;
	tx->from = NULL;
	tx->rspamd.body = NULL;
	tx->rspamd.subject = NULL;

	while (dict_poproot(&tx->rcpts, &data))
		;

	free(tx);
}


int
session_set_helo(struct session *s, const char *helo)
{
	return ((s->helo = strdup(helo)) != NULL);
}

int
session_set_ip(struct session *s, const char *ip)
{
	return ((s->ip = strdup(ip)) != NULL);
}

int
session_set_hostname(struct session *s, const char *hostname)
{
	return ((s->hostname = strdup(hostname)) != NULL);
}

int
transaction_set_from(struct transaction *t, const char *from)
{
	return ((t->from = strdup(from)) != NULL);
}

int
transaction_add_rcpt(struct transaction *t, const char *rcpt)
{
	/* XXX - not the best data structure */
	dict_set(&t->rcpts, rcpt, NULL);
	return 1;
}


int
rspamd_connect(struct transaction *tx)
{
	return (io_connect(&tx->io, (struct sockaddr *)&ss, NULL) != -1);
}

void
rspamd_disconnect(struct transaction *tx)
{
	iobuf_clear(&tx->iobuf);
	io_clear(&tx->io);
}

void
rspamd_connected(struct transaction *tx)
{
	/* answer to DATA phase */
	filter_api_accept(tx->id);
}

void
rspamd_error(struct transaction *tx)
{
	filter_api_reject_code(tx->id, FILTER_FAIL, 421, "temporary failure");
}

void
rspamd_send_query(struct transaction *tx)
{
	struct session	*rs = filter_api_session(tx->id);
	void		*iter;
	const  char	*key;

	iobuf_xfqueue(&tx->iobuf, "io",
	    "POST /check HTTP/1.0\r\n"
	    "Transfer-Encoding: chunked\r\n"
	    "Pass: all\r\n"
	    "IP: %s\r\n"
	    "Helo: %s\r\n"
	    "Hostname: %s\r\n"
	    "From: %s\r\n",
	    rs->ip,
	    rs->helo,
	    rs->hostname,
	    tx->from);

	iter = NULL;
	while (dict_iter(&tx->rcpts, &iter, &key, NULL))
		iobuf_xfqueue(&tx->iobuf, "io", "Rcpt: %s\r\n", key);
	iobuf_xfqueue(&tx->iobuf, "io", "\r\n");
	io_reload(&tx->io);
}

void
rspamd_send_chunk(struct transaction *tx, const char *line)
{
	if (line)
		iobuf_xfqueue(&tx->iobuf, "io", "%x\r\n%s\r\n\r\n",
		    strlen(line)+2, line);
	else {
		iobuf_xfqueue(&tx->iobuf, "io", "0\r\n\r\n");
		tx->eom = 1;
	}
		
	io_reload(&tx->io);
}

void
rspamd_read_response(struct transaction *tx)
{
	char	       *line;

	while ((line = iobuf_getline(&tx->iobuf, NULL)))
		if (strlen(line) == 0)
			tx->rspamd.eoh = 1;

	if (tx->rspamd.eoh)
		if (iobuf_len(&tx->iobuf) != 0) {
			tx->rspamd.body = xmemdup(iobuf_data(&tx->iobuf),
			    iobuf_len(&tx->iobuf) + 1, "rspamd_read_response");
			tx->rspamd.body[iobuf_len(&tx->iobuf)] = 0;
		}

	iobuf_normalize(&tx->iobuf);
}

/* XXX this can certainly be cleaned up */
int
rspamd_parse_response(struct transaction *tx)
{
	json_value     *jv = NULL;
	json_value     *def = NULL;
	char	       *name;
	json_value     *val;
	size_t		i;

	if (tx->rspamd.body == NULL)
		goto fail;

	jv = json_parse(tx->rspamd.body, strlen(tx->rspamd.body));
	if (jv == NULL || jv->type != json_object)
		goto fail;

	for (i = 0; i < jv->u.object.length; ++i)
		if (strcmp(jv->u.object.values[i].name, "default") == 0) {
			def = jv->u.object.values[i].value;
			break;
		}
	if (def == NULL)
		goto fail;

	for (i = 0; i < def->u.object.length; ++i) {
		name = def->u.object.values[i].name;

		if (strcmp(name, "is_spam") == 0) {
			val = def->u.object.values[i].value;
			if (val->type != json_boolean)
				goto fail;
			tx->rspamd.is_spam = val->u.boolean;
		}
		else if (strcmp(name, "is_skipped") == 0) {
			val = def->u.object.values[i].value;
			if (val->type != json_boolean)
				goto fail;
			tx->rspamd.is_skipped = val->u.boolean;
		}
		else if (strcmp(name, "score") == 0) {
			val = def->u.object.values[i].value;
			if (val->type != json_double)
				goto fail;
			tx->rspamd.score = val->u.dbl;
		}
		else if (strcmp(name, "required_score") == 0) {
			val = def->u.object.values[i].value;
			if (val->type != json_double)
				goto fail;
			tx->rspamd.required_score = val->u.dbl;
		}
		else if (strcmp(name, "action") == 0) {
			val = def->u.object.values[i].value;
			if (val->type != json_string)
				goto fail;
			if (strncmp(val->u.string.ptr, "no action",
				val->u.string.length) == 0)
				tx->rspamd.action = NO_ACTION;
			else if (strncmp(val->u.string.ptr, "greylist",
				val->u.string.length) == 0)
				tx->rspamd.action = GREYLIST;
			else if (strncmp(val->u.string.ptr, "add header",
				val->u.string.length) == 0)
				tx->rspamd.action = ADD_HEADER;
			else if (strncmp(val->u.string.ptr, "rewrite subject",
				val->u.string.length) == 0)
				tx->rspamd.action = REWRITE_SUBJECT;
			else if (strncmp(val->u.string.ptr, "soft reject",
				val->u.string.length) == 0)
				tx->rspamd.action = SOFT_REJECT;
			else if (strncmp(val->u.string.ptr, "reject",
				val->u.string.length) == 0)
				tx->rspamd.action = REJECT;
		}
		else if (strcmp(name, "subject") == 0) {
			val = def->u.object.values[i].value;
			if (val->type != json_string)
				goto fail;
			tx->rspamd.subject = xmemdup(val->u.string.ptr,
			    val->u.string.length, "rspamd_parse_result");
		}
	}

	json_value_free(jv);
	return 1;

fail:
	if (jv)
		json_value_free(jv);
	return 0;
}

void
rspamd_spam_headers(struct transaction *tx)
{
	filter_api_header_add(tx->id, "X-Spam-Flag", "%s",
	    tx->rspamd.is_spam ? "Yes" : "No");
	filter_api_header_add(tx->id, "X-Spam-Score", "%.2f",
	    tx->rspamd.score);
}

int
rspamd_proceed(struct transaction *tx)
{
	if (! rspamd_parse_response(tx))
		return 0;

	switch (tx->rspamd.action) {
	case NO_ACTION:
		return 1;

	case SOFT_REJECT:
		filter_api_reject_code(tx->id, FILTER_FAIL, 421,
		    "message content rejected");
		return 0;

	case GREYLIST:
		/* XXX - don't greylist until filter is finished */
		/*
		  filter_api_reject_code(tx->id, FILTER_FAIL, 421,
			"greylisted");
		return 0;
		*/
		return 1;

	case REJECT:
		filter_api_reject_code(tx->id, FILTER_FAIL, 550,
		    "message content rejected");
		return 0;

	case ADD_HEADER:
		/* insert header */
		rspamd_spam_headers(tx);
		return 1;

	case REWRITE_SUBJECT:
		/* rewrite subject */
		return 1;
	}

	filter_api_reject_code(tx->id, FILTER_FAIL, 550,
	    "server internal error");
	return 0;
}


void
rspamd_io(struct io *io, int evt)
{
	struct transaction	*tx = io->arg;

	switch (evt) {
	case IO_CONNECTED:
		rspamd_connected(tx);
		rspamd_send_query(tx);
		io_set_write(io);
		return;

	case IO_LOWAT:
		/* we've hit EOM and no more data, toggle to read */
		if (tx->eom)
			io_set_read(io);
		return;

	case IO_DATAIN:
		rspamd_read_response(tx);
		return;

	case IO_DISCONNECTED:
		rspamd_disconnect(tx);

		/* we're done with rspamd, if there was a local error
		 * during transaction, reject now, else move forward.
		 */
		if (! rspamd_proceed(tx))
			goto fail;

		filter_api_data_buffered_stream(tx->id);
		return;

	case IO_TIMEOUT:
	case IO_ERROR:
	default:
		break;
	}

fail:
	rspamd_error(tx);
	return;
}
