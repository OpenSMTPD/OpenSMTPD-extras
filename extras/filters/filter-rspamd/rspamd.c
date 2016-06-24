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

struct sockaddr_storage	ss;

static void	datahold_stream(uint64_t, FILE *, void *);


void *
session_allocator(uint64_t id)
{
	struct session	*rs;

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

	return tx;
}

void
transaction_destructor(void *ctx)
{
	struct transaction *tx = ctx;

	iobuf_clear(&tx->iobuf);
	io_clear(&tx->io);

	filter_api_datahold_close(tx->id);

	if (tx->from)
		free(tx->from);
	if (tx->rcpt)
		free(tx->rcpt);

	tx->eom = 0;
	tx->error = 0;
	tx->from = NULL;
	tx->rcpt = NULL;

}





/* XXX
 * this needs to be handled differently, but lets focus on the filter for now
 */
void
rspamd_resolve(const char *h, const char *p)
{
	struct addrinfo hints, *addresses, *ai;
	int fd, r;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	if ((r = getaddrinfo(h, p, &hints, &addresses)))
		fatalx("resolve: getaddrinfo %s", gai_strerror(r));
	for (ai = addresses; ai; ai = ai->ai_next) {
		if ((fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1)
			continue;
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == -1) {
			close(fd);
			continue;
		}
		close(fd);
		memmove(&ss, ai->ai_addr, ai->ai_addrlen);
		break;
	}
	freeaddrinfo(addresses);
	if (!ai)
		fatalx("resolve: failed");
}

static void
headers_callback(const struct rfc2822_header *hdr, void *arg)
{
	struct transaction	*tx = arg;
	struct rfc2822_line	*l;
	char			 buffer[4096];
	int			 i = 0;

	log_debug("#######1");
	TAILQ_FOREACH(l, &hdr->lines, next) {
		if (i++ == 0) {
			snprintf(buffer, sizeof buffer,  "%s:%s", hdr->name, l->buffer);
			filter_api_writeln(tx->id, buffer);
			continue;
		}
		filter_api_writeln(tx->id, l->buffer);
	}
}

static void
dataline_callback(const char *line, void *arg)
{
	struct transaction	*tx = arg;

	log_debug("debug: STREAM BACK: [%s]", tx->line);
	filter_api_writeln(tx->id, tx->line);
}


int
rspamd_buffer(struct transaction *tx)
{
	tx->fp = filter_api_datahold_open(tx->id, datahold_stream, tx);
	if (tx->fp == NULL)
		return 0;
	return 1;
}

int
rspamd_connect(struct transaction *tx)
{
	iobuf_xinit(&tx->iobuf, LINE_MAX, LINE_MAX, "on_eom");
	io_init(&tx->io, -1, tx, rspamd_io, &tx->iobuf);
	if (io_connect(&tx->io, (struct sockaddr *)&ss, NULL) == -1)
		return 0;
	return 1;
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
	
	iobuf_xfqueue(&tx->iobuf, "io",
	    "POST /check HTTP/1.0\r\n"
	    "Transfer-Encoding: chunked\r\n"
	    "Pass: all\r\n"
	    "IP: %s\r\n"
	    "Helo: %s\r\n"
	    "Hostname: %s\r\n"
	    "From: %s\r\n"
	    "Rcpt: %s\r\n"
	    "\r\n",
	    rs->ip,
	    rs->helo,
	    rs->hostname,
	    tx->from,
	    tx->rcpt);
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

	if (tx->rspamd.eoh) {
		if (iobuf_len(&tx->iobuf) != 0) {
			tx->rspamd.body = xmemdup(iobuf_data(&tx->iobuf),
			    iobuf_len(&tx->iobuf) + 1, "rspamd_read_response");
			tx->rspamd.body[iobuf_len(&tx->iobuf)] = 0;
		}
	}
	iobuf_normalize(&tx->iobuf);
}

int
rspamd_parse_response(struct transaction *tx)
{
	json_value     *jv;
	json_value     *def = NULL;
	char	       *name;
	json_value     *val;
	size_t		i;
	
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
			log_debug("[%.*s]", val->u.string.length, val->u.string.ptr);
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
	json_value_free(jv);
	return -1;
}

void
rspamd_spam_header(const char *header, void *arg)
{
	struct transaction	*tx = arg;
	char		buffer[4096];

	snprintf(buffer, sizeof buffer, "X-Spam-Flag: %s",
	    tx->rspamd.is_spam ? "Yes" : "No");
	filter_api_writeln(tx->id, buffer);

	snprintf(buffer, sizeof buffer, "X-Spam-Score: %.2f",
	    tx->rspamd.score);
	filter_api_writeln(tx->id, buffer);

	snprintf(buffer, sizeof buffer, "X-Spam-Status: %s, score=%.2f, required=%.2f",
	    tx->rspamd.is_spam ? "Yes" : "No",
	    tx->rspamd.score,
	    tx->rspamd.required_score);
	filter_api_writeln(tx->id, buffer);
}

int
rspamd_proceed(struct transaction *tx)
{
	rfc2822_parser_init(&tx->rfc2822_parser);
	rfc2822_parser_reset(&tx->rfc2822_parser);
	rfc2822_header_default_callback(&tx->rfc2822_parser,
	    headers_callback, tx);
	rfc2822_body_callback(&tx->rfc2822_parser,
	    dataline_callback, tx);

	switch (tx->rspamd.action) {
	case NO_ACTION:
		return 1;

	case SOFT_REJECT:
		filter_api_reject_code(tx->id, FILTER_FAIL, 421,
		    "message content rejected");
		return 0;

	case GREYLIST:
		filter_api_reject_code(tx->id, FILTER_FAIL, 421,
		    "greylisted");
		return 0;

	case REJECT:
		filter_api_reject_code(tx->id, FILTER_FAIL, 550,
		    "message content rejected");
		return 0;

	case ADD_HEADER:
		/* insert header */
		log_debug("ADDING X-SPAM");
		rfc2822_missing_header_callback(&tx->rfc2822_parser,
		    "x-spam", rspamd_spam_header, tx);
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
		break;

	case IO_LOWAT:
		/* we've hit EOM and no more data, toggle to read */
		if (tx->eom)
			io_set_read(io);
		break;

	case IO_DATAIN:
		/* accumulate reply */
		rspamd_read_response(tx);
		break;

	case IO_DISCONNECTED:
		rspamd_disconnect(tx);

		/* we're done with rspamd, if there was a local error
		 * during transaction, reject now, else move forward.
		 */
		if (tx->error) {
			rspamd_error(tx);
			break;
		}
		/* process rspamd reply and start processing datahold */
		if (! rspamd_parse_response(tx)) {
			rspamd_error(tx);
			break;
		}

		if (! rspamd_proceed(tx))
			break;
		
		filter_api_datahold_start(tx->id);
		break;

	case IO_TIMEOUT:
	case IO_ERROR:
	default:
		rspamd_error(tx);
		break;
	}
	return;
}

static void
datahold_stream(uint64_t id, FILE *fp, void *arg)
{
	struct transaction     *tx = arg;
	size_t			sz;
	ssize_t			len;
	int			ret;
	
	errno = 0;
	if ((len = getline(&tx->line, &sz, fp)) == -1) {
		if (errno) {
			filter_api_reject_code(id, FILTER_FAIL, 421,
			    "temporary failure");
			return;
		}
		filter_api_accept(id);
		return;
	}

	tx->line[strcspn(tx->line, "\n")] = '\0';
	ret = rfc2822_parser_feed(&tx->rfc2822_parser,
	    tx->line);
	datahold_stream(id, fp, arg);
}
