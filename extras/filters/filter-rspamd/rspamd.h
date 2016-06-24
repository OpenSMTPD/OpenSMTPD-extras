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

#define RSPAMD_HOST "127.0.0.1"
#define RSPAMD_PORT "11333"

struct session {
	uint64_t	id;

	struct iobuf	iobuf;
	struct io	io;
	
	char	       *ip;
	char	       *hostname;
	char	       *helo;

	struct tx {
		FILE   *fp;
		char   *line;
		int	error;
		int	eom;

		char   *from;
		char   *rcpt;
		struct rfc2822_parser	rfc2822_parser;
	} tx;
	
	struct rspamd_response {
		int	eoh;
		char   *body;

		int	is_spam;
		int	is_skipped;
		double	score;
		double	required_score;
		enum {
			NO_ACTION,
			GREYLIST,
			ADD_HEADER,
			REWRITE_SUBJECT,
			SOFT_REJECT,
			REJECT
		} action;
		char   *subject;
	} rspamd;

};

struct session  *session_init(uint64_t);
void		session_reset(struct session *);
void		session_free(struct session *);

int		rspamd_connect(struct session *);
void		rspamd_connected(struct session *);
void		rspamd_error(struct session *);
void		rspamd_io(struct io *, int);
void		rspamd_send_query(struct session *);
void		rspamd_send_chunk(struct session *, const char *);
void		rspamd_read_response(struct session *);
int		rspamd_parse_response(struct session *);


