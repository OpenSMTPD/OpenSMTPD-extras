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
	char	       *ip;
	char	       *hostname;
	char	       *helo;
};

struct transaction {
	uint64_t	id;

	struct iobuf	iobuf;
	struct io	io;
	
	char	       *from;
	int		eom;
	struct dict	rcpts;

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

	char   *line;
};

void   *session_allocator(uint64_t);
void	session_destructor(void *);
int	session_set_helo(struct session *, const char *);
int	session_set_ip(struct session *, const char *);
int	session_set_hostname(struct session *, const char *);

void   *transaction_allocator(uint64_t);
void	transaction_destructor(void *);
int	transaction_set_from(struct transaction *, const char *);
int	transaction_add_rcpt(struct transaction *, const char *);

int	rspamd_connect(struct transaction *);
void	rspamd_connected(struct transaction *);
void	rspamd_send_query(struct transaction *);
void	rspamd_send_chunk(struct transaction *, const char *);
void	rspamd_read_response(struct transaction *);
int	rspamd_parse_response(struct transaction *);
void	rspamd_error(struct transaction *);

void	rspamd_io(struct io *, int);






