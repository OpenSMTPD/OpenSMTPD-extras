/*
 * Copyright (c) 2014 Sunil Nimmagadda <sunil@nimmagadda.net>
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

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <smtpd-api.h>

#define DKIM_SIGNER_CRLF "\r\n"
#define DKIM_SIGNER_CRLF_LEN 2
#define DKIM_SIGNER_PRIVATE_KEY	"/etc/ssl/private/rsa.private"
#define DKIM_SIGNER_TEMPLATE	"DKIM-Signature: v=1; a=rsa-sha256; "	\
				"c=simple/simple; d=%s; "		\
				"h=%s; "				\
				"s=%s; "				\
				"bh=%s; "				\
				"b="

struct entry {
	SIMPLEQ_ENTRY(entry)	 entries;
	char			*line;
};

struct dkim_signer {
	SIMPLEQ_HEAD(, entry)	 lines;
	SHA256_CTX		 hdr_ctx;
	SHA256_CTX		 body_ctx;
	char			 b64_rsa_sig[BUFSIZ];
	char			 b64_body_hash[BUFSIZ];
	char			 hdrs_list[BUFSIZ];
	char			 hdr_hash[SHA256_DIGEST_LENGTH];
	char			 body_hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX		*ctx;
	size_t			 nlines;
	size_t			 emptylines;
};

static RSA *dkim_signer_rsa;
static const char *dkim_signer_domain, *dkim_signer_selector = "default";

static int
dkim_signer_add_hdr_line(struct dkim_signer *s, const char *line)
{
	const char *want_hdrs[] = {
	    "from:", "to:", "subject:", "date:", "message-id:"
	};
	size_t i;

	for (i = 0; i < nitems(want_hdrs); i++) {
		if (strncasecmp(want_hdrs[i], line, strlen(want_hdrs[i])))
			continue;

		if (strlcat(s->hdrs_list, want_hdrs[i],
		    sizeof(s->hdrs_list)) >= sizeof(s->hdrs_list))
			fatalx("headers list overflow");
		else
			return 1;
	}

	return 0;
}

static void
dkim_signer_clear(struct dkim_signer *s)
{
	struct entry *n;

	if (s == NULL)
		return;
	while (!SIMPLEQ_EMPTY(&s->lines)) {
		n = SIMPLEQ_FIRST(&s->lines);
		SIMPLEQ_REMOVE_HEAD(&s->lines, entries);
		free(n->line);
		free(n);
	}
	free(s);
}

static int
dkim_signer_on_data(uint64_t id)
{
	struct dkim_signer *s = xmalloc(sizeof *s, "dkim_signer: on_data");

	SIMPLEQ_INIT(&s->lines);
	SHA256_Init(&s->hdr_ctx);
	SHA256_Init(&s->body_ctx);
	s->ctx = &s->hdr_ctx;
	s->nlines = 0;
	s->emptylines = 0;
	s->hdrs_list[0] = '\0';

	filter_api_set_udata(id, s);
	return filter_api_accept(id);
}

static void
dkim_signer_on_dataline(uint64_t id, const char *line)
{
	struct dkim_signer *s;
	struct entry *n;

	if ((s = filter_api_get_udata(id)) == NULL)
		return;
	n = xmalloc(sizeof *n, "dkim_signer: on_dataline");
	n->line = xstrdup(line, "dkim_signer: on_dataline");
	SIMPLEQ_INSERT_TAIL(&s->lines, n, entries);

	/* first emptyline seperates headers and body */
	if (s->ctx == &s->hdr_ctx && strlen(line) == 0) {
		s->ctx = &s->body_ctx;
		return;
	}

	if (s->ctx == &s->hdr_ctx) {
		if (dkim_signer_add_hdr_line(s, line) == 0)
			return; /* skip unwanted headers */
	} else {
		s->nlines += 1;
		/*
		 * treat trailing two or more emptylines at end of
		 * message as a single emptyline
		 */
		if (strlen(line) == 0) {
			s->emptylines += 1;
			return;
		} else {
			while (s->emptylines--)
				SHA256_Update(s->ctx, DKIM_SIGNER_CRLF, DKIM_SIGNER_CRLF_LEN);

			s->emptylines = 0;
		}
	}

	SHA256_Update(s->ctx, line, strlen(line));
	/* explicitly terminate with a CRLF */
	SHA256_Update(s->ctx, DKIM_SIGNER_CRLF, DKIM_SIGNER_CRLF_LEN);
}

static int
dkim_signer_on_eom(uint64_t id, size_t size)
{
	struct dkim_signer *s;
	struct entry *n;
	char *dkim_header = NULL, *dkim_sig = NULL, *rsa_sig = NULL;
	int dkim_sig_len, rsa_sig_len, r = 0;

	if ((s = filter_api_get_udata(id)) == NULL) {
		log_warnx("warn: on_eom: get_udata failed");
		goto done;
	}
	/* empty body should be treated as a single CRLF */
	if (s->nlines == 0)
		SHA256_Update(&s->body_ctx, DKIM_SIGNER_CRLF, DKIM_SIGNER_CRLF_LEN);

	SHA256_Final(s->body_hash, &s->body_ctx);
	if (base64_encode(s->body_hash, sizeof(s->body_hash),
	    s->b64_body_hash, sizeof(s->b64_body_hash)) == -1) {
		log_warnx("warn: on_eom: __b64_ntop failed");
		goto done;
	}

	/* trim trailing colon in the hdrs_list */
	s->hdrs_list[strlen(s->hdrs_list) - 1] = '\0';

	if ((dkim_sig_len = asprintf(&dkim_sig, DKIM_SIGNER_TEMPLATE,
	    dkim_signer_domain, s->hdrs_list, dkim_signer_selector,
	    s->b64_body_hash)) == -1) {
		log_warn("warn: on_eom: asprintf failed");
		goto done;
	}

	SHA256_Update(&s->hdr_ctx, dkim_sig, dkim_sig_len);
	SHA256_Final(s->hdr_hash, &s->hdr_ctx);

	rsa_sig = xmalloc(RSA_size(dkim_signer_rsa), "dkim_signer: on_eom");
	if (RSA_sign(NID_sha256, s->hdr_hash, sizeof(s->hdr_hash),
	    rsa_sig, &rsa_sig_len, dkim_signer_rsa) == 0)
		fatalx("dkim_signer: on_eom: RSA_sign");

	if (base64_encode(rsa_sig, rsa_sig_len, s->b64_rsa_sig,
	    sizeof(s->b64_rsa_sig)) == -1) {
		log_warnx("warn: on_eom: __b64_ntop failed");
		goto done;
	}

	if (asprintf(&dkim_header, "%s%s", dkim_sig, s->b64_rsa_sig) == -1) {
		log_warn("warn: on_eom: asprintf failed");
		goto done;
	}

	/* prepend dkim header to the mail */
	filter_api_writeln(id, dkim_header);

	/* write out message */
	SIMPLEQ_FOREACH(n, &s->lines, entries)
		filter_api_writeln(id, n->line);
	r = 1;
done:
	free(dkim_header);
	free(dkim_sig);
	free(rsa_sig);
	return r ? filter_api_accept(id) : filter_api_reject(id, FILTER_FAIL);
}

static void
dkim_signer_on_tx_commit(uint64_t id)
{
	dkim_signer_clear(filter_api_get_udata(id));
	filter_api_set_udata(id, NULL);
}

static void
dkim_signer_on_tx_rollback(uint64_t id)
{
	dkim_signer_clear(filter_api_get_udata(id));
	filter_api_set_udata(id, NULL);
}

int
main(int argc, char **argv)
{
	int ch, C = 0, d = 0, v = 0;
	const char *p = DKIM_SIGNER_PRIVATE_KEY;
	char *c = NULL, *D = NULL, *s = NULL;
	FILE *fp;
	static char hostname[SMTPD_MAXHOSTNAMELEN];

	log_init(1);

	while ((ch = getopt(argc, argv, "Cc:D:dp:s:v")) != -1) {
		switch (ch) {
		case 'C':
			C = 1;
			break;
		case 'c':
			c = optarg;
			break;
		case 'D':
			D = optarg;
			break;
		case 'd':
			d = 1;
			break;
		case 'p':
			p = optarg;
			break;
		case 's':
			s = optarg;
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

	if (c)
		c = strip(c);
	if (D)
		dkim_signer_domain = strip(D);
	if (s)
		dkim_signer_selector = strip(s);

	log_init(d);
	log_verbose(v);

	log_debug("debug: starting...");
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	if (dkim_signer_domain == NULL) {
		if (gethostname(hostname, sizeof(hostname)) == -1)
			fatal("gethostname");
		dkim_signer_domain = hostname;
	}
	if ((fp = fopen(p, "r")) == NULL)
		fatal("fopen %s", p);
	if ((dkim_signer_rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)) == NULL)
		fatalx("PEM_read_RSAPrivateKey");

	filter_api_on_data(dkim_signer_on_data);
	filter_api_on_dataline(dkim_signer_on_dataline);
	filter_api_on_eom(dkim_signer_on_eom);
	filter_api_on_tx_commit(dkim_signer_on_tx_commit);
	filter_api_on_tx_rollback(dkim_signer_on_tx_rollback);
	if (c)
		filter_api_set_chroot(c);
	if (C)
		filter_api_no_chroot();

	/* XXX */
	/*
	 * OpenSSL will not be able to seed PRNG after chroot which will
	 * lead to runtime failures if we don't seed PRNG pre-chroot. We
	 * shouldn't have to do that, LibreSSL does not suffer from this
	 * shortcoming but luckily provides RAND_status() as a no-op for
	 * ABI compat...
	 */
	RAND_status();

	filter_api_loop();
	log_debug("debug: exiting");

	return 1;
}
