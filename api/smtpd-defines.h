/*	$OpenBSD$	*/

/*
 * Copyright (c) 2013 Gilles Chehade <gilles@poolp.org>
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

#ifndef _SMTPD_DEFINES_H
#define _SMTPD_DEFINES_H

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

enum smtp_proc_type {
	PROC_PARENT = 0,
	PROC_LKA,
	PROC_QUEUE,
	PROC_CONTROL,
	PROC_SCHEDULER,
	PROC_PONY,
	PROC_CA,

	PROC_FILTER,
	PROC_CLIENT,
};

#define	TRACE_DEBUG	0x0001
#define	TRACE_IMSG	0x0002
#define	TRACE_IO	0x0004
#define	TRACE_SMTP	0x0008
#define	TRACE_FILTERS	0x0010
#define	TRACE_MTA	0x0020
#define	TRACE_BOUNCE	0x0040
#define	TRACE_SCHEDULER	0x0080
#define	TRACE_LOOKUP	0x0100
#define	TRACE_STAT	0x0200
#define	TRACE_RULES	0x0400
#define	TRACE_MPROC	0x0800
#define	TRACE_EXPAND	0x1000
#define	TRACE_TABLES	0x2000
#define	TRACE_QUEUE	0x4000

#define PROFILE_TOSTAT	0x0001
#define PROFILE_IMSG	0x0002
#define PROFILE_QUEUE	0x0004
#define PROFILE_BUFFERS	0x0008


#define SMTPD_MAXLOCALPARTSIZE	 (255 + 1)
#define SMTPD_MAXDOMAINPARTSIZE	 (255 + 1)

#define SMTPD_USER		"_smtpd"
#define PATH_CHROOT		"/var/empty"
#define SMTPD_QUEUE_USER	 "_smtpq"
#define PATH_SPOOL		"/var/spool/smtpd"

#define TAG_CHAR	'+'	/* gilles+tag@ */

#endif
