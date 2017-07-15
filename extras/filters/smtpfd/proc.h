/*	$OpenBSD: log.h,v 1.7 2017/01/09 14:49:22 reyk Exp $	*/

/*
 * Copyright (c) 2017 Eric Faurot <eric@openbsd.org>
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

struct imsgproc;

struct imsgproc *proc_bypid(pid_t);
struct imsgproc *proc_exec(int, char **);
struct imsgproc *proc_attach(int, int);
void	         proc_enable(struct imsgproc *);
void	         proc_free(struct imsgproc *);
pid_t		 proc_getpid(struct imsgproc *);
int		 proc_gettype(struct imsgproc *);
int		 proc_getinstance(struct imsgproc *);
const char 	*proc_gettitle(struct imsgproc *);
void		 proc_setpid(struct imsgproc *, pid_t);
void		 proc_settitle(struct imsgproc *, const char *);
void		 proc_setinstance(struct imsgproc *, int);
void		 proc_setcallback(struct imsgproc *,
    void(*)(struct imsgproc *, struct imsg *, void *), void *);
int		 proc_compose(struct imsgproc *, int, uint32_t, pid_t, int, void *,
    uint16_t);
