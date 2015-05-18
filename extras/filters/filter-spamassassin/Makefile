CFLAGS+=-Wall -Wextra
PROG=	filter-spamassassin
SRCS=	filter_spamassassin.c
MAN=	filter-spamassassin.8

uninstall:
	rm -f /usr/share/man/man8/filter-spamassassin.8
	rm -f ${BINDIR}/filter-spamassassin

.include <bsd.prog.mk>
