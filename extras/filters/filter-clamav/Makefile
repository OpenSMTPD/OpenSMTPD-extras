CFLAGS+=-Wall -Wextra
PROG=	filter-clamav
SRCS=	filter_clamav.c
MAN=	filter-clamav.8

uninstall:
	rm -f /usr/share/man/man8/filter-clamav.8
	rm -f ${BINDIR}/filter-clamav

.include <bsd.prog.mk>
