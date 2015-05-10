CFLAGS+=-Wall -Wextra
PROG=	filter-regex
SRCS=	filter_regex.c
NOMAN=	noman

uninstall:
	rm -f ${BINDIR}/filter-regex

afterinstall:
	${INSTALL} -c -o root -g wheel -m 644 filter-regex.conf ${DESTDIR}/etc/mail

.include <bsd.prog.mk>
