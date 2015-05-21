CFLAGS+=-Wall -Wextra
PROG=	filter-regex
SRCS=	filter_regex.c
MAN=	filter-regex.8 filter-regex.conf.5

uninstall:
	rm -f /usr/share/man/man8/filter-regex.conf.5
	rm -f /usr/share/man/man8/filter-regex.8
	rm -f ${BINDIR}/filter-regex
	#rm -f ${DESTDIR}/etc/mail/filter-regex.conf

#afterinstall:
#	${INSTALL} -c -o root -g wheel -m 644 filter-regex.conf ${DESTDIR}/etc/mail

.include <bsd.prog.mk>
