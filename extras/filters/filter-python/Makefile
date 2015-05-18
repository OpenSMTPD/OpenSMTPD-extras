PROG=	filter-python
SRCS+=	filter_python.c
NOMAN=	noman

CFLAGS+=	-I/usr/local/include/python2.7
DPADD+=		${LIBPYTHON2.7}
LDADD+=		-L/usr/local/lib -lpython2.7

uninstall:
	rm -f ${BINDIR}/filter-python

.include <bsd.prog.mk>
