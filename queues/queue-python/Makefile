.PATH: ${.CURDIR}/../../api

PROG=	queue-python

SRCS+=	log.c
SRCS+=	queue_api.c
SRCS+=	queue_python.c

CFLAGS+=	-I${.CURDIR}/../../api -I/usr/local/include/python2.7
DPADD+=		${LIBUTIL} ${LIBPYTHON2.7}
LDADD+=		${LIBUTIL} -L/usr/local/lib -lpython2.7

NOMAN=	noman

.include <bsd.prog.mk>
