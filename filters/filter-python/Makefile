.PATH: ${.CURDIR}/../../api

PROG=	filter-python
SRCS=	to.c
SRCS+=	log.c
SRCS+=	ioev.c
SRCS+=	iobuf.c
SRCS+=	tree.c
SRCS+=	mproc.c
SRCS+=	filter_api.c
SRCS+=	filter_python.c

CFLAGS+=	-I${.CURDIR}/../../api -I/usr/local/include/python2.7
DPADD+=	${LIBUTIL} ${LIBEVENT} ${LIBPYTHON2.7}
LDADD+= ${LIBUTIL} ${LIBEVENT} -L/usr/local/lib -lpython2.7

NOMAN=	noman

.include <bsd.prog.mk>
