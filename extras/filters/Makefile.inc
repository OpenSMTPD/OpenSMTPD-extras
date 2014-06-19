.PATH: ${.CURDIR}/../../api

SRCS+=	filter_api.c
SRCS+=	log.c
SRCS+=	tree.c
SRCS+=	dict.c
SRCS+=	ioev.c
SRCS+=	iobuf.c
SRCS+=	mproc.c

CFLAGS+=	-I${.CURDIR}/../../api
DPADD+=		${LIBUTIL} ${LIBEVENT}
LDADD+=		${LIBUTIL} ${LIBEVENT}

BINDIR	= /usr/libexec/smtpd

NOMAN	= noman
