.PATH: ${.CURDIR}/../../api

BINDIR=/usr/libexec/smtpd

SRCS+=	log.c
SRCS+=	tree.c
SRCS+=	dict.c
SRCS+=	queue_api.c
SRCS+=	queue_utils.c

CFLAGS+=	-I${.CURDIR}/../../api
DPADD+=		${LIBUTIL}
LDADD+=		${LIBUTIL}

NOMAN=noman
