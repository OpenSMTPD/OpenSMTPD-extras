.PATH: ${.CURDIR}/../../api

PROG=	queue-null

SRCS+=	log.c
SRCS+=	tree.c
SRCS+=	queue_api.c
SRCS+=	queue_utils.c
SRCS+=	queue_null.c

CFLAGS+=	-I${.CURDIR}/../../api
DPADD+=		${LIBUTIL}
LDADD+=		${LIBUTIL}

NOMAN=	noman

.include <bsd.prog.mk>
