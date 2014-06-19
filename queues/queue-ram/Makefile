.PATH: ${.CURDIR}/../../api

PROG=	queue-ram

SRCS+=	log.c
SRCS+=	tree.c
SRCS+=	queue_api.c
SRCS+=	queue_utils.c
SRCS+=	queue_ram.c

CFLAGS+=	-I${.CURDIR}/../../api
DPADD+=		${LIBUTIL}
LDADD+=		${LIBUTIL}

NOMAN=	noman

.include <bsd.prog.mk>
