#	$OpenBSD$

PROG=	smtpfd
SRCS=	control.c engine.c frontend.c log.c smtpfd.c parse.y
SRCS+=	proc.c

MAN=	smtpfd.8 smtpfd.conf.5

CFLAGS+= -Wall -I${.CURDIR}
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
YFLAGS=
LDADD+=	-levent -lutil
DPADD+= ${LIBEVENT} ${LIBUTIL}

.include <bsd.prog.mk>
