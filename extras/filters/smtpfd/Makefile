#	$OpenBSD$

PROG=	smtpfd

SRCS+=	control.c
SRCS+=	engine.c
SRCS+=	frontend.c
SRCS+=	frontend_smtpf.c
SRCS+=	io.c
SRCS+=	iobuf.c
SRCS+=	log.c
SRCS+=	logmsg.c
SRCS+=	parse.y
SRCS+=	proc.c
SRCS+=	resolver.c
SRCS+=	smtpfd.c

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
