.PATH: ${.CURDIR}/../../api

SRCS+=	table_api.c
SRCS+=	dict.c
SRCS+=	log.c
NOMAN=	noman

BINDIR=	/usr/libexec/smtpd

DPADD+=	${LIBUTIL}
LDADD+=	-lutil

CFLAGS+=	-I${.CURDIR}/../../api
CFLAGS+=	-g3 -ggdb -I${.CURDIR}/..
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare -Wbounded
CFLAGS+=	-DNO_IO
#CFLAGS+=	-Werror # during development phase (breaks some archs) 
