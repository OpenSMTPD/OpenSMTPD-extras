PROG=	filter-lua
SRCS=	filter_lua.c
NOMAN=	noman

CFLAGS+= -I /usr/local/include/lua-5.2
LDFLAGS+= -L /usr/local/lib
LDADD+= -llua5.2 -lm

uninstall:
	rm -f ${BINDIR}/filter-lua

.include <bsd.prog.mk>
