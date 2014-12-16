PROG=	filter-lua
SRCS=	filter_lua.c

CFLAGS+= -I /usr/local/include/lua-5.2
LDFLAGS+= -L /usr/local/lib
LDADD+= -llua5.2 -lm

.include <bsd.prog.mk>
