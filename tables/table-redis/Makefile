PROG	= table-redis

SRCS	= table_redis.c

DPADD	= ${LIBHIREDIS}
LDADD	= -L/usr/local/lib -lhiredis

CFLAGS	= -I/usr/local/include/hiredis

.include <bsd.prog.mk>
