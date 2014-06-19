PROG	= table-postgres

SRCS	= table_postgres.c

DPADD	= ${LIBPQ}
LDADD	= -L/usr/local/lib -lpq

CFLAGS	= -I/usr/local/include/postgresql

.include <bsd.prog.mk>
