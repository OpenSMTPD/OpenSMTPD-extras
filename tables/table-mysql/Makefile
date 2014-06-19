PROG	= table-mysql

SRCS	= table_mysql.c

DPADD	= ${LIBMYSQLCLIENT}
LDADD	= -L/usr/local/lib -lmysqlclient

CFLAGS	= -I/usr/local/include

.include <bsd.prog.mk>
