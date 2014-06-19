include	$(top_srcdir)/mk/pathnames
include	$(top_srcdir)/mk/table.mk

pkglibexec_PROGRAMS	 = table-redis

table_redis_SOURCES	 = $(SRCS)
table_redis_SOURCES	+= $(tables_srcdir)/table-redis/table_redis.c

CFLAGS	+= -I/usr/include/hiredis
LDADD	+= -lhiredis
