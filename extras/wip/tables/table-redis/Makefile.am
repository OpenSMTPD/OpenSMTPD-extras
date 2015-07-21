include	$(top_srcdir)/mk/wip.mk
include	$(top_srcdir)/mk/table.mk

pkglibexec_PROGRAMS	 = table-redis

table_redis_SOURCES	 = $(SRCS)
table_redis_SOURCES	+= $(tables_srcdir)/table-redis/table_redis.c

CFLAGS                  += ${REDIS_CPPFLAGS}
LDFLAGS                 += ${REDIS_LDFLAGS}
