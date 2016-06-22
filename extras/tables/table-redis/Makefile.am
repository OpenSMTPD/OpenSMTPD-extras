include	$(top_srcdir)/mk/paths.mk
include	$(top_srcdir)/mk/table.mk

pkglibexec_PROGRAMS	 = table-redis

table_redis_SOURCES	 = $(SRCS)
table_redis_SOURCES	+= table_redis.c

man_MANS		 = table-redis.5

CFLAGS                  += ${REDIS_CPPFLAGS}
LDFLAGS                 += ${REDIS_LDFLAGS}
