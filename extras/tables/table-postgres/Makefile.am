include	$(top_srcdir)/mk/paths.mk
include	$(top_srcdir)/mk/table.mk

pkglibexec_PROGRAMS	 = table-postgres

table_postgres_SOURCES	 = $(SRCS)
table_postgres_SOURCES	+= table_postgres.c

CFLAGS	+= -I/usr/include/postgresql
LDADD	+= -lpq
