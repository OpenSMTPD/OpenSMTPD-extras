include	$(top_srcdir)/mk/paths.mk
include	$(top_srcdir)/mk/table.mk

pkglibexec_PROGRAMS	 = table-sqlite

table_sqlite_SOURCES	 = $(SRCS)
table_sqlite_SOURCES	+= table_sqlite.c

man_MANS		 = table-sqlite.5

LDADD	+= -lsqlite3
