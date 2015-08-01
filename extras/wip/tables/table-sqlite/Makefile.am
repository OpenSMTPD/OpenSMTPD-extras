include	$(top_srcdir)/mk/wip.mk
include	$(top_srcdir)/mk/table.mk

pkglibexec_PROGRAMS	 = table-sqlite

table_sqlite_SOURCES	 = $(SRCS)
table_sqlite_SOURCES	+= $(tables_srcdir)/table-sqlite/table_sqlite.c

LDADD	+= -lsqlite3

man_MANS		 = $(tables_srcdir)/table-sqlite/table_sqlite.5
