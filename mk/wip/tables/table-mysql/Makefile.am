include	$(top_srcdir)/mk/wip.mk
include	$(top_srcdir)/mk/table.mk

pkglibexec_PROGRAMS	 = table-mysql

table_mysql_SOURCES	 = $(SRCS)
table_mysql_SOURCES	+= $(tables_srcdir)/table-mysql/table_mysql.c

LDADD	+= -lmysqlclient

