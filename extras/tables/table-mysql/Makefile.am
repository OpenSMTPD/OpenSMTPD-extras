include	$(top_srcdir)/mk/paths.mk
include	$(top_srcdir)/mk/table.mk

pkglibexec_PROGRAMS	 = table-mysql

table_mysql_SOURCES	 = $(SRCS)
table_mysql_SOURCES	+= table_mysql.c

LDADD	+= -lmysqlclient
