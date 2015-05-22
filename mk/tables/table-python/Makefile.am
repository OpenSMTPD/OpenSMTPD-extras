include	$(top_srcdir)/mk/wip.mk
include	$(top_srcdir)/mk/table.mk

pkglibexec_PROGRAMS	 = table-python

table_python_SOURCES	 = $(SRCS)
table_python_SOURCES	+= $(tables_srcdir)/table-python/table_python.c

CFLAGS+=	-I/usr/include/python2.7
DPADD=		${LIBPYTHON2.7}
LDADD+=		-L/usr/lib -lpython2.7
