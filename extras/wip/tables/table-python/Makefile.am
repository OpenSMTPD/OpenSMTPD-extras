include	$(top_srcdir)/mk/wip.mk
include	$(top_srcdir)/mk/table.mk

pkglibexec_PROGRAMS	 = table-python

table_python_SOURCES	 = $(SRCS)
table_python_SOURCES	+= table_python.c

CFLAGS+=	${PYTHON_CPPFLAGS}
LDFLAGS =	${PYTHON_LDFLAGS}
