include $(top_srcdir)/mk/wip.mk
include $(top_srcdir)/mk/filter.mk

pkglibexec_PROGRAMS	 = filter-python

filter_python_SOURCES	 = $(SRCS)
filter_python_SOURCES	+= $(filters_srcdir)/filter-python/filter_python.c

CFLAGS+=	-I/usr/local/include/python2.7
DPADD=		${LIBPYTHON2.7}
LDADD+=		-L/usr/local/lib -lpython2.7

