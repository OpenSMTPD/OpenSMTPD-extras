include	$(top_srcdir)/mk/pathnames
include	$(top_srcdir)/mk/queue.mk

pkglibexec_PROGRAMS	 = queue-python

queue_python_SOURCES	 = $(SRCS)
queue_python_SOURCES	+= $(queues_srcdir)/queue-python/queue_python.c

CFLAGS+=	-I/usr/include/python2.7
DPADD=		${LIBPYTHON2.7}
LDADD+=		-L/usr/lib -lpython2.7
