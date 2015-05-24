include	$(top_srcdir)/mk/wip.mk
include	$(top_srcdir)/mk/queue.mk

pkglibexec_PROGRAMS	 = queue-python

queue_python_SOURCES	 = $(SRCS)
queue_python_SOURCES	+= $(queues_srcdir)/queue-python/queue_python.c

CFLAGS+=	-I/usr/local/include/python2.7
DPADD=		${LIBPYTHON2.7}
LDADD+=		-L/usr/local/lib -lpython2.7
