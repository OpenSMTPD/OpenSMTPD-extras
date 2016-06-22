include	$(top_srcdir)/mk/paths.mk
include	$(top_srcdir)/mk/queue.mk

pkglibexec_PROGRAMS	 = queue-python

queue_python_SOURCES	 = $(SRCS)
queue_python_SOURCES	+= $(queues_srcdir)/queue-python/queue_python.c

CFLAGS	+=	${PYTHON_CPPFLAGS}
LDFLAGS	+=	${PYTHON_LDFLAGS}
