include	$(top_srcdir)/mk/paths.mk
include	$(top_srcdir)/mk/scheduler.mk

pkglibexec_PROGRAMS	 = scheduler-python

scheduler_python_SOURCES	 = $(SRCS)
scheduler_python_SOURCES	+= $(schedulers_srcdir)/scheduler-python/scheduler_python.c

CFLAGS	+=	${PYTHON_CPPFLAGS}
LDFLAGS	+=	${PYTHON_LDFLAGS}
