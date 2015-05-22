include	$(top_srcdir)/mk/wip.mk
include	$(top_srcdir)/mk/scheduler.mk

pkglibexec_PROGRAMS	 = scheduler-python

scheduler_python_SOURCES	 = $(SRCS)
scheduler_python_SOURCES	+= $(schedulers_srcdir)/scheduler-python/scheduler_python.c

CFLAGS+=	-I/usr/local/include/python2.7
DPADD=	${LIBPYTHON2.7}
LDADD+=	-L/usr/local/lib -lpython2.7
