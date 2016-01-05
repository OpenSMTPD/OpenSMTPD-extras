include $(top_srcdir)/mk/wip.mk
include $(top_srcdir)/mk/filter.mk

pkglibexec_PROGRAMS	 = filter-python

filter_python_SOURCES	 = $(SRCS)
filter_python_SOURCES	+= filter_python.c

CFLAGS	+=	${PYTHON_CPPFLAGS}
LDFLAGS	+=	${PYTHON_LDFLAGS}
