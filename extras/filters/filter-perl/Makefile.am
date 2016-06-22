include $(top_srcdir)/mk/paths.mk
include $(top_srcdir)/mk/filter.mk

pkglibexec_PROGRAMS	 = filter-perl

filter_perl_SOURCES	 = $(SRCS)
filter_perl_SOURCES	+= filter_perl.c

CFLAGS  +=	${PERL_CPPFLAGS}
LDFLAGS +=	${PERL_LDFLAGS}
