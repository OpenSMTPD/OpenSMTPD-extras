include $(top_srcdir)/mk/wip.mk
include $(top_srcdir)/mk/filter.mk

pkglibexec_PROGRAMS	 = filter-perl

filter_perl_SOURCES	 = $(SRCS)
filter_perl_SOURCES	+= $(filters_srcdir)/filter-perl/filter_perl.c

CFLAGS  +=	${PERL_CPPFLAGS}
LDFLAGS +=	${PERL_LDFLAGS}
