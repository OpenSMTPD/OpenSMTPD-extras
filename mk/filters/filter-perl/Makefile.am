include $(top_srcdir)/mk/pathnames
include $(top_srcdir)/mk/filter.mk

pkglibexec_PROGRAMS	 = filter-perl

filter_perl_SOURCES	 = $(SRCS)
filter_perl_SOURCES	+= $(filters_srcdir)/filter-perl/filter_perl.c

AM_CFLAGS= `perl -MExtUtils::Embed -e ccopts`
AM_LDFLAGS= `perl -MExtUtils::Embed -e ldopts`

