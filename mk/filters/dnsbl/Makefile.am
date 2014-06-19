include $(top_srcdir)/mk/pathnames
include $(top_srcdir)/mk/filter.mk

pkglibexec_PROGRAMS	 = filter-dnsbl

filter_dnsbl_SOURCES	 = $(SRCS)
filter_dnsbl_SOURCES	+= $(filters_srcdir)/filter-dnsbl/filter_dnsbl.c

LIBCOMPAT		 = $(top_builddir)/openbsd-compat/libopenbsd-compat.a

filter_dnsbl_LDADD	 = $(LIBCOMPAT) -lasr 
