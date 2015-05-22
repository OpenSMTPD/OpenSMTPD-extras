include $(top_srcdir)/mk/wip.mk
include $(top_srcdir)/mk/filter.mk

pkglibexec_PROGRAMS	 = filter-dnsbl

filter_dnsbl_SOURCES	 = $(SRCS)
filter_dnsbl_SOURCES	+= $(filters_srcdir)/filter-dnsbl/filter_dnsbl.c

filter_dnsbl_LDADD	 = $(LIBCOMPAT) -lasr
