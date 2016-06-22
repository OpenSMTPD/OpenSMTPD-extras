include $(top_srcdir)/mk/paths.mk
include $(top_srcdir)/mk/filter.mk

pkglibexec_PROGRAMS	 = filter-dnsbl

filter_dnsbl_SOURCES	 = $(SRCS)
filter_dnsbl_SOURCES	+= filter_dnsbl.c

man_MANS		 = filter-dnsbl.8

if !NO_LIBASR
LDADD	 += -lasr
endif
