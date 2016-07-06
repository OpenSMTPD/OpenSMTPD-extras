include $(top_srcdir)/mk/paths.mk
include $(top_srcdir)/mk/filter.mk
include $(top_srcdir)/mk/experimental.mk

pkglibexec_PROGRAMS	 = filter-rspamd

filter_rspamd_SOURCES	 = $(SRCS)
filter_rspamd_SOURCES	+= filter_rspamd.c
filter_rspamd_SOURCES	+= rspamd.c
filter_rspamd_SOURCES	+= json.c
filter_rspamd_SOURCES	+= fixme.c

LDFLAGS	+= -lm
