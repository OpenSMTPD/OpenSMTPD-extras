include $(top_srcdir)/mk/wip.mk
include $(top_srcdir)/mk/filter.mk

pkglibexec_PROGRAMS	 = filter-monkey

filter_monkey_SOURCES	 = $(SRCS)
filter_monkey_SOURCES	+= filter_monkey.c
filter_monkey_SOURCES	+= $(top_srcdir)/api/dict.c

man_MANS		 = filter-monkey.8
