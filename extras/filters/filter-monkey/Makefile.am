include $(top_srcdir)/mk/paths.mk
include $(top_srcdir)/mk/filter.mk

pkglibexec_PROGRAMS	 = filter-monkey

filter_monkey_SOURCES	 = $(SRCS)
filter_monkey_SOURCES	+= filter_monkey.c

man_MANS		 = filter-monkey.8 filter-monkey.conf.5

filter-monkey.8: filter-monkey.8.in
	$(SED) -e 's|[@]SYSCONFDIR@|$(sysconfdir)|g' < filter-monkey.8.in > "$@"
filter-monkey.conf.5: filter-monkey.conf.5.in
	$(SED) -e 's|[@]SYSCONFDIR@|$(sysconfdir)|g' < filter-monkey.conf.5.in > "$@"

clean-local:
	rm -f filter-monkey.8 filter-monkey.conf.5
