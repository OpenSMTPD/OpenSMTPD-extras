include $(top_srcdir)/mk/paths.mk
include $(top_srcdir)/mk/filter.mk
include $(top_srcdir)/mk/experimental.mk

pkglibexec_PROGRAMS	 = filter-regex

filter_regex_SOURCES	 = $(SRCS)
filter_regex_SOURCES	+= filter_regex.c

man_MANS		= filter-regex.8 filter-regex.conf.5

filter-regex.8: filter-regex.8.in
	$(SED) -e 's|[@]SYSCONFDIR@|$(sysconfdir)|g' < filter-regex.8.in > "$@"
filter-regex.conf.5: filter-regex.conf.5.in
	$(SED) -e 's|[@]SYSCONFDIR@|$(sysconfdir)|g' < filter-regex.conf.5.in > "$@"

clean-local:
	rm -f filter-regex.8 filter-regex.conf.5
