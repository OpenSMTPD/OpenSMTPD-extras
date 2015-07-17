api_srcdir		= $(top_srcdir)/api
asr_srcdir		= $(top_srcdir)/contrib/lib/libc/asr
compat_srcdir		= $(top_srcdir)/openbsd-compat
regress_srcdir		= $(top_srcdir)/regress/bin

filters_srcdir		= $(top_srcdir)/extras/stable/filters
queues_srcdir		= $(top_srcdir)/extras/stable/queues
schedulers_srcdir	= $(top_srcdir)/extras/stable/schedulers
tables_srcdir		= $(top_srcdir)/extras/stable/tables

PATHS=		-DSMTPD_CONFDIR=\"$(sysconfdir)\"			\
		-DPATH_CHROOT=\"$(PRIVSEP_PATH)\"			\
		-DPATH_LIBEXEC=\"$(pkglibexecdir)\"
