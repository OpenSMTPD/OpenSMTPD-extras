noinst_LIBRARIES = libopenbsd-compat.a

libopenbsd_compat_a_SOURCES = \
		arc4random.c base64.c bsd-closefrom.c bsd-misc.c		\
		event_asr_run.c imsg.c					\
		imsg-buffer.c mktemp.c strlcat.c strlcpy.c strtonum.c strsep.c

EXTRA_DIST =	asr.h base64.h bsd-misc.h chacha_private.h defines.h		\
		imsg.h includes.h openbsd-compat.h sys/queue.h sys/tree.h

AM_CPPFLAGS =	-I$(top_srcdir)/smtpd -I$(top_srcdir)/openbsd-compat \
		-I${top_srcdir}/api
