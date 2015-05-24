AM_CPPFLAGS	 = -I$(api_srcdir)
AM_CPPFLAGS	+= -I$(compat_srcdir)
AM_CPPFLAGS	+= -I$(asr_srcdir)

SRCS	=  $(api_srcdir)/filter_api.c
SRCS	+= $(api_srcdir)/mproc.c
SRCS	+= $(api_srcdir)/log.c
SRCS	+= $(api_srcdir)/tree.c
SRCS	+= $(api_srcdir)/util.c
SRCS	+= $(api_srcdir)/iobuf.c
SRCS	+= $(api_srcdir)/ioev.c

LIBCOMPAT	= $(top_builddir)/openbsd-compat/libopenbsd-compat.a
LDADD		= $(LIBCOMPAT)

CFLAGS=			-DNO_IO -DBUILD_FILTER

