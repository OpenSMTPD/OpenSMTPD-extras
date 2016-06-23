AM_CPPFLAGS	 = -I$(api_srcdir)
AM_CPPFLAGS	+= -I$(compat_srcdir)
AM_CPPFLAGS	+= -I$(asr_srcdir)
AM_CPPFLAGS	+= $(PATHS)

SRCS	=  $(api_srcdir)/filter_api.c
SRCS	+= $(api_srcdir)/mproc.c
SRCS	+= $(api_srcdir)/log.c
SRCS	+= $(api_srcdir)/tree.c
SRCS	+= $(api_srcdir)/dict.c
SRCS	+= $(api_srcdir)/util.c
SRCS	+= $(api_srcdir)/iobuf.c
SRCS	+= $(api_srcdir)/ioev.c
SRCS	+= $(api_srcdir)/rfc2822.c

LIBCOMPAT	= $(top_builddir)/openbsd-compat/libopenbsd-compat.a
LDADD		= $(LIBCOMPAT)
