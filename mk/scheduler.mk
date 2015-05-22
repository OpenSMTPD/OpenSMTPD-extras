AM_CPPFLAGS	 = -I$(api_srcdir)
AM_CPPFLAGS	+= -I$(compat_srcdir)

LIBCOMPAT	= $(top_builddir)/openbsd-compat/libopenbsd-compat.a
LDADD		= $(LIBCOMPAT)

SRCS	 = $(api_srcdir)/log.c
SRCS	+= $(api_srcdir)/scheduler_api.c
SRCS	+= $(api_srcdir)/tree.c
