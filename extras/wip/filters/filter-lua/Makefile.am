include $(top_srcdir)/mk/wip.mk
include $(top_srcdir)/mk/filter.mk

pkglibexec_PROGRAMS	 = filter-lua

filter_lua_SOURCES	 = $(SRCS)
filter_lua_SOURCES	+= $(filters_srcdir)/filter-lua/filter_lua.c

CFLAGS+=	-I /usr/local/include/lua-5.2
LDFLAGS+=	-L /usr/local/lib
LDADD+=		-llua5.2 -lm
