include $(top_srcdir)/mk/wip.mk
include $(top_srcdir)/mk/filter.mk

pkglibexec_PROGRAMS	 = filter-lua

filter_lua_SOURCES	 = $(SRCS)
filter_lua_SOURCES	+= $(filters_srcdir)/filter-lua/filter_lua.c

CFLAGS			+= ${LUA_CPPFLAGS}
LDFLAGS			+= ${LUA_LDFLAGS}
