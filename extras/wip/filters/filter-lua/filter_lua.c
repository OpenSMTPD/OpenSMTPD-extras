/*
 * Copyright (c) 2013 Eric Faurot <eric@openbsd.org>
 * Copyright (c) 2014 Emmanuel Vadot <manu@bocal.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM == 501
#define luaL_Reg luaL_reg
void luaL_setfuncs (lua_State *L, const luaL_Reg *l, int nup) {
  luaL_checkstack(L, nup+1, "too many upvalues");
  for (; l->name != NULL; l++) {  /* fill the table with given functions */
    int i;
    lua_pushstring(L, l->name);
    for (i = 0; i < nup; i++)  /* copy upvalues to the top */
      lua_pushvalue(L, -(nup + 1));
    lua_pushcclosure(L, l->func, nup);  /* closure with those upvalues */
    lua_settable(L, -(nup + 3)); /* table must be below the upvalues, the name and the closure */
  }
  lua_pop(L, nup);  /* remove upvalues */
}
#define luaL_newlib(L, l) \
  (lua_newtable((L)),luaL_setfuncs((L), (l), 0))
#endif

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

#define ID_STR_SZ 20

lua_State *L;

static int
l_filter_accept(lua_State *L)
{
	uint64_t	 id;
	const char	*s_hex_id;

	if (lua_gettop(L) != 1)
		return 0;

	s_hex_id = luaL_checklstring(L, 1, NULL);
	id = strtoumax(s_hex_id, NULL, 16);
	filter_api_accept(id);
	return 0;
}

static int
l_filter_reject(lua_State *L)
{
	uint64_t	id;
	const char	*s_hex_id;
	uint32_t	action;

	if (lua_gettop(L) != 2)
		return 0;

	s_hex_id = luaL_checklstring(L, 1, NULL);
	id = strtoumax(s_hex_id, NULL, 16);
	action = luaL_checkinteger(L, 2);
	switch (action) {
	case FILTER_FAIL:
	case FILTER_CLOSE:
		filter_api_reject(id, action);
		break;
	}

	return 0;
}

static int
l_filter_reject_code(lua_State *L)
{
	uint64_t	id;
	const char	*s_hex_id;
	uint32_t	action;
	uint32_t	code;
	const char	*line;

	if (lua_gettop(L) != 4)
		return 0;

	s_hex_id = luaL_checklstring(L, 1, NULL);
	id = strtoumax(s_hex_id, NULL, 16);
	action = luaL_checkinteger(L, 2);
	code = luaL_checkinteger(L, 3);
	line = luaL_checklstring(L, 4, NULL);

	switch (action) {
	case FILTER_FAIL:
	case FILTER_CLOSE:
		filter_api_reject_code(id, action, code, line);
		break;
	}

	return 0;
}

static int
l_filter_writeln(lua_State *L)
{
	uint64_t	id;
	const char	*s_hex_id;
	const char	*line;

	if (lua_gettop(L) != 2)
		return 0;

	s_hex_id = luaL_checklstring(L, 1, NULL);
	id = strtoumax(s_hex_id, NULL, 16);
	line = luaL_checklstring(L, 2, NULL);

	filter_api_writeln(id, line);

	return 0;
}

static const luaL_Reg l_filter [] = {
	{"accept", l_filter_accept},
	{"reject", l_filter_reject},
	{"reject_code", l_filter_reject_code},
	{"writeln", l_filter_writeln},
	{NULL, NULL}
};

static int
on_connect(uint64_t id, struct filter_connect *conn)
{
	char	s_id[ID_STR_SZ];

	(void)snprintf(s_id, sizeof(s_id), "%016"PRIx64"", id);

	lua_getglobal(L, "on_connect");
	lua_pushstring(L, s_id);
	lua_pushstring(L,
	    filter_api_sockaddr_to_text((struct sockaddr *)&conn->local));
	lua_pushstring(L,
	    filter_api_sockaddr_to_text((struct sockaddr *)&conn->remote));
	lua_pushstring(L, conn->hostname);

	if (lua_pcall(L, 4, 0, 0)) {
		log_warnx("warn: on_connect: %s",
		    lua_tostring(L, -1));
		exit(1);
	}

	return 1;
}

static int
on_helo(uint64_t id, const char *helo)
{
	char	s_id[ID_STR_SZ];

	(void)snprintf(s_id, sizeof(s_id), "%016"PRIx64"", id);
	lua_getglobal(L, "on_helo");
	lua_pushstring(L, s_id);
	lua_pushstring(L, helo);

	if (lua_pcall(L, 2, 0, 0)) {
		log_warnx("warn: on_helo: %s",
		    lua_tostring(L, -1));
		exit(1);
	}

	return 1;
}

static int
on_mail(uint64_t id, struct mailaddr *mail)
{
	char	s_id[ID_STR_SZ];

	(void)snprintf(s_id, sizeof(s_id), "%016"PRIx64"", id);
	lua_getglobal(L, "on_mail");
	lua_pushstring(L, s_id);
	lua_pushstring(L, filter_api_mailaddr_to_text(mail));

	if (lua_pcall(L, 2, 0, 0)) {
		log_warnx("warn: on_mail: %s",
		    lua_tostring(L, -1));
		exit(1);
	}

	return 1;
}

static int
on_rcpt(uint64_t id, struct mailaddr *rcpt)
{
	char	s_id[ID_STR_SZ];

	(void)snprintf(s_id, sizeof(s_id), "%016"PRIx64"", id);
	lua_getglobal(L, "on_rcpt");
	lua_pushstring(L, s_id);
	lua_pushstring(L, filter_api_mailaddr_to_text(rcpt));

	if (lua_pcall(L, 2, 0, 0)) {
		log_warnx("warn: on_rcpt: %s",
		    lua_tostring(L, -1));
		exit(1);
	}

	return 1;
}

static int
on_data(uint64_t id)
{
	char	s_id[ID_STR_SZ];

	(void)snprintf(s_id, sizeof(s_id), "%016"PRIx64"", id);
	lua_getglobal(L, "on_data");
	lua_pushstring(L, s_id);

	if (lua_pcall(L, 1, 0, 0)) {
		log_warnx("warn: on_data: %s",
		    lua_tostring(L, -1));
		exit(1);
	}

	return 1;
}

static void
on_dataline(uint64_t id, const char *line)
{
	char	s_id[ID_STR_SZ];

	(void)snprintf(s_id, sizeof(s_id), "%016"PRIx64"", id);
	lua_getglobal(L, "on_dataline");
	lua_pushstring(L, s_id);
	lua_pushstring(L, line);

	if (lua_pcall(L, 2, 0, 0)) {
		log_warnx("warn: on_dataline: %s",
		    lua_tostring(L, -1));
		exit(1);
	}
}

static int
on_eom(uint64_t id, size_t size)
{
	char	s_id[ID_STR_SZ];

	(void)snprintf(s_id, sizeof(s_id), "%016"PRIx64"", id);
	lua_getglobal(L, "on_eom");
	lua_pushstring(L, s_id);

	if (lua_pcall(L, 1, 0, 0)) {
		log_warnx("warn: on_eom: %s", lua_tostring(L, -1));
		exit(1);
	}

	return 1;
}

static void
on_commit(uint64_t id)
{
	char	s_id[ID_STR_SZ];

	(void)snprintf(s_id, sizeof(s_id), "%016"PRIx64"", id);
	lua_getglobal(L, "on_commit");
	lua_pushstring(L, s_id);

	if (lua_pcall(L, 1, 0, 0)) {
		log_warnx("warn: on_commit: %s",
		    lua_tostring(L, -1));
		exit(1);
	}
}

static void
on_rollback(uint64_t id)
{
	char	s_id[ID_STR_SZ];

	(void)snprintf(s_id, sizeof(s_id), "%016"PRIx64"", id);
	lua_getglobal(L, "on_rollback");
	lua_pushstring(L, s_id);

	if (lua_pcall(L, 1, 0, 0)) {
		log_warnx("warn: on_rollback: %s",
		    lua_tostring(L, -1));
		exit(1);
	}
}

static void
on_disconnect(uint64_t id)
{
	char	s_id[ID_STR_SZ];

	(void)snprintf(s_id, sizeof(s_id), "%016"PRIx64"", id);
	lua_getglobal(L, "on_disconnect");
	lua_pushstring(L, s_id);

	if (lua_pcall(L, 1, 0, 0)) {
		log_warnx("warn: on_disconnect: %s",
		    lua_tostring(L, -1));
		exit(1);
	}
}

int
main(int argc, char **argv)
{
	int ch, d = 0, v = 0;
	char *path;

	log_init(1);

	while ((ch = getopt(argc, argv, "dv")) != -1) {
		switch (ch) {
		case 'd':
			d = 1;
			break;
		case 'v':
			v |= TRACE_DEBUG;
			break;
		default:
			log_warnx("warn: bad option");
			return 1;
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		errx(1, "missing path");
	path = argv[0];

	log_init(d);
	log_verbose(v);

	log_debug("debug: starting...");

	if ((L = luaL_newstate()) == NULL) {
		log_warnx("warn: can't create lua state");
		return 1;
	}
	luaL_openlibs(L);
	luaL_newlib(L, l_filter);
#if 0
	luaL_newmetatable(L, "filter");
	lua_setmetatable(L, -2);

	lua_pushnumber(L, FILTER_OK);
	lua_setfield(L, -2, "FILTER_OK");
	lua_pushnumber(L, FILTER_FAIL);
	lua_setfield(L, -2, "FILTER_FAIL");
	lua_pushnumber(L, FILTER_CLOSE);
	lua_setfield(L, -2, "FILTER_CLOSE");
#endif
	lua_setglobal(L, "filter");

	if (luaL_dofile(L, path) != 0) {
		log_warnx("warn: error loading script: %s", path);
		return 1;
	}

	lua_getglobal(L, "on_connect");
	if (lua_isfunction(L, -1)) {
		log_debug("debug: on_connect is present");
		filter_api_on_connect(on_connect);
	}

	lua_getglobal(L, "on_helo");
	if (lua_isfunction(L, 1)) {
		log_debug("debug: on_helo is present");
		filter_api_on_helo(on_helo);
	}

	lua_getglobal(L, "on_mail");
	if (lua_isfunction(L, 1)) {
		log_debug("debug: on_mail is present");
		filter_api_on_mail(on_mail);
	}

	lua_getglobal(L, "on_rcpt");
	if (lua_isfunction(L, 1)) {
		log_debug("debug: on_rcpt is present");
		filter_api_on_rcpt(on_rcpt);
	}

	lua_getglobal(L, "on_data");
	if (lua_isfunction(L, 1)) {
		log_debug("debug: on_data is present");
		filter_api_on_data(on_data);
	}

	lua_getglobal(L, "on_dataline");
	if (lua_isfunction(L, 1)) {
		log_debug("debug: on_dataline is present");
		filter_api_on_dataline(on_dataline);
	}

	lua_getglobal(L, "on_eom");
	if (lua_isfunction(L, 1)) {
		log_debug("debug: on_eom is present");
		filter_api_on_eom(on_eom);
	}

	lua_getglobal(L, "on_commit");
	if (lua_isfunction(L, 1)) {
		log_debug("debug: on_commit is present");
		filter_api_on_commit(on_commit);
	}

	lua_getglobal(L, "on_rollback");
	if (lua_isfunction(L, 1)) {
		log_debug("debug: on_rollback is present");
		filter_api_on_rollback(on_rollback);
	}

	lua_getglobal(L, "on_disconnect");
	if (lua_isfunction(L, 1)) {
		log_debug("debug: on_disconnect is present");
		filter_api_on_disconnect(on_disconnect);
	}

	filter_api_no_chroot();
	filter_api_loop();

	log_debug("debug: exiting");

	return 0;
}
