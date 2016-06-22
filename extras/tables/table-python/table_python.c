/*
 * Copyright (c) 2014 Eric Faurot <eric@openbsd.org>
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

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

/* _GNU_SOURCE is not properly protected in Python.h ... */
#undef _GNU_SOURCE
#include <Python.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

static int table_python_update(void);
static int table_python_check(int, struct dict *, const char *);
static int table_python_lookup(int, struct dict *, const char *, char *, size_t);
static int table_python_fetch(int, struct dict *, char *, size_t);

static PyObject *py_on_update;
static PyObject *py_on_lookup;
static PyObject *py_on_check;
static PyObject *py_on_fetch;

static void
check_err(const char *name)
{
	if (PyErr_Occurred()) {
		PyErr_Print();
		fatalx("warn: table-python: error in %s handler", name);
	}
}

static PyObject *
dispatch(PyObject *handler, PyObject *args)
{
	PyObject *ret;

	ret = PyObject_CallObject(handler, args);
	Py_DECREF(args);

	if (PyErr_Occurred()) {
		PyErr_Print();
		fatalx("warn: table-python: exception");
	}

	return ret;
}

static PyObject *
dict_to_py(struct dict *dict)
{
	PyObject	*o, *s;
	const char *key;
	char *value;
	void *iter;

	o = PyDict_New();

	iter = NULL;
	while (dict_iter(dict, &iter, &key, (void **)&value)) {
		s = PyString_FromString(value);
		if (s == NULL)
			goto fail;
		if (PyDict_SetItemString(o, key, s) == -1)
			goto fail;
	}

	return o;

    fail:
	if (o)
		Py_DECREF(o);
	if (s)
		Py_DECREF(s);

	return NULL;
}

static int
table_python_update(void)
{
	PyObject *ret;

	if (py_on_update == NULL)
		return 0;

	ret = dispatch(py_on_update, PyTuple_New(0));

	if (ret == NULL) {
		log_warnx("table-python: update failed");
		return -1;
	}

	Py_DECREF(ret);

	check_err("init");
	return 1;
}

static int
table_python_check(int service, struct dict *params, const char *key)
{
	PyObject *dict, *args, *ret;
	int r;

	if (py_on_check == NULL)
		return -1;

	dict = dict_to_py(params);
	if (dict == NULL)
		return -1;

	args = Py_BuildValue("iOs", service, dict, key);
	if (args ==  NULL) {
		Py_DECREF(dict);
		return -1;
	}

	ret = dispatch(py_on_check, args);
	if (ret == NULL)
		return -1;

	r = PyObject_IsTrue(ret);
	Py_DECREF(ret);

	return r;
}

static int
table_python_lookup(int service, struct dict *params, const char *key, char *buf, size_t sz)
{
	PyObject *dict, *args, *ret;
	char	 *s;
	int	  r;

	if (py_on_lookup == NULL)
		return -1;

	dict = dict_to_py(params);
	if (dict == NULL)
		return -1;

	args = Py_BuildValue("iOs", service, dict, key);
	if (args ==  NULL) {
		Py_DECREF(dict);
		return -1;
	}

	ret = dispatch(py_on_lookup, args);

	if (ret == NULL)
		return -1;

	if (ret == Py_None)
		r = 0;
	else if (PyString_CheckExact(ret)) {
		r = 1;
		s = PyString_AS_STRING(ret);
		if (strlcpy(buf, s, sz) >= sz) {
			log_warnx("table-python: lookup: result too long");
			r = -1;
		}
	} else {
		log_warnx("table-python: lookup: invalid object returned");
		r = -1;
	}

	Py_DECREF(ret);

	return r;
}

static int
table_python_fetch(int service, struct dict *params, char *buf, size_t sz)
{
	PyObject *dict, *args, *ret;
	char	 *s;
	int	  r;
	
	if (py_on_fetch == NULL)
		return -1;

	dict = dict_to_py(params);
	if (dict == NULL)
		return -1;

	args = Py_BuildValue("iO", service, dict);
	if (args ==  NULL) {
		Py_DECREF(dict);
		return -1;
	}

	ret = dispatch(py_on_fetch, args);

	if (ret == NULL)
		return -1;

	if (ret == Py_None)
		r = 0;
	else if (PyString_CheckExact(ret)) {
		r = 1;
		s = PyString_AS_STRING(ret);
		if (strlcpy(buf, s, sz) >= sz) {
			log_warnx("table-python: lookup: result too long");
			r = -1;
		}
	} else {
		log_warnx("table-python: lookup: invalid object returned");
		r = -1;
	}

	Py_DECREF(ret);

	return r;
}

static char *
loadfile(const char * path)
{
	FILE	*f;
	off_t	 oz;
	size_t	 sz;
	char	*buf;

	if ((f = fopen(path, "r")) == NULL)
		err(1, "fopen");

	if (fseek(f, 0, SEEK_END) == -1)
		err(1, "fseek");

	oz = ftello(f);

	if (fseek(f, 0, SEEK_SET) == -1)
		err(1, "fseek");

	if ((size_t)oz >= SIZE_MAX)
		errx(1, "too big");

	sz = oz;

	buf = xmalloc(sz + 1, "loadfile");

	if (fread(buf, 1, sz, f) != sz)
		err(1, "fread");

	buf[sz] = '\0';

	fclose(f);

	return buf;
}

static PyMethodDef py_methods[] = {
	{ NULL, NULL, 0, NULL }
};

int
main(int argc, char **argv)
{
	int		 ch;
	char		*path;
	char		*buf;
	PyObject	*self, *code, *module;

	log_init(-1);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			log_warnx("warn: table-python: bad option");
			return 1;
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		errx(1, "missing path");
	path = argv[0];

	Py_Initialize();
	self = Py_InitModule("table", py_methods);

	PyModule_AddIntConstant(self, "K_NONE", K_NONE);
	PyModule_AddIntConstant(self, "K_ALIAS", K_ALIAS);
	PyModule_AddIntConstant(self, "K_DOMAIN", K_DOMAIN);
	PyModule_AddIntConstant(self, "K_CREDENTIALS", K_CREDENTIALS);
	PyModule_AddIntConstant(self, "K_NETADDR", K_NETADDR);
	PyModule_AddIntConstant(self, "K_USERINFO", K_USERINFO);
	PyModule_AddIntConstant(self, "K_SOURCE", K_SOURCE);
	PyModule_AddIntConstant(self, "K_MAILADDR", K_MAILADDR);
	PyModule_AddIntConstant(self, "K_ADDRNAME", K_ADDRNAME);

	buf = loadfile(path);
	code = Py_CompileString(buf, path, Py_file_input);
	free(buf);

	if (code == NULL) {
		PyErr_Print();
		log_warnx("warn: table-python: failed to compile %s", path);
		return 1;
	}

	module = PyImport_ExecCodeModuleEx("mytable", code, path);

	if (module == NULL) {
		PyErr_Print();
		log_warnx("warn: table-python: failed to install module %s", path);
		return 1;
	}

	log_debug("debug: table-python: starting...");

	py_on_update = PyObject_GetAttrString(module, "table_update");
	py_on_check = PyObject_GetAttrString(module, "table_check");
	py_on_lookup = PyObject_GetAttrString(module, "table_lookup");
	py_on_fetch = PyObject_GetAttrString(module, "table_fetch");

	table_api_on_update(table_python_update);
	table_api_on_check(table_python_check);
	table_api_on_lookup(table_python_lookup);
	table_api_on_fetch(table_python_fetch);

	table_api_dispatch();

	log_debug("debug: table-python: exiting");
	Py_Finalize();

	return 1;
}
