/*
 * Copyright (c) 2014 Gilles Chehade <gilles@poolp.org>
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

#include <err.h>
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

static PyObject	*py_message_create;
static PyObject	*py_message_commit;
static PyObject	*py_message_delete;
static PyObject	*py_message_fd_r;
static PyObject	*py_message_corrupt;
static PyObject	*py_message_uncorrupt;

static PyObject	*py_envelope_create;
static PyObject	*py_envelope_delete;
static PyObject	*py_envelope_update;
static PyObject	*py_envelope_load;
static PyObject	*py_envelope_walk;
static PyObject	*py_message_walk;

static void
check_err(const char *name)
{
	if (PyErr_Occurred()) {
		PyErr_Print();
		fatalx("fatal: queue-python: error in %s handler", name);
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
		fatalx("fatal: queue-python: exception");
	}

	return ret;
}

static int
get_int(PyObject *o)
{
	if (PyLong_Check(o))
		return PyLong_AsLong(o);
	if (PyInt_Check(o))
		return PyInt_AsLong(o);

	PyErr_SetString(PyExc_TypeError, "int type expected");
	return 0;
}

static size_t
get_uint32_t(PyObject *o)
{
        if (PyLong_Check(o))
                return PyLong_AsUnsignedLong(o);
        if (PyInt_Check(o))
                return PyInt_AsUnsignedLongMask(o);

        PyErr_SetString(PyExc_TypeError, "int type expected");
        return 0;
}

static size_t
get_uint64_t(PyObject *o)
{
        if (PyLong_Check(o))
                return PyLong_AsUnsignedLongLong(o);
        if (PyInt_Check(o))
                return PyInt_AsUnsignedLongLongMask(o);

        PyErr_SetString(PyExc_TypeError, "int type expected");
        return 0;
}

static int
queue_python_message_create(uint32_t *msgid)
{
	PyObject       *py_ret;

	py_ret = dispatch(py_message_create, Py_BuildValue("()"));

	*msgid = get_uint32_t(py_ret);
	Py_DECREF(py_ret);

	check_err("message_create");
	return *msgid ? 1 : 0;
}

static int
queue_python_message_commit(uint32_t msgid, const char *path)
{
	PyObject       *py_ret;
	int		ret;

	py_ret = dispatch(py_message_commit, Py_BuildValue("ks",
		(unsigned long)msgid, path));

	ret = get_int(py_ret);
	Py_DECREF(py_ret);

	check_err("message_commit");
	return ret ? 1 : 0;
}

static int
queue_python_message_delete(uint32_t msgid)
{
	PyObject       *py_ret;
	int		ret;

	py_ret = dispatch(py_message_delete, Py_BuildValue("(k)",
		(unsigned long)msgid));

	ret = get_int(py_ret);
	Py_DECREF(py_ret);

	check_err("message_delete");
	return ret ? 1 : 0;
}

static int
queue_python_message_fd_r(uint32_t msgid)
{
	PyObject       *py_ret;
	int		ret;

	py_ret = dispatch(py_message_fd_r, Py_BuildValue("(k)",
		(unsigned long)msgid));

	ret = get_int(py_ret);
	Py_DECREF(py_ret);

	check_err("message_fd_r");
	return ret;
}

static int
queue_python_message_corrupt(uint32_t msgid)
{
	PyObject       *py_ret;
	int		ret;

	py_ret = dispatch(py_message_corrupt, Py_BuildValue("(k)",
		(unsigned long)msgid));

	ret = get_int(py_ret);
	Py_DECREF(py_ret);

	check_err("message_corrupt");
	return ret;
}

static int
queue_python_message_uncorrupt(uint32_t msgid)
{
	PyObject       *py_ret;
	int		ret;

	py_ret = dispatch(py_message_uncorrupt, Py_BuildValue("(k)",
		(unsigned long)msgid));

	ret = get_int(py_ret);
	Py_DECREF(py_ret);

	check_err("message_uncorrupt");
	return ret;
}

static int
queue_python_envelope_create(uint32_t msgid, const char *buf, size_t len,
    uint64_t *evpid)
{
	PyObject       *py_ret;

	py_ret = dispatch(py_envelope_create, Py_BuildValue("ks#",
		(unsigned long)msgid, (const char *)buf, (int)len));
	*evpid = get_uint64_t(py_ret);
	Py_DECREF(py_ret);

	check_err("envelope_create");
	return *evpid ? 1 : 0;
}

static int
queue_python_envelope_delete(uint64_t evpid)
{
	PyObject       *py_ret;
	int		ret;

	py_ret = dispatch(py_envelope_delete, Py_BuildValue("(K)",
		(unsigned long)evpid));

	ret = get_int(py_ret);
	Py_DECREF(py_ret);

	check_err("envelope_delete");
	return ret ? 1 : 0;
}

static int
queue_python_envelope_update(uint64_t evpid, const char *buf, size_t len)
{
	PyObject       *py_ret;
	int		ret;

	py_ret = dispatch(py_envelope_update, Py_BuildValue("Ks#",
		(unsigned long long)evpid, (const char *)buf, (int)len));
	ret = get_int(py_ret);
	Py_DECREF(py_ret);

	check_err("envelope_create");
	return ret ? 1 : 0;
}

static int
queue_python_envelope_load(uint64_t evpid, char *buf, size_t len)
{
	PyObject       *py_ret;
	Py_buffer	view;
	int		ret;

	py_ret = dispatch(py_envelope_load, Py_BuildValue("K", (unsigned long long)evpid));
	ret = PyObject_GetBuffer(py_ret, &view, PyBUF_SIMPLE);
	Py_DECREF(py_ret);
	if (ret == -1)
		return 0;
	if ((size_t)view.len >= len) {
		PyBuffer_Release(&view);
		return 0;
	}

	memset(buf, 0, len);
	memcpy(buf, view.buf, view.len);
	ret = view.len;
	PyBuffer_Release(&view);
	check_err("envelope_load");
	return ret;
}

static int
queue_python_envelope_walk(uint64_t *evpid, char *buf, size_t len)
{
	static uint64_t	curevpid = 0;
	PyObject       *py_ret;
	Py_buffer	py_view;
	int		ret;

	py_ret = dispatch(py_envelope_walk, Py_BuildValue("(K)",
		(unsigned long)curevpid));
	if (py_ret == Py_None)
		return -1;

	if (!PyTuple_Check(py_ret) || PyTuple_Size(py_ret) != 2) {
		PyErr_SetString(PyExc_TypeError, "2-elements tuple expected");
		ret = -1;
	}
	else {
		curevpid = *evpid = get_uint64_t(PyTuple_GetItem(py_ret, 0));
		ret = PyObject_GetBuffer(PyTuple_GetItem(py_ret, 1), &py_view, PyBUF_SIMPLE);
	}
	Py_DECREF(py_ret);

	if (ret == -1)
		return 0;
	if ((size_t)py_view.len >= len) {
		PyBuffer_Release(&py_view);
		return 0;
	}

	memset(buf, 0, len);
	memcpy(buf, py_view.buf, py_view.len);
	ret = py_view.len;
	PyBuffer_Release(&py_view);
	check_err("envelope_walk");
	return ret;
}

static int
queue_python_message_walk(uint64_t *evpid, char *buf, size_t len,
    uint32_t msgid, int *done, void **data)
{
	static uint64_t	curevpid = 0;
	PyObject       *py_ret;
	Py_buffer	py_view;
	int		ret;

	py_ret = dispatch(py_envelope_walk, Py_BuildValue("(K)",
		(unsigned long)curevpid));
	if (py_ret == Py_None)
		return -1;

	if (!PyTuple_Check(py_ret) || PyTuple_Size(py_ret) != 2) {
		PyErr_SetString(PyExc_TypeError, "2-elements tuple expected");
		ret = -1;
	}
	else {
		curevpid = *evpid = get_uint64_t(PyTuple_GetItem(py_ret, 0));
		ret = PyObject_GetBuffer(PyTuple_GetItem(py_ret, 1), &py_view, PyBUF_SIMPLE);
	}
	Py_DECREF(py_ret);

	if (ret == -1)
		return 0;
	if ((size_t)py_view.len >= len) {
		PyBuffer_Release(&py_view);
		return 0;
	}

	memset(buf, 0, len);
	memcpy(buf, py_view.buf, py_view.len);
	ret = py_view.len;
	PyBuffer_Release(&py_view);
	check_err("message_walk");
	return ret;
}

static int
queue_python_init(int server)
{
	queue_api_on_message_create(queue_python_message_create);
	queue_api_on_message_commit(queue_python_message_commit);
	queue_api_on_message_delete(queue_python_message_delete);
	queue_api_on_message_fd_r(queue_python_message_fd_r);
	queue_api_on_message_corrupt(queue_python_message_corrupt);
	queue_api_on_message_uncorrupt(queue_python_message_uncorrupt);
	queue_api_on_envelope_create(queue_python_envelope_create);
	queue_api_on_envelope_delete(queue_python_envelope_delete);
	queue_api_on_envelope_update(queue_python_envelope_update);
	queue_api_on_envelope_load(queue_python_envelope_load);
	queue_api_on_envelope_walk(queue_python_envelope_walk);
	queue_api_on_message_walk(queue_python_message_walk);

	return 1;
}

static PyMethodDef py_methods[] = {
	{ NULL, NULL, 0, NULL }
};

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

	if (oz >= (off_t)SSIZE_MAX)
		errx(1, "too big");

	sz = oz;

	buf = xmalloc(sz + 1, "loadfile");

	if (fread(buf, 1, sz, f) != sz)
		err(1, "fread");

	buf[sz] = '\0';

	fclose(f);

	return buf;
}

int
main(int argc, char **argv)
{
	int		ch;
	char	       *path;
	char	       *buf;
	PyObject       *self, *code, *module;

	log_init(1);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			log_warnx("warn: backend-queue-python: bad option");
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
	self = Py_InitModule("queue", py_methods);

	buf = loadfile(path);
	code = Py_CompileString(buf, path, Py_file_input);
	free(buf);

	if (code == NULL) {
		PyErr_Print();
		log_warnx("warn: queue-python: failed to compile %s", path);
		return 1;
	}

	module = PyImport_ExecCodeModuleEx("queue_python", code, path);
	if (module == NULL) {
		PyErr_Print();
		log_warnx("warn: queue-python: failed to install module %s", path);
		return 1;
	}

	log_debug("debug: queue-python: starting...");

	if ((py_message_create = PyObject_GetAttrString(module, "message_create")) == NULL)
		goto nosuchmethod;
	if ((py_message_commit = PyObject_GetAttrString(module, "message_commit")) == NULL)
		goto nosuchmethod;
	if ((py_message_delete = PyObject_GetAttrString(module, "message_delete")) == NULL)
		goto nosuchmethod;
	if ((py_message_fd_r = PyObject_GetAttrString(module, "message_fd_r")) == NULL)
		goto nosuchmethod;
	if ((py_message_corrupt = PyObject_GetAttrString(module, "message_corrupt")) == NULL)
		goto nosuchmethod;
	if ((py_message_uncorrupt = PyObject_GetAttrString(module, "message_uncorrupt")) == NULL)
		goto nosuchmethod;
	if ((py_envelope_create = PyObject_GetAttrString(module, "envelope_create")) == NULL)
		goto nosuchmethod;
	if ((py_envelope_delete = PyObject_GetAttrString(module, "envelope_delete")) == NULL)
		goto nosuchmethod;
	if ((py_envelope_update = PyObject_GetAttrString(module, "envelope_update")) == NULL)
		goto nosuchmethod;
	if ((py_envelope_load = PyObject_GetAttrString(module, "envelope_load")) == NULL)
		goto nosuchmethod;
	if ((py_envelope_walk = PyObject_GetAttrString(module, "envelope_walk")) == NULL)
		goto nosuchmethod;
	if ((py_message_walk = PyObject_GetAttrString(module, "message_walk")) == NULL)
		goto nosuchmethod;

	queue_python_init(1);

	queue_api_no_chroot();
	queue_api_dispatch();

	return 0;

nosuchmethod:
	PyErr_Print();
	return 1;
}
