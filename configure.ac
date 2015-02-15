# $Id: configure.ac,v 1.519 2013/03/22 01:49:15 dtucker Exp $
#
# Copyright (c) 1999-2004 Damien Miller
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

dnl AC_INIT([OpenSMTPD-portable],[4.9.0],[Charles Longeau <chl@openbsd.org>])
dnl AC_INIT([OpenSMTPD-portable], m4_esyscmd(date +%Y%m%d%H%M%S | sed -e 's/^\(.*\)$/5.2-\1/' | tr -d '\n'),[Charles Longeau <chl@openbsd.org>])
AC_INIT([opensmtpd], [portable], [bugs@opensmtpd.org])
AC_LANG([C])
AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_HEADER([config.h])
AC_PROG_CC
AC_CANONICAL_HOST
AC_C_BIGENDIAN

# Checks for programs.
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PATH_PROG([AR], [ar])
AC_PATH_PROG([CAT], [cat])
AC_PATH_PROG([ZCAT], [zcat])
AC_SUBST([ZCAT])
AC_PATH_PROG([SED], [sed])
AC_PATH_PROG([TEST_MINUS_S_SH], [bash])
AC_PATH_PROG([TEST_MINUS_S_SH], [ksh])
AC_PATH_PROG([TEST_MINUS_S_SH], [sh])
AC_PATH_PROG([SH], [sh])
AC_PATH_PROG([GROFF], [groff])
AC_PATH_PROG([NROFF], [nroff])
AC_PATH_PROG([MANDOC], [mandoc])
AC_PROG_YACC

AM_INIT_AUTOMAKE

LT_INIT

#here we should test for variables set by libtool detection
if test "x$with_pic" != "xno" ; then
	CFLAGS="$CFLAGS ${pic_flag}"
fi


#from here everything comes from portable openssh configure.ac script

#l50
dnl select manpage formatter
if test "x$MANDOC" != "x" ; then
	MANFMT="$MANDOC"
elif test "x$NROFF" != "x" ; then
	MANFMT="$NROFF -mandoc"
elif test "x$GROFF" != "x" ; then
	MANFMT="$GROFF -mandoc -Tascii"
else
	AC_MSG_WARN([no manpage formatted found])
	MANFMT="false"
fi
AC_SUBST([MANFMT])
#l61

#l78
if test -z "$AR" ; then
	AC_MSG_ERROR([*** 'ar' missing, please install or fix your \$PATH ***])
fi
#l80

#l101
if test -z "$LD" ; then
	LD=$CC
fi
AC_SUBST([LD])

AC_C_INLINE

AC_CHECK_DECL([LLONG_MAX], [have_llong_max=1], , [#include <limits.h>])
#l108

#l150 (without _FORTIFY_SOURCE=2)
if test "$GCC" = "yes" || test "$GCC" = "egcs"; then
	OSSH_CHECK_CFLAG_COMPILE([-Qunused-arguments])
	OSSH_CHECK_CFLAG_COMPILE([-Wunknown-warning-option])
	OSSH_CHECK_CFLAG_COMPILE([-Wall])
	OSSH_CHECK_CFLAG_COMPILE([-Wpointer-arith])
	OSSH_CHECK_CFLAG_COMPILE([-Wuninitialized])
	OSSH_CHECK_CFLAG_COMPILE([-Wsign-compare])
	OSSH_CHECK_CFLAG_COMPILE([-Wformat-security])
	OSSH_CHECK_CFLAG_COMPILE([-Wsizeof-pointer-memaccess])
	OSSH_CHECK_CFLAG_COMPILE([-Wpointer-sign], [-Wno-pointer-sign])
	OSSH_CHECK_CFLAG_COMPILE([-Wunused-result], [-Wno-unused-result])
	OSSH_CHECK_CFLAG_COMPILE([-fno-strict-aliasing])
#	OSSH_CHECK_CFLAG_COMPILE([-D_FORTIFY_SOURCE=2])
    if test "x$use_toolchain_hardening" = "x1"; then
	OSSH_CHECK_LDFLAG_LINK([-Wl,-z,relro])
	OSSH_CHECK_LDFLAG_LINK([-Wl,-z,now])
	OSSH_CHECK_LDFLAG_LINK([-Wl,-z,noexecstack])
	# NB. -ftrapv expects certain support functions to be present in
	# the compiler library (libgcc or similar) to detect integer operations
	# that can overflow. We must check that the result of enabling it
	# actually links. The test program compiled/linked includes a number
	# of integer operations that should exercise this.
	OSSH_CHECK_CFLAG_LINK([-ftrapv])
    fi
	AC_MSG_CHECKING([gcc version])
	GCC_VER=`$CC -v 2>&1 | $AWK '/gcc version /{print $3}'`
	case $GCC_VER in
		1.*) no_attrib_nonnull=1 ;;
		2.8* | 2.9*)
		     no_attrib_nonnull=1
		     ;;
		2.*) no_attrib_nonnull=1 ;;
		*) ;;
	esac
	AC_MSG_RESULT([$GCC_VER])

	AC_MSG_CHECKING([if $CC accepts -fno-builtin-memset])
	saved_CFLAGS="$CFLAGS"
	CFLAGS="$CFLAGS -fno-builtin-memset"
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[ #include <string.h> ]],
			[[ char b[10]; memset(b, 0, sizeof(b)); ]])],
		[ AC_MSG_RESULT([yes]) ],
		[ AC_MSG_RESULT([no])
		  CFLAGS="$saved_CFLAGS" ]
	)

	# -fstack-protector-all doesn't always work for some GCC versions
	# and/or platforms, so we test if we can.  If it's not supported
	# on a given platform gcc will emit a warning so we use -Werror.
	if test "x$use_stack_protector" = "x1"; then
	    for t in -fstack-protector-strong -fstack-protector-all \
		    -fstack-protector; do
		AC_MSG_CHECKING([if $CC supports $t])
		saved_CFLAGS="$CFLAGS"
		saved_LDFLAGS="$LDFLAGS"
		CFLAGS="$CFLAGS $t -Werror"
		LDFLAGS="$LDFLAGS $t -Werror"
		AC_LINK_IFELSE(
			[AC_LANG_PROGRAM([[ #include <stdio.h> ]],
			[[
	char x[256];
	snprintf(x, sizeof(x), "XXX");
			 ]])],
		    [ AC_MSG_RESULT([yes])
		      CFLAGS="$saved_CFLAGS $t"
		      LDFLAGS="$saved_LDFLAGS $t"
		      AC_MSG_CHECKING([if $t works])
		      AC_RUN_IFELSE(
			[AC_LANG_PROGRAM([[ #include <stdio.h> ]],
			[[
	char x[256];
	snprintf(x, sizeof(x), "XXX");
			]])],
			[ AC_MSG_RESULT([yes])
			  break ],
			[ AC_MSG_RESULT([no]) ],
			[ AC_MSG_WARN([cross compiling: cannot test])
			  break ]
		      )
		    ],
		    [ AC_MSG_RESULT([no]) ]
		)
		CFLAGS="$saved_CFLAGS"
		LDFLAGS="$saved_LDFLAGS"
	    done
	fi

	if test -z "$have_llong_max"; then
		# retry LLONG_MAX with -std=gnu99, needed on some Linuxes
		unset ac_cv_have_decl_LLONG_MAX
		saved_CFLAGS="$CFLAGS"
		CFLAGS="$CFLAGS -std=gnu99"
		AC_CHECK_DECL([LLONG_MAX],
		    [have_llong_max=1],
		    [CFLAGS="$saved_CFLAGS"],
		    [#include <limits.h>]
		)
	fi
fi

AC_MSG_CHECKING([if compiler allows __attribute__ on return types])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[
#include <stdlib.h>
__attribute__((__unused__)) static void foo(void){return;}]],
    [[ exit(0); ]])],
    [ AC_MSG_RESULT([yes]) ],
    [ AC_MSG_RESULT([no])
      AC_DEFINE(NO_ATTRIBUTE_ON_RETURN_TYPE, 1,
	 [compiler does not accept __attribute__ on return types]) ]
)

if test "x$no_attrib_nonnull" != "x1" ; then
	AC_DEFINE([HAVE_ATTRIBUTE__NONNULL__], [1], [Have attribute nonnull])
fi

AC_ARG_WITH([rpath],
	[  --without-rpath         Disable auto-added -R linker paths],
	[
		if test "x$withval" = "xno" ; then
			need_dash_r=""
		fi
		if test "x$withval" = "xyes" ; then
			need_dash_r=1
		fi
	]
)

# Allow user to specify flags
AC_ARG_WITH([cflags],
	[  --with-cflags           Specify additional flags to pass to compiler],
	[
		if test -n "$withval"  &&  test "x$withval" != "xno"  &&  \
		    test "x${withval}" != "xyes"; then
			CFLAGS="$CFLAGS $withval"
		fi
	]
)
AC_ARG_WITH([cppflags],
	[  --with-cppflags         Specify additional flags to pass to preprocessor] ,
	[
		if test -n "$withval"  &&  test "x$withval" != "xno"  &&  \
		    test "x${withval}" != "xyes"; then
			CPPFLAGS="$CPPFLAGS $withval"
		fi
	]
)
AC_ARG_WITH([ldflags],
	[  --with-ldflags          Specify additional flags to pass to linker],
	[
		if test -n "$withval"  &&  test "x$withval" != "xno"  &&  \
		    test "x${withval}" != "xyes"; then
			LDFLAGS="$LDFLAGS $withval"
		fi
	]
)
AC_ARG_WITH([libs],
	[  --with-libs             Specify additional libraries to link with],
	[
		if test -n "$withval"  &&  test "x$withval" != "xno"  &&  \
		    test "x${withval}" != "xyes"; then
			LIBS="$LIBS $withval"
		fi
	]
)
AC_ARG_WITH([Werror],
	[  --with-Werror           Build main code with -Werror],
	[
		if test -n "$withval"  &&  test "x$withval" != "xno"; then
			werror_flags="-Werror"
			if test "x${withval}" != "xyes"; then
				werror_flags="$withval"
			fi
		fi
	]
)
#l325

AC_CHECK_HEADERS([ \
	crypt.h \
	dirent.h \
	fcntl.h \
	getopt.h \
	limits.h \
	maillock.h \
	mach/mach_time.h \
	ndir.h \
	netdb.h \
	pam/pam_appl.h \
	paths.h \
	security/pam_appl.h \
	shadow.h \
	sys/dir.h \
	sys/file.h \
	sys/ndir.h \
	sys/pstat.h \
	sys/time.h \
	sys/un.h \
	time.h \
	ucred.h \
	util.h \
	utime.h \
	vis.h
])

#l432 (customized)
# Check for some target-specific stuff
	case "$host" in
*-*-aix*)
	check_for_aix_broken_getaddrinfo=1
	AC_DEFINE([BROKEN_REALPATH], [1], [Define if you have a broken realpath.])
	AC_DEFINE([SETEUID_BREAKS_SETUID], [1],
	    [Define if your platform breaks doing a seteuid before a setuid])
	AC_DEFINE([BROKEN_SETREUID], [1], [Define if your setreuid() is broken])
	AC_DEFINE([BROKEN_SETREGID], [1], [Define if your setregid() is broken])
	AC_DEFINE([SPT_TYPE], [SPT_REUSEARGV],
		[Define to a Set Process Title type if your system is
		supported by bsd-setproctitle.c])
	;;
*-*-darwin*)
	use_pie=auto
	AC_MSG_CHECKING([if we have working getaddrinfo])
	AC_RUN_IFELSE([AC_LANG_SOURCE([[ #include <mach-o/dyld.h>
main() { if (NSVersionOfRunTimeLibrary("System") >= (60 << 16))
		exit(0);
	else
		exit(1);
}
			]])],
	[AC_MSG_RESULT([working])],
	[AC_MSG_RESULT([buggy])
	AC_DEFINE([BROKEN_GETADDRINFO], [1],
		[getaddrinfo is broken (if present)])
	],
	[AC_MSG_RESULT([assume it is working])])
	AC_DEFINE([SETEUID_BREAKS_SETUID])
	AC_DEFINE([BROKEN_SETREUID])
	AC_DEFINE([BROKEN_SETREGID])
	AC_DEFINE([BROKEN_GLOB], [1], [OS X glob does not do what we expect])
	AC_DEFINE_UNQUOTED([BIND_8_COMPAT], [1],
		[Define if your resolver libs need this for getrrsetbyname])
	AC_DEFINE([SPT_TYPE], [SPT_REUSEARGV],
		[Define to a Set Process Title type if your system is
		supported by bsd-setproctitle.c])
	;;
*-*-dragonfly*)
	SMTPDLIBS="$SMTPDLIBS -lcrypt"
	;;
*-*-linux* | *-gnu* | *-k*bsd*-gnu* )
	use_pie=auto
	check_for_libcrypt_later=1
	AC_DEFINE([SPT_TYPE], [SPT_REUSEARGV])
	case `uname -r` in
	1.*|2.0.*)
		AC_DEFINE(BROKEN_CMSG_TYPE, 1,
			[Define if cmsg_type is not passed correctly])
		;;
	esac
	;;
*-*-netbsd*)
	check_for_libcrypt_before=1
	if test "x$withval" != "xno" ; then
		need_dash_r=1
	fi
	AC_DEFINE([BROKEN_STRNVIS], [1],
	    [NetBSD strnvis argument order is swapped compared to OpenBSD])
	;;
*-*-freebsd*)
	check_for_libcrypt_later=1
	AC_DEFINE([BROKEN_GLOB], [1], [FreeBSD glob does not do what we need])
	AC_DEFINE([BROKEN_STRNVIS], [1],
	    [FreeBSD strnvis argument order is swapped compared to OpenBSD])
	;;
*-*-openbsd*)
	use_pie=auto
	AC_DEFINE([HAVE_ATTRIBUTE__SENTINEL__], [1], [OpenBSD's gcc has sentinel])
	AC_DEFINE([HAVE_ATTRIBUTE__BOUNDED__], [1], [OpenBSD's gcc has bounded])
	echo "Please use -current or a native version at http://www.opensmtpd.org/archives/"
	;;
esac

AC_MSG_CHECKING([compiler and flags for sanity])
AC_RUN_IFELSE([AC_LANG_PROGRAM([[ #include <stdio.h> ]], [[ exit(0); ]])],
	[	AC_MSG_RESULT([yes]) ],
	[
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([*** compiler cannot create working executables, check config.log ***])
	],
	[	AC_MSG_WARN([cross compiling: not checking compiler sanity]) ]
)

dnl Checks for header files.
# Checks for libraries.
AC_CHECK_FUNC([setsockopt], , [AC_CHECK_LIB([socket], [setsockopt])])

dnl    Checks for libutil functions
AC_CHECK_HEADERS([bsd/libutil.h libutil.h])
AC_SEARCH_LIBS([fmt_scaled], [util bsd])
AC_SEARCH_LIBS([scan_scaled], [util bsd])
AC_CHECK_FUNCS([fmt_scaled scan_scaled])
#l1242


#l1525
AC_ARG_WITH([pie],
    [  --with-pie             Build Position Independent Executables if possible], [
	if test "x$withval" = "xno"; then
		use_pie=no
	fi
	if test "x$withval" = "xyes"; then
		use_pie=yes
	fi
    ]
)
if test "x$use_pie" = "x"; then
	use_pie=no
fi
if test "x$use_toolchain_hardening" != "x1" && test "x$use_pie" = "xauto"; then
	# Turn off automatic PIE when toolchain hardening is off.
	use_pie=no
fi
if test "x$use_pie" = "xauto"; then
	# Automatic PIE requires gcc >= 4.x
	AC_MSG_CHECKING([for gcc >= 4.x])
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#if !defined(__GNUC__) || __GNUC__ < 4
#error gcc is too old
#endif
]])],
	[ AC_MSG_RESULT([yes]) ],
	[ AC_MSG_RESULT([no])
	  use_pie=no ]
)
fi
if test "x$use_pie" != "xno"; then
	SAVED_CFLAGS="$CFLAGS"
	SAVED_LDFLAGS="$LDFLAGS"
	OSSH_CHECK_CFLAG_COMPILE([-fPIE])
	OSSH_CHECK_LDFLAG_LINK([-pie])
	# We use both -fPIE and -pie or neither.
	AC_MSG_CHECKING([whether both -fPIE and -pie are supported])
	if echo "x $CFLAGS"  | grep ' -fPIE' >/dev/null 2>&1 && \
	   echo "x $LDFLAGS" | grep ' -pie'  >/dev/null 2>&1 ; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
		CFLAGS="$SAVED_CFLAGS"
		LDFLAGS="$SAVED_LDFLAGS"
	fi
fi
#l1570

#l1572 (customized)
dnl    Checks for library functions. Please keep in alphabetical order
AC_CHECK_FUNCS([ \
	arc4random \
	arc4random_buf \
	arc4random_stir \
	arc4random_uniform \
	asprintf \
	b64_ntop \
	__b64_ntop \
	b64_pton \
	__b64_pton \
	bcopy \
	chflags \
	closefrom \
	dirfd \
	dirname \
	endgrent \
	explicit_bzero \
	fgetln \
	freeaddrinfo \
	getaddrinfo \
	getnameinfo \
	getopt \
	getpeereid \
	getspnam \
	inet_aton \
	inet_ntoa \
	inet_ntop \
	isblank \
	memmove \
	nsleep \
	pidfile \
	pw_dup \
	reallocarray \
	setenv \
	setlinebuf \
	setproctitle \
	setregid \
	setreuid \
	setsid \
	sigaction \
	socketpair \
	strdup \
	strerror \
	strlcat \
	strlcpy \
	strnvis \
	strmode \
	strtonum \
	sysconf \
	tcgetpgrp \
	truncate \
	vasprintf \
	vsnprintf \
	waitpid \
])
#l1685

#l1715
AC_SEARCH_LIBS([nanosleep], [rt posix4], [AC_DEFINE([HAVE_NANOSLEEP], [1],
	[Some systems put nanosleep outside of libc])])

AC_SEARCH_LIBS([clock_gettime], [rt],
	[AC_DEFINE([HAVE_CLOCK_GETTIME], [1], [Have clock_gettime])])
#l1719

#l1723
AC_CHECK_DECL([strsep],
	[AC_CHECK_FUNCS([strsep])],
	[],
	[
#ifdef HAVE_STRING_H
# include <string.h>
#endif
	])
#l1730

#l1747
AC_CHECK_DECLS([O_NONBLOCK], , ,
	[
#include <sys/types.h>
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
	])

AC_CHECK_DECLS([writev], , , [
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
	])

AC_CHECK_DECLS([MAXSYMLINKS], , , [
#include <sys/param.h>
	])

AC_CHECK_DECLS([offsetof], , , [
#include <stddef.h>
	])

# extra bits for select(2)
AC_CHECK_DECLS([howmany, NFDBITS], [], [], [[
#include <sys/param.h>
#include <sys/types.h>
#ifdef HAVE_SYS_SYSMACROS_H
#include <sys/sysmacros.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
	]])
AC_CHECK_TYPES([fd_mask], [], [], [[
#include <sys/param.h>
#include <sys/types.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
	]])

AC_CHECK_FUNCS([setresuid], [
	dnl Some platorms have setresuid that isn't implemented, test for this
	AC_MSG_CHECKING([if setresuid seems to work])
	AC_RUN_IFELSE(
		[AC_LANG_PROGRAM([[
#include <stdlib.h>
#include <errno.h>
		]], [[
	errno=0;
	setresuid(0,0,0);
	if (errno==ENOSYS)
		exit(1);
	else
		exit(0);
		]])],
		[AC_MSG_RESULT([yes])],
		[AC_DEFINE([BROKEN_SETRESUID], [1],
			[Define if your setresuid() is broken])
		 AC_MSG_RESULT([not implemented])],
		[AC_MSG_WARN([cross compiling: not checking setresuid])]
	)
])

AC_CHECK_FUNCS([setresgid], [
	dnl Some platorms have setresgid that isn't implemented, test for this
	AC_MSG_CHECKING([if setresgid seems to work])
	AC_RUN_IFELSE(
		[AC_LANG_PROGRAM([[
#include <stdlib.h>
#include <errno.h>
		]], [[
	errno=0;
	setresgid(0,0,0);
	if (errno==ENOSYS)
		exit(1);
	else
		exit(0);
		]])],
		[AC_MSG_RESULT([yes])],
		[AC_DEFINE([BROKEN_SETRESGID], [1],
			[Define if your setresgid() is broken])
		 AC_MSG_RESULT([not implemented])],
		[AC_MSG_WARN([cross compiling: not checking setresuid])]
	)
])

dnl    Checks for time functions
AC_CHECK_FUNCS([gettimeofday time])
#l1850

#l1860
AC_CHECK_FUNC([daemon],
	[AC_DEFINE([HAVE_DAEMON], [1], [Define if your libraries define daemon()])],
	[AC_CHECK_LIB([bsd], [daemon],
		[LIBS="$LIBS -lbsd"; AC_DEFINE([HAVE_DAEMON])])]
)
#l1864

##chl
AC_CHECK_FUNC([fparseln],
	[AC_DEFINE([HAVE_FPARSELN], [1], [Define if your libraries define fparseln()])],
	[AC_CHECK_LIB([util], [fparseln],
		[LIBS="$LIBS -lutil"; AC_DEFINE([HAVE_FPARSELN])])]
)

AC_SEARCH_LIBS(res_9_b64_ntop, resolv)
##chl

#l1873
# Check for broken snprintf
if test "x$ac_cv_func_snprintf" = "xyes" ; then
	AC_MSG_CHECKING([whether snprintf correctly terminates long strings])
	AC_RUN_IFELSE(
		[AC_LANG_PROGRAM([[ #include <stdio.h> ]],
		[[
	char b[5];
	snprintf(b,5,"123456789");
	exit(b[4]!='\0'); 
		]])],
		[AC_MSG_RESULT([yes])],
		[
			AC_MSG_RESULT([no])
			AC_DEFINE([BROKEN_SNPRINTF], [1],
				[Define if your snprintf is busted])
			AC_MSG_WARN([****** Your snprintf() function is broken, complain to your vendor])
		],
		[ AC_MSG_WARN([cross compiling: Assuming working snprintf()]) ]
	)
fi

# If we don't have a working asprintf, then we strongly depend on vsnprintf
# returning the right thing on overflow: the number of characters it tried to
# create (as per SUSv3)
if test "x$ac_cv_func_asprintf" != "xyes" && \
   test "x$ac_cv_func_vsnprintf" = "xyes" ; then
	AC_MSG_CHECKING([whether vsnprintf returns correct values on overflow])
	AC_RUN_IFELSE(
		[AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>

int x_snprintf(char *str,size_t count,const char *fmt,...)
{
	size_t ret; va_list ap;
	va_start(ap, fmt); ret = vsnprintf(str, count, fmt, ap); va_end(ap);
	return ret;
}
		]], [[
	char x[1];
	exit(x_snprintf(x, 1, "%s %d", "hello", 12345) == 11 ? 0 : 1);
		]])],
		[AC_MSG_RESULT([yes])],
		[
			AC_MSG_RESULT([no])
			AC_DEFINE([BROKEN_SNPRINTF], [1],
				[Define if your snprintf is busted])
			AC_MSG_WARN([****** Your vsnprintf() function is broken, complain to your vendor])
		],
		[ AC_MSG_WARN([cross compiling: Assuming working vsnprintf()]) ]
	)
fi

# On systems where [v]snprintf is broken, but is declared in stdio,
# check that the fmt argument is const char * or just char *.
# This is only useful for when BROKEN_SNPRINTF
AC_MSG_CHECKING([whether snprintf can declare const char *fmt])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdio.h>
int snprintf(char *a, size_t b, const char *c, ...) { return 0; }
		]], [[
	snprintf(0, 0, 0);
		]])],
   [AC_MSG_RESULT([yes])
    AC_DEFINE([SNPRINTF_CONST], [const],
              [Define as const if snprintf() can declare const char *fmt])],
   [AC_MSG_RESULT([no])
    AC_DEFINE([SNPRINTF_CONST], [/* not const */])])

# Check for missing getpeereid (or equiv) support
NO_PEERCHECK=""
if test "x$ac_cv_func_getpeereid" != "xyes" -a "x$ac_cv_func_getpeerucred" != "xyes"; then
	AC_MSG_CHECKING([whether system supports SO_PEERCRED getsockopt])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>]], [[int i = SO_PEERCRED;]])],
		[ AC_MSG_RESULT([yes])
		  AC_DEFINE([HAVE_SO_PEERCRED], [1], [Have PEERCRED socket option])
		], [AC_MSG_RESULT([no])
		NO_PEERCHECK=1
        ])
fi

dnl see whether mkstemp() requires XXXXXX
if test "x$ac_cv_func_mkdtemp" = "xyes" ; then
AC_MSG_CHECKING([for (overly) strict mkstemp])
AC_RUN_IFELSE(
	[AC_LANG_PROGRAM([[
#include <stdlib.h>
	]], [[
	char template[]="conftest.mkstemp-test";
	if (mkstemp(template) == -1)
		exit(1);
	unlink(template);
	exit(0);
	]])],
	[
		AC_MSG_RESULT([no])
	],
	[
		AC_MSG_RESULT([yes])
		AC_DEFINE([HAVE_STRICT_MKSTEMP], [1], [Silly mkstemp()])
	],
	[
		AC_MSG_RESULT([yes])
		AC_DEFINE([HAVE_STRICT_MKSTEMP])
	]
)
fi
#l1982

#l2030
if test "x$ac_cv_func_getaddrinfo" = "xyes" && \
    test "x$check_for_hpux_broken_getaddrinfo" = "x1"; then
	AC_MSG_CHECKING([if getaddrinfo seems to work])
	AC_RUN_IFELSE(
		[AC_LANG_PROGRAM([[
#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/in.h>

#define TEST_PORT "2222"
		]], [[
	int err, sock;
	struct addrinfo *gai_ai, *ai, hints;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV], *name = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	err = getaddrinfo(name, TEST_PORT, &hints, &gai_ai);
	if (err != 0) {
		fprintf(stderr, "getaddrinfo failed (%s)", gai_strerror(err));
		exit(1);
	}

	for (ai = gai_ai; ai != NULL; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET6)
			continue;

		err = getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop,
		    sizeof(ntop), strport, sizeof(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV);

		if (err != 0) {
			if (err == EAI_SYSTEM)
				perror("getnameinfo EAI_SYSTEM");
			else
				fprintf(stderr, "getnameinfo failed: %s\n",
				    gai_strerror(err));
			exit(2);
		}

		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0)
			perror("socket");
		if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
			if (errno == EBADF)
				exit(3);
		}
	}
	exit(0);
		]])],
		[
			AC_MSG_RESULT([yes])
		],
		[
			AC_MSG_RESULT([no])
			AC_DEFINE([BROKEN_GETADDRINFO])
		],
		[
			AC_MSG_RESULT([cross-compiling, assuming yes])
		]
	)
fi

if test "x$ac_cv_func_getaddrinfo" = "xyes" && \
    test "x$check_for_aix_broken_getaddrinfo" = "x1"; then
	AC_MSG_CHECKING([if getaddrinfo seems to work])
	AC_RUN_IFELSE(
		[AC_LANG_PROGRAM([[
#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/in.h>

#define TEST_PORT "2222"
		]], [[
	int err, sock;
	struct addrinfo *gai_ai, *ai, hints;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV], *name = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	err = getaddrinfo(name, TEST_PORT, &hints, &gai_ai);
	if (err != 0) {
		fprintf(stderr, "getaddrinfo failed (%s)", gai_strerror(err));
		exit(1);
	}

	for (ai = gai_ai; ai != NULL; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;

		err = getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop,
		    sizeof(ntop), strport, sizeof(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV);

		if (ai->ai_family == AF_INET && err != 0) {
			perror("getnameinfo");
			exit(2);
		}
	}
	exit(0);
		]])],
		[
			AC_MSG_RESULT([yes])
			AC_DEFINE([AIX_GETNAMEINFO_HACK], [1],
				[Define if you have a getaddrinfo that fails
				for the all-zeros IPv6 address])
		],
		[
			AC_MSG_RESULT([no])
			AC_DEFINE([BROKEN_GETADDRINFO])
		],
		[
			AC_MSG_RESULT([cross-compiling, assuming no])
		]
	)
fi
#l2155

#l2174 (customized, bu adding -lssl to LIBS)
# Search for OpenSSL
saved_CPPFLAGS="$CPPFLAGS"
saved_LDFLAGS="$LDFLAGS"
AC_ARG_WITH([ssl-dir],
	[  --with-ssl-dir=PATH     Specify path to OpenSSL installation ],
	[
		if test "x$withval" != "xno" ; then
			case "$withval" in
				# Relative paths
				./*|../*)	withval="`pwd`/$withval"
			esac
			if test -d "$withval/lib"; then
				if test -n "${need_dash_r}"; then
					LDFLAGS="-L${withval}/lib -R${withval}/lib ${LDFLAGS}"
				else
					LDFLAGS="-L${withval}/lib ${LDFLAGS}"
				fi
			elif test -d "$withval/lib64"; then
				if test -n "${need_dash_r}"; then
					LDFLAGS="-L${withval}/lib64 -R${withval}/lib64 ${LDFLAGS}"
				else
					LDFLAGS="-L${withval}/lib64 ${LDFLAGS}"
				fi
			else
				if test -n "${need_dash_r}"; then
					LDFLAGS="-L${withval} -R${withval} ${LDFLAGS}"
				else
					LDFLAGS="-L${withval} ${LDFLAGS}"
				fi
			fi
			if test -d "$withval/include"; then
				CPPFLAGS="-I${withval}/include ${CPPFLAGS}"
			else
				CPPFLAGS="-I${withval} ${CPPFLAGS}"
			fi
		fi
	]
)
## XXX chl -lssl manually added
LIBS="-lcrypto -lssl $LIBS"
AC_TRY_LINK_FUNC([RAND_add], [AC_DEFINE([HAVE_OPENSSL], [1],
	[Define if your ssl headers are included
	with #include <openssl/header.h>])],
	[
		dnl Check default openssl install dir
		if test -n "${need_dash_r}"; then
			LDFLAGS="-L/usr/local/ssl/lib -R/usr/local/ssl/lib ${saved_LDFLAGS}"
		else
			LDFLAGS="-L/usr/local/ssl/lib ${saved_LDFLAGS}"
		fi
		CPPFLAGS="-I/usr/local/ssl/include ${saved_CPPFLAGS}"
		AC_CHECK_HEADER([openssl/opensslv.h], ,
		    [AC_MSG_ERROR([*** OpenSSL headers missing - please install first or check config.log ***])])
		AC_TRY_LINK_FUNC([RAND_add], [AC_DEFINE([HAVE_OPENSSL])],
			[
				AC_MSG_ERROR([*** Can't find recent OpenSSL libcrypto (see config.log for details) ***])
			]
		)
	]
)

# Determine OpenSSL header version
AC_MSG_CHECKING([OpenSSL header version])
AC_RUN_IFELSE(
	[AC_LANG_PROGRAM([[
#include <stdio.h>
#include <string.h>
#include <openssl/opensslv.h>
#define DATA "conftest.sslincver"
	]], [[
	FILE *fd;
	int rc;

	fd = fopen(DATA,"w");
	if(fd == NULL)
		exit(1);

	if ((rc = fprintf(fd ,"%x (%s)\n", OPENSSL_VERSION_NUMBER, OPENSSL_VERSION_TEXT)) <0)
		exit(1);

	exit(0);
	]])],
	[
		ssl_header_ver=`cat conftest.sslincver`
		AC_MSG_RESULT([$ssl_header_ver])
	],
	[
		AC_MSG_RESULT([not found])
		AC_MSG_ERROR([OpenSSL version header not found.])
	],
	[
		AC_MSG_WARN([cross compiling: not checking])
	]
)

# Determine OpenSSL library version
AC_MSG_CHECKING([OpenSSL library version])
AC_RUN_IFELSE(
	[AC_LANG_PROGRAM([[
#include <stdio.h>
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#define DATA "conftest.ssllibver"
	]], [[
	FILE *fd;
	int rc;

	fd = fopen(DATA,"w");
	if(fd == NULL)
		exit(1);

	if ((rc = fprintf(fd ,"%x (%s)\n", SSLeay(), SSLeay_version(SSLEAY_VERSION))) <0)
		exit(1);

	exit(0);
	]])],
	[
		ssl_library_ver=`cat conftest.ssllibver`
		AC_MSG_RESULT([$ssl_library_ver])
	],
	[
		AC_MSG_RESULT([not found])
		AC_MSG_ERROR([OpenSSL library not found.])
	],
	[
		AC_MSG_WARN([cross compiling: not checking])
	]
)

# XXX make --without-openssl work
AC_DEFINE_UNQUOTED([WITH_OPENSSL], [1], [use libcrypto for cryptography])

AC_ARG_WITH([openssl-header-check],
	[  --without-openssl-header-check Disable OpenSSL version consistency check],
	[  if test "x$withval" = "xno" ; then
		openssl_check_nonfatal=1
	   fi
	]
)

# Sanity check OpenSSL headers
AC_MSG_CHECKING([whether OpenSSL's headers match the library])
AC_RUN_IFELSE(
	[AC_LANG_PROGRAM([[
#include <string.h>
#include <openssl/opensslv.h>
	]], [[
	exit(SSLeay() == OPENSSL_VERSION_NUMBER ? 0 : 1);
	]])],
	[
		AC_MSG_RESULT([yes])
	],
	[
		AC_MSG_RESULT([no])
		if test "x$openssl_check_nonfatal" = "x"; then
			AC_MSG_ERROR([Your OpenSSL headers do not match your
library. Check config.log for details.
If you are sure your installation is consistent, you can disable the check
by running "./configure --without-openssl-header-check".
Also see contrib/findssl.sh for help identifying header/library mismatches.
])
		else
			AC_MSG_WARN([Your OpenSSL headers do not match your
library. Check config.log for details.
Also see contrib/findssl.sh for help identifying header/library mismatches.])
		fi
	],
	[
		AC_MSG_WARN([cross compiling: not checking])
	]
)

AC_MSG_CHECKING([if programs using OpenSSL functions will link])
AC_LINK_IFELSE(
	[AC_LANG_PROGRAM([[ #include <openssl/evp.h> ]],
	[[ SSLeay_add_all_algorithms(); ]])],
	[
		AC_MSG_RESULT([yes])
	],
	[
		AC_MSG_RESULT([no])
		saved_LIBS="$LIBS"
		LIBS="$LIBS -ldl"
		AC_MSG_CHECKING([if programs using OpenSSL need -ldl])
		AC_LINK_IFELSE(
			[AC_LANG_PROGRAM([[ #include <openssl/evp.h> ]],
			[[ SSLeay_add_all_algorithms(); ]])],
			[
				AC_MSG_RESULT([yes])
			],
			[
				AC_MSG_RESULT([no])
				LIBS="$saved_LIBS"
			]
		)
	]
)
#l2371

#l2494
# Some systems want crypt() from libcrypt, *not* the version in OpenSSL,
# because the system crypt() is more featureful.
if test "x$check_for_libcrypt_before" = "x1"; then
	AC_CHECK_LIB([crypt], [crypt])
fi

# Some Linux systems (Slackware) need crypt() from libcrypt, *not* the
# version in OpenSSL.
if test "x$check_for_libcrypt_later" = "x1"; then
	AC_CHECK_LIB([crypt], [crypt], [LIBS="$LIBS -lcrypt"])
fi
#l2504

#l2645
### Configure cryptographic random number support

# Check wheter OpenSSL seeds itself
AC_MSG_CHECKING([whether OpenSSL's PRNG is internally seeded])
AC_RUN_IFELSE(
	[AC_LANG_PROGRAM([[
#include <string.h>
#include <openssl/rand.h>
	]], [[
	exit(RAND_status() == 1 ? 0 : 1);
	]])],
	[
		OPENSSL_SEEDS_ITSELF=yes
		AC_MSG_RESULT([yes])
	],
	[
		AC_MSG_RESULT([no])
	],
	[
		AC_MSG_WARN([cross compiling: assuming yes])
		# This is safe, since we will fatal() at runtime if
		# OpenSSL is not seeded correctly.
		OPENSSL_SEEDS_ITSELF=yes
	]
)
#l2669


SMTPD_USER=_smtpd
AC_ARG_WITH([privsep-user],
	[  --with-privsep-user=user Specify non-privileged user for privilege separation],
	[
		if test -n "$withval"  &&  test "x$withval" != "xno"  &&  \
		    test "x${withval}" != "xyes"; then
			SMTPD_USER=$withval
		fi
	]
)
AC_DEFINE_UNQUOTED([SMTPD_USER], ["$SMTPD_USER"],
	[non-privileged user for privilege separation])
AC_SUBST([SMTPD_USER])

#l3037 (customized s/SSH/SMTPD/)
# Check for  long long datatypes
AC_CHECK_TYPES([long long, unsigned long long, long double])

# Check datatype sizes
AC_CHECK_SIZEOF([short int], [2])
AC_CHECK_SIZEOF([int], [4])
AC_CHECK_SIZEOF([long int], [4])
AC_CHECK_SIZEOF([long long int], [8])

# Sanity check long long for some platforms (AIX)
if test "x$ac_cv_sizeof_long_long_int" = "x4" ; then
	ac_cv_sizeof_long_long_int=0
fi

# compute LLONG_MIN and LLONG_MAX if we don't know them.
if test -z "$have_llong_max"; then
	AC_MSG_CHECKING([for max value of long long])
	AC_RUN_IFELSE(
		[AC_LANG_PROGRAM([[
#include <stdio.h>
/* Why is this so damn hard? */
#ifdef __GNUC__
# undef __GNUC__
#endif
#define __USE_ISOC99
#include <limits.h>
#define DATA "conftest.llminmax"
#define my_abs(a) ((a) < 0 ? ((a) * -1) : (a))

/*
 * printf in libc on some platforms (eg old Tru64) does not understand %lld so
 * we do this the hard way.
 */
static int
fprint_ll(FILE *f, long long n)
{
	unsigned int i;
	int l[sizeof(long long) * 8];

	if (n < 0)
		if (fprintf(f, "-") < 0)
			return -1;
	for (i = 0; n != 0; i++) {
		l[i] = my_abs(n % 10);
		n /= 10;
	}
	do {
		if (fprintf(f, "%d", l[--i]) < 0)
			return -1;
	} while (i != 0);
	if (fprintf(f, " ") < 0)
		return -1;
	return 0;
}
		]], [[
	FILE *f;
	long long i, llmin, llmax = 0;

	if((f = fopen(DATA,"w")) == NULL)
		exit(1);

#if defined(LLONG_MIN) && defined(LLONG_MAX)
	fprintf(stderr, "Using system header for LLONG_MIN and LLONG_MAX\n");
	llmin = LLONG_MIN;
	llmax = LLONG_MAX;
#else
	fprintf(stderr, "Calculating  LLONG_MIN and LLONG_MAX\n");
	/* This will work on one's complement and two's complement */
	for (i = 1; i > llmax; i <<= 1, i++)
		llmax = i;
	llmin = llmax + 1LL;	/* wrap */
#endif

	/* Sanity check */
	if (llmin + 1 < llmin || llmin - 1 < llmin || llmax + 1 > llmax
	    || llmax - 1 > llmax || llmin == llmax || llmin == 0
	    || llmax == 0 || llmax < LONG_MAX || llmin > LONG_MIN) {
		fprintf(f, "unknown unknown\n");
		exit(2);
	}

	if (fprint_ll(f, llmin) < 0)
		exit(3);
	if (fprint_ll(f, llmax) < 0)
		exit(4);
	if (fclose(f) < 0)
		exit(5);
	exit(0);
		]])],
		[
			llong_min=`$AWK '{print $1}' conftest.llminmax`
			llong_max=`$AWK '{print $2}' conftest.llminmax`

			AC_MSG_RESULT([$llong_max])
			AC_DEFINE_UNQUOTED([LLONG_MAX], [${llong_max}LL],
			    [max value of long long calculated by configure])
			AC_MSG_CHECKING([for min value of long long])
			AC_MSG_RESULT([$llong_min])
			AC_DEFINE_UNQUOTED([LLONG_MIN], [${llong_min}LL],
			    [min value of long long calculated by configure])
		],
		[
			AC_MSG_RESULT([not found])
		],
		[
			AC_MSG_WARN([cross compiling: not checking])
		]
	)
fi


# More checks for data types
AC_CACHE_CHECK([for u_int type], ac_cv_have_u_int, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <sys/types.h> ]],
	[[ u_int a; a = 1;]])],
	[ ac_cv_have_u_int="yes" ], [ ac_cv_have_u_int="no" 
	])
])
if test "x$ac_cv_have_u_int" = "xyes" ; then
	AC_DEFINE([HAVE_U_INT], [1], [define if you have u_int data type])
	have_u_int=1
fi

AC_CACHE_CHECK([for intXX_t types], ac_cv_have_intxx_t, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <sys/types.h> ]],
	[[ int8_t a; int16_t b; int32_t c; a = b = c = 1;]])],
	[ ac_cv_have_intxx_t="yes" ], [ ac_cv_have_intxx_t="no" 
	])
])
if test "x$ac_cv_have_intxx_t" = "xyes" ; then
	AC_DEFINE([HAVE_INTXX_T], [1], [define if you have intxx_t data type])
	have_intxx_t=1
fi

if (test -z "$have_intxx_t" && \
	   test "x$ac_cv_header_stdint_h" = "xyes")
then
    AC_MSG_CHECKING([for intXX_t types in stdint.h])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <stdint.h> ]],
	[[ int8_t a; int16_t b; int32_t c; a = b = c = 1;]])],
		[
			AC_DEFINE([HAVE_INTXX_T])
			AC_MSG_RESULT([yes])
		], [ AC_MSG_RESULT([no]) 
	])
fi

AC_CACHE_CHECK([for int64_t type], ac_cv_have_int64_t, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#include <sys/socket.h>
#ifdef HAVE_SYS_BITYPES_H
# include <sys/bitypes.h>
#endif
		]], [[
int64_t a; a = 1;
		]])],
	[ ac_cv_have_int64_t="yes" ], [ ac_cv_have_int64_t="no" 
	])
])
if test "x$ac_cv_have_int64_t" = "xyes" ; then
	AC_DEFINE([HAVE_INT64_T], [1], [define if you have int64_t data type])
fi

AC_CACHE_CHECK([for u_intXX_t types], ac_cv_have_u_intxx_t, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <sys/types.h> ]],
	[[ u_int8_t a; u_int16_t b; u_int32_t c; a = b = c = 1;]])],
	[ ac_cv_have_u_intxx_t="yes" ], [ ac_cv_have_u_intxx_t="no" 
	])
])
if test "x$ac_cv_have_u_intxx_t" = "xyes" ; then
	AC_DEFINE([HAVE_U_INTXX_T], [1], [define if you have u_intxx_t data type])
	have_u_intxx_t=1
fi

if test -z "$have_u_intxx_t" ; then
    AC_MSG_CHECKING([for u_intXX_t types in sys/socket.h])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <sys/socket.h> ]],
	[[ u_int8_t a; u_int16_t b; u_int32_t c; a = b = c = 1;]])],
		[
			AC_DEFINE([HAVE_U_INTXX_T])
			AC_MSG_RESULT([yes])
		], [ AC_MSG_RESULT([no]) 
	])
fi

AC_CACHE_CHECK([for u_int64_t types], ac_cv_have_u_int64_t, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <sys/types.h> ]],
	[[ u_int64_t a; a = 1;]])],
	[ ac_cv_have_u_int64_t="yes" ], [ ac_cv_have_u_int64_t="no" 
	])
])
if test "x$ac_cv_have_u_int64_t" = "xyes" ; then
	AC_DEFINE([HAVE_U_INT64_T], [1], [define if you have u_int64_t data type])
	have_u_int64_t=1
fi

if (test -z "$have_u_int64_t" && \
	   test "x$ac_cv_header_sys_bitypes_h" = "xyes")
then
    AC_MSG_CHECKING([for u_int64_t type in sys/bitypes.h])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <sys/bitypes.h> ]],
	[[ u_int64_t a; a = 1]])],
		[
			AC_DEFINE([HAVE_U_INT64_T])
			AC_MSG_RESULT([yes])
		], [ AC_MSG_RESULT([no]) 
	])
fi

if test -z "$have_u_intxx_t" ; then
	AC_CACHE_CHECK([for uintXX_t types], ac_cv_have_uintxx_t, [
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
			]], [[
	uint8_t a;
	uint16_t b;
	uint32_t c;
	a = b = c = 1;
			]])],
		[ ac_cv_have_uintxx_t="yes" ], [ ac_cv_have_uintxx_t="no" 
		])
	])
	if test "x$ac_cv_have_uintxx_t" = "xyes" ; then
		AC_DEFINE([HAVE_UINTXX_T], [1],
			[define if you have uintxx_t data type])
	fi
fi

if (test -z "$have_uintxx_t" && \
	   test "x$ac_cv_header_stdint_h" = "xyes")
then
    AC_MSG_CHECKING([for uintXX_t types in stdint.h])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <stdint.h> ]],
	[[ uint8_t a; uint16_t b; uint32_t c; a = b = c = 1;]])],
		[
			AC_DEFINE([HAVE_UINTXX_T])
			AC_MSG_RESULT([yes])
		], [ AC_MSG_RESULT([no]) 
	])
fi

if (test -z "$have_uintxx_t" && \
	   test "x$ac_cv_header_inttypes_h" = "xyes")
then
    AC_MSG_CHECKING([for uintXX_t types in inttypes.h])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <inttypes.h> ]],
	[[ uint8_t a; uint16_t b; uint32_t c; a = b = c = 1;]])],
		[
			AC_DEFINE([HAVE_UINTXX_T])
			AC_MSG_RESULT([yes])
		], [ AC_MSG_RESULT([no]) 
	])
fi

if (test -z "$have_u_intxx_t" || test -z "$have_intxx_t" && \
	   test "x$ac_cv_header_sys_bitypes_h" = "xyes")
then
	AC_MSG_CHECKING([for intXX_t and u_intXX_t types in sys/bitypes.h])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/bitypes.h>
		]], [[
			int8_t a; int16_t b; int32_t c;
			u_int8_t e; u_int16_t f; u_int32_t g;
			a = b = c = e = f = g = 1;
		]])],
		[
			AC_DEFINE([HAVE_U_INTXX_T])
			AC_DEFINE([HAVE_INTXX_T])
			AC_MSG_RESULT([yes])
		], [AC_MSG_RESULT([no])
	])
fi


AC_CACHE_CHECK([for u_char], ac_cv_have_u_char, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <sys/types.h> ]],
	[[ u_char foo; foo = 125; ]])],
	[ ac_cv_have_u_char="yes" ], [ ac_cv_have_u_char="no" 
	])
])
if test "x$ac_cv_have_u_char" = "xyes" ; then
	AC_DEFINE([HAVE_U_CHAR], [1], [define if you have u_char data type])
fi

AC_CHECK_TYPES([intmax_t, uintmax_t], , , [
#include <sys/types.h>
#include <stdint.h>
])

TYPE_SOCKLEN_T

AC_CHECK_TYPES([sig_atomic_t], , , [#include <signal.h>])

AC_CACHE_CHECK([for size_t], ac_cv_have_size_t, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <sys/types.h> ]],
	[[ size_t foo; foo = 1235; ]])],
	[ ac_cv_have_size_t="yes" ], [ ac_cv_have_size_t="no" 
	])
])
if test "x$ac_cv_have_size_t" = "xyes" ; then
	AC_DEFINE([HAVE_SIZE_T], [1], [define if you have size_t data type])
fi

AC_CACHE_CHECK([for ssize_t], ac_cv_have_ssize_t, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <sys/types.h> ]],
	[[ ssize_t foo; foo = 1235; ]])],
	[ ac_cv_have_ssize_t="yes" ], [ ac_cv_have_ssize_t="no" 
	])
])
if test "x$ac_cv_have_ssize_t" = "xyes" ; then
	AC_DEFINE([HAVE_SSIZE_T], [1], [define if you have ssize_t data type])
fi

AC_CACHE_CHECK([for clock_t], ac_cv_have_clock_t, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <time.h> ]],
	[[ clock_t foo; foo = 1235; ]])],
	[ ac_cv_have_clock_t="yes" ], [ ac_cv_have_clock_t="no" 
	])
])
if test "x$ac_cv_have_clock_t" = "xyes" ; then
	AC_DEFINE([HAVE_CLOCK_T], [1], [define if you have clock_t data type])
fi

AC_CACHE_CHECK([for sa_family_t], ac_cv_have_sa_family_t, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
		]], [[ sa_family_t foo; foo = 1235; ]])],
	[ ac_cv_have_sa_family_t="yes" ],
	[ AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
		]], [[ sa_family_t foo; foo = 1235; ]])],
		[ ac_cv_have_sa_family_t="yes" ],
		[ ac_cv_have_sa_family_t="no" ]
	)
	])
])
if test "x$ac_cv_have_sa_family_t" = "xyes" ; then
	AC_DEFINE([HAVE_SA_FAMILY_T], [1],
		[define if you have sa_family_t data type])
fi

AC_CACHE_CHECK([for pid_t], ac_cv_have_pid_t, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <sys/types.h> ]],
	[[ pid_t foo; foo = 1235; ]])],
	[ ac_cv_have_pid_t="yes" ], [ ac_cv_have_pid_t="no" 
	])
])
if test "x$ac_cv_have_pid_t" = "xyes" ; then
	AC_DEFINE([HAVE_PID_T], [1], [define if you have pid_t data type])
fi

AC_CACHE_CHECK([for mode_t], ac_cv_have_mode_t, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <sys/types.h> ]],
	[[ mode_t foo; foo = 1235; ]])],
	[ ac_cv_have_mode_t="yes" ], [ ac_cv_have_mode_t="no" 
	])
])
if test "x$ac_cv_have_mode_t" = "xyes" ; then
	AC_DEFINE([HAVE_MODE_T], [1], [define if you have mode_t data type])
fi


AC_CACHE_CHECK([for struct sockaddr_storage], ac_cv_have_struct_sockaddr_storage, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
		]], [[ struct sockaddr_storage s; ]])],
	[ ac_cv_have_struct_sockaddr_storage="yes" ],
	[ ac_cv_have_struct_sockaddr_storage="no" 
	])
])
if test "x$ac_cv_have_struct_sockaddr_storage" = "xyes" ; then
	AC_DEFINE([HAVE_STRUCT_SOCKADDR_STORAGE], [1],
		[define if you have struct sockaddr_storage data type])
fi

AC_CACHE_CHECK([for struct sockaddr_in6], ac_cv_have_struct_sockaddr_in6, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <netinet/in.h>
		]], [[ struct sockaddr_in6 s; s.sin6_family = 0; ]])],
	[ ac_cv_have_struct_sockaddr_in6="yes" ],
	[ ac_cv_have_struct_sockaddr_in6="no" 
	])
])
if test "x$ac_cv_have_struct_sockaddr_in6" = "xyes" ; then
	AC_DEFINE([HAVE_STRUCT_SOCKADDR_IN6], [1],
		[define if you have struct sockaddr_in6 data type])
fi

AC_CACHE_CHECK([for struct in6_addr], ac_cv_have_struct_in6_addr, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <netinet/in.h>
		]], [[ struct in6_addr s; s.s6_addr[0] = 0; ]])],
	[ ac_cv_have_struct_in6_addr="yes" ],
	[ ac_cv_have_struct_in6_addr="no" 
	])
])
if test "x$ac_cv_have_struct_in6_addr" = "xyes" ; then
	AC_DEFINE([HAVE_STRUCT_IN6_ADDR], [1],
		[define if you have struct in6_addr data type])

dnl Now check for sin6_scope_id
	AC_CHECK_MEMBERS([struct sockaddr_in6.sin6_scope_id], , ,
		[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <netinet/in.h>
		])
fi

AC_CACHE_CHECK([for struct addrinfo], ac_cv_have_struct_addrinfo, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
		]], [[ struct addrinfo s; s.ai_flags = AI_PASSIVE; ]])],
	[ ac_cv_have_struct_addrinfo="yes" ],
	[ ac_cv_have_struct_addrinfo="no" 
	])
])
if test "x$ac_cv_have_struct_addrinfo" = "xyes" ; then
	AC_DEFINE([HAVE_STRUCT_ADDRINFO], [1],
		[define if you have struct addrinfo data type])
fi

AC_CACHE_CHECK([for struct timeval], ac_cv_have_struct_timeval, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <sys/time.h> ]],
	[[ struct timeval tv; tv.tv_sec = 1;]])],
	[ ac_cv_have_struct_timeval="yes" ],
	[ ac_cv_have_struct_timeval="no" 
	])
])
if test "x$ac_cv_have_struct_timeval" = "xyes" ; then
	AC_DEFINE([HAVE_STRUCT_TIMEVAL], [1], [define if you have struct timeval])
	have_struct_timeval=1
fi

AC_CHECK_TYPES([struct timespec])

# We need int64_t or else certian parts of the compile will fail.
if test "x$ac_cv_have_int64_t" = "xno" && \
	test "x$ac_cv_sizeof_long_int" != "x8" && \
	test "x$ac_cv_sizeof_long_long_int" = "x0" ; then
	echo "OpenSMTPD requires int64_t support.  Contact your vendor or install"
	echo "an alternative compiler (I.E., GCC) before continuing."
	echo ""
	exit 1;
else
dnl test snprintf (broken on SCO w/gcc)
	AC_RUN_IFELSE(
		[AC_LANG_SOURCE([[
#include <stdio.h>
#include <string.h>
#ifdef HAVE_SNPRINTF
main()
{
	char buf[50];
	char expected_out[50];
	int mazsize = 50 ;
#if (SIZEOF_LONG_INT == 8)
	long int num = 0x7fffffffffffffff;
#else
	long long num = 0x7fffffffffffffffll;
#endif
	strcpy(expected_out, "9223372036854775807");
	snprintf(buf, mazsize, "%lld", num);
	if(strcmp(buf, expected_out) != 0)
		exit(1);
	exit(0);
}
#else
main() { exit(0); }
#endif
		]])], [ true ], [ AC_DEFINE([BROKEN_SNPRINTF]) ],
		AC_MSG_WARN([cross compiling: Assuming working snprintf()])
	)
fi
#l3539

#l3561
AC_CHECK_MEMBERS([struct passwd.pw_gecos, struct passwd.pw_class,
struct passwd.pw_change, struct passwd.pw_expire],
[], [], [[
#include <sys/types.h>
#include <pwd.h>
]])

AC_CHECK_MEMBER([struct __res_state.retrans], [], [AC_DEFINE([__res_state], [state],
	[Define if we don't have struct __res_state in resolv.h])],
[[
#include <stdio.h>
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
]])

AC_CACHE_CHECK([for ss_family field in struct sockaddr_storage],
		ac_cv_have_ss_family_in_struct_ss, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
		]], [[ struct sockaddr_storage s; s.ss_family = 1; ]])],
	[ ac_cv_have_ss_family_in_struct_ss="yes" ],
	[ ac_cv_have_ss_family_in_struct_ss="no" ])
])
if test "x$ac_cv_have_ss_family_in_struct_ss" = "xyes" ; then
	AC_DEFINE([HAVE_SS_FAMILY_IN_SS], [1], [Fields in struct sockaddr_storage])
fi

AC_CACHE_CHECK([for __ss_family field in struct sockaddr_storage],
		ac_cv_have___ss_family_in_struct_ss, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
		]], [[ struct sockaddr_storage s; s.__ss_family = 1; ]])],
	[ ac_cv_have___ss_family_in_struct_ss="yes" ],
	[ ac_cv_have___ss_family_in_struct_ss="no" 
	])
])
if test "x$ac_cv_have___ss_family_in_struct_ss" = "xyes" ; then
	AC_DEFINE([HAVE___SS_FAMILY_IN_SS], [1],
		[Fields in struct sockaddr_storage])
fi

dnl make sure we're using the real structure members and not defines
AC_CACHE_CHECK([for msg_accrights field in struct msghdr],
		ac_cv_have_accrights_in_msghdr, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
		]], [[
#ifdef msg_accrights
#error "msg_accrights is a macro"
exit(1);
#endif
struct msghdr m;
m.msg_accrights = 0;
exit(0);
		]])],
		[ ac_cv_have_accrights_in_msghdr="yes" ],
		[ ac_cv_have_accrights_in_msghdr="no" ]
	)
])
if test "x$ac_cv_have_accrights_in_msghdr" = "xyes" ; then
	AC_DEFINE([HAVE_ACCRIGHTS_IN_MSGHDR], [1],
		[Define if your system uses access rights style
		file descriptor passing])
fi

AC_CACHE_CHECK([for msg_control field in struct msghdr],
		ac_cv_have_control_in_msghdr, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
		]], [[
#ifdef msg_control
#error "msg_control is a macro"
exit(1);
#endif
struct msghdr m;
m.msg_control = 0;
exit(0);
		]])],
		[ ac_cv_have_control_in_msghdr="yes" ],
		[ ac_cv_have_control_in_msghdr="no" ]
	)
])
if test "x$ac_cv_have_control_in_msghdr" = "xyes" ; then
	AC_DEFINE([HAVE_CONTROL_IN_MSGHDR], [1],
		[Define if your system uses ancillary data style
		file descriptor passing])
fi

AC_CACHE_CHECK([if libc defines __progname], ac_cv_libc_defines___progname, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[]],
		[[ extern char *__progname; printf("%s", __progname); ]])],
	[ ac_cv_libc_defines___progname="yes" ],
	[ ac_cv_libc_defines___progname="no" 
	])
])
if test "x$ac_cv_libc_defines___progname" = "xyes" ; then
	AC_DEFINE([HAVE___PROGNAME], [1], [Define if libc defines __progname])
fi

AC_CACHE_CHECK([whether $CC implements __FUNCTION__], ac_cv_cc_implements___FUNCTION__, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[ #include <stdio.h> ]],
		[[ printf("%s", __FUNCTION__); ]])],
	[ ac_cv_cc_implements___FUNCTION__="yes" ],
	[ ac_cv_cc_implements___FUNCTION__="no" 
	])
])
if test "x$ac_cv_cc_implements___FUNCTION__" = "xyes" ; then
	AC_DEFINE([HAVE___FUNCTION__], [1],
		[Define if compiler implements __FUNCTION__])
fi

AC_CACHE_CHECK([whether $CC implements __func__], ac_cv_cc_implements___func__, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[ #include <stdio.h> ]],
		[[ printf("%s", __func__); ]])],
	[ ac_cv_cc_implements___func__="yes" ],
	[ ac_cv_cc_implements___func__="no" 
	])
])
if test "x$ac_cv_cc_implements___func__" = "xyes" ; then
	AC_DEFINE([HAVE___func__], [1], [Define if compiler implements __func__])
fi

AC_CACHE_CHECK([whether va_copy exists], ac_cv_have_va_copy, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <stdarg.h>
va_list x,y;
		]], [[ va_copy(x,y); ]])],
	[ ac_cv_have_va_copy="yes" ],
	[ ac_cv_have_va_copy="no" 
	])
])
if test "x$ac_cv_have_va_copy" = "xyes" ; then
	AC_DEFINE([HAVE_VA_COPY], [1], [Define if va_copy exists])
fi

AC_CACHE_CHECK([whether __va_copy exists], ac_cv_have___va_copy, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <stdarg.h>
va_list x,y;
		]], [[ __va_copy(x,y); ]])],
	[ ac_cv_have___va_copy="yes" ], [ ac_cv_have___va_copy="no" 
	])
])
if test "x$ac_cv_have___va_copy" = "xyes" ; then
	AC_DEFINE([HAVE___VA_COPY], [1], [Define if __va_copy exists])
fi

AC_CACHE_CHECK([whether getopt has optreset support],
		ac_cv_have_getopt_optreset, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[ #include <getopt.h> ]],
		[[ extern int optreset; optreset = 0; ]])],
	[ ac_cv_have_getopt_optreset="yes" ],
	[ ac_cv_have_getopt_optreset="no" 
	])
])
if test "x$ac_cv_have_getopt_optreset" = "xyes" ; then
	AC_DEFINE([HAVE_GETOPT_OPTRESET], [1],
		[Define if your getopt(3) defines and uses optreset])
fi
#l3765

#l4010
# Looking for programs, paths and files

PRIVSEP_PATH=/var/empty
AC_ARG_WITH([privsep-path],
	[  --with-privsep-path=xxx Path for privilege separation chroot (default=/var/empty)],
	[
		if test -n "$withval"  &&  test "x$withval" != "xno"  &&  \
		    test "x${withval}" != "xyes"; then
			PRIVSEP_PATH=$withval
		fi
	]
)
AC_SUBST([PRIVSEP_PATH])
#l4022

#l4045
STRIP_OPT=-s
AC_ARG_ENABLE([strip],
	[  --disable-strip         Disable calling strip(1) on install],
	[
		if test "x$enableval" = "xno" ; then
			STRIP_OPT=
		fi
	]
)
AC_SUBST([STRIP_OPT])
#l4054

#l4176 (customized s/ssh.1/smtpd/smtpd.8/)
# Options from here on. Some of these are preset by platform above
AC_ARG_WITH([mantype],
	[  --with-mantype=man|cat|doc  Set man page type],
	[
		case "$withval" in
		man|cat|doc)
			MANTYPE=$withval
			;;
		*)
			AC_MSG_ERROR([invalid man type: $withval])
			;;
		esac
	]
)
if test -z "$MANTYPE"; then
	TestPath="/usr/bin${PATH_SEPARATOR}/usr/ucb"
	AC_PATH_PROGS([NROFF], [nroff awf], [/bin/false], [$TestPath])
	if ${NROFF} -mdoc ${srcdir}/smtpd/smtpd.8 >/dev/null 2>&1; then
		MANTYPE=doc
	elif ${NROFF} -man ${srcdir}/smtpd/smtpd.8 >/dev/null 2>&1; then
		MANTYPE=man
	else
		MANTYPE=cat
	fi
fi
AC_SUBST([MANTYPE])
if test "$MANTYPE" = "doc"; then
	mansubdir=man;
else
	mansubdir=$MANTYPE;
fi
AC_SUBST([mansubdir])
#l4207



#
# individual modules
#

#
# FILTERS
#
HAVE_FILTER_DNSBL=no
AC_ARG_WITH([filter-dnsbl],
	[  --with-filter-dnsbl	Enable filter dnsbl],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_FILTER_DNSBL], [1],
				[Define if you have filter dnsbl])
			HAVE_FILTER_DNSBL=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_FILTER_DNSBL], [test $HAVE_FILTER_DNSBL = yes])

HAVE_FILTER_MONKEY=no
AC_ARG_WITH([filter-monkey],
	[  --with-filter-monkey	Enable filter monkey],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_FILTER_MONKEY], [1],
				[Define if you have filter monkey])
			HAVE_FILTER_MONKEY=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_FILTER_MONKEY], [test $HAVE_FILTER_MONKEY = yes])

HAVE_FILTER_PERL=no
AC_ARG_WITH([filter-perl],
	[  --with-filter-perl	Enable filter perl],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_FILTER_PERL], [1],
				[Define if you have filter perl])
			HAVE_FILTER_PERL=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_FILTER_PERL], [test $HAVE_FILTER_PERL = yes])

HAVE_FILTER_PYTHON=no
AC_ARG_WITH([filter-python],
	[  --with-filter-python	Enable filter python],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_FILTER_PYTHON], [1],
				[Define if you have filter python])
			HAVE_FILTER_PYTHON=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_FILTER_PYTHON], [test $HAVE_FILTER_PYTHON = yes])

HAVE_FILTER_STUB=no
AC_ARG_WITH([filter-stub],
	[  --with-filter-stub	Enable filter stub],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_FILTER_STUB], [1],
				[Define if you have filter stub])
			HAVE_FILTER_STUB=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_FILTER_STUB], [test $HAVE_FILTER_STUB = yes])

HAVE_FILTER_TRACE=no
AC_ARG_WITH([filter-trace],
	[  --with-filter-trace	Enable filter trace],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_FILTER_TRACE], [1],
				[Define if you have filter trace])
			HAVE_FILTER_TRACE=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_FILTER_TRACE], [test $HAVE_FILTER_TRACE = yes])

HAVE_FILTER_VOID=no
AC_ARG_WITH([filter-void],
	[  --with-filter-void	Enable filter void],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_FILTER_VOID], [1],
				[Define if you have filter void])
			HAVE_FILTER_VOID=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_FILTER_VOID], [test $HAVE_FILTER_VOID = yes])


#
# QUEUES
#
HAVE_QUEUE_NULL=no
AC_ARG_WITH([queue-null],
	[  --with-queue-null	Enable queue null],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_QUEUE_NULL], [1],
				[Define if you have queue null])
			HAVE_QUEUE_NULL=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_QUEUE_NULL], [test $HAVE_QUEUE_NULL = yes])

HAVE_QUEUE_PYTHON=no
AC_ARG_WITH([queue-python],
	[  --with-queue-python	Enable queue python],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_QUEUE_PYTHON], [1],
				[Define if you have queue python])
			HAVE_QUEUE_PYTHON=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_QUEUE_PYTHON], [test $HAVE_QUEUE_PYTHON = yes])

HAVE_QUEUE_RAM=no
AC_ARG_WITH([queue-ram],
	[  --with-queue-ram	Enable queue ram],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_QUEUE_RAM], [1],
				[Define if you have queue ram])
			HAVE_QUEUE_RAM=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_QUEUE_RAM], [test $HAVE_QUEUE_RAM = yes])

HAVE_QUEUE_STUB=no
AC_ARG_WITH([queue-stub],
	[  --with-queue-stub	Enable queue stub],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_QUEUE_STUB], [1],
				[Define if you have queue stub])
			HAVE_QUEUE_STUB=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_QUEUE_STUB], [test $HAVE_QUEUE_STUB = yes])



#
# TABLES
#

# Whether to enable *experimental* LDAP support
HAVE_TABLE_LDAP=no
AC_ARG_WITH([table-ldap],
	[  --with-table-ldap	Enable table LDAP],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_TABLE_LDAP], [1],
				[Define if you have experimental LDAP support])
			HAVE_TABLE_LDAP=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_TABLE_LDAP], [test $HAVE_TABLE_LDAP = yes])

# Whether to enable *experimental* MySQL support
HAVE_TABLE_MYSQL=no
AC_ARG_WITH([table-mysql],
	[  --with-table-mysql	Enable table MySQL],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_TABLE_MYSQL], [1],
				[Define if you have experimental MySQL support])
			HAVE_TABLE_MYSQL=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_TABLE_MYSQL], [test $HAVE_TABLE_MYSQL = yes])

# Whether to enable *experimental* PostgreSQL support
HAVE_TABLE_POSTGRES=no
AC_ARG_WITH([table-postgres],
	[  --with-table-postgres	Enable table PostgreSQL],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_TABLE_POSTGRES], [1],
				[Define if you have experimental PostgreSQL support])
			HAVE_TABLE_POSTGRES=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_TABLE_POSTGRES], [test $HAVE_TABLE_POSTGRES = yes])


# Whether to enable *experimental* Redis support
HAVE_TABLE_REDIS=no
AC_ARG_WITH([table-redis],
	[  --with-table-redis	Enable table Redis],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_TABLE_REDIS], [1],
				[Define if you have experimental Redis support])
			HAVE_TABLE_REDIS=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_TABLE_REDIS], [test $HAVE_TABLE_REDIS = yes])

# Whether to enable *experimental* Redis support
HAVE_TABLE_SOCKETMAP=no
AC_ARG_WITH([table-socketmap],
	[  --with-table-socketmap	Enable table socketmap],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_TABLE_SOCKETMAP], [1],
				[Define if you have experimental socketmap support])
		HAVE_TABLE_SOCKETMAP=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_TABLE_SOCKETMAP], [test $HAVE_TABLE_SOCKETMAP = yes])

# Whether to enable table_passwd
HAVE_TABLE_PASSWD=no
AC_ARG_WITH([table-passwd],
	[  --with-table-passwd	Enable table passwd],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_TABLE_PASSWD], [1],
				[Define if you want to enable table passwd])
			HAVE_TABLE_PASSWD=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_TABLE_PASSWD], [test $HAVE_TABLE_PASSWD = yes])

# Whether to enable table_python
HAVE_TABLE_PYTHON=no
AC_ARG_WITH([table-python],
	[  --with-table-python	Enable table python],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_TABLE_PYTHON], [1],
				[Define if you want to enable table python])
			HAVE_TABLE_PYTHON=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_TABLE_PYTHON], [test $HAVE_TABLE_PYTHON = yes])


#
# SCHEDULERS
#
HAVE_SCHEDULER_RAM=no
AC_ARG_WITH([scheduler-ram],
	[  --with-scheduler-ram	Enable scheduler ram],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_SCHEDULER_RAM], [1],
				[Define if you have scheduler ram])
			HAVE_SCHEDULER_RAM=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_SCHEDULER_RAM], [test $HAVE_SCHEDULER_RAM = yes])

HAVE_SCHEDULER_STUB=no
AC_ARG_WITH([scheduler-stub],
	[  --with-scheduler-stub	Enable scheduler stub],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_SCHEDULER_STUB], [1],
				[Define if you have scheduler stub])
			HAVE_SCHEDULER_STUB=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_SCHEDULER_STUB], [test $HAVE_SCHEDULER_STUB = yes])

HAVE_SCHEDULER_STUB=no
AC_ARG_WITH([scheduler-python],
	[  --with-scheduler-python	Enable scheduler python],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_SCHEDULER_PYTHON], [1],
				[Define if you have scheduler python])
			HAVE_SCHEDULER_PYTHON=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_SCHEDULER_PYTHON], [test $HAVE_SCHEDULER_PYTHON = yes])




##chl (based on OpenSSL checks, see above)
# Search for libevent
saved_CPPFLAGS="$CPPFLAGS"
saved_LDFLAGS="$LDFLAGS"
AC_ARG_WITH([libevent-dir],
	[  --with-libevent-dir=PATH     Specify path to libevent installation ],
	[
		if test "x$withval" != "xno" ; then
			case "$withval" in
				# Relative paths
				./*|../*)	withval="`pwd`/$withval"
			esac
			if test -d "$withval/lib"; then
				if test -n "${need_dash_r}"; then
					LDFLAGS="-L${withval}/lib -R${withval}/lib ${LDFLAGS}"
				else
					LDFLAGS="-L${withval}/lib ${LDFLAGS}"
				fi
			elif test -d "$withval/lib64"; then
				if test -n "${need_dash_r}"; then
					LDFLAGS="-L${withval}/lib64 -R${withval}/lib64 ${LDFLAGS}"
				else
					LDFLAGS="-L${withval}/lib64 ${LDFLAGS}"
				fi
			else
				if test -n "${need_dash_r}"; then
					LDFLAGS="-L${withval} -R${withval} ${LDFLAGS}"
				else
					LDFLAGS="-L${withval} ${LDFLAGS}"
				fi
			fi
			if test -d "$withval/include"; then
				CPPFLAGS="-I${withval}/include ${CPPFLAGS}"
			else
				CPPFLAGS="-I${withval} ${CPPFLAGS}"
			fi
		fi
	]
)

LIBS="-levent $LIBS"

# Determine libevent header version
AC_MSG_CHECKING([libevent header version])
AC_RUN_IFELSE(
	[AC_LANG_PROGRAM([[
#include <stdio.h>
#include <string.h>
#include <event.h>
#define DATA "conftest.libeventincver"
	]], [[
	FILE *fd;
	int rc;

	fd = fopen(DATA,"w");
	if(fd == NULL)
		exit(1);

	if ((rc = fprintf(fd ,"%s\n", _EVENT_VERSION)) <0)
		exit(1);

	exit(0);
	]])],
	[
		libevent_header_ver=`cat conftest.libeventincver`
		AC_MSG_RESULT([$libevent_header_ver])
	],
	[
		AC_MSG_RESULT([not found])
		AC_MSG_ERROR([libevent version header not found.])
	],
	[
		AC_MSG_WARN([cross compiling: not checking])
	]
)

# Determine libevent library version
AC_MSG_CHECKING([libevent library version])
AC_RUN_IFELSE(
	[AC_LANG_PROGRAM([[
#include <stdio.h>
#include <string.h>
#include <event.h>
#define DATA "conftest.libeventlibver"
	]], [[
	FILE *fd;
	int rc;

	fd = fopen(DATA,"w");
	if(fd == NULL)
		exit(1);

	if ((rc = fprintf(fd ,"%s\n", event_get_version())) <0)
		exit(1);

	exit(0);
	]])],
	[
		libevent_library_ver=`cat conftest.libeventlibver`
		AC_MSG_RESULT([$libevent_library_ver])
	],
	[
		AC_MSG_RESULT([not found])
		AC_MSG_ERROR([libevent library not found.])
	],
	[
		AC_MSG_WARN([cross compiling: not checking])
	]
)

libevent_major_version=`cat conftest.libeventlibver|head -c1 || echo 1`

AC_DEFINE_UNQUOTED([LIBEVENT_MAJOR_VERSION], [$libevent_major_version], [Define libevent major version])

AC_ARG_WITH([libevent-header-check],
	[  --without-libevent-header-check Disable libevent version consistency check],
	[  if test "x$withval" = "xno" ; then
		libevent_check_nonfatal=1
	   fi
	]
)

# Sanity check libevent headers
AC_MSG_CHECKING([whether libevent's headers match the library])
AC_RUN_IFELSE(
	[AC_LANG_PROGRAM([[
#if LIBEVENT_MAJOR_VERSION < 2
#include <event.h>
#else
#include <event2/event.h>
#endif
#include <stdlib.h>
#include <string.h>
	]], [[
	exit(strcmp(event_get_version(), _EVENT_VERSION) == 0 ? 0 : 1);
	]])],
	[
		AC_MSG_RESULT([yes])
	],
	[
		AC_MSG_RESULT([no])
		if test "x$libevent_check_nonfatal" = "x"; then
			AC_MSG_ERROR([Your libevent headers do not match your
library. Check config.log for details.
If you are sure your installation is consistent, you can disable the check
by running "./configure --without-libevent-header-check".])
		else
			AC_MSG_WARN([Your libevent headers do not match your
library. Check config.log for details.])
		fi
	],
	[
		AC_MSG_WARN([cross compiling: not checking])
	]
)

AC_MSG_CHECKING([if programs using libevent functions will link])
AC_LINK_IFELSE(
	[AC_LANG_PROGRAM([[
#if LIBEVENT_MAJOR_VERSION < 2
#include <event.h>
#else
#include <event2/event.h>
#endif
	]], [[
	event_base_new();
	]])],
	[
		AC_MSG_RESULT([yes])
	],
	[
		AC_MSG_RESULT([no])
	]
)

# Search for libdb
AC_CHECK_HEADER(db_185.h, [AC_DEFINE([HAVE_DB_185_H], [], [if you have the <db_185.h> header file]) ] , [
AC_CHECK_HEADER(db.h,     [AC_DEFINE([HAVE_DB_H],     [], [if you have the <db.h> header file])     ] , [
AC_CHECK_HEADER(db1/db.h, [AC_DEFINE([HAVE_DB1_DB_H], [], [if you have the <db1/db.h> header file]) ] , [
				AC_MSG_ERROR([*** Can't find Berkeley DB headers (see config.log for details) ***])
])])])


save_LIBS="$LIBS"
DB_LIB=

for libdb in db db1 c; do
    AC_CHECK_LIB($libdb, dbopen,       [ DB_LIB="$libdb"; break; ], 
    AC_CHECK_LIB($libdb, __db185_open, [ DB_LIB="$libdb"; break; ]))
done

if test -z "$DB_LIB" ; then
    AC_MSG_ERROR([Berkeley DB not found or not built with --enable-185])
fi

DB_LIB="-l$DB_LIB"
AC_SUBST([DB_LIB])

LIBS="$save_LIBS"

LIBS="$LIBS ${SMTPDLIBS}"
##end of chl


AC_CONFIG_FILES([Makefile
		openbsd-compat/Makefile
		mk/Makefile
		mk/filters/Makefile
		mk/filters/filter-dnsbl/Makefile
		mk/filters/filter-monkey/Makefile
		mk/filters/filter-perl/Makefile
		mk/filters/filter-python/Makefile
		mk/filters/filter-trace/Makefile
		mk/filters/filter-stub/Makefile
		mk/filters/filter-void/Makefile
		mk/queues/Makefile
		mk/queues/queue-null/Makefile
		mk/queues/queue-python/Makefile
		mk/queues/queue-ram/Makefile
		mk/queues/queue-stub/Makefile
		mk/schedulers/Makefile
		mk/schedulers/scheduler-python/Makefile
		mk/schedulers/scheduler-ram/Makefile
		mk/schedulers/scheduler-stub/Makefile
		mk/tables/Makefile
		mk/tables/table-passwd/Makefile
		mk/tables/table-ldap/Makefile
		mk/tables/table-mysql/Makefile
		mk/tables/table-postgres/Makefile
		mk/tables/table-python/Makefile
		mk/tables/table-redis/Makefile
		mk/tables/table-socketmap/Makefile
		])

#l4761
AC_OUTPUT

# Print summary of options

# Someone please show me a better way :)
A=`eval echo ${prefix}` ; A=`eval echo ${A}`
B=`eval echo ${bindir}` ; B=`eval echo ${B}`
C=`eval echo ${sbindir}` ; C=`eval echo ${C}`
D=`eval echo ${sysconfdir}` ; D=`eval echo ${D}`
E=`eval echo ${libexecdir}/${PACKAGE}/mail.local` ; E=`eval echo ${E}`
F=`eval echo ${libexecdir}/${PACKAGE}/encrypt` ; F=`eval echo ${F}`
G=`eval echo ${mandir}/${mansubdir}X` ; G=`eval echo ${G}`
H=`eval echo ${sockdir}` ; H=`eval echo ${H}`
I=`eval echo ${PRIVSEP_PATH}` ; I=`eval echo ${I}`
J=`eval echo ${user_path}` ; J=`eval echo ${J}`
K=`eval echo ${superuser_path}` ; K=`eval echo ${K}`

echo ""
echo "OpenSMTPD has been configured with the following options:"
echo "                     User binaries: $B"
echo "                   System binaries: $C"
echo "               Configuration files: $D"
echo "                mail.local program: $E"
echo "                   encrypt program: $F"
echo "                      Manual pages: $G"
echo "                    smtpd.sock dir: $H"
echo "  Privilege separation chroot path: $I"
echo "                    Manpage format: $MANTYPE"

echo ""

echo "              Host: ${host}"
echo "          Compiler: ${CC}"
echo "    Compiler flags: ${CFLAGS}"
echo "Preprocessor flags: ${CPPFLAGS}"
echo "      Linker flags: ${LDFLAGS}"
echo "         Libraries: ${LIBS}"
echo "      DB Libraries: ${DB_LIB}"
if test ! -z "${SMTPDLIBS}"; then
echo "         +for sshd: ${SMTPDLIBS}"
fi

echo ""
