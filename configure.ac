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

AC_PREREQ(2.69)

dnl AC_INIT([OpenSMTPD-extras], m4_esyscmd(date +%Y%m%d%H%M%S | sed -e 's/^\(.*\)$/5.7-\1/' | tr -d '\n'), [bugs@opensmtpd.org], [opensmtpd-extras], [https://github.com/OpenSMTPD/OpenSMTPD-extras])
AC_INIT([OpenSMTPD-extras], [5.7.2], [bugs@opensmtpd.org], [opensmtpd-extras], [https://github.com/OpenSMTPD/OpenSMTPD-extras])

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

AM_INIT_AUTOMAKE([subdir-objects no-dependencies])

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
	arpa/inet.h \
	dirent.h \
	fcntl.h \
	inttypes.h \
	limits.h \
	mach/mach_time.h \
	ndir.h \
	netdb.h \
	netinet/in.h \
	pam/pam_appl.h \
	paths.h \
	security/pam_appl.h \
	stdint.h \
	stdlib.h \
	string.h \
	strings.h \
	sys/dir.h \
	sys/ndir.h \
	sys/param.h \
	sys/pstat.h \
	sys/socket.h \
	sys/time.h \
	sys/un.h \
	syslog.h \
	time.h \
	ucred.h \
	unistd.h
])

#l432 (customized)
# Check for some target-specific stuff
	case "$host" in
*-*-aix*)
	check_for_aix_broken_getaddrinfo=1
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
	;;
*-*-freebsd*)
	check_for_libcrypt_later=1
	AC_DEFINE([BROKEN_GLOB], [1], [FreeBSD glob does not do what we need])
	;;
*-*-openbsd*)
	use_pie=auto
	AC_DEFINE([HAVE_ATTRIBUTE__SENTINEL__], [1], [OpenBSD's gcc has sentinel])
	AC_DEFINE([HAVE_ATTRIBUTE__BOUNDED__], [1], [OpenBSD's gcc has bounded])
	asr_in_libc=1
	;;
esac
AM_CONDITIONAL([NO_LIBASR], [test x$asr_in_libc = x1])

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

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_FSEEKO
AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_CHECK_FUNCS([ \
	arc4random \
	arc4random_uniform \
	asprintf \
	closefrom \
	dirfd \
	freeaddrinfo \
	getaddrinfo \
	getline \
	gethostname \
	getnameinfo \
	getopt \
	memmove \
	memchr \
	memset \
	regcomp \
	setsid \
	socketpair \
	strdup \
	strerror \
	strncasecmp \
	strpbrk \
	strrchr \
	strtol \
	strtoumax \
	strtoull \
	strlcat \
	strlcpy \
	strtonum \
	sysconf \
	time \
	tzset \
	vasprintf \
	vsnprintf
])

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

<<<<<<< HEAD
AC_CHECK_DECLS([MAXSYMLINKS], , , [
#include <sys/param.h>
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

=======
AC_CHECK_DECLS([offsetof], , , [
#include <stddef.h>
	])

>>>>>>> remove unused functions from configure and compat layer
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

dnl see whether mkstemp() requires XXXXXX
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

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AC_CHECK_TYPES([long long, unsigned long long])

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

if (test -z "$have_u_intxx_t" && \
	   test "x$ac_cv_header_sys_bitypes_h" = "xyes")
then
	AC_MSG_CHECKING([for and u_intXX_t types in sys/bitypes.h])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/bitypes.h>
		]], [[
			u_int8_t a; u_int16_t b; u_int32_t c;
			a = b = c = 1;
		]])],
		[
			AC_DEFINE([HAVE_U_INTXX_T])
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

TYPE_SOCKLEN_T

AC_CHECK_TYPES([sig_atomic_t], , , [#include <signal.h>])

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

case "$host" in
*-*-openbsd*)
	pkglibexecdir="$libexecdir/smtpd"
	;;
*)
	pkglibexecdir="$libexecdir/opensmtpd"
	;;
esac
AC_SUBST([pkglibexecdir])


#
# individual modules
#

#
# FILTERS
#
HAVE_FILTER_CLAMAV=no
AC_ARG_WITH([filter-clamav],
	[  --with-filter-clamav	Enable filter clamav],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_FILTER_CLAMAV], [1],
				[Define if you have filter clamav])
			HAVE_FILTER_CLAMAV=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_FILTER_CLAMAV], [test $HAVE_FILTER_CLAMAV = yes])

HAVE_FILTER_DKIM_SIGNER=no
AC_ARG_WITH([filter-dkim-signer],
	[  --with-filter-dkim-signer	Enable filter dkim-signer],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_FILTER_DKIM_SIGNER], [1],
				[Define if you have filter dkim-signer])
			HAVE_FILTER_DKIM_SIGNER=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_FILTER_DKIM_SIGNER], [test $HAVE_FILTER_DKIM_SIGNER = yes])

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

HAVE_FILTER_LUA=no
AC_ARG_WITH([filter-lua],
	[  --with-filter-lua	Enable filter lua],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_FILTER_LUA], [1],
				[Define if you have filter lua])
			HAVE_FILTER_LUA=yes
			need_lua=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_FILTER_LUA], [test $HAVE_FILTER_LUA = yes])

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

HAVE_FILTER_PAUSE=no
AC_ARG_WITH([filter-pause],
	[  --with-filter-pause	Enable filter pause],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_FILTER_PAUSE], [1],
				[Define if you have filter pause])
			HAVE_FILTER_PAUSE=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_FILTER_PAUSE], [test $HAVE_FILTER_PAUSE = yes])

HAVE_FILTER_PERL=no
AC_ARG_WITH([filter-perl],
	[  --with-filter-perl	Enable filter perl],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_FILTER_PERL], [1],
				[Define if you have filter perl])
			HAVE_FILTER_PERL=yes
			need_perl=yes
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
			need_python=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_FILTER_PYTHON], [test $HAVE_FILTER_PYTHON = yes])

HAVE_FILTER_REGEX=no
AC_ARG_WITH([filter-regex],
	[  --with-filter-regex	Enable filter regex],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_FILTER_REGEX], [1],
				[Define if you have filter regex])
			HAVE_FILTER_REGEX=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_FILTER_REGEX], [test $HAVE_FILTER_REGEX = yes])

HAVE_FILTER_SPAMASSASSIN=no
AC_ARG_WITH([filter-spamassassin],
	[  --with-filter-spamassassin	Enable filter spamassassin],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_FILTER_SPAMASSASSIN], [1],
				[Define if you have filter spamassassin])
			HAVE_FILTER_SPAMASSASSIN=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_FILTER_SPAMASSASSIN], [test $HAVE_FILTER_SPAMASSASSIN = yes])

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
			need_python=yes
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
			need_redis=yes
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
			need_python=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_TABLE_PYTHON], [test $HAVE_TABLE_PYTHON = yes])

HAVE_TABLE_SQLITE=no
AC_ARG_WITH([table-sqlite],
	[  --with-table-sqlite	Enable table SQLite],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_TABLE_SQLITE], [1],
				[Define if you have SQLite support])
			HAVE_TABLE_SQLITE=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_TABLE_SQLITE], [test $HAVE_TABLE_SQLITE = yes])

HAVE_TABLE_STUB=no
AC_ARG_WITH([table-stub],
	[  --with-table-stub	Enable table stub],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_TABLE_STUB], [1],
				[Define if you have stub support])
			HAVE_TABLE_STUB=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_TABLE_STUB], [test $HAVE_TABLE_STUB = yes])


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

HAVE_SCHEDULER_PYTHON=no
AC_ARG_WITH([scheduler-python],
	[  --with-scheduler-python	Enable scheduler python],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE([HAVE_SCHEDULER_PYTHON], [1],
				[Define if you have scheduler python])
			HAVE_SCHEDULER_PYTHON=yes
			need_python=yes
		fi
	]
)
AM_CONDITIONAL([HAVE_SCHEDULER_PYTHON], [test $HAVE_SCHEDULER_PYTHON = yes])


AC_ARG_WITH([python],
	[  --with-python=PATH    Specify prefix of python installation ],
	[
		if test "x$withval" != "xno" ; then
			python_prefix="${withval}"
		fi
	]
)

AC_ARG_WITH([perl],
	[  --with-perl=PATH      Specify prefix of perl installation ],
	[
		if test "x$withval" != "xno" ; then
			perl_prefix="${withval}"
		fi
	]
)

AC_ARG_WITH([lua],
	[  --with-lua=PATH       Specify prefix of lua installation ],
	[
		if test "x$withval" != "xno" ; then
			lua_prefix="${withval}"
		fi
	]

)
AC_ARG_WITH([lua-type],
	[  --with-lua-type=PATH  Specify the type of lua used (automatic if unspecified, otherwise luajit, lua, or another version) ],
	[
		if test "x$withval" != "xno" ; then
			lua_type="${withval}"
		fi
	]
)

#
# check for python
#
PYTHON_CPPFLAGS=
PYTHON_LDFLAGS=
if test x"${need_python}" = x"yes"; then
   PYTHON_CONFIG=
   for path in /usr/local/bin /usr/bin; do
	if test -f ${path}/python-config; then
		PYTHON_CONFIG=${path}/python-config
		break
	fi
   done

   # if python provided --with-python, override
   if test x"${with_python}" != x""; then
      PYTHON_CONFIG="${python_prefix}/bin/python-config"
   fi

   if ! test -f $PYTHON_CONFIG; then
      AC_MSG_ERROR([*** $PYTHON_CONFIG could not be found, please install or use --with-python ***])
   fi

   PYTHON_CPPFLAGS="`$PYTHON_CONFIG --includes`"
   PYTHON_LDFLAGS="-L`$PYTHON_CONFIG --prefix`/lib `$PYTHON_CONFIG --libs`"
fi
AC_SUBST([PYTHON_CPPFLAGS])
AC_SUBST([PYTHON_LDFLAGS])

#
# check for perl
#
PERL_CPPFLAGS=
PERL_LDFLAGS=
if test x"${need_perl}" = x"yes"; then
   PERL_CONFIG=
   for path in /usr/local/bin /usr/bin; do
	if test -f ${path}/perl; then
		PERL_CONFIG=${path}/perl
		break
	fi
   done

   # if perl provided --with-perl, override
   if test x"${with_perl}" != x""; then
      PERL_CONFIG="${perl_prefix}/bin/perl"
   fi

   if ! test -f $PERL_CONFIG; then
      AC_MSG_ERROR([*** $PERL_CONFIG could not be found, please install or use --with-perl ***])
   fi

   PERL_CPPFLAGS="`perl -MExtUtils::Embed -e ccopts`"
   PERL_LDFLAGS="`perl -MExtUtils::Embed -e ldopts`"
fi
AC_SUBST([PERL_CPPFLAGS])
AC_SUBST([PERL_LDFLAGS])

#
# check for lua
#
LUA_CPPFLAGS=
LUA_LDFLAGS=
if test x"${need_lua}" = x"yes"; then
   LUA_CONFIG=
   for path in /usr/local/bin /usr/bin; do
	if test -f ${path}/pkg-config; then
		LUA_CONFIG=${path}/pkg-config
		break
	fi
   done

   # if lua provided --with-lua, override
   if test x"${with_lua}" != x""; then
      LUA_CONFIG="${lua_prefix}/bin/pkg-config"
   fi

   if ! test -f $LUA_CONFIG; then
     if test x"${lua_type}" = x""; then
       for i in luajit lua lua5.2 lua-5.2 lua5.1 lua-5.1; do
         if test -d ${lua_prefix:-/usr/local}/include/${i}*; then
	   lua_type=$i
	   break
	 fi
       done
     fi
     LUA_CPPFLAGS="-I${lua_prefix:-/usr/local}/include/${lua_type}"
     LUA_LDFLAGS="-L${lua_prefix:-/usr/local}/lib -l${lua_type} -lm"
   else
     if test x"${lua_type}" = x""; then
       for i in luajit lua lua5.2 lua-5.2 lua5.1 lua-5.1; do
         if $LUA_CONFIG --exists $i 2>/dev/null; then
	   lua_type=$i
	   break
	 fi
       done
     fi
     LUA_CPPFLAGS="`$LUA_CONFIG --cflags $lua_type`"
     LUA_LDFLAGS="`$LUA_CONFIG --libs $lua_type`"
   fi
fi
AC_SUBST([LUA_CPPFLAGS])
AC_SUBST([LUA_LDFLAGS])

#
# check for hiredis
#
REDIS_CPPFLAGS=
REDIS_LDFLAGS=
if test x"${need_redis}" = x"yes"; then
   REDIS_CONFIG=
   for path in /usr/local/bin /usr/bin; do
	if test -f ${path}/pkg-config; then
		REDIS_CONFIG=${path}/pkg-config
		break
	fi
   done

   # if redis provided --with-redis, override
   if test x"${with_hiredis}" != x""; then
      REDIS_CONFIG="${redis_prefix}/bin/pkg-config"
   fi

   if ! test -f $REDIS_CONFIG; then
      AC_MSG_ERROR([*** $REDIS_CONFIG could not be found, please install or use --with-redis ***])
   fi

   REDIS_CPPFLAGS="`$REDIS_CONFIG --cflags hiredis`"
   REDIS_LDFLAGS="`$REDIS_CONFIG --libs hiredis`"
fi
AC_SUBST([REDIS_CPPFLAGS])
AC_SUBST([REDIS_LDFLAGS])

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
			need_libevent_autodetect=no
		fi
	]
)

if test x"${need_libevent_autodetect}" != x"no"; then
   for path in /usr/local /usr; do
       if test -f "${path}/include/event.h"; then
       	  CPPFLAGS="-I${path}/include ${CPPFLAGS}"
	  LDFLAGS="-L${path}/lib ${LDFLAGS}"
       fi
   done
fi

LIBS="-levent $LIBS"

AC_MSG_CHECKING([if programs using libevent functions will link])
AC_LINK_IFELSE(
	[AC_LANG_PROGRAM([[
	#include <event.h>
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

LIBS="$LIBS ${SMTPDLIBS}"
##end of chl


AC_CONFIG_FILES([Makefile
		openbsd-compat/Makefile

		extras/Makefile
		extras/stable/Makefile
		extras/wip/Makefile

		extras/wip/filters/Makefile
		extras/wip/filters/filter-clamav/Makefile
		extras/wip/filters/filter-dkim-signer/Makefile
		extras/wip/filters/filter-dnsbl/Makefile
		extras/wip/filters/filter-lua/Makefile
		extras/wip/filters/filter-monkey/Makefile
		extras/wip/filters/filter-pause/Makefile
		extras/wip/filters/filter-perl/Makefile
		extras/wip/filters/filter-python/Makefile
		extras/wip/filters/filter-regex/Makefile
		extras/wip/filters/filter-spamassassin/Makefile
		extras/wip/filters/filter-stub/Makefile
		extras/wip/filters/filter-trace/Makefile
		extras/wip/filters/filter-void/Makefile

		extras/wip/queues/Makefile
		extras/wip/queues/queue-null/Makefile
		extras/wip/queues/queue-python/Makefile
		extras/wip/queues/queue-ram/Makefile
		extras/wip/queues/queue-stub/Makefile

		extras/wip/schedulers/Makefile
		extras/wip/schedulers/scheduler-python/Makefile
		extras/wip/schedulers/scheduler-ram/Makefile
		extras/wip/schedulers/scheduler-stub/Makefile

		extras/wip/tables/Makefile
		extras/wip/tables/table-passwd/Makefile
		extras/wip/tables/table-ldap/Makefile
		extras/wip/tables/table-mysql/Makefile
		extras/wip/tables/table-postgres/Makefile
		extras/wip/tables/table-python/Makefile
		extras/wip/tables/table-redis/Makefile
		extras/wip/tables/table-socketmap/Makefile
		extras/wip/tables/table-sqlite/Makefile
		extras/wip/tables/table-stub/Makefile
		])

#l4761
AC_OUTPUT

# Print summary of options

# Someone please show me a better way :)
A=`eval echo ${prefix}` ; A=`eval echo ${A}`
B=`eval echo ${bindir}` ; B=`eval echo ${B}`
C=`eval echo ${sbindir}` ; C=`eval echo ${C}`
D=`eval echo ${sysconfdir}` ; D=`eval echo ${D}`
E=`eval echo ${mandir}/${mansubdir}X` ; E=`eval echo ${E}`
F=`eval echo ${PRIVSEP_PATH}` ; F=`eval echo ${F}`

echo ""
echo "OpenSMTPD-extras have been configured with the following options:"
echo "                     User binaries: $B"
echo "                   System binaries: $C"
echo "               Configuration files: $D"
echo "                      Manual pages: $E"
echo "  Privilege separation chroot path: $F"
echo "                Package libexecdir: ${pkglibexecdir}"
echo "                    Manpage format: $MANTYPE"
echo ""

echo "              Host: ${host}"
echo "          Compiler: ${CC}"
echo "    Compiler flags: ${CFLAGS}"
echo "Preprocessor flags: ${CPPFLAGS}"
echo "      Linker flags: ${LDFLAGS}"
echo "         Libraries: ${LIBS}"
echo ""

if test x"${need_python}" = x"yes"; then
echo "Built with Python support:"
echo "          CPPFLAGS: ${PYTHON_CPPFLAGS}"
echo "           LDFLAGS: ${PYTHON_LDFLAGS}"
echo ""
fi

if test x"${need_perl}" = x"yes"; then
echo "Built with Perl support:"
echo "          CPPFLAGS: ${PERL_CPPFLAGS}"
echo "           LDFLAGS: ${PERL_LDFLAGS}"
echo ""
fi

if test x"${need_lua}" = x"yes"; then
echo "Built with Lua support:"
echo "          CPPFLAGS: ${LUA_CPPFLAGS}"
echo "           LDFLAGS: ${LUA_LDFLAGS}"
echo ""
fi

if test x"${need_redis}" = x"yes"; then
echo "Built with redis support:"
echo "          CPPFLAGS: ${REDIS_CPPFLAGS}"
echo "           LDFLAGS: ${REDIS_LDFLAGS}"
echo ""
fi
