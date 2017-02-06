AC_PREREQ(2.67)
AC_INIT(CM4all libwas, 1.9, mk@cm4all.com, libcm4all-was)
AC_COPYRIGHT(Copyright 2010-2016 Content Management AG)
AC_CONFIG_SRCDIR(src/simple.cxx)
AC_CONFIG_AUX_DIR(build)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign 1.11 subdir-objects silent-rules])

LIBWAS_LIBTOOL_VERSION=1:0:0
AC_SUBST(LIBWAS_LIBTOOL_VERSION)

dnl Checks for programs.

AC_PROG_INSTALL
AC_PROG_CC_C99
AC_PROG_CXX
AC_PROG_LIBTOOL

dnl Checks for OS features

AC_SYS_LARGEFILE

dnl
dnl Checks for libraries.
dnl

AM_LIBAPR
AM_LIBAPR_UTIL
AX_LIBAPREQ2([], [AC_MSG_ERROR([libapreq2 not found])])

PKG_CHECK_MODULES([LIBCM4ALL_INLINE], [libcm4all-inline >= 0.3.5],,
	[AC_MSG_ERROR([libcm4all-inline not found])])

PKG_CHECK_MODULES([LIBHTTP], [libcm4all-http >= 1.2.5],,
	[AC_MSG_ERROR([libcm4all-http is required])])

PKG_CHECK_MODULES([LIBCORE], [libcore >= 1.20.5],,
	[AC_MSG_ERROR([libcore not found])])

dnl
dnl CFLAGS
dnl

AC_SUBST(AM_CFLAGS)
AC_SUBST(AM_CXXFLAGS)
AC_SUBST(AM_CPPFLAGS)

AM_CFLAGS="-Wall -Wextra"
AM_CXXFLAGS="-std=c++11"
AM_CPPFLAGS="-D_REENTRANT -D_GNU_SOURCE"

AM_CFLAGS="$AM_CFLAGS -Wmissing-prototypes -Wwrite-strings -Wcast-qual -Wfloat-equal -Wshadow -Wpointer-arith -Wbad-function-cast -Wsign-compare -Waggregate-return -Wmissing-declarations -Wmissing-noreturn -Wpacked -Wredundant-decls -Wnested-externs -Winline -Wdisabled-optimization -Wno-long-long -Wstrict-prototypes -Wundef -pedantic"

AM_CXXFLAGS="$AM_CXXFLAGS -fno-exceptions"
AM_CXXFLAGS="$AM_CXXFLAGS -fno-threadsafe-statics -fmerge-all-constants"
AM_CXXFLAGS="$AM_CXXFLAGS -Wall -Wextra"
AM_CXXFLAGS="$AM_CXXFLAGS -Wwrite-strings -Wcast-qual -Wcast-align -Wfloat-equal"
AM_CXXFLAGS="$AM_CXXFLAGS -Wshadow -Wpointer-arith -Wsign-compare"
AM_CXXFLAGS="$AM_CXXFLAGS -Wmissing-declarations -Wmissing-noreturn -Wmissing-format-attribute"
AM_CXXFLAGS="$AM_CXXFLAGS -Wredundant-decls -Wno-long-long -Wundef"
AM_CXXFLAGS="$AM_CXXFLAGS -Wno-variadic-macros"

dnl
dnl DEBUG
dnl

AC_ARG_ENABLE(debug,
	AS_HELP_STRING([--disable-debug],
		[Disable debugging (default: enabled)]),,
	enable_debug=yes)

if test x$enable_debug != xyes; then
    AM_CPPFLAGS="$AM_CPPFLAGS -DNDEBUG"
fi

AC_ARG_ENABLE(werror,
	AS_HELP_STRING([--enable-werror],
		[treat warnings as errors]),,
	enable_werror=$enable_debug)

if test x$enable_werror = xyes; then
    AM_CFLAGS="$AM_CFLAGS -Werror -pedantic-errors"
	AM_CXXFLAGS="$AM_CXXFLAGS -Werror"
fi

dnl
dnl Output files
dnl

AC_OUTPUT(
Makefile
libcm4all-was-protocol.pc
libcm4all-was-simple.pc
libcm4all-was-apreq.pc
libcm4all-was-xios.pc
)
