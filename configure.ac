AC_PREREQ(2.60)
AC_INIT(CM4all libwas, 0.5, mk@cm4all.com, libcm4all-was)
AC_COPYRIGHT(Copyright 2010-2014 Content Management AG)
AC_CONFIG_SRCDIR(src/simple.c)
AC_CONFIG_AUX_DIR(build)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign 1.11 subdir-objects silent-rules])

dnl Checks for programs.

AC_PROG_INSTALL
AC_PROG_RANLIB
AC_PROG_CC_C99

dnl Checks for OS features

AC_SYS_LARGEFILE

dnl
dnl Checks for libraries.
dnl

AM_LIBAPR
AM_LIBAPR_UTIL
AX_LIBAPREQ2([], [AC_MSG_ERROR([libapreq2 not found])])

PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.16],,
	[AC_MSG_ERROR([glib 2.16 is required])])

PKG_CHECK_MODULES([LIBHTTP], [libcm4all-http >= 1.2],,
	[AC_MSG_ERROR([libcm4all-http is required])])

PKG_CHECK_MODULES([LIBCORE], [libcore >= 1.20.5],,
	[AC_MSG_ERROR([libcore not found])])

dnl
dnl CFLAGS
dnl

AC_SUBST(AM_CFLAGS)
AC_SUBST(AM_CPPFLAGS)

AM_CFLAGS="-Wall -Wextra"
AM_CPPFLAGS="-D_REENTRANT"

if test "$am_cv_CC_dependencies_compiler_type" = "gcc3"; then
    AM_CFLAGS="$AM_CFLAGS -Wmissing-prototypes -Wwrite-strings -Wcast-qual -Wfloat-equal -Wshadow -Wpointer-arith -Wbad-function-cast -Wsign-compare -Waggregate-return -Wmissing-declarations -Wmissing-noreturn -Wpacked -Wredundant-decls -Wnested-externs -Winline -Wdisabled-optimization -Wno-long-long -Wstrict-prototypes -Wundef -pedantic"
fi

AM_CFLAGS="$AM_CFLAGS -ffunction-sections -fdata-sections"

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
fi

dnl
dnl Output files
dnl

AC_OUTPUT(
Makefile
libcm4all-was-simple.pc
libcm4all-was-apreq.pc
libcm4all-was-xios.pc
)
