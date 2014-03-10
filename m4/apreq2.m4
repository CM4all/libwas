dnl
dnl Usage:
dnl AX_LIBAPREQ2([ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
dnl

AC_DEFUN([AX_LIBAPREQ2], [
	AC_ARG_WITH([apreq2-config],
		AS_HELP_STRING([--with-apreq2-config=PATH],
			[Location of the apreq2-config program]),
		[],
		[AC_PATH_PROG([with_apreq2_config], [apreq2-config], [no])])

	if test x$with_apreq2_config = xno; then
		$2
		:
	else
                LIBAPREQ2_CFLAGS="-isystem `$with_apreq2_config --includedir`"
                LIBAPREQ2_LIBS="`$with_apreq2_config --link-ld`"
		$1
	fi

        AC_SUBST(LIBAPREQ2_CFLAGS)
        AC_SUBST(LIBAPREQ2_LIBS)
])
