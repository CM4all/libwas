dnl CM4all acinclude.m4 $Rev: 905 $
dnl $Date: 2009-03-10 12:13:57 +0100 (Tue, 10 Mar 2009) $
dnl Author: Max Kellermann (mke@cm4all.com)
dnl
dnl The master version of this file can be found at:
dnl http://subversion.intern.cm-ag/svn/dfs/trunk/acinclude.m4
dnl  - 2004/03/25 Max Kellermann (mke@cm4all.com)

dnl -----------------------------------+
dnl  Apache2                           |
dnl -----------------------------------+

AC_DEFUN([AM_LIBAPR],[

        AC_ARG_WITH(
                apr-config,
                [  --with-apr-config=FILE        apr-config script],
                ,
                [ AC_PATH_PROG(with_apr_config, [apr-config]) ]
        )

        AC_MSG_CHECKING( apr-config )

        if ! test -x "$with_apr_config"; then
                AC_MSG_ERROR( apr-config not found )
        fi

        AC_MSG_RESULT( $with_apr_config )

        LIBAPR_CFLAGS="`$with_apr_config --cppflags` -isystem`$with_apr_config --includedir`"
        LIBAPR_LIBS=`$with_apr_config --link-ld`

        AC_SUBST(LIBAPR_CFLAGS)
        AC_SUBST(LIBAPR_LIBS)
])

AC_DEFUN([AM_LIBAPR_UTIL],[

        AC_ARG_WITH(
                apu-config,
                [  --with-apu-config=FILE        apu-config script],
                ,
                [ AC_PATH_PROG(with_apu_config, [apu-config]) ]
        )

        AC_MSG_CHECKING( apu-config )

        if ! test -x "$with_apu_config"; then
                AC_MSG_ERROR( apu-config not found )
        fi

        AC_MSG_RESULT( $with_apu_config )

        LIBAPR_UTIL_CFLAGS="-isystem`$with_apu_config --includedir`"
        LIBAPR_UTIL_LIBS=`$with_apu_config --link-ld`

        AC_SUBST(LIBAPR_UTIL_CFLAGS)
        AC_SUBST(LIBAPR_UTIL_LIBS)
])
