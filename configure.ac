dnl Process this File with autoconf to produce a configure script.
AC_PREREQ([2.69])
AC_INIT([gsocket],[1.4.40])
AC_CONFIG_AUX_DIR(config)
AC_CANONICAL_TARGET

dnl we use automake
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_HEADERS(config.h)
AM_PROG_AR
dnl for --enable-maintainer-mode fun use:
dnl AM_MAINTAINER_MODE 
dnl AC_DISABLE_STATIC
dnl LT_INIT([disable-static])

dnl AC_CONFIG_MACRO_DIRS([m4])

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_CHECK_PROG([MAKE_CHECK], [make], [yes], [no])
AS_IF([test x$MAKE_CHECK = xno], [AC_MSG_ERROR([make not found])])

dnl
dnl Use these compiler flags if we have gcc.
dnl
if test $ac_cv_c_compiler_gnu = yes; then
  CCOPTS='-O2 -Wall'
  CFLAGS="$CCOPTS $CFLAGS"
fi
test "x$prefix" != "xNONE" || prefix="/usr/local"
test "x$exec_prefix" != "xNONE" || exec_prefix="${prefix}"

dnl Do "gcc -xc -E -v -" to figure out default paths
dnl Scenarios
dnl --prefix=$HOME/usr                                 => -I$HOME/usr/include /usr/include /usr/local/include
dnl --prefix=/usr       --includedir=$HOME/usr/include => -I$HOME/usr/include /usr/include /usr/local/include
dnl --prefix=/usr/local --includedir=$HOME/usr/include => -I$HOME/usr/include /usr/local/include /usr/include

dnl default: PREFIX/include unless --includedir=

dnl Try include paths (especially on OSX)
dnl Special consideration if openssl/srp.h exist in $HOME/usr/include
dnl and also the /usr/include/openssl exists. GCC shall use
dnl $HOME/usr/include/openssl/srp.h first but not if $prefix is /usr or any
dnl of the default system paths
dnl To make everyone happy we have to consider:
dnl --prefix=$HOME/usr          => Must _first_ add $HOME/usr/include
dnl --prefix=/usr               => Must _never_ add /usr/include (or _last_)

test "x$prefix" != "x/usr" && test "x$prefix" != "x/usr/local" && trydir_i="${prefix}/include"
trydir_i="${trydir_i} /usr/local/opt/openssl/include /opt/homebrew/opt/openssl/include"

for xincdir in $includedir $trydir_i ; do
	if test ! -d "$xincdir" ; then
		continue;
	fi
	if test x"${INCLUDES}" = x; then
		INCLUDES="-I${xincdir}";
	else
		INCLUDES="$INCLUDES -I${xincdir}";
	fi
done
CPPFLAGS="-I${srcdir}/../include ${INCLUDES} $CPPFLAGS"

dnl Try library paths...
test "x$prefix" != "x/usr" && test "x$prefix" != "x/usr/local" && trydir_l="${prefix}/lib"
trydir_l="${trydir_l} /usr/local/opt/openssl/lib /opt/homebrew/opt/openssl/lib"
for xlibdir in $libdir $trydir_l ; do
	if test ! -d "$xlibdir" ; then
		continue;
	fi
	if test -f "${xlibdir}/libssl.a"; then
		STATIC_LIBSSLDIR="${xlibdir}"
	fi
	if test x"${LIBDIR}" = x; then
		LIBDIR="-L${xlibdir}";
	else
		LIBDIR="$LIBDIR -L${xlibdir}";
	fi
done
LDFLAGS="${LIBDIR} $LDFLAGS"

dnl default perm of .so is 644 but on cygwin must be 755.
PERM_DSO="644"
case "$host" in
*-cygwin*)
	PERM_DSO="755"
	;;
mips-sony-bsd|mips-sony-newsos4)
        AC_DEFINE([NEED_SETPGRP], [1], [Need setpgrp to acquire controlling tty])
	;;
*-*-ultrix*)
        AC_DEFINE([NEED_SETPGRP], [1], [Need setpgrp to acquire controlling tty])
	;;
*-*-darwin*|*-*-*bsd*)
	AC_DEFINE([BSD_SCRIPT], [1], [/usr/bin/script is the bsd variant])
	if test x"$(which ar)" != x'/usr/bin/ar'; then
		ARDIRWARN=1
	fi
	;;
esac

dnl debian packaging requires -soname for LD_PRELOAD libs
dnl OSX's linker does not allow -soname.
SONAME_GSOCKET_DSO="-Wl,-soname=gsocket_dso.so.0"
SONAME_GSOCKET_UCHROOT_DSO="-Wl,-soname=gsocket_uchroot_dso.so.0"
case "$host" in
*-*-darwin*)
	SONAME_GSOCKET_DSO=""
	SONAME_GSOCKET_UCHROOT_DSO=""
	;;
esac

dnl Checks for header files.
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(sys/time.h sys/endian.h unistd.h fnmatch.h string.h utmp.h utmpx.h pty.h openssl/srp.h util.h libutil.h netinet/in_systm.h sys/loadavg.h libproc.h)

AC_CHECK_HEADER(openssl/srp.h, [], [AC_MSG_ERROR([openssl/srp.h not found. Update OpenSSL or apt install libssl-dev?])])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T

dnl Checks for library functions.
AC_FUNC_MEMCMP

dnl If size_t is not defined, define size_t to be unsigned. 
AC_TYPE_SIZE_T 
dnl If uid_t is not defined, define uid_t to be int and gid_t to be int.
AC_TYPE_UID_T

AC_ARG_ENABLE(static,
[  --enable-static          Compile static binary],
	[STATIC="yes"], [STATIC="no"]
)

dnl OSX does not support static binaries.
dnl At least staticly include OpenSSL libs
if test x"${STATIC}" = xyes; then
	case "$host" in
	*-*-darwin*)
		LDADD_STATIC="${STATIC_LIBSSLDIR}/libssl.a ${STATIC_LIBSSLDIR}/libcrypto.a"
		AC_DEFINE(HAVE_LIBSSL, 1, [Define to 1 if you have the `ssl' library (-lssl)])
		AC_DEFINE(HAVE_LIBCRYPTO, 1, [Define to 1 if you have the `crypto' library (-lcrypto)])
		STATIC_SSL="yes"
		;;
	*)
		CFLAGS_STATIC="-static "
		;;
	esac
fi

AC_CHECK_LIB(util, forkpty)
AC_CHECK_LIB(socket, socket)
if test x"${STATIC}" = xno; then
  AC_CHECK_LIB(nsl, gethostbyname)
fi
dnl AC_CHECK_LIB([net], [libnet_name_resolve], [AC_MSG_ERROR([libnet 1.0.x found. Requires libnet 1.1 or newer])])
dnl AC_CHECK_LIB([net], [libnet_init], ,[AC_MSG_ERROR([libnet 1.1.x not found])])
if test x"$STATIC" = xno; then
	AC_CHECK_LIB(dl, dlopen)
fi
AC_CHECK_LIB(procstat, procstat_close)
dnl 
if test x"$STATIC_SSL" != xyes; then
  AC_CHECK_LIB([crypto], [ENGINE_init], [], [AC_MSG_ERROR([libcrypto not found])])
  AC_CHECK_LIB([ssl], [SRP_VBASE_get1_by_user], [], [AC_MSG_ERROR([SRP not supported. Please upgrade OpenSSL lib])])
fi

AC_CHECK_FUNCS(gettimeofday memcpy strchr strlcat forkpty openpty getline stat64 open64 statvfs64 accept4 connectx)

AC_ARG_ENABLE([31337],
	AS_HELP_STRING([--enable-31337], [Enable experimental features.]),
	AC_DEFINE(D31337, 1, [Expermental feature])
)

AC_ARG_ENABLE([stealth],
	AS_HELP_STRING([--enable-stealth], [Stip -h and -m strings.]),
	AC_DEFINE(STEALTH, 1, [Stealth Mode])
)

AC_ARG_ENABLE([debug],
	AS_HELP_STRING([--enable-debug], [Enable debug information.]),
	[debug=true AC_DEFINE(DEBUG, 1, [Debug infos])]
)

AC_ARG_ENABLE([tests],
	AS_HELP_STRING([--enable-tests], [Enable self-tests.]),
	[selftests=true]
)

AS_IF([test x$enable_debug = xyes], AC_DEFINE(D31337, 1, [Expermental feature]))
AS_IF([test x$enable_debug = xyes], [selftests=true])

AS_IF([test x$selftests = xtrue], AC_DEFINE(SELFTESTS, 1, [Self Tests]))

AC_ARG_ENABLE(dist,
[  --enable-dist           Enable distribution mode, Use own libraries.],
	[DIST="yes"], [DIST="no"]
)

AC_ARG_ENABLE(realprefix,
[  --enable-realprefix     Set real prefix (for dpkg packaging)],
	[REALPREFIX="${enableval}"], [REALPREFIX="${prefix}"]
)

AS_IF([test x$selftests = xtrue], AC_SUBST(PROGRAMS_TEST_LIB, "list-test${EXEEXT} event-test${EXEEXT}"))
AS_IF([test x$selftests = xtrue], AC_SUBST(PROGRAMS_TEST_TOOLS, "packet-test${EXEEXT} readline-test${EXEEXT} console_display-test${EXEEXT} filetransfer-test${EXEEXT}"))

AC_SUBST(LDADD_STATIC, "${LDADD_STATIC}")
AC_SUBST(CFLAGS_STATIC, "${CFLAGS_STATIC}")
AC_SUBST(PERM_DSO, "${PERM_DSO}")
AC_SUBST(SONAME_GSOCKET_DSO, "${SONAME_GSOCKET_DSO}")
AC_SUBST(SONAME_GSOCKET_UCHROOT_DSO, "${SONAME_GSOCKET_UCHROOT_DSO}")
AC_SUBST(REALPREFIX, "${REALPREFIX}")
AC_CONFIG_FILES([Makefile lib/Makefile tools/Makefile include/Makefile include/gsocket/Makefile tools/gsocket.conf man/Makefile examples/Makefile])
AC_OUTPUT


echo "

      \"If netcat is a swiss army knife then
                        gs-netcat is a germanic battle axe\"

	                        --acpizer/United Cracking Force
"

if test x"${STATIC}" = xyes; then
	case "$host" in
	*-*-darwin*)
		echo "
*** OSX does not support static binaries. Creating dynamic binaries ***
*** instead and trying our best to included OpenSSL statically.     ***
"
		;;
	*)
		echo "
********************************** WARNING ***********************************
* Your MUST compile OpenSSL like this:                                       *
* openssl-src>                                                               *
* ./Configure --prefix=\$HOME/usr no-dso no-threads no-shared linux-generic64 * 
* mkdir -p \$HOME/usr && make install_sw                                      *
* Only then compile gsocket \(using the same --prefix=\):                    *
* gsocket-src> ./configure --prefix=\$HOME/usr --enable-static                *
* gsocket-src> make all install                                              *
* gsocket-src> export PATH=\$HOME/usr/bin:\$PATH                               *
******************************************************************************
"
		;;
	esac
fi

echo "
${PACKAGE_NAME}-${PACKAGE_VERSION} has been configured:

 Host..............: ${host}
 Prefix............: ${prefix}
 Compiler..........: ${CC}
 Compiler flags....: ${CFLAGS_STATIC}${CFLAGS}
 Preprocessor flags: ${CPPFLAGS}
 Linker flags......: ${LDFLAGS}
 Libraries.........: ${LIBS}

Configuration complete. Now type: make all install"
if test x"${ARDIRWARN}" = x1; then
	AC_MSG_WARN([Build tools seem to be a mix of GNU and Apple.])
	AC_MSG_WARN([Alex, try 'PATH=/usr/bin:\$PATH ./configure'.])
fi

