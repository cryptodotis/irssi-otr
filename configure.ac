AC_INIT([irssi-otr],[1.0.0],[dgoulet@ev0ke.net],[],[Web])
AC_CONFIG_AUX_DIR([config])
AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([config])
AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_GREP
AC_PROG_CC

AM_PROG_LIBTOOL

# Check for pthread
AC_CHECK_LIB([pthread], [pthread_create], [],
	[AC_MSG_ERROR([Cannot find libpthread. Use [LDFLAGS]=-Ldir to specify its location.])]
)

AC_SEARCH_LIBS([otrl_init], [otr], [],
	[AC_MSG_ERROR([Cannot find libotr. Use [LDFLAGS]=-Ldir to specify its location.])]
)

# Check for Glib. It needs to be installed anyway or this macro will not be defined.
AM_PATH_GLIB_2_0([2.22.0], [],
			[AC_MSG_ERROR([Glib 2.22 is required in order to compile.
			Please install the Glib development files.])], [gmodule])

AM_PATH_LIBGCRYPT(1:1.2.0,,AC_MSG_ERROR(libgcrypt 1.2.0 or newer is required.))

AM_PATH_LIBOTR(4.0.0, [], [AC_MSG_ERROR([libotr 4.0.0 or newer is required.])])

pkg_modules="gmodule-2.0 >= 2.0.0"
PKG_CHECK_MODULES(GMODULE, [$pkg_modules])
AC_SUBST(PACKAGE_LIBS)
LIBS="$LIBS $GMODULE_LIBS"

PACKAGE_CFLAGS="$GMODULE_CFLAGS -Wall -Werror=format-security"
AC_SUBST(PACKAGE_CFLAGS)

LT_INIT

CFLAGS="-Wall $CFLAGS -g -fno-strict-aliasing -fstack-protector-all -D_FORTIFY_SOURCE=2 -O1 -Wl,-z,relro,-z,now -fPIE -pie"

DEFAULT_INCLUDES="-I\$(top_srcdir) -I\$(top_builddir) -I\$(top_builddir)/src -I\$(top_builddir)/include"

AC_SUBST(DEFAULT_INCLUDES)

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])

AC_OUTPUT

#
# Mini-report on what will be built
#
AS_ECHO()

# Target architecture we're building for
target_arch=$host_cpu
[
for f in $CFLAGS; do
        if test $f = "-m32"; then
			target_arch="32-bit"
        elif test $f = "-m64"; then
			target_arch="64-bit"
        fi
done
]
AS_ECHO_N("Target architecture: ")
AS_ECHO($target_arch)

# Print the bindir and libdir this `make install' will install into.
AS_ECHO()
AS_ECHO_N("Binaries will be installed in:  ")
AS_ECHO("`eval eval echo $bindir`")
AS_ECHO_N("Libraries will be installed in: ")
AS_ECHO("`eval eval echo $libdir`")
AS_ECHO()
