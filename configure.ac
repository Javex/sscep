#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([src/sscep.c])

AC_INIT([libscep], [20121025], [https://github.com/certnanny/sscep/issues])
AM_INIT_AUTOMAKE(foreign -Wall -Werror 1.9.6)

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_SED

PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lcrypto':
#AC_CHECK_LIB([crypto], [main])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h libintl.h malloc.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/socket.h unistd.h openssl/*.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gethostbyname mempcpy memset socket strchr strdup strstr])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])
AC_OUTPUT


# Remove all optimization flags from CFLAGS
changequote({,})
CFLAGS=`echo "$CFLAGS" | $SED -e 's/-O[0-9]*//g'`
changequote([,])
# Add the special gcc flags
COVERAGE_CFLAGS="-O0 -fprofile-arcs -ftest-coverage"
COVERAGE_LDFLAGS="-lgcov"

m4_include([gcov.m4])
AC_TDD_GCOV
AC_SUBST(COVERAGE_CFLAGS)
AC_SUBST(COVERAGE_LDFLAGS)
