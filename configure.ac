#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([libscep], [20121025], [https://github.com/certnanny/sscep/issues])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE(foreign -Wall -Werror 1.9.6)
AC_CONFIG_SRCDIR([src/sscep.c])


# Checks for programs.
AC_PROG_CC

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
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
