TESTS = test_configuration test_ias test_sceputils test_fileutils

check_PROGRAMS = test_configuration test_ias test_sceputils test_fileutils
check_LDADD = -lcrypto @CHECK_LIBS@ -lgcov
test_configuration_SOURCES = test_configuration.c $(top_builddir)/src/configuration.h
test_configuration_CFLAGS = @CHECK_CFLAGS@
test_configuration_LDADD = $(top_builddir)/src/sscep-configuration.o $(top_builddir)/src/sscep-sceputils.o $(top_builddir)/src/sscep-ias.o $(check_LDADD)

test_ias_SOURCES = test_ias.c $(top_builddir)/src/ias.h
test_ias_CFLAGS = @CHECK_CFLAGS@
test_ias_LDADD = $(top_builddir)/src/sscep-ias.o $(check_LDADD)

test_sceputils_SOURCES = test_sceputils.c $(top_builddir)/src/ias.h $(top_builddir)/src/sscep.h
test_sceputils_CFLAGS = @CHECK_CFLAGS@
test_sceputils_LDADD = $(top_builddir)/src/sscep-sceputils.o $(top_builddir)/src/sscep-ias.o $(top_builddir)/src/sscep-fileutils.o $(check_LDADD)

test_fileutils_SOURCES = test_fileutils.c $(top_builddir)/src/sscep.h
test_fileutils_CFLAGS = @CHECK_CFLAGS@
test_fileutils_LDADD = $(top_builddir)/src/sscep-fileutils.o
