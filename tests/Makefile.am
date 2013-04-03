TESTS = test_configuration

check_PROGRAMS = test_configuration
test_configuration_SOURCES = test_configuration.c $(top_builddir)/src/configuration.h
test_configuration_CFLAGS = @CHECK_CFLAGS@
test_configuration_LDADD = $(top_builddir)/src/sscep-configuration.o $(top_builddir)/src/sscep-sceputils.o $(top_builddir)/src/sscep-ias.o -lcrypto @CHECK_LIBS@ -lgcov

