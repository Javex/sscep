#include <check.h>
#include <stdlib.h>
#include "../src/sscep.h"
#include "../src/ias.h"

START_TEST(test_write_crl)
{
	// Todo: Normal run that successfully ends
}
END_TEST

START_TEST(test_write_crl_multiple)
{
	// Todo: Make a CRL reply with more than one CRL. This should lead to exit
	// code SCEP_PKISTATUS_FILE
}
END_TEST


START_TEST(test_write_crl_invalid_file_write)
{
	// Todo: Let the output file be invalid somehow. This should lead to exit
	// code SCEP_PKISTATUS_FILE
}
END_TEST

START_TEST(test_compare_subject)
{
	// Todo: Make a normal run. Perhaps we can ignore the workaround in the
	// function (see comments there). Or maybe we should raise the version
	// requirement to 0.9.7f?

	// Also do a failing comparison here as well.
}
END_TEST

START_TEST(test_write_local_cert)
{
	// Todo: Implement a function that executes normally through.
}
END_TEST

Suite * scep_conf_suite(void)
{
	Suite *s = suite_create("Fileutils");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_write_crl);
	tcase_add_test(tc_core, test_write_crl_multiple);
	tcase_add_test(tc_core, test_write_crl_invalid_file_write);
	tcase_add_test(tc_core, test_compare_subject);
	tcase_add_test(tc_core, test_write_local_cert);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s = scep_conf_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
