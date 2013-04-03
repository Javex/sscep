#include <check.h>
#include <stdlib.h>
#include "../src/sscep.h"
#include "../src/ias.h"

START_TEST(test_write_crl)
{
	struct scep s;
	/* NYI */
}
END_TEST

Suite * scep_conf_suite(void)
{
	Suite *s = suite_create("Fileutils");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_write_crl);

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
