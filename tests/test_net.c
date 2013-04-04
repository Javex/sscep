#include <check.h>
#include <stdlib.h>

Suite * scep_conf_suite(void)
{
	Suite *s = suite_create("Net");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");


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
