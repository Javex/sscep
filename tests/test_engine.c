#include <check.h>
#include <stdlib.h>
#include <openssl/ossl_typ.h>
#include "../src/configuration.h"

#define ENGINE_CNF "test-conf/test_sscep_engine.cnf"
#define ENGINE_TEST_KEY "test-pki/test-ias.key"

ENGINE *test_e;

void setup()
{
	scep_conf_init(ENGINE_CNF);
	test_e = scep_engine_init(test_e);
}

void teardown()
{
	ENGINE_free(test_e);
}


START_TEST(test_scep_engine_init)
{
	ENGINE *local_test_e = NULL;
	scep_conf_init(ENGINE_CNF);
	scep_engine_init(local_test_e);

}
END_TEST

START_TEST(test_scep_engine_init_jksengine)
{
	// todo: Make a test with the JKSEngine engine to make sure that path is taken.
}
END_TEST

START_TEST(test_scep_engine_init_pkcs11)
{
	// todo: Make a test with the PKCS#11 engine to make sure that path is taken.
}
END_TEST

START_TEST(test_scep_engine_load_dynamic)
{
	// todo: Dynamically load an engine and make sure it initalizes
}
END_TEST

START_TEST(test_sscep_engine_read_key)
{
	EVP_PKEY *test_key;
	sscep_engine_read_key(&test_key, ENGINE_TEST_KEY, test_e);
	ck_assert(test_key != NULL);
}
END_TEST

START_TEST(test_sscep_engine_read_key_invalid_key)
{
	// need a test with a key that does not work
	// expect exit with SCEP_PKISTATUS_FILE
}
END_TEST

START_TEST(test_sscep_engine_read_key_old)
{
	EVP_PKEY *test_key;
	sscep_engine_read_key_old(&test_key, ENGINE_TEST_KEY, test_e);
	ck_assert(test_key != NULL);
}
END_TEST

START_TEST(test_sscep_engine_read_key_new)
{
	EVP_PKEY *test_key;
	sscep_engine_read_key_new(&test_key, ENGINE_TEST_KEY, test_e);
	ck_assert(test_key != NULL);
}
END_TEST

START_TEST(test_sscep_engine_report_error)
{
	// just make sure it executes
	sscep_engine_report_error();

	/* Todo: In the future it might be a good idea to force some errors and
	 * then overwrite "stderr" with a file and check that the expected errors
	 * got written. For now it is enough that this function cleanly executes.
	 */
}
END_TEST

#ifdef WIN32
START_TEST(test_scep_engine_init_capi)
{
	// todo: Make a test with the CAPI engine to make sure that path is taken.
}
END_TEST

START_TEST(test_sscep_engine_read_key_old_capi)
{
	// todo: implement windows only test where engine_id is "capi".
}
END_TEST

START_TEST(test_sscep_engine_read_key_new_capi)
{
	// todo: implement windows only test where engine_id is "capi".
}
END_TEST

START_TEST(test_sscep_engine_read_key_capi)
{
	// todo: implement function that performs a standard load through
	// the capi function "sscep_engine_read_key_capi"
}
END_TEST

START_TEST(test_sscep_engine_read_key_capi_cmd_fail)
{
	// todo: implement version where ENGINE_ctrl fails (for coverage)
}
END_TEST
#endif /* WIN32 */

Suite * scep_conf_suite(void)
{
	Suite *s = suite_create("Engine");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");
	tcase_add_checked_fixture(tc_core, setup, teardown);
	tcase_add_test(tc_core, test_scep_engine_init);
	tcase_add_test(tc_core, test_scep_engine_init_jksengine);
	tcase_add_test(tc_core, test_scep_engine_init_pkcs11);
	tcase_add_test(tc_core, test_scep_engine_load_dynamic);
	tcase_add_test(tc_core, test_sscep_engine_read_key);
	tcase_add_test(tc_core, test_sscep_engine_read_key_invalid_key);
	tcase_add_test(tc_core, test_sscep_engine_read_key_old);
	tcase_add_test(tc_core, test_sscep_engine_read_key_new);
	tcase_add_test(tc_core, test_sscep_engine_report_error);

#ifdef WIN32
	tcase_add_test(tc_core, test_scep_engine_init_capi);
	tcase_add_test(tc_core, test_sscep_engine_read_key_old_capi);
	tcase_add_test(tc_core, test_sscep_engine_read_key_new_capi);
	tcase_add_test(tc_core, test_sscep_engine_read_key_capi);
	tcase_add_test(tc_core, test_sscep_engine_read_key_capi_cmd_fail);
#endif /* WIN32 */

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
