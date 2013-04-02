#include <check.h>
#include <stdlib.h>
#include "../src/configuration.h"

#define TEST_CONFIG_FILE "test_sscep.cnf"

CONF *conf;

void setup(void)
{
	long err;
	const char *filename = TEST_CONFIG_FILE;
	conf = NCONF_new(NCONF_default());
	NCONF_load(conf, filename, &err);
}

void teardown(void)
{
	NCONF_free(conf);
	if(scep_conf)
	{
		if(scep_conf->engine)
			free(scep_conf->engine);
		free(scep_conf);
	}
}

START_TEST(test_scep_conf_init)
{
	char *filename = TEST_CONFIG_FILE;
	int ret;
	ret = scep_conf_init(TEST_CONFIG_FILE);
	ck_assert(ret == 0);

	ck_assert(scep_conf_init(NULL) == -1);

}
END_TEST

START_TEST(test_scep_conf_init_exit)
{
	scep_conf_init("nonexistentfile...");
}
END_TEST

START_TEST(test_scep_conf_load)
{
	char *filename = TEST_CONFIG_FILE;
	int ret;

	// specify *some* operation flag, so the function does not return badly
	operation_flag = SCEP_OPERATION_ENROLL;

	ret = scep_conf_load(conf);
	fail_unless(ret == 0, "Function did not return cleanly.");

	// [sscep] section
	ck_assert(strcmp(scep_conf->engine_str, "sscep_engine") == 0);
	ck_assert(u_flag && strcmp(url_char, "http://my-test-url.com") == 0);
	ck_assert(p_flag && strcmp(p_char, "127.0.0.1:8000") == 0);
	ck_assert(c_flag && strcmp(c_char, "TestCACert.crt") == 0);
	ck_assert(E_flag && strcmp(E_char, "des") == 0);
	ck_assert(S_flag && strcmp(S_char, "sha1") == 0);
	ck_assert(M_flag && strcmp(M_char, "key1=value1&key2=value2") == 0);
	ck_assert(v_flag);
	ck_assert(d_flag);

	// [sscep_engine] section
	ck_assert_str_eq(scep_conf->engine->engine_id, "capi");
	ck_assert_str_eq(scep_conf->engine->dynamic_path, "..\\capi\\capi.dll");
	ck_assert(g_flag && strcmp(g_char, "capi") == 0);

	// [sscep_engine_capi] section
	ck_assert(strcmp(scep_conf->engine->new_key_location, "REQUEST") == 0);
	ck_assert(scep_conf->engine->storelocation == LOCAL_MACHINE);
	ck_assert(scep_conf->engine->module_path == NULL);
}
END_TEST

START_TEST(test_scep_conf_init_enroll)
{
	char *filename = TEST_CONFIG_FILE;
	int ret;
	operation_flag = SCEP_OPERATION_ENROLL;

	ret = scep_conf_init(filename);
	fail_unless(ret == 0, "Function did not return cleanly.");

	// [sscep] section
	ck_assert(strcmp(scep_conf->engine_str, "sscep_engine") == 0);
	ck_assert(u_flag && strcmp(url_char, "http://my-test-url.com") == 0);
	ck_assert(p_flag && strcmp(p_char, "127.0.0.1:8000") == 0);
	ck_assert(c_flag && strcmp(c_char, "TestCACert.crt") == 0);
	ck_assert(E_flag && strcmp(E_char, "des") == 0);
	ck_assert(S_flag && strcmp(S_char, "sha1") == 0);
	ck_assert(v_flag);
	ck_assert(d_flag);

	// [sscep_engine] section
	ck_assert(strcmp(scep_conf->engine->engine_id, "capi") == 0);
	ck_assert(strcmp(scep_conf->engine->dynamic_path, "..\\capi\\capi.dll") == 0);

	// [sscep_engine_capi] section
	ck_assert(strcmp(scep_conf->engine->new_key_location, "REQUEST") == 0);
	ck_assert(scep_conf->engine->storelocation == 1);

	// A single check is sufficient here: We only need to make sure that this
	// section of code was entered at all.
	ck_assert(k_flag && strcmp(k_char, "Test.key") == 0);

}
END_TEST

START_TEST(test_scep_conf_load_operation_enroll)
{
	int ret;

	ret = scep_conf_load_operation_enroll(conf);
	fail_if(ret);

	// [sscep_enroll] section
	ck_assert(k_flag && strcmp(k_char, "Test.key") == 0);
	ck_assert(r_flag && strcmp(r_char, "Test.csr") == 0);
	ck_assert(K_flag && strcmp(K_char, "Old_Test.key") == 0);
	ck_assert(O_flag && strcmp(O_char, "Old_Test.crt") == 0);
	ck_assert(l_flag && strcmp(l_char, "Test.crt") == 0);
	ck_assert(e_flag && strcmp(e_char, "EncCA.crt") == 0);
	ck_assert(L_flag && strcmp(L_char, "Selfsigned.crt") == 0);
	ck_assert(t_flag && t_num == 5);
	ck_assert(T_flag && T_num == 6);
	ck_assert(n_flag && n_num == 3);
	ck_assert(R_flag);
}
END_TEST

START_TEST(test_scep_conf_init_getca)
{
	char *filename = TEST_CONFIG_FILE;
	int ret;
	operation_flag = SCEP_OPERATION_GETCA;

	ret = scep_conf_init(filename);
	fail_unless(ret == 0, "Function did not return cleanly.");

	// [sscep_getca] section
	ck_assert(i_flag && strcmp(i_char, "TestCAIdentifier") == 0);
	ck_assert(F_flag && strcmp(F_char, "md5") == 0);

}
END_TEST

START_TEST(test_scep_conf_init_getcert)
{
	char *filename = TEST_CONFIG_FILE;
	int ret;
	operation_flag = SCEP_OPERATION_GETCERT;

	ret = scep_conf_init(filename);
	fail_unless(ret == 0, "Function did not return cleanly.");

	// [sscep_getcert] section
	ck_assert(k_flag && strcmp(k_char, "Test.key") == 0);
	ck_assert(l_flag && strcmp(l_char, "Old-Test.crt") == 0);
	ck_assert(s_flag && strcmp(s_char, "81985529216486895") == 0);
	ck_assert(w_flag && strcmp(w_char, "Test.crt") == 0);

}
END_TEST

START_TEST(test_scep_conf_init_getcrl)
{
	char *filename = TEST_CONFIG_FILE;
	int ret;
	operation_flag = SCEP_OPERATION_GETCRL;

	ret = scep_conf_init(filename);
	fail_unless(ret == 0, "Function did not return cleanly.");

	// [sscep_getcrl] section
	ck_assert(k_flag && strcmp(k_char, "Test.key") == 0);
	ck_assert(l_flag && strcmp(l_char, "Test.crt") == 0);
	ck_assert(w_flag && strcmp(w_char, "Test.crl") == 0);

}
END_TEST

START_TEST(test_scep_conf_init_getnextca)
{
	char *filename = TEST_CONFIG_FILE;
	int ret;
	operation_flag = SCEP_OPERATION_GETNEXTCA;

	ret = scep_conf_init(filename);
	fail_unless(ret == 0, "Function did not return cleanly.");

	// [sscep_getnextca] section
	ck_assert(i_flag && strcmp(i_char, "TestCAIdentifier") == 0);
	ck_assert(C_flag && strcmp(C_char, "TestChain.pem") == 0);
	ck_assert(F_flag && strcmp(F_char, "sha1") == 0);

}
END_TEST

Suite * scep_conf_suite(void)
{
	Suite *s = suite_create("Configuration");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");
	TCase *tc_operations = tcase_create("Operations");

	tcase_add_checked_fixture(tc_core, setup, teardown);
	tcase_add_test(tc_core, test_scep_conf_init);
	tcase_add_exit_test(tc_core, test_scep_conf_init_exit, SCEP_PKISTATUS_FILE);
	tcase_add_test(tc_core, test_scep_conf_load);


	tcase_add_checked_fixture(tc_operations, setup, teardown);
	tcase_add_test(tc_operations, test_scep_conf_init_enroll);
	tcase_add_test(tc_operations, test_scep_conf_load_operation_enroll);
	tcase_add_test(tc_operations, test_scep_conf_init_getca);
	tcase_add_test(tc_operations, test_scep_conf_init_getcert);
	tcase_add_test(tc_operations, test_scep_conf_init_getcrl);
	tcase_add_test(tc_operations, test_scep_conf_init_getnextca);

	suite_add_tcase(s, tc_core);
	suite_add_tcase(s, tc_operations);

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
