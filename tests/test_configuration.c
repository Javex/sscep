#include <check.h>
#include <stdlib.h>
#include "../src/configuration.h"

START_TEST(test_scep_conf_init_enroll)
{
	char *filename = "test_sscep.cnf";
	int ret;
	operation_flag = SCEP_OPERATION_ENROLL;

	ret = scep_conf_init(filename);
	fail_unless(ret == 0, "Function did not return cleanly.");

	// [sscep] section
	fail_unless(strcmp(scep_conf->engine_str, "sscep_engine") == 0, NULL);
	fail_unless(u_flag && strcmp(url_char, "http://my-test-url.com") == 0, NULL);
	fail_unless(p_flag && strcmp(p_char, "127.0.0.1:8000") == 0, NULL);
	fail_unless(c_flag && strcmp(c_char, "TestCACert.crt") == 0, NULL);
	fail_unless(E_flag && strcmp(E_char, "des") == 0, NULL);
	fail_unless(S_flag && strcmp(S_char, "sha1") == 0, NULL);
	fail_unless(v_flag, NULL);
	fail_unless(d_flag, NULL);

	// [sscep_engine] section
	fail_unless(strcmp(scep_conf->engine->engine_id, "capi") == 0, NULL);
	fail_unless(strcmp(scep_conf->engine->dynamic_path, "..\\capi\\capi.dll") == 0, NULL);

	// [sscep_engine_capi] section
	fail_unless(strcmp(scep_conf->engine->new_key_location, "REQUEST") == 0, NULL);
	fail_unless(scep_conf->engine->storelocation == 1, NULL);

	// [sscep_enroll] section
	fail_unless(k_flag && strcmp(k_char, "Test.key") == 0, NULL);
	fail_unless(r_flag && strcmp(r_char, "Test.csr") == 0, NULL);
	fail_unless(K_flag && strcmp(K_char, "Old_Test.key") == 0, NULL);
	fail_unless(O_flag && strcmp(O_char, "Old_Test.crt") == 0, NULL);
	fail_unless(l_flag && strcmp(l_char, "Test.crt") == 0, NULL);
	fail_unless(e_flag && strcmp(e_char, "EncCA.crt") == 0, NULL);
	fail_unless(L_flag && strcmp(L_char, "Selfsigned.crt") == 0, NULL);
	fail_unless(t_flag && t_num == 5, NULL);
	fail_unless(T_flag && T_num == 6, NULL);
	fail_unless(n_flag && n_num == 3, NULL);
	fail_unless(R_flag, NULL);

	free(scep_conf);
}
END_TEST

START_TEST(test_scep_conf_init_getca)
{
	char *filename = "test_sscep.cnf";
	int ret;
	operation_flag = SCEP_OPERATION_GETCA;

	ret = scep_conf_init(filename);
	fail_unless(ret == 0, "Function did not return cleanly.");

	// [sscep_getca] section
	fail_unless(i_flag && strcmp(i_char, "TestCAIdentifier") == 0, NULL);
	fail_unless(F_flag && strcmp(F_char, "md5") == 0, NULL);

	free(scep_conf);
}
END_TEST

START_TEST(test_scep_conf_init_getcert)
{
	char *filename = "test_sscep.cnf";
	int ret;
	operation_flag = SCEP_OPERATION_GETCERT;

	ret = scep_conf_init(filename);
	fail_unless(ret == 0, "Function did not return cleanly.");

	// [sscep_getcert] section
	fail_unless(k_flag && strcmp(k_char, "Test.key") == 0, NULL);
	fail_unless(l_flag && strcmp(l_char, "Old-Test.crt") == 0, NULL);
	fail_unless(s_flag && strcmp(s_char, "81985529216486895") == 0, NULL);
	fail_unless(w_flag && strcmp(w_char, "Test.crt") == 0, NULL);

	free(scep_conf);
}
END_TEST

START_TEST(test_scep_conf_init_getcrl)
{
	char *filename = "test_sscep.cnf";
	int ret;
	operation_flag = SCEP_OPERATION_GETCRL;

	ret = scep_conf_init(filename);
	fail_unless(ret == 0, "Function did not return cleanly.");

	// [sscep_getcrl] section
	fail_unless(k_flag && strcmp(k_char, "Test.key") == 0, NULL);
	fail_unless(l_flag && strcmp(l_char, "Test.crt") == 0, NULL);
	fail_unless(w_flag && strcmp(w_char, "Test.crl") == 0, NULL);

	free(scep_conf);
}
END_TEST

START_TEST(test_scep_conf_init_getnextca)
{
	char *filename = "test_sscep.cnf";
	int ret;
	operation_flag = SCEP_OPERATION_GETNEXTCA;

	ret = scep_conf_init(filename);
	fail_unless(ret == 0, "Function did not return cleanly.");

	// [sscep_getnextca] section
	fail_unless(i_flag && strcmp(i_char, "TestCAIdentifier") == 0, NULL);
	fail_unless(C_flag && strcmp(C_char, "TestChain.pem") == 0, NULL);
	fail_unless(F_flag && strcmp(F_char, "sha1") == 0, NULL);

	free(scep_conf);
}
END_TEST

Suite * scep_conf_suite(void)
{
	Suite *s = suite_create("Configuration");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");
	tcase_add_test(tc_core, test_scep_conf_init_enroll);
	tcase_add_test(tc_core, test_scep_conf_init_getca);
	tcase_add_test(tc_core, test_scep_conf_init_getcert);
	tcase_add_test(tc_core, test_scep_conf_init_getcrl);
	tcase_add_test(tc_core, test_scep_conf_init_getnextca);
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
