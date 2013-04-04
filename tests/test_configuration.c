#include <check.h>
#include <stdlib.h>
#include "../src/configuration.h"

#define TEST_CONFIG_FILE "test-conf/test_sscep.cnf"

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

void tc_load_setup(void)
{
	setup();
	scep_conf = malloc(sizeof(*scep_conf));
	scep_conf->engine = malloc(sizeof(struct scep_engine_conf_st));
	scep_conf->engine_str = NULL;
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

START_TEST(test_scep_conf_init_exit_invalid_format)
{
	scep_conf_init("test-conf/test_sscep_invalid_format.cnf");
}
END_TEST

START_TEST(test_error_memory)
{
	error_memory();
}
END_TEST

START_TEST(test_dump_conf)
{
	scep_conf_init(TEST_CONFIG_FILE);
	scep_dump_conf();
}
END_TEST

START_TEST(test_scep_conf_load)
{
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
	// (it doesn't matter if this isn't windows, we just need a test string)
	ck_assert_str_eq(scep_conf->engine->engine_id, "capi");
	ck_assert_str_eq(scep_conf->engine->dynamic_path, "..\\capi\\capi.dll");
	ck_assert(g_flag && strcmp(g_char, "capi") == 0);

#ifdef WIN32
	// [sscep_engine_capi] section
	ck_assert(strcmp(scep_conf->engine->new_key_location, "REQUEST") == 0);
	ck_assert(scep_conf->engine->storelocation == LOCAL_MACHINE);
	ck_assert(scep_conf->engine->module_path == NULL);
#endif
}
END_TEST

START_TEST(test_scep_conf_load_operation_switch)
{
	int ret, i;
	int ops[] = {SCEP_OPERATION_ENROLL,
				 SCEP_OPERATION_GETCA,
				 SCEP_OPERATION_GETCERT,
				 SCEP_OPERATION_GETCRL,
				 SCEP_OPERATION_GETNEXTCA};
	scep_conf = malloc(sizeof(*scep_conf));
	scep_conf->engine = malloc(sizeof(struct scep_engine_conf_st));
	scep_conf->engine_str = NULL;
	for(i=0; i<(sizeof(ops)/sizeof(int)); ++i)
	{
		operation_flag = ops[i];
		ret = scep_conf_load(conf);
		fail_if(ret);
	}

	operation_flag = NULL;
	ret = scep_conf_load(conf);
	ck_assert(ret == -1);
}
END_TEST

START_TEST(test_scep_conf_load_no_engine_section)
{
	int ret;
	CONF *local_conf;
	long err;
	local_conf = NCONF_new(NCONF_default());
	NCONF_load(local_conf, "test-conf/test_sscep_no_engine.cnf", &err);
	operation_flag = SCEP_OPERATION_ENROLL;
	ret = scep_conf_load(local_conf);
	fail_if(ret);
	NCONF_free(local_conf);
}
END_TEST

START_TEST(test_scep_conf_load_missing_engine_section)
{
	CONF *local_conf;
	long err;
	local_conf = NCONF_new(NCONF_default());
	NCONF_load(local_conf, "test-conf/test_sscep_missing_engine_section.cnf", &err);
	operation_flag = SCEP_OPERATION_ENROLL;
	scep_conf_load(local_conf);
	NCONF_free(local_conf);
}
END_TEST

START_TEST(test_scep_conf_load_missing_engine_id)
{
	CONF *local_conf;
	long err;
	local_conf = NCONF_new(NCONF_default());
	NCONF_load(local_conf, "test-conf/test_sscep_missing_engine_id.cnf", &err);
	operation_flag = SCEP_OPERATION_ENROLL;
	scep_conf_load(local_conf);
	NCONF_free(local_conf);
}
END_TEST

#ifdef WIN32
START_TEST(test_scep_conf_load_capi_defaults)
{
	CONF *local_conf;
	long err;
	int ret;
	local_conf = NCONF_new(NCONF_default());
	NCONF_load(local_conf, "test-conf/test_sscep_capi_defaults.cnf", &err);
	operation_flag = SCEP_OPERATION_ENROLL;
	ret = scep_conf_load(local_conf);
	fail_if(ret);
	ck_assert_str_eq(scep_conf->engine->new_key_location, "REQUEST");
	ck_assert(scep_conf->engine->storelocation == CURRENT_USER);
	NCONF_free(local_conf);

	local_conf = NCONF_new(NCONF_default());
	NCONF_load(local_conf, "test-conf/test_sscep_capi_current_user.cnf", &err);
	ret = scep_conf_load(local_conf);
	fail_if(ret);
	ck_assert(scep_conf->engine->storelocation == CURRENT_USER);
	NCONF_free(local_conf);

	local_conf = NCONF_new(NCONF_default());
	NCONF_load(local_conf, "test-conf/test_sscep_capi_invalid_storename.cnf", &err);
	ret = scep_conf_load(local_conf);
	fail_if(ret);

	ck_assert(scep_conf->engine->storelocation == CURRENT_USER);

	NCONF_free(local_conf);
}
END_TEST
#endif

START_TEST(test_scep_conf_load_jksengine)
{
	CONF *local_conf;
	long err;
	int ret;
	local_conf = NCONF_new(NCONF_default());
	NCONF_load(local_conf, "test-conf/test_sscep_jksengine.cnf", &err);
	operation_flag = SCEP_OPERATION_ENROLL;
	ret = scep_conf_load(local_conf);
	fail_if(ret);
	ck_assert_str_eq(scep_conf->engine->storepass, "helloworld");
	ck_assert_str_eq(scep_conf->engine->jconnpath, "/path/to/ConnJKSEngine.jar");
	ck_assert_str_eq(scep_conf->engine->provider, "SomeProvider");
	ck_assert_str_eq(scep_conf->engine->javapath, "/path/to/java");
	NCONF_free(local_conf);
}
END_TEST

START_TEST(test_scep_conf_load_pkcs11)
{
	CONF *local_conf;
	long err;
	int ret;
	local_conf = NCONF_new(NCONF_default());
	NCONF_load(local_conf, "test-conf/test_sscep_pkcs11engine.cnf", &err);
	operation_flag = SCEP_OPERATION_ENROLL;
	ret = scep_conf_load(local_conf);
	fail_if(ret);
	ck_assert_str_eq(scep_conf->engine->pin, "123");
	ck_assert_str_eq(scep_conf->engine->module_path, "/path/to/module.so");
	NCONF_free(local_conf);
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

START_TEST(test_scep_conf_load_operation_getca)
{
	int ret;

	ret = scep_conf_load_operation_getca(conf);
	fail_if(ret);

	// [sscep_getca] section
	ck_assert(i_flag && strcmp(i_char, "TestCAIdentifier") == 0);
	ck_assert(F_flag && strcmp(F_char, "md5") == 0);

}
END_TEST

START_TEST(test_scep_conf_load_operation_getcert)
{
	int ret;

	ret = scep_conf_load_operation_getcert(conf);
	fail_if(ret);

	// [sscep_getcert] section
	ck_assert(k_flag && strcmp(k_char, "Test.key") == 0);
	ck_assert(l_flag && strcmp(l_char, "Old-Test.crt") == 0);
	ck_assert(s_flag && strcmp(s_char, "81985529216486895") == 0);
	ck_assert(w_flag && strcmp(w_char, "Test.crt") == 0);

}
END_TEST

START_TEST(test_scep_conf_load_operation_getcrl)
{
	int ret;

	ret = scep_conf_load_operation_getcrl(conf);
	fail_if(ret);

	// [sscep_getcrl] section
	ck_assert(k_flag && strcmp(k_char, "Test.key") == 0);
	ck_assert(l_flag && strcmp(l_char, "Test.crt") == 0);
	ck_assert(w_flag && strcmp(w_char, "Test.crl") == 0);

}
END_TEST

START_TEST(test_scep_conf_load_operation_getnextca)
{
	int ret;

	ret = scep_conf_load_operation_getnextca(conf);
	fail_if(ret);

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
	TCase *tc_load = tcase_create("Config load");
	TCase *tc_operations = tcase_create("Operations");

	tcase_add_checked_fixture(tc_core, setup, teardown);
	tcase_add_test(tc_core, test_scep_conf_init);
	tcase_add_exit_test(tc_core, test_scep_conf_init_exit, SCEP_PKISTATUS_FILE);
	tcase_add_exit_test(tc_core, test_scep_conf_init_exit_invalid_format, SCEP_PKISTATUS_FILE);
	tcase_add_exit_test(tc_core, test_error_memory, 1);
	tcase_add_exit_test(tc_core, test_dump_conf, 0);

	tcase_add_checked_fixture(tc_load, tc_load_setup, teardown);
	tcase_add_test(tc_load, test_scep_conf_load);
	tcase_add_test(tc_load, test_scep_conf_load_operation_switch);
	tcase_add_test(tc_load, test_scep_conf_load_no_engine_section);
	tcase_add_exit_test(tc_load, test_scep_conf_load_missing_engine_section, SCEP_PKISTATUS_FILE);
	tcase_add_exit_test(tc_load, test_scep_conf_load_missing_engine_id, SCEP_PKISTATUS_FILE);
#ifdef WIN32
	tcase_add_test(tc_load, test_scep_conf_load_capi_defaults);
#endif
	tcase_add_test(tc_load, test_scep_conf_load_jksengine);
	tcase_add_test(tc_load, test_scep_conf_load_pkcs11);


	tcase_add_checked_fixture(tc_operations, setup, teardown);
	tcase_add_test(tc_operations, test_scep_conf_load_operation_enroll);
	tcase_add_test(tc_operations, test_scep_conf_load_operation_getca);
	tcase_add_test(tc_operations, test_scep_conf_load_operation_getcert);
	tcase_add_test(tc_operations, test_scep_conf_load_operation_getcrl);
	tcase_add_test(tc_operations, test_scep_conf_load_operation_getnextca);

	suite_add_tcase(s, tc_core);
	suite_add_tcase(s, tc_load);
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
