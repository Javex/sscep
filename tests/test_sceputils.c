#include <check.h>
#include <stdlib.h>
#include "../src/sscep.h"
#include "../src/ias.h"

#define TEST_CSR "test-pki/test-ias.csr"
#define TEST_KEY "test-pki/test-ias.key"

START_TEST(test_new_transaction)
{
	struct scep s;
	int ret;

	v_flag = 1;
	ret = new_transaction(&s);
	fail_if(ret);

	ck_assert(s.request_type == SCEP_REQUEST_NONE);
	ck_assert(s.request_type_str == NULL);
	ck_assert(s.reply_type == SCEP_REPLY_NONE);
	ck_assert(s.reply_type_str == NULL);
	ck_assert(s.pki_status == SCEP_PKISTATUS_UNSET);
	ck_assert(s.pki_status_str == NULL);
	ck_assert(s.fail_info_str == NULL);

	ck_assert(s.ias_getcertinit != NULL);
	ck_assert(s.ias_getcrl != NULL);
	ck_assert(s.ias_getcert != NULL);
	ck_assert_str_eq(s.transaction_id, TRANS_ID_GETCERT);
}
END_TEST

START_TEST(test_new_transaction_enroll)
{
	struct scep s;
	int ret;
	X509_REQ *test_request;
	FILE *f;

	v_flag = 1;
	f = fopen(TEST_CSR, "r");
	PEM_read_X509_REQ(f, &test_request, NULL, NULL);
	fclose(f);

	operation_flag = SCEP_OPERATION_ENROLL;
	request = test_request;
	ret = new_transaction(&s);
	fail_if(ret);

	ck_assert_str_eq(s.transaction_id, "12CA5E2C9D841915219123D0B5691196");
}
END_TEST

START_TEST(test_new_selfsigned)
{
	int ret;
	struct scep s;
	X509_REQ *test_request = NULL;
	FILE *f;
	EVP_PKEY *test_key = NULL;

	f = fopen(TEST_CSR, "r");
	PEM_read_X509_REQ(f, &test_request, NULL, NULL);
	fclose(f);
	request = test_request;
	read_key(&test_key, TEST_KEY);
	rsa = test_key;
	sig_alg = (EVP_MD *)EVP_md5();
	new_transaction(&s);
	mark_point();
	new_selfsigned(&s);
	mark_point();
	fail_if(ret);
}
END_TEST

START_TEST(test_init_scep)
{
	ck_assert(init_scep() == 0);
}
END_TEST

START_TEST(test_key_fingerprint)
{
	X509_REQ *test_request = NULL;
	FILE *f;
	char *tid;

	f = fopen(TEST_CSR, "r");
	PEM_read_X509_REQ(f, &test_request, NULL, NULL);
	fclose(f);
	tid = key_fingerprint(test_request);

	ck_assert_str_eq(tid, "12CA5E2C9D841915219123D0B5691196");
}
END_TEST

START_TEST(test_handle_serial)
{
	ck_assert_str_eq(handle_serial("0a"), "10");
	ck_assert_str_eq(handle_serial("0A"), "10");
	ck_assert_str_eq(handle_serial("12"), "12");
	ck_assert_str_eq(handle_serial("00:0A"), "10");
	ck_assert_str_eq(handle_serial("00:10"), "16");

}
END_TEST

Suite * scep_conf_suite(void)
{
	Suite *s = suite_create("Sceputils");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_new_transaction);
	tcase_add_test(tc_core, test_new_transaction_enroll);
	tcase_add_test(tc_core, test_new_selfsigned);
	tcase_add_test(tc_core, test_init_scep);
	tcase_add_test(tc_core, test_key_fingerprint);
	tcase_add_test(tc_core, test_handle_serial);

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
