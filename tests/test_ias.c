#include <check.h>
#include <stdlib.h>
#include "../src/sscep.h"
#include "../src/ias.h"

#define TEST_CSR "test-pki/test-ias.csr"
#define TEST_CA "test-pki/test-ias-ca.crt"


START_TEST(test_i2d_pkcs7_issuer_and_subject)
{
	BIO *test_databio;
	pkcs7_issuer_and_subject test_ias;
	X509_REQ *test_request = NULL;
	X509 *test_cacert = NULL;
	int ret;
	FILE *f;

	f = fopen(TEST_CSR, "r");
	PEM_read_X509_REQ(f, &test_request, NULL, NULL);
	fclose(f);
	f = fopen(TEST_CA, "r");
	PEM_read_X509(f, &test_cacert, NULL, NULL);
	fclose(f);
	test_databio = BIO_new(BIO_s_mem());
	test_ias.issuer = X509_get_issuer_name(test_cacert);
	test_ias.subject = X509_REQ_get_subject_name(test_request);
	ret = i2d_pkcs7_issuer_and_subject_bio(test_databio, &test_ias);
	ck_assert(ret > 0);

	BIO_free(test_databio);
	X509_REQ_free(test_request);
	X509_free(test_cacert);
}
END_TEST

START_TEST(test_pkcs7_issuer_and_subject_new_and_free)
{
	pkcs7_issuer_and_subject_free(pkcs7_issuer_and_subject_new());
}
END_TEST

Suite * scep_conf_suite(void)
{
	Suite *s = suite_create("Issuer and subject");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_i2d_pkcs7_issuer_and_subject);
	tcase_add_test(tc_core, test_pkcs7_issuer_and_subject_new_and_free);

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
