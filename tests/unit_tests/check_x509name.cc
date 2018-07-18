// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#include <anssipki-client.h>
#include <csr.h>

#include <check.h>

START_TEST (test_basic_1)
{
	CSR csr("C=FR", false);
	ck_assert_str_eq(csr.getSubjectDNString().c_str(), "C=FR");
}
END_TEST

START_TEST (test_basic_2)
{
	CSR csr("C=FR1,C=FR2", false);
	ck_assert_str_eq(csr.getSubjectDNString().c_str(), "C=FR1,C=FR2");
}
END_TEST

START_TEST (test_basic_3)
{
	CSR csr("C=FR,ST=France,L=Paris,O=FOO_O,OU=FOO_OU,CN=FOO_CN_ROOT", false);
	ck_assert_str_eq(csr.getSubjectDNString().c_str(),"C=FR,ST=France,L=Paris,O=FOO_O,OU=FOO_OU,CN=FOO_CN_ROOT");
}
END_TEST

START_TEST (test_basic_4)
{
	CSR csr("ST=France,L=Paris,O=FOO_O,OU=FOO_OU,CN=FOO_CN_ROOT,C=FR", false);
	ck_assert_str_eq(csr.getSubjectDNString().c_str(),"ST=France,L=Paris,O=FOO_O,OU=FOO_OU,CN=FOO_CN_ROOT,C=FR");
}
END_TEST

START_TEST (test_basic_5)
{
	try
	{
		CSR csr("CC=FR", false);
	} catch (BadFormatException e) {
		return;
	}
	ck_abort_msg("X509Name::addField should throw an exception if the field name != (C,ST,L,O,OU,CN)");
}
END_TEST

Suite*
x509name_suite(void)
{
	Suite *s = suite_create("X509Name");

	TCase *tc_core = tcase_create ("Core");
	tcase_add_test (tc_core, test_basic_1);
	tcase_add_test (tc_core, test_basic_2);
	tcase_add_test (tc_core, test_basic_3);
	tcase_add_test (tc_core, test_basic_4);
	tcase_add_test (tc_core, test_basic_5);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s = x509name_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all (sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free (sr);
	return (number_failed == 0) ? EXIT_SUCCESS :EXIT_FAILURE;
}