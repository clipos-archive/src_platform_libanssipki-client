// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#include <assert.h>
#include <fstream>
#include <string>
#include "csr.h"
#include "ca-certificate.h"
#include "p11-helper.h"
#include "db-helper.h"
#include "csr-template.h"
#include <unistd.h>
#include <iostream>
#include "anssipki-common.h"


const char* template1 = 
"[template]\n\
dn=c=FR,st=France,l=Paris,o=FOO_O,ou=FOO_OU,cn=FOO_CN_ROOT\n\
keyUsage=CA\n\
signAlgo=SHA512RSA\n\
publicKeyAlgo=RSA\n\
publicKeySize=1024\n\
validityFrom=2012-10-10\n\
validityTo=2014-10-10\n\
issuerDN=SELF\n";

const char* template2 = 
"[template]\n\
dn=c=FR,st=France,l=Paris,o=FOO_O,ou=FOO_OU,cn=FOO_CN_SERVERS\n\
keyUsage=CA\n\
signAlgo=SHA512RSA\n\
publicKeyAlgo=RSA\n\
publicKeySize=1024\n\
validityFrom=2012-10-10\n\
validityTo=2014-10-10\n\
issuerDN=c=FR,st=France,l=Paris,o=FOO_O,ou=FOO_OU,cn=FOO_CN_ROOT\n";

const char* template3 = 
"[template]\n\
dn=c=FR,st=France,l=Paris,o=FOO_O,ou=FOO_OU,cn=FOO_CN_CLIENTS\n\
keyUsage=CA\n\
signAlgo=SHA512RSA\n\
publicKeyAlgo=RSA\n\
publicKeySize=1024\n\
validityFrom=2012-10-10\n\
validityTo=2014-10-10\n\
issuerDN=c=FR,st=France,l=Paris,o=FOO_O,ou=FOO_OU,cn=FOO_CN_ROOT\n";

void list() {
	P11Helper::initInstance("/usr/lib/softhsm/libsofthsm.so",
		CKU_USER, "4242", "test");
	DBHelper::open("./libanssipki_client.db");


	std::list<CACertificate*> rootCAList = DBHelper::getInstance()->listRootCA();

	std::cout << "Listing root CA" << std::endl;
	for (std::list<CACertificate*>::iterator it = rootCAList.begin(); it != rootCAList.end(); ++it)
	{
		std::cout << "\t" << (*it)->getName() << std::endl;
	}


	P11Helper::closeInstance();
	DBHelper::close();
}


void tree(CACertificate& ca, int depth) {
	std::list<Certificate*> children = DBHelper::getInstance()->getChildren(ca);
	for (int i = 0; i < depth; i++)
		std::cout << "\t";
	std::cout << ca.getName() << std::endl;

	for (std::list<Certificate*>::iterator it = children.begin(); it != children.end(); ++it)
	{
		if ((*it)->isCA())
			tree(*(dynamic_cast<CACertificate*>(*it)), depth + 1);
		else
		{
			for (int i = 0; i < depth + 1; i++)
				std::cout << "\t";
			std::cout << (*it)->getName() << std::endl;
		}
	}

}

void tree() {
	P11Helper::initInstance("/usr/lib/softhsm/libsofthsm.so",
		CKU_USER, "4242", "test");
	DBHelper::open("./libanssipki_client.db");
	unsigned int depth;


	std::list<CACertificate*> rootCAList = DBHelper::getInstance()->listRootCA();

	std::cout << "Listing root CA" << std::endl;
	for (std::list<CACertificate*>::iterator it = rootCAList.begin(); it != rootCAList.end(); ++it)
	{
		tree(*(*it), 0);
	}


	P11Helper::closeInstance();
	DBHelper::close();
}


void create() {
	P11Helper::initInstance("/usr/lib/softhsm/libsofthsm.so",
		CKU_USER, "4242", "test");
	DBHelper::open("./libanssipki_client.db");

	CSRTemplate t1, t2, t3;

	if (t1.loadFromData(template1))
		t1.generate();
	if (t2.loadFromData(template2))
		t2.generate();
	if (t3.loadFromData(template3))
		t3.generate();
	P11Helper::closeInstance();
	DBHelper::close();
}

int main(void)
{
	// std::ifstream infile ("test.template");
	// 	std::string str ((std::istreambuf_iterator<char>(infile)),
	// 	std::istreambuf_iterator<char>());
	// std::cout << str << std::endl;
	create();
	tree();
}



